#!/bin/bash

versionString="1.2"

version()
{
	echo "cvechecker $versionString"
}


usage()
{
	cat <<'EOUSAGE'
Description: Check for all/specific CVEs on multiple servers and docker containers.

Usage:	cvechecker path/to/hosts/file
        cvechecker -l "HOST1 HOST2 USER@HOST3..."
        cvechecker [-c "CVE CVE2"] path/to/hosts/file
        cvechecker [-d "/path/to/dir /path/to/another/dir"] path/to/hosts/file
        cvechecker [-s] path/to/hosts/file
        cvechecker [-j NUMBER] path/to/hosts/file
        cvechecker [-n] path/to/hosts/file
        cvechecker -h | -V | -v | --help | --version

        -l give remote hosts as a command line argument instead of a path to a file
        -c for which CVEs to search. To search for any CVE just write 'all'. Defaults to all if none are specified
        -d which directories of the host to search through. Defaults to '/', if none are specified
        -s slow/step-by-step mode in which there are no more than 10 ssh connections simultaneously
        -j how many ssh sessions to have simultaneously
        -n create the remote script and print it
        -h display program usage information and exit
        -V display program version information and exit
        -v display program version information and exit

EOUSAGE
}

#Dafaults
maxNumberOfSshSessions=10
numberOfRequiredArguments=1
dirToCheck="/"

while getopts 'lc:d:sj:nhVv-:' o; do
	case "$o" in
        l)
            lFlag=1
            ((numberOfRequiredArguments++))
            ;;

        c)
            cveList=$OPTARG
            cveList=$(sed 's+ +\\|+g' <<< "${cveList}")
            ((numberOfRequiredArguments+=2))
            ;;

        d)
            dirToCheck=$OPTARG
            ((numberOfRequiredArguments++))
            ;;

        s)
            sFlag=1
            ((numberOfRequiredArguments++))
            ;;

        j)
            maxNumberOfSshSessions=$OPTARG
            sFlag=1
            ((numberOfRequiredArguments+=2))
            ;;

		n)
            nFlag=1
            ((numberOfRequiredArguments++))
            ;;

        h)
			hFlag=1
			;;

        V)
			vFlag=1
			;;

		v)
			vFlag=1
			;;

		-)
			if [ "$OPTARG" = 'help' ]; then
				hFlag=1
			elif [ "$OPTARG" = 'version' ]; then
				vFlag=1
			else
				echo "Invalid long option ""$OPTARG"" specified" 1>&2
				usage 1>&2
				exit 1
			fi
			;;

		*)
			usage 1>&2
			exit 1
			;;
	esac
done

[ -z "$vFlag" ] || version
[ -z "$hFlag" ] || usage
[ -z "$vFlag$hFlag" ] || exit 0

#Check if the needed number of arguments are provided

if [[ $# -ne $numberOfRequiredArguments ]]; then
	usage 1>&2
	exit 1
fi

#Check if hosts are provided either as file or as an argument

if [ $lFlag ]
then
    hosts=${@:$#:1}
else
    if ! [ -f "${@:$#:1}" ]
    then
        echo "There is no ${@:$#:1} file in this directory" 1>&2
        exit 2
    fi
    hosts=$(cat "${@:$#:1}")
fi

#Prepare local directory for storing results

mkdir -p "cvechecker"

#Prepare remote script

remoteScript=$(cat << EOREMOTESCRIPT

#!/bin/bash

#Install all needed dependencies
apt-get install -y jq
yum install -y jq
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin


#get starting directory

ogDir=\$(pwd)


#get directories to check

dirs=${dirToCheck}


#create directory for docker image save files and go into it

mkdir -p dockerImages
cd dockerImages


#check if there is docker

if command -v docker &> /dev/null
then

#Collect 'docker image save' for all containers
    for i in \$(sudo docker ps --format "{{json . }}" | jq -r '"\(.Image) \(.Names)"' | sed 's/ /*/g')
    do
        image=\$(echo "\${i}" | awk -F* '{print \$1}')
        name=\$(echo "\${i}" | awk -F* '{print \$2}')
        docker image save "\${image}" > "\${name}.image"
    done

#Check all images for packets with CVE
    for i in \$(ls)
    do
        echo "Container name: \${i}"
        grype "\${i}" | grep "${cveList}" >> \${ogDir}/cvecheck.results
    done
fi

#Check host for packets with CVE
echo "Host:\$(hostname)"
for i in \$(echo "\${dirs}")
do
    grype dir:\${i} | grep "${cveList}" >> \${ogDir}/cvecheck.results
done

#Mark the job as finished
echo 'Checks finished. Job done.' >> \${ogDir}/cvecheck.results

EOREMOTESCRIPT
)

if [ $nFlag ]
then
    echo "${remoteScript}"
    rm -r "cvechecker"
    exit 0
fi

#Function to copy, run, disown and check for end of script on remote hosts. Explanation on `>&- 2>&- <&- &` can be found right here: https://serverfault.com/questions/172484/doing-a-long-running-command-on-ssh

function runScript() {

    hostToCheck="$1"
    echo "Starting check on host \"${hostToCheck}\""
    ssh -q "${hostToCheck}" "mkdir -p cvecheck" < /dev/null #Prepare remote directory
    echo "${remoteScript}" | ssh -q "${hostToCheck}" "cat > cvecheck/cvecheck.sh" #Copy script
    ssh -q "${hostToCheck}" "sudo chmod +x cvecheck/cvecheck.sh" #make script executable
    ssh -q "${hostToCheck}" "cd cvecheck ; nohup sudo ./cvecheck.sh >> ./cvecheck.messages 2>&1 &" < /dev/null #Run and disown script

#Check if script has finished
    for (( ; ; ))
    do
        jobDone=$(ssh -q "${hostToCheck}" 'grep "Checks finished. Job done." cvecheck/cvecheck.results' < /dev/null)
        if [ -n "${jobDone}" ]
        then
            break
        fi
        sleep 5m
        echo "Waiting on check to finish on host \"${hostToCheck}\""
    done

#Copy results to a local file
    result=$(ssh -q "${hostToCheck}" "sudo cat cvecheck/cvecheck.results" < /dev/null)
    echo "${result}" >> "cvechecker/${hostToCheck}.results"

#Copy messages to a local file
    result=$(ssh -q "${hostToCheck}" "sudo cat cvecheck/cvecheck.messages" < /dev/null)
    echo "${result}" >> "cvechecker/${hostToCheck}.messages"

#Cleanup remote directory
    ssh -q "${hostToCheck}" "sudo rm -r cvecheck" < /dev/null

    echo "Check has finished on host \"${hostToCheck}\""

    return 0
}

if [ -z "$sFlag" ]
then
    numberOfSshSessions=0
    for server in $hosts; do
        if [[ ${numberOfSshSessions} -ge ${maxNumberOfSshSessions} ]]
        then
            wait -n
            ((numberOfSshSessions--))
        fi
        runScript "${server}" &
        ((numberOfSshSessions++))
    done
else
    for server in $hosts; do
        runScript "${server}" &
    done
fi

wait

echo "Start of file" > cvechecker-output.txt

for server in $hosts; do

    outputFile="cvechecker/${server}.results"
    echo "Host ${server}:" >> cvechecker-output.txt
    head -n -1 "${outputFile}" >> cvechecker-output.txt

    messagesFile="cvechecker/${server}.messages"
    echo "Host ${server}:" >> cvechecker-messages.txt
    head -n -1 "${outputFile}" >> cvechecker-messages.txt
done

cat cvechecker-output.txt

rm -r "cvechecker"

exit 0
