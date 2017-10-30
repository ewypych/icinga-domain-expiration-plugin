#!/bin/bash

#############################################
#
# This plugin checks domain expiration date
#
# Author: Emil Wypych
#
# Contact: wypychemil at gmail.com
#
#############################################

# default days for warning (can change with -w cmd)
WARNING=30
 
# default days for critical (can change with -c cmd)
ALARM=10

# binaries path
WHOIS="/usr/bin/whois"
AWK="/usr/bin/awk"

# Main check function
check_domain()
{
	# Set domain
	DOMAIN=$1

	# check root domain
	DTYPE=$( echo $DOMAIN | awk -F "." '{print $NF}' )
	
	if [ "$DTYPE" == "com" ]
	then
		# "=${1}" because of many possibilities - check out google.com with "whois google.com"
		EXDATE_TMP=$(${WHOIS} -h whois.internic.com "=${1}" | ${AWK} '/Expiration Date:/ { print $3 }')
		EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
		EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
        elif [ "$DTYPE" == "asia" ]
        then
                EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/Registry Expiry Date:/ { print $4 }')
                EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
                EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
	elif [ "$DTYPE" == "org" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.pir.org "${1}" | ${AWK} '/Expiry Date:/ { print $4 }')
		EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
		EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
	elif [ "$DTYPE" == "info" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.afilias.info "${1}" | ${AWK} '/Expiry Date:/ { print $4 }')
		EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
		EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
	elif [ "$DTYPE" == "net" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.verisign-grs.com "${1}" | ${AWK} '/Expiration Date:/ { print $5 }')
		EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
		EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
	elif [ "$DTYPE" == "ru" ]
	then
		EXDATE=$(${WHOIS} -h whois.tcinet.ru "${1}" | ${AWK} '/free-date:/ { print $2 }')
		EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
	elif [ "$DTYPE" == "pl" ]
	then
		EXDATE=$(${WHOIS} "${1}" | ${AWK} '/renewal date:/ { gsub("[:.]","-"); print $3 }') 
		if [ -z "$EXDATE" ]
		then
			EXDATE=$(${WHOIS} -h whois.dns.pl "${1}" | ${AWK} '/expiration date:/ { gsub("[:.]","-"); print $3 }') 
		fi
		EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
	else
		echo "UNKNOWN - "$DTYPE" unsupported"
		exit 3
	fi
}

# Help function
help()
{
        echo "Usage: $0 [ -d domain_name ] [ -w ex_days ] [ -c ex_days ] [ -h ]"
        echo ""
        echo "  -d domain        : Domain to check"
        echo "  -h               : Show help"
        echo "  -w days          : Domain expiration days (warning)"
	echo "  -c days          : Domain expiration days (critical)"
        echo ""
}

while getopts :hd:w:c: option
do
        case "${option}"
        in
                d) DOMAIN=${OPTARG};;
                w) WARNING=$OPTARG;;
		c) ALARM=$OPTARG;;
                h | *) help
                    exit 3;;
        esac
done

# check whether ALARM is greater or equal WARNING
if [ $ALARM -ge $WARNING ]
then
	echo "UNKNOWN - CRITICAL threshold cannot be bigger than WARNING"
	exit 3
fi

check_domain "${DOMAIN}"

# exit codes based on the check_domain result

if [ $EXP_DAYS -gt $WARNING  ]
then
	echo "OK - $EXP_DAYS days until domain expires"
	exit 0
elif [ $EXP_DAYS -le $WARNING -a $EXP_DAYS -gt $ALARM ]
then
	echo "WARNING - $EXP_DAYS days until domain expires"
	exit 1
elif [ $EXP_DAYS -le $ALARM -a $EXP_DAYS -gt 0 ]
then 
	echo "CRITICAL - $EXP_DAYS days until domain expires"
	exit 2
elif [  $EXP_DAYS -lt 0  ]
then
	echo "CRITICAL - domain has expired!"
	exit 2
else
	echo "UNKNOW - $EXP_DAYS"
	exit 3
fi
