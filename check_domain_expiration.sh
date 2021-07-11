#!/bin/bash

#############################################
#
# This plugin checks domain expiration date
#
# Author: Emil Wypych
#
# Contact: wypychemil at gmail.com
#
# GitHub: https://github.com/ewypych/icinga-domain-expiration-plugin
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
		EXDATE_TMP=$(${WHOIS} -h whois.internic.com "=${1}" | ${AWK} '/Registry Expiry Date:/ { print $4 }' | cut -c 1-16)
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "ie" ]
	then
	        EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/Registry Expiry Date:/ { gsub("[:.]","-"); print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE_TMP" ]
		then
		        EXP_DAYS=NULL
		else
		        EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
	        fi
	elif [ "$DTYPE" == "se" ] || [ "$DTYPE" == "nu"  ]
	then
		EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/expires:/ { print $2 }')
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "ua" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.ua "${1}" | ${AWK} '/expires:/ { print $2 }')
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "asia" ]
	then
		EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/Registry Expiry Date:/ { print $4 }' | cut -c 1-16)
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "org" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.pir.org "${1}" | ${AWK} '/Expiry Date:/ { print $4 }' | cut -c 1-16)
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "info" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.afilias.info "${1}" | ${AWK} '/Expiry Date:/ { print $4 }' | cut -c 1-16)
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "net" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.verisign-grs.com "${1}" | ${AWK} '/Registry Expiry Date:/ { print $4 }' | cut -c 1-16)
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "dev" ]
	then
		EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/Registry Expiry Date:/ { print $4 }' | cut -c 1-16)
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "center" ]
	then
		EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/Registry Expiry Date:/ { print $4 }' | cut -c 1-16)
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "pro" ]
	then
		EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/Registry Expiry Date:/ { print $4 }' | cut -c 1-16)
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "me" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.nic.me "${1}" | ${AWK} '/Registry Expiry Date:/ { print $4 }' | cut -c 1-16)
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "su" ]
	then
		EXDATE=$(${WHOIS} "${1}" | ${AWK} '/paid-till:/ { print $2 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "xn--p1ai" ]
	then
		EXDATE=$(${WHOIS} "${1}" | ${AWK} '/paid-till:/ { print $2 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "ru" ]
	then
		EXDATE=$(${WHOIS} "${1}" | ${AWK} '/paid-till:/ { print $2 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "moscow" ]
	then
		EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/Registry Expiry Date:/ { print $4 }' | cut -c 1-16)
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "art" ]
	then
		EXDATE=$(${WHOIS} -h whois.nic.art "${1}" | ${AWK} '/Registry Expiry Date:/ { gsub("[:.]","-"); print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "pl" ]
	then
		EXDATE=$(${WHOIS} "${1}" | ${AWK} '/renewal date:/ { gsub("[:.]","-"); print $3 }')
		if [ -z "$EXDATE" ]
		then
			EXDATE=$(${WHOIS} -h whois.dns.pl "${1}" | ${AWK} '/expiration date:/ { gsub("[:.]","-"); print $3 }')
			if [ -z "$EXDATE" ]
			then
				EXP_DAYS=NULL
			else
				EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
			fi
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "cz" ]
	then
		EXDATE=$(${WHOIS} -h whois.nic.cz "${1}" | ${AWK} '/expire:/ { print $2 }' | ${AWK} '{ split($0, d, "."); print d[3]"-"d[2]"-"d[1] }')
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "sk" ]
	then
		EXDATE=$(${WHOIS} -h whois.sk-nic.sk "${1}" | ${AWK} '/Valid Until:/ { print $3 }')
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "biz" ]
	then
		EXDATE=$(${WHOIS} -h whois.biz "${1}" | ${AWK} '/Registry Expiry Date:/ { print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "fr" -o "$DTYPE" == "re" -o "$DTYPE" == "yt" -o "$DTYPE" == "tf" -o "$DTYPE" == "wf" -o "$DTYPE" == "pm" ]
	then
		EXDATE=$(${WHOIS} -h whois.afnic.fr "${1}" | ${AWK} '/Expiry Date:/ { gsub("[:.]","-"); print $3 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "shop" ]
	then
		EXDATE=$(${WHOIS} -h whois.nic.shop "${1}" | ${AWK} '/Registry Expiry Date:/ { gsub("[:.]","-"); print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi


	elif [ "$DTYPE" == "tv" ]
	then
		EXDATE=$(${WHOIS} -h tvwhois.verisign-grs.com "${1}" | ${AWK} '/Registry Expiry Date:/ { gsub("[:.]","-"); print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi


	elif [ "$DTYPE" == "im" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.nic.im "${1}" | ${AWK} '/Expiry Date:/ { gsub("[:.]","-"); print $3 }' | cut -d 'T' -f1 | awk -F[/] '{print $2"/"$1"/"$3}')
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi

	elif [ "$DTYPE" == "uk" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.nic.uk "${1}" | grep 'Expiry date' | ${AWK} '{ print $3 }' )
		if [ -z "$EXDATE_TMP" ]
			then
				EXP_DAYS=NULL
			else
				EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
				EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi


	elif [ "$DTYPE" == "tech" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.nic.tech "${1}" | grep -i 'Expiry Date' | ${AWK} '{ print $4 }' )
		if [ -z "$EXDATE_TMP" ]
			then
				EXP_DAYS=NULL
			else
				EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
				EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi


	elif [ "$DTYPE" == "co" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.nic.co "${1}" | grep -i 'Expiry Date' | ${AWK} '{ print $4 }' )
		if [ -z "$EXDATE_TMP" ]
			then
				EXP_DAYS=NULL
			else
				EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
				EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi


	elif [ "$DTYPE" == "digital" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.nic.digital "${1}" | grep -i 'Expiry Date' | ${AWK} '{ print $4 }' )
		if [ -z "$EXDATE_TMP" ]
			then
				EXP_DAYS=NULL
			else
				EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
				EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi


	elif [ "$DTYPE" == "br" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.registro.br "${1}" | grep -i 'expires' | ${AWK} '{ print $2 }' )
		if [ -z "$EXDATE_TMP" ]
			then
				EXP_DAYS=NULL
			else
				EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
				EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi

	elif [ "$DTYPE" == "do" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.nic.do "${1}" | ${AWK} '/Registrar Registration Expiration Date:/ { print $5 }')
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "id" ]
	then
	        EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/Expiration Date:/ { print $3 }')
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "it" ]
	then
		EXDATE_TMP=$(${WHOIS} -h whois.nic.it "${1}" | grep -i "Expire Date" | ${AWK} '{ print $3 }')
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "club" ]
	then
		EXDATE=$(${WHOIS} -h whois.nic.club "${1}" | ${AWK} '/Registry Expiry Date:/ { gsub("[:.]","-"); print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "io" ]
	then
		EXDATE=$(${WHOIS} -h whois.nic.io "${1}" | ${AWK} '/Registry Expiry Date:/ { gsub("[:.]","-"); print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "space" ]
	then
	        EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/Registry Expiry Date:/ { gsub("[:.]","-"); print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE_TMP" ]
		then
		        EXP_DAYS=NULL
		else
		        EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
	        fi
	elif [ "$DTYPE" == "rocks" ]
	then
	        EXDATE_TMP=$(${WHOIS} "${1}" | ${AWK} '/Registry Expiry Date:/ { gsub("[:.]","-"); print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE_TMP" ]
		then
		        EXP_DAYS=NULL
		else
		        EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
	        fi
	elif [ "$DTYPE" == "us"  ]
	then
		EXDATE=$(${WHOIS} -h www.whois.us "${1}" | ${AWK} '/Registry Expiry Date:/ { gsub("[:.]","-"); print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	elif [ "$DTYPE" == "in" ]
	then
		EXDATE=$(${WHOIS} -h whois.registry.in "${1}" | ${AWK} '/Registry Expiry Date:/ { gsub("[:.]","-"); print $4 }' | cut -d 'T' -f1)
		if [ -z "$EXDATE" ]
		then
			EXP_DAYS=NULL
		else
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi
	else
		echo "UNKNOWN - "$DTYPE" unsupported"
		exit 3
	fi
}

# Check function for a specific whois
check_domain_by_whois()
{
	# Set domain
	DOMAIN=$1
	SERVER=$2

	if [ "$SERVER" == "whois.crazydomains.com" ]
	then
		EXDATE_TMP=$(${WHOIS} -h ${SERVER} "${DOMAIN}" | grep -i 'Expiration Date' | ${AWK} '{ print $5 }' )
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi


	elif [ "$SERVER" == "whois.cloudflare.com" ]
	then
		EXDATE_TMP=$(${WHOIS} -h ${SERVER} "${DOMAIN}" | grep -i 'Expiration Date' | ${AWK} '{ print $5 }' )
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi

	elif [ "$SERVER" == "whois.drs.ua" -o "$SERVER" == "whois.pp.ua" -o "$SERVER" == "whois.biz.ua" ]
	then
		EXDATE_TMP=$(${WHOIS} -h ${SERVER} "${DOMAIN}" | awk '/Expiration Date:/ { gsub("[:.]"," "); print $3 }' )
		if [ -z "$EXDATE_TMP" ]
		then
			EXP_DAYS=NULL
		else
			EXDATE=`date -d"$EXDATE_TMP" +%Y-%m-%d`
			EXP_DAYS=$(( ( $(date -ud ${EXDATE} +'%s') - $(date -ud `date +%Y-%m-%d` +'%s') )/60/60/24 ))
		fi

	else
		echo "UNKNOWN - "$SERVER" unsupported"
		exit 3
	fi
}

# Help function
help()
{
	echo "Usage: $0 [ -d domain_name ] [ -s whois_server ] [ -w ex_days ] [ -c ex_days ] [ -h ]"
	echo
	echo "  -d domain        : Domain to check"
	echo "  -s whois server  : Whois server to query by"
	echo "  -h               : Show help"
	echo "  -w days          : Domain expiration days (warning)"
	echo "  -c days          : Domain expiration days (critical)"
	echo
}

while getopts :hd:s:w:c: option
do
	case "${option}"
	in
		d) DOMAIN=$( echo ${OPTARG} );;
		s) SERVER=$OPTARG;;
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

if [ "${SERVER:=auto}" == auto ]
then
	check_domain "${DOMAIN}"
else
	check_domain_by_whois "${DOMAIN}" "${SERVER}"
fi

# exit codes based on the check_domain result

if ! [[ "$EXP_DAYS" =~ ^-?[0-9]+$ ]]
then
	echo "UNKNOWN - ${DOMAIN}: expiration date has not been provided by WHOIS server"
	exit 3
else
	if [ $EXP_DAYS -gt $WARNING  ]
	then
		echo "OK - ${DOMAIN}: $EXP_DAYS days until domain expires"
		exit 0
	elif [ $EXP_DAYS -le $WARNING -a $EXP_DAYS -gt $ALARM ]
	then
		echo "WARNING - ${DOMAIN}: $EXP_DAYS days until domain expires"
		exit 1
	elif [ $EXP_DAYS -le $ALARM -a $EXP_DAYS -gt 0 ]
	then
		echo "CRITICAL - ${DOMAIN}: $EXP_DAYS days until domain expires"
		exit 2
	elif [  $EXP_DAYS -lt 0  ]
	then
		echo "CRITICAL - ${DOMAIN}: domain has expired!"
		exit 2
	else
		echo "UNKNOWN - ${DOMAIN}: $EXP_DAYS"
		exit 3
	fi
fi
