#!/bin/bash


#Defining Variables.
reg="(slice)"
MYPATH=/security/DEV/jsscanner
#ALLDOMAINSFILE=$MYPATH/alldomains.txt
domain=$1
ALLDOMAINSFILE="/security/DEV/Asset-Discovery/files/$domain/currently-active-subdomains.txt"
FILENAME="$(uuidgen)_dailyreport_`date +"%Y-%m-%d"`.txt"
REPORTFILE=$MYPATH/$FILENAME
TEMPJSCONTENTFILE=$MYPATH/tempjscontent.txt


ALLJSFILE=$MYPATH/alljs.txt
BLACKLISTEDJSFILE=$MYPATH/blacklistedjs.txt
BLACKLISTEDDOMAINFILE=$MYPATH/blacklisteddomains.txt
DIGESTDB=$MYPATH/digestdb.txt
SECRETFINDERFILE=$MYPATH/SecretFinder.py
REPORTHANDLERFILE=$MYPATH/reporthandler.py
TEMPWORKINGDOMAINSFILE=$MYPATH/tempworkingdomains.txt
#Creating required files
#touch $REPORTFILE
#touch $TEMPJSCONTENTFILE
test -e  $BLACKLISTEDJSFILE|| touch $BLACKLISTEDJSFILE
test -e $DIGESTDB || touch $DIGESTDB
test -e $BLACKLISTEDDOMAINFILE || touch $BLACKLISTEDDOMAINFILE
#cheking working domains
cat  $ALLDOMAINSFILE |httpx   -silent >$TEMPWORKINGDOMAINSFILE

#Gathering js files with tools

for subdom in $(cat $TEMPWORKINGDOMAINSFILE);do

subd=$(echo $subdom|cut -d "/" -f3)
touch $ALLJSFILE
echo $subd

gospider -s $subdom  -c 10| egrep -i "\.js$|\.js\?"| egrep -io "http.*"| cut -d "]" -f1 | \
httpx  -mc 200 -silent  |tee  -a $ALLJSFILE
echo "Gospider done"

#echo $subdom|gau|egrep -i "\.js$|\.js\?"| httpx  -mc 200 -silent| tee -a $ALLJSFILE$subd.txt
echo "Gau done"
#echo $subdom|waybackurls|egrep -i "\.js$|\.js\?"| httpx -mc 200  -silent  |tee -a $ALLJSFILE$subd.txt
echo "waybackurls done"
#Working on each js file in loop.
done


executeb () { 

#extracting domain from js url.
DOMAIN=$(echo $URL|cut -d "/" -f3|cut -d "?" -f1)
    #check if the js file is blacklisted or not(whole domain or this js url only).
    if grep -Fxq $URL $BLACKLISTEDJSFILE | grep -Fxq $DOMAIN $BLACKLISTEDDOMAINFILE 
    then
        echo "$(tput setaf 1)$URL has been blacklisted $(tput setaf 0)"
    else
        curl -s $URL > $TEMPJSCONTENTFILE
    
        #calculating message digest of file's content.
        DIGEST=$(sha256sum $TEMPJSCONTENTFILE |cut -d " " -f 1)
        #check if the js file has already been scanned in past by comparing its digest with the previously scanned ones.
        if grep -Fxq $DIGEST  $DIGESTDB
        then
	    rm $TEMPJSCONTENTFILE
            echo  "$(tput setaf 3)$URL has already been scanned. $(tput setaf 0)"
        else
            echo "$(tput setaf 2)$URL is being scanned. $(tput setaf 0)"
            python3 $SECRETFINDERFILE -i $URL -o cli>> $REPORTFILE
            echo "" >>$REPORTFILE
        
            #Adding message digest of this file to our database.
            echo $DIGEST >>$DIGESTDB
        fi
    fi

}





executew () { 

#extracting domain from js url.
DOMAIN=$(echo $URL|cut -d "/" -f3|cut -d "?" -f1)
    #check if the js file is blacklisted or not(whole domain or this js url only).
    if egrep $reg <<< $URL ;then
        
        curl -s $URL > $TEMPJSCONTENTFILE
    
        #calculating message digest of file's content.
        DIGEST=$(sha256sum $TEMPJSCONTENTFILE |cut -d " " -f 1)
        #check if the js file has already been scanned in past by comparing its digest with the previously scanned ones.
        if grep -Fxq $DIGEST  $DIGESTDB
        then
            rm $TEMPJSCONTENTFILE
            echo  "$(tput setaf 3)$URL has already been scanned. $(tput setaf 0)"
        else
            echo "$(tput setaf 2)$URL is being scanned. $(tput setaf 0)"
            python3 $SECRETFINDERFILE -i $URL -o cli>> $REPORTFILE
            echo "" >>$REPORTFILE
        
            #Adding message digest of this file to our database.
            echo $DIGEST >>$DIGESTDB
        fi
    else
	echo "$(tput setaf 1) $URL is not in the whitelist $(tput setaf 0)"
    fi

}





if [ $2="w" ] ;then
	threads=1
	for URL in $(cat $ALLJSFILE)
		do
		((i=i%threads)); ((i++==0)) && wait
		executew &
	done



else
	threads=1
	for URL in $(cat $ALLJSFILE)
	do
		((i=i%threads)); ((i++==0)) && wait
	executeb &
	done

fi

echo "Cooling down..."
sleep 25

#Refreshing our message digest database
sort -u -o $DIGESTDB $DIGESTDB
#Counting new js files scanned

if test -e $REPORTFILE; then
	SCANNEDJSCOUNT=$(egrep "^(\[ \+ \])" $REPORTFILE|wc -l)
	FINDINGSCOUNT=$(egrep "\s+\->\s+" $REPORTFILE|wc -l)
#uploading report to s3 bucket
	aws s3 cp $REPORTFILE s3://jslamb/
#Getting presigned url of report
	REPORTURL=$(aws s3 presign s3://jslamb/$FILENAME --expires-in 60000)
echo $REPORTURL
#Forwarding presigned-url of report to reporthandler, that will send this url to slack channel.
	python3 $REPORTHANDLERFILE $REPORTURL $SCANNEDJSCOUNT $FINDINGSCOUNT
#cleaning
	cp $FILENAME Results/$FILENAME
	rm $REPORTFILE
else
echo "There are no findings at all."
fi
#rm $TEMPWORKINGDOMAINSFILE
rm $ALLJSFILE
