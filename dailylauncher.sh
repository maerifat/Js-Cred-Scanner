#!/bin/bash
#Defining Variables.
MYPATH=/appsec/jsscanner
ALLDOMAINSFILE=$MYPATH/alldomains.txt
REPORTFILE=$MYPATH/dailyreport_`date +"%Y-%m-%d"`.txt
TEMPJSCONTENTFILE=$MYPATH/tempjscontent.txt
ALLJSFILE=$MYPATH/alljs.txt
BLACKLISTEDJSFILE=$MYPATH/blacklistedjs.txt
BLACKLISTEDDOMAINFILE=$MYPATH/blacklisteddomains.txt
DIGESTDB=$MYPATH/digestdb.txt
SECRETFINDERFILE=$MYPATH/SecretFinder.py
REPORTHANDLERFILE=$MYPATH/reporthandler.py
TEMPWORKINGDOMAINSFILE=$MYPATH/tempworkingdomains.txt
#Creating required files
touch $REPORTFILE
touch $TEMPJSCONTENTFILE
touch $ALLJSFILE 
test -e  $BLACKLISTEDJSFILE|| touch $BLACKLISTEDJSFILE
test -e $DIGESTDB || touch $DIGESTDB
test -e $BLACKLISTEDDOMAINFILE || touch $BLACKLISTEDDOMAINFILE
#cheking working domains
cat  $ALLDOMAINSFILE |httpx  -silent >$TEMPWORKINGDOMAINSFILE
#Gathering js files with tools
gospider -S $TEMPWORKINGDOMAINSFILE -d 0 -a -w | egrep -i "\.js$|\.js\?"| egrep -io "http.*"| cut -d "]" -f1 |sort -u |httpx -mc 200 -silent >  $ALLJSFILE
cat $TEMPWORKINGDOMAINSFILE|gau|egrep -i "\.js$|\.js\?"|sort -u| httpx -mc 200 -silent>> $ALLJSFILE 
cat $TEMPWORKINGDOMAINSFILE|waybackurls|egrep -i "\.js$|\.js\?"| sort -u|httpx -mc 200 -silent  >> $ALLJSFILE
#Working on each js file in loop.
for URL in $(cat $ALLJSFILE)
do
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
            echo  "$(tput setaf 3)$URL has already been scanned. $(tput setaf 0)"
        else
            echo "$(tput setaf 2)$URL is being scanned. $(tput setaf 0)"
            python3 $SECRETFINDERFILE -i $URL -o cli>> $REPORTFILE
            echo "" >>$REPORTFILE
        
            #Adding message digest of this file to our database.
            echo $DIGEST >>$DIGESTDB
        fi
        rm $TEMPJSCONTENTFILE
    fi
done
#Refreshing our message digest database
sort -u -o $DIGESTDB $DIGESTDB
#Counting new js files scanned
SCANNEDJSCOUNT=$(egrep "^(\[ \+ \])" $REPORTFILE|wc -l)
FINDINGSCOUNT=$(egrep "\s+\->\s+" $REPORTFILE|wc -l)
#uploading report to s3 bucket
aws s3 cp $REPORTFILE s3://appsec-js-scanner/
#Getting presigned url of report
REPORTURL=$(aws s3 presign s3://appsec-js-scanner$REPORTFILE --expires-in 60000)
#Forwarding presigned-url of report to reporthandler, that will send this url to slack channel.
python3 $REPORTHANDLERFILE $REPORTURL $SCANNEDJSCOUNT $FINDINGSCOUNT
#cleaning
rm $REPORTFILE
rm $TEMPWORKINGDOMAINSFILE
rm $ALLJSFILE
