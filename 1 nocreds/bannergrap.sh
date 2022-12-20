#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo " "
echo "Syntax: bannergrap.sh IP PORT" 
echo "Example: ./bannergrap.sh 10.10.10.10 22"
echo "Only works for open ports i.e. run masscan or nmap first"
echo " "
rm ./*.tmp # for dev only
sleep 5 | telnet "$1" "$2" > telgrap_"$1"_"$2".tmp
# wget "$1":"$2" -q -S | tee wgetgrap_"$1"_"$2".tmp
# curl -s -I "$1":"$2" | grep -e "Server: " > curlgrap_"$1"_"$2".tmp
nc -z -v "$1" "$2" > ncgrap_"$1"_"$2".tmp 
#sleep 2 | dmitry -bp "$1" "$2" #| tee dmitrygrap_"$1"_"$2".tmp
#
# Should you wish to use nmap uncomment next line:
# nmap -sV -v -Pn -T4 --max-retries 3 --version-intensity 5 --version-all --script=banner "$1"  
#
echo "Listing tmp files:"
ls ./*.tmp
echo "Textfile output:"
cat ./*.tmp | less
