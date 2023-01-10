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
echo "Syntax: spray.sh 'usersnamefile' 'domain name' 'DC IP address'" 
echo "Example: ./spray.sh users.txt mydomain.local 10.10.10.10"
echo " "

./sprayhound/sprayhound.py -U "$1" -d "$2" -dc "$3"