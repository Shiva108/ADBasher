#!/bin/bash

# Check if the user is running the script with root privileges
if [ "$EUID" -ne 0 ]
then
  echo "Please run as root"
  exit
fi

# Check if the required number of arguments was provided
if [ $# -lt 2 ]
then
  echo " "
  echo "Syntax: zeroscanmsf.sh 'NBNAME' 'server ip'" 
  echo "Example: ./zeroscanmsf.sh server2016 10.10.10.20"
  echo " "
    exit
fi

echo "Starting MSF and running msfscripts/zeroscanmsf.rc"
msfdb start
msfconsole -q -x "set NBNAME $1; setg RHOSTS $2;resource ./msfscripts/zerologonscan.rc"