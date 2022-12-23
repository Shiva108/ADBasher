#!/bin/bash

# Check if the user is running the script with root privileges
if [ "$EUID" -ne 0 ]
then
  echo "Please run as root"
  exit
fi

# Check if the required number of arguments was provided
if [ $# -lt 1 ]
then
  echo " "
  echo "Syntax: proxylogon.sh 'exchange server ip'" 
  echo "Example: ./proxylogon.sh 10.10.10.10"
  echo " "
    exit
fi

echo "Starting MSF and running msfscripts/proxylogonscan.rc"
msfdb start
msfconsole -q -x "setg RHOSTS $1;resource ./msfscripts/proxylogonscan.rc"

