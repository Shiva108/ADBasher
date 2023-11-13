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
echo "Syntax: smbscan 'DC IP address'" 
echo "Example: ./smbscan.sh 10.10.10.10"
echo " "