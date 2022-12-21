#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

net="$1"
subnetStr=${net:0:13}
echo "$subnetStr" # for dev only
echo " "
echo "Syntax: ADnetscan.sh 'IP range' 'domain'" 
echo "Example: ./ADnetscan.sh 192.168.123.1/24 domain.local"
echo " 'Domain' is optional for most scans"
echo "Scanning network..."
echo " "
echo "Enumerating smb hosts"
# crackmapexec smb — gen-relay-list smb_targets_"$subnetStr".txt "$1"
echo " "
echo "Finding vulnerable hosts with nmap"