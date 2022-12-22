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
echo "Syntax: FindDCip 'interface' 'domain name'" 
echo "Example: ./FindDCip.sh eth0 mydomain.local"
echo "Finding DC IP address..."
nmcli dev show "$1" | tee FindDCip_"$1".txt
nslookup -type=SRV _ldap._tcp.dc._msdcs."$2" | tee FindDCip_"$2".txt
echo "Results: "
cat FindDCip_"$1".txt
cat FindDCip_"$2".txt
rm FindDCip_* # For dev only