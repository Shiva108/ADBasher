#!/bin/sh
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if [ $# -eq 0 ]
  then
    echo ""
    echo "Syntax: smbscan 'DC IP address'" 
    echo "Example: ./smbscan.sh 10.10.10.10"
    echo " "
fi

echo "=========================="
echo "Using anon creds"
echo " "
echo "=========================="
grc nmap -n -Pn -vv -sV --script "ldap* and not brute" "$1"  #Using anonymous credentials
