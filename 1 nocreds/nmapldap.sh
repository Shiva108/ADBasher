#!/bin/sh
# shellcheck disable=SC3000-SC4000

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if [ $# -eq 0 ]
  then
    echo ""
    echo "Syntax: nmapldap 'DC IP address'" 
    echo "Example: ./nmapldap.sh 10.10.10.10"
    echo " "
fi

echo "=========================="
echo "Using anon creds"
echo " "
echo "=========================="
grc nmap -n -Pn -vv -sV --script "ldap* and not brute" "$1"  #Using anonymous credentials
