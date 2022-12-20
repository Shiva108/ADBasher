#!/bin/sh
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo "=========================="
echo "Using anon creds"
echo " "
echo "=========================="
grc nmap -n -Pn -vv -sV --script "ldap* and not brute" "$1"  #Using anonymous credentials
