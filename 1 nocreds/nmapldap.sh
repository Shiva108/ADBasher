#!/bin/sh
echo "=========================="
echo "Using anon creds"
echo " "
echo "=========================="
grc nmap -n -Pn -vv -sV --script "ldap* and not brute" $1  #Using anonymous credentials
