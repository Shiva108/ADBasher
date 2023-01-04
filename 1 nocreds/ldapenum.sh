#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if [ $# -eq 0 ]
  then
    echo " "
    echo "Syntax: ldapenum.sh 'DC IP address'" 
    echo "Example: ./ldapenum.sh 10.10.10.10"
fi

rm ldapsearch_*.txt  nmap_ldapenum_* # for dev only
echo "Enumerating LDAP" "$1"
echo "Nmap LDAP enum..."
grc nmap -n -Pn -vv -sV --script "ldap* and not brute" "$1" -oA nmap_ldapenum_"$1"  #Using anonymous credentials
echo "LDAP enum with ldapsearch using anon creds..."
ldapsearch -x -h "$1" -s base namingcontexts | tee ldapsearch_"$1".txt
echo "Results:"
cat nmap_ldapenum_"$1".nmap
cat ldapsearch_"$1".txt
cat ldapsearch_"$1".txt | grep "schemaNamingContext:"
cat ldapsearch_"$1".txt | grep "serverName:"