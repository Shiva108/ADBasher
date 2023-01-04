#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if [ $# -eq 0 ]
  then
    echo "Runs against TCP/88 by default - usage ./kerbscan.sh ip domain"
    echo "eg ./kerbscan.sh attack.local THM-AD"
fi

grc nmap -Pn -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm=$2 -oX "nmap_kerb_$1" "$1"
