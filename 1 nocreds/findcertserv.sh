#!/bin/bash

# Perform initial service discovery scan
nmap -sV -p 80,443,389,636 -oG - "$1" | awk '/Up$/{print $2}' > live_hosts.txt

# Read each IP and perform script scanning
while IFS= read -r target_ip; do
    nmap --script "ldap-*,ssl-*" -p 389,636 --open  "$target_ip"
done < live_hosts.txt
