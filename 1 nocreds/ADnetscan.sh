#!/bin/bash
net="$1"
subnetStr=${net:0:10}
echo "$subnetStr" # for dev only
echo " "
echo "Syntax: ADnetscan.sh 'IP range'" 
echo "Example: ./ADnetscan.sh 192.168.123.1/24"
echo "Scanning network..."
echo " "
echo "Enumerating smb hosts"
# crackmapexec smb — gen-relay-list smb_targets_"$subnetStr".txt "$1"
echo " "
echo "Finding vulnerable hosts with nmap"
grc nmap -sP "$1" -oA nmap_"$subnetStr"_ping # ping scan
grc nmap -sV -Pn --top-ports 50 --open "$1" -oA nmap_"$subnetStr"_quick # quick scan
grc nmap -Pn --script smb-vuln* -p139,445 "$1" -oA nmap_"$subnetStr"_smbvuln # search vuln scan
grc nmap -sU -sC -sV "$1" -oA nmap_"$subnetStr"_udp # udp scan 
# Uncomment to include full scan:
#grc nmap -sSCV -Pn -p- -T4 -vv --version-intensity 5 --script=banner --max-retries 3 --version-all -oA $1 $1
rm nmap_"$subnetStr"* # for dev only


