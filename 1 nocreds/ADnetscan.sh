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
grc nmap -sP "$1" -oA nmap_"$subnetStr"_ping # ping scan
grc nmap -sV -Pn --top-ports 50 --open "$1" -oA nmap_"$subnetStr"_quick # quick scan
grc nmap -Pn --script smb-vuln* -p139,445 "$1" -oA nmap_"$subnetStr"_smbvuln # search vuln scan
grc nmap -sU -sC -sV "$1" -oA nmap_"$subnetStr"_udp # udp scan 
# Uncomment to include full scan:
# grc nmap -sSCV -Pn -p- -T4 -vv --version-intensity 5 --script=banner --max-retries 3 --version-all -oA $1 $1
 rm nmap_"$subnetStr"* # for dev only

# Additional nmap information gathering using nse

# sudo nmap -p 3389 --script rdp-ntlm-info "$2"
# sudo nmap -sSC -Pn --script=*-ntlm-info -p 23,25,80,3389 "$2"
# sudo nmap -sSCV --script=*-ntlm-info --script-args http-ntlm-info.root=/ews/ -p 443,587,993 "$2"





