#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
fi

echo ""
echo "Syntax: smbscan 'DC IP address'" 
echo "Example: ./smbscan.sh 10.10.10.10"
echo " "
echo "Starting nmap smb for " "$1"
echo "=========================="
# grc nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse "$1"
# grc nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount "$1"

echo " "
echo "Starting enum4linux for" "$1"
echo "=========================="
# enum4linux -U "$1" 
# enum4linux -a "$1" 
# enum4linux -a -u "" -p "" "$1" && enum4linux -a -u "guest" -p "" "$1"

echo "Trying to login with smbclient with anonymous and guest for" "$1"
echo "=========================="
smbclient //"$1"/anonymous
smbclient //"$1"/guest
smbclient --no-pass -L //"$1"

echo " "
echo "Running smbmap for " "$1"
echo "=========================="
smbmap -H "$1"
smbmap -u '' -p '' -P 445 -H "$1"
smbmap -u 'guest' -p '' -P 445 -H "$1"
smbmap -u '' -p '' -H "$1" -R

echo " "
echo "Running nbtscan for " "$1"
echo "=========================="
nbtscan "$1" -v

echo " "
echo "Starting crackmapexec smb for " "$1"
echo "=========================="
/root/.local/bin/crackmapexec smb "$1"
/root/.local/bin/crackmapexec smb "$1" -u '' -p ''
/root/.local/bin/crackmapexec smb "$1" -u 'guest' -p ''
/root/.local/bin/crackmapexec smb "$1" -u '' -p '' # --share 'sharename'
