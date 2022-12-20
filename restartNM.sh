#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo "Edit /etc/resolv.conf to fit current domain i.e. DC and domain name"
echo "Example:"
echo " "
cat example.conf
sleep 5
echo " "
nano -l /etc/resolv.conf
systemctl restart NetworkManager
ifdown -a
ifup -a
echo "Done"
