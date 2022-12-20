#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo "Remember to change /etc/resolv.conf before running this"
nano -l /etc/resolv.conf
systemctl restart NetworkManager
ifdown -a
ifup -a
echo "Done"
