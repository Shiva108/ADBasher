#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo "ADBasher Installer, tested on Kali and Parrot"
sudo apt update && apt autoremove && apt autoclean 
echo "Current OS version is:"
sudo uname -a
sudo apt install grc crackmapexec 