#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo "ADBasher Installer, tested on Kali and Parrot"
sudo apt install --fix-missing -y
sudo apt update && apt autoremove && apt autoclean
echo "Current OS version is:"
sudo uname -a
sudo apt install grc crackmapexec impacket-scripts
cd 2\ quick/ || exit
sudo git clone https://github.com/dirkjanm/CVE-2020-1472.git
sudo git clone https://github.com/rth0pper/zerologon.git
cd .. || exit
sudo chmod -R +x ./*.{sh,py}
sudo cat ./README.md | more