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
sleep 3
sudo apt install grc crackmapexec impacket-scripts msfpc

# cd 2\ quick/ || exit
# sudo git clone https://github.com/dirkjanm/CVE-2020-1472.git
# sudo git clone https://github.com/rth0pper/zerologon.git
# cd .. || exit

echo ""
echo "Installing Powershell for Linux "
echo " "
sleep 3
# If you wish to download instead: https://github.com/PowerShell/PowerShell/releases/tag/v7.3.1
# Install system components
sudo apt update  && sudo apt install -y curl gnupg apt-transport-https
# Import the public repository GPG keys
curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
# Register the Microsoft Product feed
sudo sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-bullseye-prod bullseye main" > /etc/apt/sources.list.d/microsoft.list'
# Install PowerShell
sudo apt update && sudo apt install -y powershell
# Send command to pwsh for installing pwsh module
eval "pwsh -c {Install-Module -Name WindowsCompatibility}"

sudo chmod -R +x ./*.sh
sudo cat ./README.md | more