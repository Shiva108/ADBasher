#!/bin/bash

echo " *** Under Development *** "

if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

if [ $# -eq 0 ]
  then
    echo "No arguments supplied"
fi

echo ""
echo "Syntax: getpasspolicy.sh 'DC IP address'" 
echo "Example: ./getpasspolicy.sh 10.10.10.10"
echo " "

# Invoke-Command -ComputerName Server01 -Credential Domain01\User01 -ScriptBlock { Get-Culture }
#  Import-PSSession -Session (New-PSSession -ComputerName WindowsServer01) -Module Import-Module ActiveDirectory