#!/bin/bash
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo " "
echo "Syntax: coerce.sh 'domain' 'listener ip' 'target ip" 
echo "Example: ./coerce.sh domain.local 10.10.10.10 10.10.10.11"
echo "coercing with unauthent PetitPotam (CVE-2022-26925)"
echo " "