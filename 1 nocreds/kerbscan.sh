#!/bin/bash

# Function to display usage
usage() {
    echo "Usage: ./kerbscan.sh <ip> <domain>"
    echo "eg ./kerbscan.sh 192.168.1.1 attack.local"
    echo "Domain controller ip can be found using the FindDCip.sh tool"
 }

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Validate input parameters
if [ $# -ne 2 ]; then
    usage
    exit 1
fi

# Assign input to variables
IP_ADDRESS="$1"
DOMAIN="$2"

# Check for required command
if ! command -v grc &> /dev/null; then
    echo "Error: grc is not installed."
    exit 1
fi

# Output file naming
output_file="nmap_kerb_$IP_ADDRESS.xml"

# Perform Kerberos Enumeration
echo "Running Kerberos enumeration against $IP_ADDRESS in domain $DOMAIN..."

if ! grc nmap -Pn -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm="$DOMAIN" -oX "$output_file" "$IP_ADDRESS"; then
    echo "Nmap Kerberos enumeration failed."
    exit 1
fi

echo "Kerberos enumeration completed. Check the output file: $output_file"

