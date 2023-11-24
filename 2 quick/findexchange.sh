#!/bin/bash

# Function to display usage
usage() {
    printf "\nSyntax: find_exchange.sh <IP Range>"
    printf "Example: ./find_exchange.sh 192.168.1.0/24\n"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Validate input parameters
if [ $# -ne 1 ]; then
    usage
    exit 1
fi

IP_RANGE="$1"

# Check for required tool (nmap)
if ! command -v nmap &> /dev/null; then
    echo "Error: nmap is not installed."
    exit 1
fi

# Common Exchange Server ports: 25 (SMTP), 80 (HTTP), 443 (HTTPS), 110 (POP3), 995 (POP3S), 143 (IMAP), 993 (IMAPS), 587 (SMTP)
echo "Scanning for Exchange servers in IP range: $IP_RANGE"
nmap -p 25,80,443,110,995,143,993,587 --open "$IP_RANGE"

echo "Scan completed."
