#!/bin/bash

# Function to display the usage of the script
usage() {
    echo "Syntax: $0 'IP address' [username] [password]"
    echo "Example: $0 192.168.1.1 'admin' 'Password123!'"
    echo "Note: If the password contains special characters, remember to escape them or enclose them in single quotes."
    echo "Username and password are optional."
    echo ""
    exit 1
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

# Check if at least one argument is supplied
if [ $# -lt 1 ]; then
    echo "Error: IP address not supplied."
    usage
fi

# Assign variables to arguments for better readability
ipaddress=$1
username=${2:-}
password=${3:-}

# Check if username and password are provided and set the credentials string
credentials=""
if [ -n "$username" ] && [ -n "$password" ]; then
    credentials="-u \"$username\" -p \"$password\""
fi

# Run enum4linux and enum4linux-ng
echo "Running enum4linux..."
eval enum4linux -a $credentials $ipaddress

echo "Running enum4linux-ng..."
eval enum4linux-ng -A $credentials $ipaddress

# Run nmap
echo "Running nmap..."
nmap --script "safe or smb-enum-*" -p 445 $ipaddress

echo "Enumeration complete."