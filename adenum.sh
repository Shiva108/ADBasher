#!/bin/bash

# Function to display the usage of the script
usage() {
    echo "Syntax: $0 'IP address' 'username' 'password' 'domain'"
    echo "Example: $0 10.10.10.10 'admin' 'Password123!' 'mydomain.local'"
    echo "Note: If the password contains special characters, remember to escape them or enclose them in single quotes."
    echo ""
    exit 1
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

# Check if four arguments are supplied
if [ $# -ne 4 ]; then
    echo "Error: Incorrect number of arguments supplied."
    usage
fi

# Assign variables to arguments for better readability
ipaddress=$1
username=$2
password=$3
domain=$4

# Run ADenum.py with the provided arguments
echo "Running ADenum.py with the supplied arguments..."
python ./ADenum.py -ip "$ipaddress" -u "$username" -p "$password" -d "$domain" -c
