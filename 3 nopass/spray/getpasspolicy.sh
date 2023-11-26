#!/bin/bash

# Function to display usage
usage() {
    printf "\nSyntax: getpasspolicy.sh <DC IP address> <username> <password>\n"
    printf "Example: ./getpasspolicy.sh 192.168.1.100 Administrator Password\n"
    printf "Note: If the password contains special characters, they should be escaped.\n\n"
}

# Check if the user is running the script with root privileges
if [ "$(id -u)" -ne 0 ]; then
    printf "Please run as root\n"
    exit 1
fi

# Check if the required number of arguments was provided
if [ $# -ne 3 ]; then
    printf "Incorrect number of arguments supplied\n"
    usage
    exit 1
fi

DC_IP="$1"
USERNAME="$2"
PASSWORD="$3"
OUTPUT_FILE="password_policy_${DC_IP}.txt"

# Check for required tool (polenum)
if ! command -v polenum &> /dev/null; then
    printf "Error: polenum not found. Please install it.\n"
    exit 1
fi

# Run polenum to get the password policy and save output to file
printf "Getting password policy for domain controller at %s. Output will be saved to %s\n" "$DC_IP" "$OUTPUT_FILE"
polenum --username "$USERNAME" --password "$PASSWORD" --domain "$DC_IP" | tee "$OUTPUT_FILE"