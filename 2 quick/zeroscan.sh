#!/bin/bash

# Function to display usage
usage() {
    echo -e "\nSyntax: zeroscan.sh <DC NetBIOS name> <DC IP address>"
    echo "Example: ./zeroscan.sh DC01 192.168.123.1"
    echo -e "Hint: To find the DC NetBIOS name and IP, run 'ADnetscan.sh' & 'FindDCip.sh' found in '1 nocreds/'\n"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Check if the required number of arguments was provided
if [ $# -ne 2 ]; then
    echo "No arguments supplied or insufficient arguments provided"
    usage
    exit 1
fi

# Check for required script
if [ ! -f "./zerologon/zerologon.py" ]; then
    echo "Error: zerologon.py script not found in the expected directory."
    exit 1
fi

NETBIOS_NAME="$1"
DC_IP="$2"

# Scans the target for the vulnerability
echo "Scanning the target for the Zerologon vulnerability"
python3 ./zerologon/zerologon.py "$NETBIOS_NAME" "$DC_IP"

echo "Scan completed."
