#!/bin/bash

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to display the usage of the script
usage() {
    echo -e "${RED}Syntax:${NC} $0 'IP address' 'domain' 'username' 'NT_HASH'"
    echo -e "${RED}Example:${NC} $0 machine.htb localdomain admin '31D6CFE0D16AE931B73C59D7E0C089C0'"
    echo -e "${GREEN}Note:${NC} Enter the NT hash for the password."
    echo ""
    exit 1
}

# Ensure all arguments are provided
if [ $# -ne 4 ]; then
    echo -e "${RED}Error:${NC} Incorrect number of arguments. Domain, username, and NT hash are required."
    usage
fi

# Assign variables to arguments for better readability
ipaddress=$1
domain=$2
username=$3
nt_hash=$4
outputfile="${ipaddress}_rpcclient_connection.txt"

# Inform the user about the actions to be taken
echo -e "${GREEN}Attempting to connect with rpcclient using credentials...${NC}"
echo -e "${GREEN}Output will be saved to:${NC} $outputfile"

# Attempt connection with credentials
echo -e "${GREEN}Using username and NT hash...${NC}"
rpcclient -U "${domain}/${username}%${nt_hash}" "$ipaddress" | tee "$outputfile"

echo -e "${GREEN}Connection attempt complete.${NC}"
