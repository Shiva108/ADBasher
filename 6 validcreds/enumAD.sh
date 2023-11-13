#!/bin/bash

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to display the usage of the script
usage() {
    echo -e "${RED}Syntax:${NC} $0 'IP address' 'username' 'password' ['hash']"
    echo -e "${RED}Example (password):${NC} $0 192.168.1.1 admin 'Password123'"
    echo -e "${RED}Example (hash):${NC} $0 192.168.1.1 admin 'aad3b435b51404eeaad3b435b51404ee:ed2b435b51404eeaad3b435b51404ee' hash"
    echo -e "${GREEN}Note:${NC} If the password contains special characters, remember to escape them or enclose them in single quotes."
    echo -e "${GREEN}Note:${NC} For NT hash, add 'hash' at the end of the command."
    echo ""
    exit 1
}

# Check if the minimum arguments are provided
if [ $# -lt 3 ]; then
    echo -e "${RED}Error:${NC} Incorrect number of arguments."
    usage
fi

# Assign variables to arguments for better readability
ipaddress=$1
username=$2
password=$3
mode=${4:-password} # Default mode is password
outputfile="${ipaddress}_rpcclient_connection.txt"

# Inform the user about the actions to be taken
echo -e "${GREEN}Attempting to connect with rpcclient...${NC}"
echo -e "${GREEN}Output will be saved to:${NC} $outputfile"

# Choose connection method based on the presence of the fourth argument
if [ "$mode" == "hash" ]; then
    # NT hash authentication
    echo -e "${GREEN}Using NT hash...${NC}"
    rpcclient //"$ipaddress" -U "$username%$password" --pw-nt-hash | tee "$outputfile"
else
    # Plain password authentication
    echo -e "${GREEN}Using username and password...${NC}"
    rpcclient -U "$username%$password" "$ipaddress" | tee "$outputfile"
fi

echo -e "${GREEN}Connection attempt complete!!!.${NC}"
