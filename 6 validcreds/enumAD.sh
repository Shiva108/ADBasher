#!/bin/bash

# Define colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Function to display the usage of the script
usage() {
    echo -e "${RED}Syntax:${NC} $0 'IP address' 'username' 'password'"
    echo -e "${RED}Example:${NC} $0 192.168.1.1 admin 'Password123!'"
    echo -e "${GREEN}Note:${NC} If the password contains special characters, remember to escape them or enclose them in single quotes."
    echo ""
    exit 1
}

# Ensure username and password are provided
if [ $# -ne 3 ]; then
    echo -e "${RED}Error:${NC} Incorrect number of arguments. Username and password are required."
    usage
fi

# Assign variables to arguments for better readability
ipaddress=$1
username=$2
password=$3
outputfile="${ipaddress}_enumeration.txt"

# Inform the user about the actions to be taken
echo -e "${GREEN}Running enumeration tools on IP address:${NC} $ipaddress"
echo -e "${GREEN}Output will be saved to:${NC} $outputfile"

# Run enum4linux with provided username and password
echo -e "${GREEN}Running enum4linux...${NC}"
enum4linux -a -u "$username" -p "$password" "$ipaddress" | tee --append "$outputfile"

# Run enum4linux with provided username and password
echo -e "${GREEN}Running enum4linux-ng...${NC}"
enum4linux -A -u "$username" -p "$password" "$ipaddress" | tee --append "$outputfile"

# Run nmap with provided IP address
echo -e "${GREEN}Running nmap for SMB enumeration...${NC}"
nmap --script "safe or smb-enum-*" -p 445 "$ipaddress" | tee --append "$outputfile"

echo -e "${GREEN}Enumeration complete.${NC}"
