#!/bin/bash

# ANSI Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to display usage
usage() {
    echo -e "${YELLOW}nmapldap: Perform an LDAP scan using Nmap and checks for open RPC port${NC}"
    echo ""
    echo "Syntax: nmapldap.sh 'DC IP address or subnet'"
    echo "Example: ./nmapldap.sh 10.10.10.10"
    echo "Example: ./nmapldap.sh 10.10.10.0/24"
    echo ""
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Validate input parameters
if [ $# -ne 1 ]; then
    usage
    exit 1
fi

# Assign input to a variable
dc_ip_subnet="$1"

# Check if the input format is valid (IP address or subnet)
if ! echo "$dc_ip_subnet" | grep -E -q "^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$"; then
    echo -e "${RED}Invalid IP address or subnet format.${NC}"
    usage
    exit 1
fi

# Replace '/' with '_' in the subnet to use in the filename
filename_subnet=$(echo "$dc_ip_subnet" | tr '/' '_')

# Define output file
output_file="nmapldap_scan_results_$filename_subnet.txt"

echo -e "${GREEN}==================================================${NC}"
echo -e "Performing LDAP scan using anonymous credentials"
echo -e "Target: $dc_ip_subnet"
echo -e " "
echo -e "Scan results will be saved to $output_file"
echo -e "${GREEN}==================================================${NC}" | tee "$output_file"

# Perform the LDAP scan and save the output to a file
echo "Scanning subnet: $dc_ip_subnet" | tee -a "$output_file"
grc nmap -n -Pn -vv -sV -v --script "ldap* and not brute" "$dc_ip_subnet" | tee -a "$output_file"

# Check for open port 111
if grep -q "111/tcp open  rpcbind" "$output_file"; then
    echo -e "${YELLOW}Port 111 is open. Initiating RPC and NFS penetration test...${NC}" | tee -a "$output_file"
    ./test_rpc_nfs.sh "$dc_ip_subnet" | tee -a "$output_file"
fi

echo -e "${GREEN}LDAP scan completed.${NC}" | tee -a "$output_file"