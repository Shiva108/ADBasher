#!/bin/bash

# Function to display usage
usage() {
    printf "\nSyntax: findsccm.sh <IP Range>\n"
    printf "Example: ./findSCCM.sh 192.168.1.0/24\n\n"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    printf "Please run as root\n"
    exit 1
fi

# Validate input parameters
if [ $# -ne 1 ]; then
    usage
    exit 1
fi

IP_RANGE="$1"
OUTPUT_FILE="sccm_scan_results.txt"

# Check for required tool (nmap)
if ! command -v nmap &> /dev/null; then
    printf "Error: nmap is not installed.\n"
    exit 1
fi

printf "Scanning for SCCM servers in IP range: %s\n" "$IP_RANGE"
printf "Scanning IP range: %s\n" "$IP_RANGE" > "$OUTPUT_FILE"

# Perform an advanced scan with service detection and Nmap scripts
nmap -T4 -p 80,443,445 --open -sV \
     --script=http-title,smb-os-discovery \
     "$IP_RANGE" | tee -a "$OUTPUT_FILE"

# Check if potential SCCM servers are found
if grep -qE "(SCCM|Configuration Manager)" "$OUTPUT_FILE"; then
    printf "\nPotential SCCM servers found. Check %s for details.\n" "$OUTPUT_FILE"
else
    printf "\nNo SCCM servers found in the specified IP range.\n"
fi

printf "Scan completed.\n"
