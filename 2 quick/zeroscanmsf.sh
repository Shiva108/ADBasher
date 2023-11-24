#!/bin/bash

# Function to display usage
usage() {
    printf "\nSyntax: zeroscanmsf.sh <NBNAME> <Server IP>\n"
    printf "Example: ./zeroscanmsf.sh server2016 10.10.10.20\n\n"
}

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    printf "Please run as root\n"
    exit 1
fi

# Check if the required number of arguments was provided
if [ $# -ne 2 ]; then
    printf "Incorrect number of arguments supplied\n"
    usage
    exit 1
fi

NBNAME="$1"
SERVER_IP="$2"

# Check for required tools (msfdb and msfconsole)
if ! command -v msfdb &> /dev/null || ! command -v msfconsole &> /dev/null; then
    printf "Error: Required Metasploit tools not found.\n"
    exit 1
fi

# Check if MSF script file exists
MSF_SCRIPT="./msfscripts/zerologonscan.rc"
if [ ! -f "$MSF_SCRIPT" ]; then
    printf "Error: Metasploit script file %s not found.\n" "$MSF_SCRIPT"
    exit 1
fi

printf "Starting Metasploit Database...\n"
msfdb start

printf "Starting Metasploit Console and running Zerologon scan...\n"
msfconsole -q -x "set NBNAME $NBNAME; setg RHOSTS $SERVER_IP; resource $MSF_SCRIPT"


