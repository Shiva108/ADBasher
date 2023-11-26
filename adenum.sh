#!/bin/bash

# Function to display the usage of the script
usage() {
    printf "%s\n" "Syntax: $0 'IP address' 'username' 'password' 'domain'"
    printf "%s\n" "Example: $0 10.10.10.10 'admin' 'Password123!' 'mydomain.local'"
    printf "%s\n" "Note: If the password contains special characters, remember to escape them or enclose them in single quotes."
    printf "\n"
    exit 1
}

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    printf "%s\n" "Please run as root"
    exit
fi

# Check if four arguments are supplied
if [ $# -ne 4 ]; then
    printf "%s\n" "Error: Incorrect number of arguments supplied."
    usage
fi

# Assign variables to arguments for better readability
ipaddress=$1
username=$2
password=$3
domain=$4
output_file="ADenum_output_${ipaddress//./_}.txt"

# Run ADenum.py with the provided arguments and save output to file
printf "Running ADenum.py with the supplied arguments...\n"
python ./ADenum/ADenum.py -ip "$ipaddress" -u "$username" -p "$password" -d "$domain" -c | tee "$output_file"
