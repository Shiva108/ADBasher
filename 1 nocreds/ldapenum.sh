#!/bin/bash

# Function to display usage
usage() {
    echo -e "\nSyntax: ldapenum.sh 'DC IP address'"
    printf "Example: ./ldapenum.sh 10.10.10.10\n"
}

# Check for required commands
for cmd in ldapsearch nmap grc; do
    if ! command -v "$cmd" &> /dev/null; then
        echo "Error: $cmd is not installed." >&2
        exit 1
    fi
done

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# Validate input parameters
if [ $# -ne 1 ]; then
    usage
    exit 1
fi

# Validate IP address format
if ! echo "$1" | grep -E -q "^([0-9]{1,3}\.){3}[0-9]{1,3}$"; then
    echo "Invalid IP address format."
    usage
    exit 1
fi

TARGET="$1"

# Output file naming
ldapsearch_file="ldapsearch_namingcontexts_$TARGET.txt"
ldapsearch_bigdump_file="ldapsearch_bigdump_$TARGET.txt"
nmap_file="nmap_ldapenum_$TARGET"

# Perform LDAP Enumeration
echo "Enumerating LDAP for $TARGET"

# Nmap LDAP Enumeration
echo "Running Nmap LDAP enumeration..."
if ! grc nmap -n -T4 -Pn -vv -sV --script "ldap* and not brute" "$TARGET" -oA "$nmap_file"; then
    echo "Nmap LDAP enumeration failed."
    exit 1
fi

# LDAP Enumeration with ldapsearch
echo "Running LDAP enumeration with ldapsearch using anonymous credentials..."
if ! ldapsearch -x -H ldap://"$TARGET" -b "" -s base namingcontexts | tee "$ldapsearch_file"; then
    echo "ldapsearch failed."
    exit 1
fi

# Extract Naming Context
naming_context=$(grep "namingContexts:" "$ldapsearch_file" | awk '{print $2}' | tr -d '[:space:]')

# LdapSearch Big Dump
if [ -n "$naming_context" ]; then
    echo "Running LDAP big dump for the naming context: $naming_context"
    if ! ldapsearch -x -H ldap://"$TARGET" -b "$naming_context" | tee "$ldapsearch_bigdump_file"; then
        echo "LDAP big dump failed."
    fi
else
    echo "Naming context not found."
fi

# Display Results
echo "Results:"
cat "$nmap_file.nmap"
cat "$ldapsearch_file"
grep --color=always "schemaNamingContext:" "$ldapsearch_file"
grep --color=always "serverName:" "$ldapsearch_file"
grep --color=always "dnsHostName:" "$nmap_file.nmap"
grep --color=always "ldapServiceName:" "$nmap_file.nmap"

echo " "
echo "Enumeration completed. Check the output files for detailed results."

