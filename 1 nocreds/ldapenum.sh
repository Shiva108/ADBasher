#!/bin/bash


# Function to display usage
usage() {
    echo " "
    echo "Syntax: ldapenum.sh 'DC IP address'"
    echo "Example: ./ldapenum.sh 10.10.10.10"
}

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

# Clear previous results (for development only; comment out or remove for production)
rm -f ldapsearch_*_"$TARGET".txt nmap_ldapenum_"$TARGET"*

# Perform LDAP Enumeration
echo "Enumerating LDAP for $TARGET"

# Nmap LDAP Enumeration
echo "Running Nmap LDAP enumeration..."
grc nmap -n -Pn -vv -sV --script "ldap* and not brute" "$TARGET" -oA nmap_ldapenum_"$TARGET"

# LDAP Enumeration with ldapsearch
echo "Running LDAP enumeration with ldapsearch using anonymous credentials..."
ldapsearch -x -h "$TARGET" -s base namingcontexts | tee ldapsearch_namingcontexts_"$TARGET".txt

# Display Results
echo "Results:"
cat nmap_ldapenum_"$TARGET".nmap
cat ldapsearch_namingcontexts_"$TARGET".txt
grep "schemaNamingContext:" ldapsearch_namingcontexts_"$TARGET".txt
grep "serverName:" ldapsearch_namingcontexts_"$TARGET".txt

echo "Enumeration completed. Check the output files for detailed results."
