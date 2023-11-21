#!/bin/bash

# Function to display usage
usage() {
    echo -e "Usage: $0 'DC IP address'"
    echo -e "Example: $0 10.10.10.10"
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
OUTPUT_FILE="smbscan_results_$TARGET.txt"

# Function to perform scans
perform_scan() {
    echo -e "\nStarting scans for $TARGET"
    echo "=========================="
    echo -e "nmap SMB and NFS scans for $TARGET" | tee -a "$OUTPUT_FILE"
    grc nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse "$TARGET" | tee -a "$OUTPUT_FILE"
    grc nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount "$TARGET" | tee -a "$OUTPUT_FILE"

    echo -e "\nenum4linux scans for $TARGET" | tee -a "$OUTPUT_FILE"
    enum4linux -U "$TARGET" | tee -a "$OUTPUT_FILE"
    enum4linux -a "$TARGET" | tee -a "$OUTPUT_FILE"
    enum4linux -a -u "" -p "" "$TARGET" | tee -a "$OUTPUT_FILE"
    enum4linux -a -u "guest" -p "" "$TARGET" | tee -a "$OUTPUT_FILE"

    echo -e "\nsmbclient scans for $TARGET" | tee -a "$OUTPUT_FILE"
    smbclient //"$TARGET"/anonymous | tee -a "$OUTPUT_FILE"
    smbclient //"$TARGET"/guest | tee -a "$OUTPUT_FILE"
    smbclient --no-pass -L //"$TARGET" | tee -a "$OUTPUT_FILE"

    echo -e "\nsmbmap scans for $TARGET" | tee -a "$OUTPUT_FILE"
    smbmap -H "$TARGET" | tee -a "$OUTPUT_FILE"
    smbmap -u '' -p '' -P 445 -H "$TARGET" | tee -a "$OUTPUT_FILE"
    smbmap -u 'guest' -p '' -P 445 -H "$TARGET" | tee -a "$OUTPUT_FILE"
    smbmap -u '' -p '' -H "$TARGET" -R | tee -a "$OUTPUT_FILE"

    echo -e "\nnbtscan for $TARGET" | tee -a "$OUTPUT_FILE"
    nbtscan "$TARGET" -v | tee -a "$OUTPUT_FILE"

    echo -e "\ncrackmapexec scans for $TARGET" | tee -a "$OUTPUT_FILE"
    /root/.local/bin/crackmapexec smb "$TARGET" | tee -a "$OUTPUT_FILE"
    /root/.local/bin/crackmapexec smb "$TARGET" -u '' -p '' | tee -a "$OUTPUT_FILE"
    /root/.local/bin/crackmapexec smb "$TARGET" -u 'guest' -p '' | tee -a "$OUTPUT_FILE"
    # Uncomment the following line if you have a specific share to scan
    # /root/.local/bin/crackmapexec smb "$TARGET" -u '' -p '' --share 'sharename' | tee -a "$OUTPUT_FILE"
}

# Run the scan function
perform_scan