#!/bin/bash
# Combined Penetration Testing Script for RPC and NFS
# Usage: ./test_rpc_nfs.sh <target_ip>

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip>"
    exit 1
fi

# Check for necessary commands
if ! command -v showmount &> /dev/null; then
    echo "showmount command could not be found. Please install nfs-common (or nfs-utils on RPM-based systems)."
    exit 1
fi

# Function to enumerate RPC services
enumerate_rpc() {
    echo "Enumerating RPC services on $TARGET"
    rpcinfo -p $TARGET
}

# Function to exploit NFS shares
exploit_nfs() {
    echo "Searching for NFS shares on $TARGET"
    showmount -e "$TARGET"

    echo "Attempting to mount NFS shares"
    mkdir -p /tmp/nfs_mount
    for share in $(showmount -e "$TARGET" | awk '(NR>1) {print $1}'); do
        mount -o nolock "$TARGET":"$share" /tmp/nfs_mount
        echo "Contents of $share:"
        ls -lah /tmp/nfs_mount
        umount /tmp/nfs_mount
    done
}

# Function to check NFS share permissions
check_nfs_permissions() {
    echo "Checking write permissions on NFS shares of $TARGET"
    for share in $(showmount -e "$TARGET" | awk '(NR>1) {print $1}'); do
        mkdir -p /tmp/nfs_test
        mount -o nolock "$TARGET":"$share" /tmp/nfs_test
        if touch /tmp/nfs_test/test_file; then 
            echo "Write permission on $share"
            rm /tmp/nfs_test/test_file
        else 
            echo "No write permission on $share"
        fi
        umount /tmp/nfs_test
        rmdir /tmp/nfs_test
    done
}

# Running the functions
enumerate_rpc
exploit_nfs
check_nfs_permissions