#!/bin/bash

# Function to display usage
usage() {
    echo -e "\nUsage: ./rpcdump_enum.sh <target_ip> [port]"
    echo "If no port is specified, defaults to port 135."
    echo -e "Example: ./rpcdump_enum.sh 192.168.1.1 135\n"
}

# Validate input parameters
if [ $# -lt 1 ]; then
    usage
    exit 1
fi

# Check for required command
if ! command -v rpcdump.py &> /dev/null; then
    echo "Error: rpcdump.py is not installed or not in the PATH."
    exit 1
fi

# Assign input to variables
TARGET="$1"
PORT="${2:-135}"  # Default to port 135 if no port is specified

# Output file naming
output_file="rpcdump_${TARGET}_port${PORT}.txt"

# Perform RPC Endpoint Enumeration
echo "Enumerating RPC endpoints on $TARGET:$PORT"
rpcdump.py "$TARGET" -p "$PORT" | tee "$output_file"

# Check the exit status
if [ $? -ne 0 ]; then
    echo "RPC endpoint enumeration failed."
    exit 1
else
    echo "RPC endpoint enumeration completed successfully. Results are saved in $output_file"
fi
