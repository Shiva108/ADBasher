#!/bin/bash
# RPC Endpoint Enumeration using rpcdump.py
# Usage: ./rpcdump_enum.sh <target_ip> [port]

TARGET=$1
PORT=$2

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_ip> [port]"
    exit 1
fi

# Default to port 135 if no port is specified
if [ -z "$PORT" ]; then
    PORT=135
fi

echo "Enumerating RPC endpoints on $TARGET:$PORT"
rpcdump.py "$TARGET" -p $PORT