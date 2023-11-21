#!/bin/bash

# Dependency check
for cmd in telnet wget curl nc dmitry; do
  if ! command -v "$cmd" &> /dev/null; then
    echo "Error: $cmd is not installed." >&2
    exit 1
  fi
done

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Validate arguments
if [ $# -ne 2 ]; then
  echo -e "\nSyntax: bannergrap.sh IP PORT" 
  echo "Example: ./bannergrap.sh 10.10.10.10 22"
  echo "Only works for open ports i.e., run masscan or nmap first"
  exit 1
fi

# Temporary files setup
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Banner grabbing commands
# telnet "$1" "$2" > "$tmpdir/telgrap_$1_$2.tmp"
wget "$1:$2" -q -S | tee "$tmpdir/wgetgrap_$1_$2.tmp"
curl -s -I "$1:$2" | grep -e "Server: " > "$tmpdir/curlgrap_$1_$2.tmp"
# nc -z -v "$1" "$2" > "$tmpdir/ncgrap_$1_$2.tmp"
dmitry -bp "$1" "$2"

# Optional nmap usage
# Uncomment to enable nmap scanning
# if command -v nmap &> /dev/null; then
#   nmap -sV -v -Pn -T4 --max-retries 3 --version-intensity 5 --version-all --script=banner "$1"
# fi

# Output handling
echo "Listing tmp files:"
ls "$tmpdir/*.tmp"
echo "Textfile output:"
cat "$tmpdir"/*.tmp | less
