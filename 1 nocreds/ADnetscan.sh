#!/bin/bash

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Validate input parameters
if [ $# -lt 1 ]; then
  echo -e "\nSyntax: ADnetscan.sh 'IP range' ['domain']"
  echo "Example: ./ADnetscan.sh 192.168.123.1/24 domain.local"
  exit 1
fi

net="$1"
domain="${2:-}"

# Extract subnet string
subnetStr=$(echo "$net" | cut -d'/' -f1)

# Output directory setup
outputDir="netscan_results_$subnetStr"
mkdir -p "$outputDir"

echo "Scanning network $net..."

# Nmap scans
echo "Running Nmap scans..."
grc nmap -sP -Pn -T4 "$net" -oA "$outputDir/nmap_${subnetStr}_ping" # ping scan
grc nmap -sV -Pn -T4 --top-ports 50 --open "$net" -oA "$outputDir/nmap_${subnetStr}_quick" # quick scan
grc nmap -Pn -T4 --script smb-vuln* -p139,445 "$net" -oA "$outputDir/nmap_${subnetStr}_smbvuln" # SMB vulnerability scan
# nmap -sU -Pn -sC -sV "$net" -oA "$outputDir/nmap_${subnetStr}_udp" # UDP scan

# SMB Enumeration
echo "Enumerating SMB hosts..."
crackmapexec smb --gen-relay-list "$outputDir/smb_targets_$subnetStr.txt" "$net"

# SMB OS discovery
echo "Running SMB OS discovery..."
grc nmap -Pn -T4 -p139,445 --script smb-os-discovery "$net" -oN "$outputDir/smb_os_discovery_$subnetStr"

# SMB Security Mode check
echo "Checking SMB Security Mode..."
grc nmap -Pn -T4 -p137,139,445 --script smb-security-mode "$net" -oN "$outputDir/smb_security_mode_$subnetStr"
grc nmap -sU -Pn -p137 --script smb-security-mode "$net" -oN "$outputDir/smb_security_mode_udp_$subnetStr"

# Additional Nmap NSE scripts
if [ -n "$domain" ]; then
  echo "Running additional Nmap NSE scripts..."
  grc nmap -Pn -T4 -p 3389 --script rdp-ntlm-info "$domain" -oN "$outputDir/rdp_ntlm_info_$subnetStr"
  grc nmap -sSC -T4 -Pn --script=*-ntlm-info -p 23,25,80,3389 "$domain" -oN "$outputDir/ntlm_info_$subnetStr"
  grc nmap -sSCV -T4 -Pn --script=*-ntlm-info --script-args http-ntlm-info.root=/ews/ -p 443,587,993 "$domain" -oN "$outputDir/http_ntlm_info_$subnetStr"
fi

echo "Scans completed. Results are stored in $outputDir."