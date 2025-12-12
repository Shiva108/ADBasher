#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential
from core.logger import setup_logger, get_logger

logger = None

def check_admin_privs(session_dir, domain, dc_ip):
    """Check which credentials have admin privileges using CrackMapExec."""
    global logger
    setup_logger("admin_check", session_dir)
    logger = get_logger("admin_check")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Checking for admin privileges on {dc_ip}")
    
    # Get all valid credentials
    session = db.get_session()
    creds = session.query(Credential).filter_by(domain=domain, is_valid=True).all()
    session.close()
    
    if not creds:
        logger.info("No credentials to check")
        return
    
    admin_count = 0
    
    for cred in creds:
        if cred.password:
            cmd = [
                "crackmapexec", "smb", dc_ip,
                "-u", cred.username,
                "-p", cred.password,
                "-d", domain
            ]
        elif cred.ntlm_hash:
            cmd = [
                "crackmapexec", "smb", dc_ip,
                "-u", cred.username,
                "-H", cred.ntlm_hash,
                "-d", domain
            ]
        else:
            continue
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Check for (Pwn3d!) indicator
            if "(Pwn3d!)" in result.stdout:
                logger.info(f"[ADMIN] {cred.username} has admin rights!")
                
                # Update database
                session = db.get_session()
                db_cred = session.query(Credential).filter_by(
                    username=cred.username, domain=domain
                ).first()
                if db_cred:
                    db_cred.is_admin = True
                    session.commit()
                session.close()
                
                admin_count += 1
            
        except Exception as e:
            logger.debug(f"Error checking {cred.username}: {e}")
    
    logger.info(f"Found {admin_count} admin credentials")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)
    args = parser.parse_args()
    
    check_admin_privs(args.session_dir, args.domain, args.dc_ip)
