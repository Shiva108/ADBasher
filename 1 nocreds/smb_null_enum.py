#!/usr/bin/env python3
"""
SMB Null Session Enumeration Module
Attempts to enumerate domain information without credentials
"""
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential, Target
from core.logger import setup_logger, get_logger

logger = None

def smb_null_enum(session_dir, target_ip):
    """Attempt SMB null session enumeration"""
    global logger
    setup_logger("smb_null", session_dir)
    logger = get_logger("smb_null")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Attempting SMB null session on {target_ip}")
    
    # Method 1: enum4linux-ng (modern version)
    output_file = os.path.join(session_dir, f"smb_null_{target_ip}.txt")
    
    cmd = [
        "enum4linux-ng",
        "-A",  # All enumeration
        "-oY", output_file,  # YAML output
        target_ip
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        logger.info(f"enum4linux-ng output saved to {output_file}")
        
        # Parse users from output
        users_found = []
        for line in result.stdout.split('\n'):
            if "username:" in line.lower() or "user:" in line.lower():
                # Simple parsing - would need refinement
                parts = line.split()
                if len(parts) > 1:
                    username = parts[-1].strip()
                    if username and len(username) > 2:
                        users_found.append(username)
        
        if users_found:
            logger.info(f"Found {len(users_found)} users via null session")
            session = db.get_session()
            target = session.query(Target).filter_by(ip_address=target_ip).first()
            domain = target.domain if target else "WORKGROUP"
            
            for user in set(users_found):  # Deduplicate
                db.add_credential(
                    username=user,
                    domain=domain,
                    source="smb_null_session",
                    type="enumerated"
                )
            session.close()
        else:
            logger.info("Null session blocked or no users enumerated")
            
    except FileNotFoundError:
        logger.warning("enum4linux-ng not found. Trying rpcclient...")
        
        # Fallback: rpcclient
        try:
            rpc_cmd = f"rpcclient -U '' -N {target_ip} -c 'enumdomusers'"
            result = subprocess.run(
                rpc_cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if "user:" in result.stdout.lower():
                logger.info("Null session successful via rpcclient")
                with open(output_file, 'w') as f:
                    f.write(result.stdout)
            else:
                logger.info("Null session blocked")
                
        except Exception as e:
            logger.error(f"rpcclient failed: {e}")
            
    except Exception as e:
        logger.error(f"SMB null session enumeration failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--target-ip", required=True)
    args = parser.parse_args()
    
    smb_null_enum(args.session_dir, args.target_ip)
