#!/usr/bin/env python3
"""
ADnetscan Database Wrapper
Executes ADnetscan.sh and parses output to database
"""
import sys
import os
import argparse
import subprocess
import re

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager
from core.logger import setup_logger, get_logger

logger = None

def run_adnetscan_db(session_dir, target_cidr):
    """Run ADnetscan.sh and store results in database"""
    global logger
    setup_logger("adnetscan_db", session_dir)
    logger = get_logger("adnetscan_db")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Running ADnetscan on {target_cidr}")
    
    # Path to original ADnetscan.sh
    script_path = os.path.join(os.path.dirname(__file__), 'ADnetscan.sh')
    
    if not os.path.exists(script_path):
        logger.error(f"ADnetscan.sh not found at {script_path}")
        return
    
    output_file = os.path.join(session_dir, f"adnetscan_{target_cidr.replace('/', '_')}.txt")
    
    try:
        # Run ADnetscan.sh
        result = subprocess.run(
            ["sudo", script_path, target_cidr],
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout
        )
        
        # Save output
        with open(output_file, 'w') as f:
            f.write(result.stdout)
            f.write(result.stderr)
        
        logger.info(f"ADnetscan output saved: {output_file}")
        
        # Parse output for live hosts
        ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        
        live_hosts = set()
        for line in result.stdout.split('\n'):
            if 'open' in line.lower() or 'up' in line.lower():
                ips = ip_pattern.findall(line)
                live_hosts.update(ips)
        
        # Add to database
        for ip in live_hosts:
            if ip != target_cidr.split('/')[0]:  # Skip network address
                logger.info(f"Adding host to DB: {ip}")
                db.add_target(ip=ip, is_alive=True)
        
        logger.info(f"ADnetscan complete: {len(live_hosts)} live hosts found")
        
    except subprocess.TimeoutExpired:
        logger.error("ADnetscan timed out (>10 min)")
    except Exception as e:
        logger.error(f"ADnetscan failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--target", required=True, help="CIDR range to scan")
    args = parser.parse_args()
    
    run_adnetscan_db(args.session_dir, args.target)
