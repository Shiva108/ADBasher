#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential
from core.logger import setup_logger, get_logger

logger = None

def run_bloodhound(session_dir, domain, dc_ip, username, password):
    global logger
    setup_logger("bloodhound", session_dir)
    logger = get_logger("bloodhound")
    
    logger.info(f"Starting BloodHound collection for {domain}")
    
    output_dir = os.path.join(session_dir, "bloodhound_data")
    os.makedirs(output_dir, exist_ok=True)
    
    # bloodhound-python command
    cmd = [
        "bloodhound-python",
        "-d", domain,
        "-u", username,
        "-p", password,
        "-dc", dc_ip,
        "-c", "All",  # Collect all data
        "--zip"  # Output as ZIP for Neo4j ingestion
    ]
    
    try:
        logger.info("Running bloodhound-python collector...")
        result = subprocess.run(
            cmd,
            cwd=output_dir,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        logger.debug(result.stdout)
        
        if result.returncode == 0:
            logger.info(f"BloodHound data collected successfully in {output_dir}")
            
            # List generated files
            files = os.listdir(output_dir)
            zip_files = [f for f in files if f.endswith('.zip')]
            
            if zip_files:
                logger.info(f"Generated files: {', '.join(zip_files)}")
                logger.info("Upload these to BloodHound GUI for analysis")
            else:
                logger.warning("No ZIP files generated")
        else:
            logger.error(f"BloodHound collection failed: {result.stderr}")
            
    except FileNotFoundError:
        logger.error("bloodhound-python not found. Install with: pip3 install bloodhound")
    except subprocess.TimeoutExpired:
        logger.error("BloodHound collection timed out (>5 min)")
    except Exception as e:
        logger.error(f"Error during BloodHound collection: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()
    
    run_bloodhound(args.session_dir, args.domain, args.dc_ip, args.username, args.password)
