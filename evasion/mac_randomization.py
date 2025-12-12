#!/usr/bin/env python3
"""
MAC Address Randomization Module
Changes network interface MAC addresses for evasion
"""
import subprocess
import random
import os

from core.logger import get_logger

logger = get_logger("mac_randomization")

def generate_random_mac():
    """Generate a random MAC address"""
    # Use locally administered MAC (2nd least significant bit of first octet = 1)
    mac = [0x02, random.randint(0x00, 0xff), random.randint(0x00, 0xff),
           random.randint(0x00, 0xff), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
    return ':'.join(map(lambda x: "%02x" % x, mac))

def change_mac_address(interface="eth0", new_mac=None):
    """Change MAC address of specified interface"""
    if os.geteuid() != 0:
        logger.error("MAC randomization requires root privileges")
        return False
    
    if not new_mac:
        new_mac = generate_random_mac()
    
    logger.info(f"Changing {interface} MAC to {new_mac}")
    
    try:
        # Bring interface down
        subprocess.run(["ip", "link", "set", "dev", interface, "down"], check=True)
        
        # Change MAC
        subprocess.run(["ip", "link", "set", "dev", interface, "address", new_mac], check=True)
        
        # Bring interface up
        subprocess.run(["ip", "link", "set", "dev", interface, "up"], check=True)
        
        logger.info(f"MAC address changed successfully: {new_mac}")
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to change MAC address: {e}")
        return False
    except Exception as e:
        logger.error(f"MAC randomization error: {e}")
        return False

def get_interfaces():
    """Get list of network interfaces"""
    try:
        result = subprocess.run(
            ["ip", "link", "show"],
            capture_output=True,
            text=True
        )
        
        interfaces = []
        for line in result.stdout.split('\n'):
            if ': ' in line and '@' not in line:  # Skip virtual interfaces
                parts = line.split(': ')
                if len(parts) >= 2:
                    iface = parts[1].split('@')[0]
                    if iface != "lo":  # Skip loopback
                        interfaces.append(iface)
        
        return interfaces
    except Exception as e:
        logger.error(f"Failed to get interfaces: {e}")
        return []

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", help="Network interface to modify")
    parser.add_argument("--mac", help="Specific MAC address (otherwise random)")
    args = parser.parse_args()
    
    if args.interface:
        change_mac_address(args.interface, args.mac)
    else:
        # Randomize all interfaces
        interfaces = get_interfaces()
        print(f"Found interfaces: {interfaces}")
        for iface in interfaces:
            change_mac_address(iface)
