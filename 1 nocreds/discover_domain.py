#!/usr/bin/env python3
import sys
import os
import argparse
import dns.resolver
from datetime import datetime

# Add root directory to sys.path to ensure we can import 'core'
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager, Target
from core.logger import setup_logger, get_logger

logger = None

def find_dcs(domain, resolver=None):
    """
    Query DNS for LDAP SRV records to find Domain Controllers.
    _ldap._tcp.dc._msdcs.<DOMAIN>
    """
    logger.info(f"Querying SRV records for domain: {domain}")
    dcs = []
    srv_record = f"_ldap._tcp.dc._msdcs.{domain}"
    
    try:
        if resolver:
            answers = resolver.resolve(srv_record, 'SRV')
        else:
            answers = dns.resolver.resolve(srv_record, 'SRV')
        
        for rdata in answers:
            dc_hostname = str(rdata.target).rstrip('.')
            logger.info(f"Found DC SRV Record: {dc_hostname} on port {rdata.port}")
            
            # Resolve IP
            try:
                if resolver:
                    ip_answers = resolver.resolve(dc_hostname, 'A')
                else:
                    ip_answers = dns.resolver.resolve(dc_hostname, 'A')
                
                for ip in ip_answers:
                    dcs.append({
                        "hostname": dc_hostname,
                        "ip": str(ip)
                    })
                    logger.info(f"Resolved DC {dc_hostname} -> {ip}")
            except Exception as e:
                logger.error(f"Could not resolve IP for {dc_hostname}: {e}")
                
    except Exception as e:
        logger.warning(f"Failed to query SRV record {srv_record}: {e}")
    
    return dcs

def run(session_dir, domain):
    global logger
    # Setup logging to hook into the session log
    setup_logger("discover_domain", session_dir)
    logger = get_logger("discover_domain")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Starting Domain Discovery for: {domain}")
    
    # 1. SRV Lookup
    found_dcs = find_dcs(domain)
    
    if not found_dcs:
        logger.warning("No DCs found via DNS. Trying direct A record lookup for domain...")
        # Fallback: try to resolve the domain itself (often points to DCs)
        try:
            answers = dns.resolver.resolve(domain, 'A')
            for ip in answers:
                found_dcs.append({
                    "hostname": f"dc_unknown_{ip}", 
                    "ip": str(ip)
                })
        except Exception as e:
            logger.error(f"Failed to resolve domain A record: {e}")

    # 2. Store in DB
    count = 0
    for dc in found_dcs:
        logger.info(f"Adding DC to database: {dc['ip']} ({dc['hostname']})")
        db.add_target(
            ip=dc['ip'],
            hostname=dc['hostname'],
            domain=domain,
            is_dc=True
        )
        count += 1
        
    logger.info(f"Domain Discovery Completed. Found {count} Domain Controllers.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True, help="Path to session directory")
    parser.add_argument("--domain", required=True, help="Target Domain")
    args = parser.parse_args()
    
    run(args.session_dir, args.domain)
