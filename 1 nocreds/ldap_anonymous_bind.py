#!/usr/bin/env python3
import sys
import os
import argparse
from ldap3 import Server, Connection, ALL, ANONYMOUS

# Add root directory to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager, Target, Credential
from core.logger import setup_logger, get_logger

logger = None

def run_ldap_enum(session_dir, target_ip):
    global logger
    setup_logger("ldap_anonymous", session_dir)
    logger = get_logger("ldap_anonymous")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Attempting LDAP Anonymous Bind on {target_ip}")
    
    try:
        server = Server(target_ip, get_info=ALL)
        conn = Connection(server, user=ANONYMOUS, auto_bind=True)
        
        logger.info(f"Anonymous Bind SUCCESS on {target_ip}")
        
        # 1. Get Naming Context
        naming_context = server.info.other.get('defaultNamingContext', [''])[0]
        logger.info(f"Default Naming Context: {naming_context}")
        
        # Update Target info
        # Note: In a real implementation, we'd query for hostname/OS here too
        
        # 2. Enumerate Users (if possible)
        logger.info("Attempting to enumerate users...")
        try:
            conn.search(naming_context, '(objectClass=person)', attributes=['sAMAccountName', 'description'])
            count = 0
            for entry in conn.entries:
                username = str(entry.sAMAccountName)
                desc = str(entry.description) if entry.description else ""
                
                # Store in DB as "enumerated" credential
                logger.info(f"Found User: {username}")
                db.add_credential(
                    username=username,
                    domain=naming_context,
                    source="ldap_anonymous",
                    type="enumerated" # Plain user enumeration
                )
                count += 1
            logger.info(f"Enumerated {count} users via anonymous LDAP.")
            
        except Exception as e:
            logger.warning(f"Failed to enumerate users: {e}")

        # 3. Get Password Policy (minimal check via domain root)
        # Often requires read access to specific containers, might fail anonymously
        
    except Exception as e:
        logger.info(f"Anonymous Bind FAILED on {target_ip}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--target-ip", required=True)
    args = parser.parse_args()
    
    run_ldap_enum(args.session_dir, args.target_ip)
