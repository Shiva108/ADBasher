#!/usr/bin/env python3
"""
Database Integrity Verification Script
Checks database schema and data consistency
"""
import sys
import os
import argparse

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager, Target, Credential, Vulnerability
from sqlalchemy import inspect


def verify_database(db_path):
    """Verify database integrity"""
    print(f"[*] Verifying database: {db_path}")
    
    if not os.path.exists(db_path):
        print(f"[!] Database not found: {db_path}")
        return False
    
    try:
        db = DatabaseManager(db_path)
        session = db.get_session()
        
        # 1. Check tables exist
        inspector = inspect(session.bind)
        tables = inspector.get_table_names()
        
        required_tables = ['targets', 'credentials', 'vulnerabilities']
        missing_tables = [t for t in required_tables if t not in tables]
        
        if missing_tables:
            print(f"[!] Missing tables: {missing_tables}")
            return False
        
        print(f"[+] All required tables present: {', '.join(tables)}")
        
        # 2. Check data counts
        target_count = session.query(Target).count()
        cred_count = session.query(Credential).count()
        vuln_count = session.query(Vulnerability).count()
        
        print(f"[+] Targets: {target_count}")
        print(f"[+] Credentials: {cred_count}")
        print(f"[+] Vulnerabilities: {vuln_count}")
        
        # 3. Check for orphaned vulnerabilities
        orphaned_vulns = session.query(Vulnerability).filter(
            ~Vulnerability.target_id.in_(
                session.query(Target.id)
            )
        ).count()
        
        if orphaned_vulns > 0:
            print(f"[!] Warning: {orphaned_vulns} orphaned vulnerabilities (no matching target)")
        else:
            print("[+] No orphaned vulnerabilities")
        
        # 4. Check credential validity
        valid_creds = session.query(Credential).filter_by(is_valid=True).count()
        admin_creds = session.query(Credential).filter_by(is_admin=True).count()
        
        print(f"[+] Valid credentials: {valid_creds}/{cred_count}")
        print(f"[+] Admin credentials: {admin_creds}/{cred_count}")
        
        # 5. Check for DCs
        dcs = session.query(Target).filter_by(is_dc=True).count()
        print(f"[+] Domain Controllers: {dcs}")
        
        # 6. Check credential sources
        sources = session.query(Credential.source).distinct().all()
        print(f"[+] Credential sources: {', '.join([s[0] for s in sources])}")
        
        session.close()
        
        print("\n[✓] Database integrity verified successfully")
        return True
        
    except Exception as e:
        print(f"[!] Database verification failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify ADBasher database integrity")
    parser.add_argument("db_path", help="Path to session.db file")
    args = parser.parse_args()
    
    success = verify_database(args.db_path)
    sys.exit(0 if success else 1)
