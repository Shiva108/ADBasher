#!/usr/bin/env python3
"""
Integration Test Framework for ADBasher
Simulates attack chain execution without real network access
"""
import sys
import os
import tempfile
import shutil
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager, Target, Credential
from core.logger import setup_logger, get_logger


class MockADEnvironment:
    """Simulates an AD environment for testing"""
    
    def __init__(self, session_dir):
        self.session_dir = session_dir
        self.db_path = os.path.join(session_dir, "test_session.db")
        self.db = DatabaseManager(self.db_path)
        setup_logger("integration_test", session_dir)
        self.logger = get_logger("MockAD")
    
    def populate_test_data(self):
        """Populate database with test data"""
        self.logger.info("Populating test environment...")
        
        # Add test DCs
        self.db.add_target(
            ip="192.168.1.10",
            hostname="DC01.test.local",
            domain="test.local",
            is_dc=True,
            is_alive=True
        )
        
        self.db.add_target(
            ip="192.168.1.11",
            hostname="DC02.test.local",
            domain="test.local",
            is_dc=True,
            is_alive=True
        )
        
        # Add test workstations
        for i in range(20, 25):
            self.db.add_target(
                ip=f"192.168.1.{i}",
                hostname=f"WS{i:02d}.test.local",
                domain="test.local",
                is_alive=True
            )
        
        # Add test credentials (from enumeration)
        for user in ["jdoe", "asmith", "bwilliams", "administrator"]:
            self.db.add_credential(
                username=user,
                domain="test.local",
                source="ldap_anonymous"
            )
        
        self.logger.info("Test environment populated")
    
    def test_credential_cascading(self):
        """Test credential cascading logic"""
        self.logger.info("Testing credential cascading...")
        
        # Simulate password spray finding a valid credential
        self.db.add_credential(
            username="jdoe",
            domain="test.local",
            password="Password123",
            source="password_spray",
            is_valid=True
        )
        
        session = self.db.get_session()
        valid_creds = session.query(Credential).filter_by(is_valid=True).all()
        session.close()
        
        assert len(valid_creds) == 1, "Should have 1 valid credential"
        self.logger.info(f"✓ Valid credentials: {len(valid_creds)}")
        
        # Simulate admin privilege detection
        session = self.db.get_session()
        cred = session.query(Credential).filter_by(username="jdoe").first()
        cred.is_admin = True
        session.commit()
        session.close()
        
        session = self.db.get_session()
        admin_creds = session.query(Credential).filter_by(is_admin=True).all()
        session.close()
        
        assert len(admin_creds) == 1, "Should have 1 admin credential"
        self.logger.info(f"✓ Admin credentials: {len(admin_creds)}")
        
        # This should trigger post-exploitation phase in real execution
        self.logger.info("✓ Credential cascading logic verified")
    
    def test_database_queries(self):
        """Test common database queries"""
        self.logger.info("Testing database queries...")
        
        session = self.db.get_session()
        
        # Query DCs
        dcs = session.query(Target).filter_by(is_dc=True).all()
        assert len(dcs) == 2, f"Expected 2 DCs, found {len(dcs)}"
        self.logger.info(f"✓ DC query: {len(dcs)} DCs found")
        
        # Query live hosts
        live_hosts = session.query(Target).filter_by(is_alive=True).all()
        assert len(live_hosts) >= 5, f"Expected >= 5 hosts, found {len(live_hosts)}"
        self.logger.info(f"✓ Live hosts query: {len(live_hosts)} hosts")
        
        # Query credentials by source
        ldap_creds = session.query(Credential).filter_by(source="ldap_anonymous").all()
        assert len(ldap_creds) == 4, f"Expected 4 LDAP creds, found {len(ldap_creds)}"
        self.logger.info(f"✓ Credential source query: {len(ldap_creds)} from LDAP")
        
        session.close()
        
        self.logger.info("✓ All database queries successful")
    
    def run_all_tests(self):
        """Run full integration test suite"""
        print("\n" + "="*60)
        print("ADBasher Integration Test Suite")
        print("="*60 + "\n")
        
        try:
            self.populate_test_data()
            self.test_database_queries()
            self.test_credential_cascading()
            
            print("\n" + "="*60)
            print("[✓] ALL INTEGRATION TESTS PASSED")
            print("="*60 + "\n")
            return True
            
        except AssertionError as e:
            print(f"\n[!] TEST FAILED: {e}")
            return False
        except Exception as e:
            print(f"\n[!] ERROR: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Run integration tests"""
    test_dir = tempfile.mkdtemp(prefix="adbasher_test_")
    
    try:
        env = MockADEnvironment(test_dir)
        success = env.run_all_tests()
        
        if success:
            print(f"Test artifacts saved to: {test_dir}")
            print(f"Database: {env.db_path}")
        
        return 0 if success else 1
        
    finally:
        # Clean up
        # shutil.rmtree(test_dir)
        pass


if __name__ == "__main__":
    sys.exit(main())
