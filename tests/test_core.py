#!/usr/bin/env python3
"""
Unit Tests for Core ADBasher Modules
Run with: python3 -m pytest tests/
"""
import unittest
import tempfile
import os
import sys
import shutil
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager, Target, Credential, Vulnerability
from core.logger import setup_logger, get_logger
import yaml


class TestDatabaseManager(unittest.TestCase):
    """Test database operations"""
    
    def setUp(self):
        """Create temporary database for testing"""
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test.db")
        self.db = DatabaseManager(self.db_path)
    
    def tearDown(self):
        """Clean up test database"""
        shutil.rmtree(self.test_dir)
    
    def test_database_creation(self):
        """Test that database file is created"""
        self.assertTrue(os.path.exists(self.db_path))
    
    def test_add_target(self):
        """Test adding targets to database"""
        self.db.add_target(ip="192.168.1.10", hostname="DC01", domain="test.local", is_dc=True)
        
        session = self.db.get_session()
        targets = session.query(Target).all()
        session.close()
        
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].ip_address, "192.168.1.10")
        self.assertEqual(targets[0].hostname, "DC01")
        self.assertTrue(targets[0].is_dc)
    
    def test_add_credential(self):
        """Test adding credentials to database"""
        self.db.add_credential(
            username="admin",
            domain="test.local",
            password="Password123",
            source="password_spray"
        )
        
        session = self.db.get_session()
        creds = session.query(Credential).all()
        session.close()
        
        self.assertEqual(len(creds), 1)
        self.assertEqual(creds[0].username, "admin")
        self.assertEqual(creds[0].domain, "test.local")
        self.assertTrue(creds[0].is_valid)
    
    def test_duplicate_target_prevention(self):
        """Test that duplicate targets are not added"""
        self.db.add_target(ip="192.168.1.10", hostname="DC01")
        self.db.add_target(ip="192.168.1.10", hostname="DC01_COPY")  # Should update, not duplicate
        
        session = self.db.get_session()
        targets = session.query(Target).filter_by(ip_address="192.168.1.10").all()
        session.close()
        
        self.assertEqual(len(targets), 1)
    
    def test_credential_admin_flag(self):
        """Test admin credential flagging"""
        self.db.add_credential(
            username="admin",
            domain="test.local",
            password="Password123",
            source="password_spray",
            is_admin=True
        )
        
        session = self.db.get_session()
        admin_creds = session.query(Credential).filter_by(is_admin=True).all()
        session.close()
        
        self.assertEqual(len(admin_creds), 1)
    
    def test_vulnerability_storage(self):
        """Test vulnerability tracking"""
        # First add a target
        self.db.add_target(ip="192.168.1.10")
        
        session = self.db.get_session()
        target = session.query(Target).first()
        
        vuln = Vulnerability(
            target_id=target.id,
            name="Test Vulnerability",
            severity="High",
            description="Test description"
        )
        session.add(vuln)
        session.commit()
        
        vulns = session.query(Vulnerability).all()
        session.close()
        
        self.assertEqual(len(vulns), 1)
        self.assertEqual(vulns[0].name, "Test Vulnerability")


class TestLogger(unittest.TestCase):
    """Test logging functionality"""
    
    def setUp(self):
        """Create temporary log directory"""
        self.test_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """Clean up test logs"""
        shutil.rmtree(self.test_dir)
    
    def test_logger_creation(self):
        """Test that logger is created successfully"""
        setup_logger("test_session", self.test_dir, level="INFO")
        logger = get_logger("TestModule")
        
        self.assertIsNotNone(logger)
        logger.info("Test log message")
        
        # Check that log file was created
        log_files = list(Path(self.test_dir).glob("*.log"))
        self.assertGreater(len(log_files), 0)
    
    def test_json_logging(self):
        """Test JSON log format"""
        setup_logger("test_session", self.test_dir, level="INFO")
        logger = get_logger("TestModule")
        logger.info("Test JSON message")
        
        # Check for JSON log file
        json_logs = list(Path(self.test_dir).glob("*.json.log"))
        self.assertGreater(len(json_logs), 0)


class TestCredentialCascading(unittest.TestCase):
    """Test credential cascading logic"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test.db")
        self.db = DatabaseManager(self.db_path)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir)
    
    def test_admin_credential_triggers_escalation(self):
        """Test that admin credentials are properly flagged"""
        # Add regular credential
        self.db.add_credential(
            username="user1",
            domain="test.local",
            password="Password123",
            is_admin=False
        )
        
        # Add admin credential
        self.db.add_credential(
            username="admin",
            domain="test.local",
            password="AdminPass123",
            is_admin=True
        )
        
        session = self.db.get_session()
        
        # Verify only admin creds are flagged
        regular_creds = session.query(Credential).filter_by(is_admin=False).all()
        admin_creds = session.query(Credential).filter_by(is_admin=True).all()
        
        session.close()
        
        self.assertEqual(len(regular_creds), 1)
        self.assertEqual(len(admin_creds), 1)
        self.assertEqual(admin_creds[0].username, "admin")


class TestConfigParsing(unittest.TestCase):
    """Test configuration file parsing"""
    
    def test_config_yaml_parsing(self):
        """Test that config.yaml can be parsed"""
        config_path = os.path.join(os.path.dirname(__file__), '..', 'core', 'config.yaml')
        
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
            
            self.assertIn('global', config)
            self.assertIn('scope', config)
            self.assertIn('evasion', config)
        else:
            self.skipTest("config.yaml not found")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)
