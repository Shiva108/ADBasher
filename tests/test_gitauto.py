#!/usr/bin/env python3
"""
Test Suite for GitAuto - Automated Git Error Detection and Resolution

Tests error detection, resolution strategies, safety mechanisms,
and configuration management.
"""

import os
import sys
import unittest
import tempfile
import shutil
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from git import Repo
    from scripts.gitauto import (
        GitAutoEngine, ConfigManager, GitAnalyzer, GitResolver,
        ErrorType, ResolutionStatus, GitError, RepositoryState
    )
except ImportError as e:
    print(f"Error: {e}")
    print("Install dependencies: pip3 install GitPython PyYAML rich")
    sys.exit(1)


class TestConfigManager(unittest.TestCase):
    """Test configuration management"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.temp_dir, '.gitauto.yaml')
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_default_config_load(self):
        """Test loading default configuration"""
        config = ConfigManager(self.config_path)
        self.assertTrue(config.get('automation.enabled'))
        self.assertEqual(config.get('remote.default_remote'), 'origin')
    
    def test_config_save(self):
        """Test saving configuration file"""
        config = ConfigManager()
        config.save_default_config(self.config_path)
        self.assertTrue(os.path.exists(self.config_path))
    
    def test_dot_notation_access(self):
        """Test configuration access using dot notation"""
        config = ConfigManager()
        self.assertIsNotNone(config.get('automation.enabled'))
        self.assertEqual(config.get('nonexistent.key', 'default'), 'default')


class TestGitAnalyzer(unittest.TestCase):
    """Test Git repository analysis"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.repo = Repo.init(self.test_dir)
        
        # Configure git
        with self.repo.config_writer() as cw:
            cw.set_value("user", "name", "Test User")
            cw.set_value("user", "email", "test@example.com")
        
        self.config = ConfigManager()
        
        # Create a minimal logger for testing
        from scripts.gitauto import GitAutoLogger
        self.logger = GitAutoLogger(self.config, self.test_dir)
        
        self.analyzer = GitAnalyzer(self.test_dir, self.config, self.logger)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
        
        # Clean up log directory
        log_dir = os.path.join(self.test_dir, '.gitauto', 'logs')
        if os.path.exists(log_dir):
            shutil.rmtree(log_dir, ignore_errors=True)
    
    def test_clean_repository_state(self):
        """Test analysis of clean repository"""
        # Create initial commit
        test_file = os.path.join(self.test_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('initial content')
        
        self.repo.index.add(['test.txt'])
        self.repo.index.commit('initial commit')
        
        state = self.analyzer.get_repository_state()
        self.assertFalse(state.is_dirty)
        self.assertEqual(len(state.untracked_files), 0)
        self.assertEqual(len(state.modified_files), 0)
    
    def test_detect_uncommitted_changes(self):
        """Test detection of uncommitted changes"""
        # Create initial commit
        test_file = os.path.join(self.test_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('initial content')
        
        self.repo.index.add(['test.txt'])
        self.repo.index.commit('initial commit')
        
        # Modify file
        with open(test_file, 'w') as f:
            f.write('modified content')
        
        state = self.analyzer.get_repository_state()
        errors = self.analyzer.detect_errors(state)
        
        self.assertTrue(state.is_dirty)
        self.assertEqual(len(state.modified_files), 1)
        
        # Should detect uncommitted changes error
        error_types = [e.error_type for e in errors]
        self.assertIn(ErrorType.UNCOMMITTED_CHANGES, error_types)
    
    def test_detect_untracked_files(self):
        """Test detection of untracked files"""
        # Create untracked file
        test_file = os.path.join(self.test_dir, 'untracked.txt')
        with open(test_file, 'w') as f:
            f.write('untracked content')
        
        state = self.analyzer.get_repository_state()
        errors = self.analyzer.detect_errors(state)
        
        self.assertEqual(len(state.untracked_files), 1)
        
        error_types = [e.error_type for e in errors]
        self.assertIn(ErrorType.UNTRACKED_FILES, error_types)


class TestGitResolver(unittest.TestCase):
    """Test automated resolution strategies"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.repo = Repo.init(self.test_dir)
        
        # Configure git
        with self.repo.config_writer() as cw:
            cw.set_value("user", "name", "Test User")
            cw.set_value("user", "email", "test@example.com")
        
        self.config = ConfigManager()
        self.config.config['automation']['dry_run'] = True  # Dry run for testing
        
        from scripts.gitauto import GitAutoLogger
        self.logger = GitAutoLogger(self.config, self.test_dir)
        
        self.resolver = GitResolver(self.test_dir, self.config, self.logger)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_resolve_uncommitted_changes_dry_run(self):
        """Test uncommitted changes resolution in dry-run mode"""
        # Create file
        test_file = os.path.join(self.test_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('content')
        
        self.repo.index.add(['test.txt'])
        self.repo.index.commit('initial')
        
        # Modify
        with open(test_file, 'w') as f:
            f.write('modified')
        
        error = GitError(
            error_type=ErrorType.UNCOMMITTED_CHANGES,
            severity='medium',
            description='Test error',
            details={'files': ['test.txt']}
        )
        
        result = self.resolver.resolve_uncommitted_changes(error)
        
        # In dry-run, should succeed but not actually commit
        self.assertEqual(result.status, ResolutionStatus.SUCCESS)
        self.assertIn('DRY RUN', result.message)
    
    def test_exclusion_patterns(self):
        """Test file exclusion patterns"""
        self.config.config['exclusions']['patterns'] = ['*.log', '*.tmp']
        
        # Test pattern matching
        self.assertTrue(self.resolver._match_pattern('test.log', '*.log'))
        self.assertTrue(self.resolver._match_pattern('data.tmp', '*.tmp'))
        self.assertFalse(self.resolver._match_pattern('test.txt', '*.log'))


class TestGitAutoEngine(unittest.TestCase):
    """Test main automation engine"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.repo = Repo.init(self.test_dir)
        
        with self.repo.config_writer() as cw:
            cw.set_value("user", "name", "Test User")
            cw.set_value("user", "email", "test@example.com")
        
        # Create config
        config_path = os.path.join(self.test_dir, '.gitauto.yaml')
        config = ConfigManager()
        config.save_default_config(config_path)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_engine_initialization(self):
        """Test engine initialization"""
        engine = GitAutoEngine(self.test_dir, dry_run=True)
        self.assertIsNotNone(engine.analyzer)
        self.assertIsNotNone(engine.resolver)
        self.assertIsNotNone(engine.config)
    
    def test_check_clean_repository(self):
        """Test checking clean repository"""
        # Create initial commit
        test_file = os.path.join(self.test_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('content')
        
        self.repo.index.add(['test.txt'])
        self.repo.index.commit('initial')
        
        engine = GitAutoEngine(self.test_dir, dry_run=True)
        state, errors = engine.check()
        
        self.assertFalse(state.is_dirty)
        self.assertEqual(len(errors), 0)
    
    def test_status_report(self):
        """Test status report generation"""
        engine = GitAutoEngine(self.test_dir, dry_run=True)
        status = engine.status()
        
        self.assertIn('repository', status)
        self.assertIn('state', status)
        self.assertIn('errors', status)
        self.assertIn('is_clean', status)


class TestSafetyMechanisms(unittest.TestCase):
    """Test safety features"""
    
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.repo = Repo.init(self.test_dir)
        
        with self.repo.config_writer() as cw:
            cw.set_value("user", "name", "Test User")
            cw.set_value("user", "email", "test@example.com")
        
        self.config = ConfigManager()
        
        from scripts.gitauto import GitAutoLogger
        self.logger = GitAutoLogger(self.config, self.test_dir)
        
        self.resolver = GitResolver(self.test_dir, self.config, self.logger)
    
    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_backup_creation(self):
        """Test automatic backup creation"""
        # Create and modify file
        test_file = os.path.join(self.test_dir, 'test.txt')
        with open(test_file, 'w') as f:
            f.write('content')
        
        # Repository is dirty, backup should be created
        backup_msg = self.resolver.create_backup()
        
        if backup_msg:  # Only if not in dry-run
            self.assertIn('gitauto_backup', backup_msg)
            
            # Verify stash was created
            stash_list = self.repo.git.stash('list')
            self.assertIn('gitauto_backup', stash_list)


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(TestConfigManager))
    suite.addTests(loader.loadTestsFromTestCase(TestGitAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestGitResolver))
    suite.addTests(loader.loadTestsFromTestCase(TestGitAutoEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestSafetyMechanisms))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())
