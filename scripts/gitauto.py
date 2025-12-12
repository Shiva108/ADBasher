#!/usr/bin/env python3
"""
GitAuto - Automated Git Error Detection and Resolution System

A production-ready tool for autonomous Git error handling, conflict resolution,
and repository maintenance without manual intervention.

Author: DevOps Automation Team
License: MIT
"""

import os
import sys
import json
import subprocess
import argparse
import yaml
import re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum
import shutil
import hashlib

try:
    from git import Repo, GitCommandError, InvalidGitRepositoryError
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Install with: pip3 install GitPython PyYAML rich")
    sys.exit(1)


# ============================================================================
# CONSTANTS AND ENUMS
# ============================================================================

class ErrorType(Enum):
    """Git error classification"""
    UNCOMMITTED_CHANGES = "uncommitted_changes"
    DETACHED_HEAD = "detached_head"
    MERGE_CONFLICT = "merge_conflict"
    DIVERGED_BRANCHES = "diverged_branches"
    UNTRACKED_FILES = "untracked_files"
    SUBMODULE_ISSUES = "submodule_issues"
    UNPUSHED_COMMITS = "unpushed_commits"
    AUTH_FAILURE = "auth_failure"
    NETWORK_ERROR = "network_error"
    STALE_BRANCHES = "stale_branches"
    CORRUPTED_INDEX = "corrupted_index"


class ResolutionStatus(Enum):
    """Resolution attempt status"""
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    PARTIAL = "partial"


class ConflictStrategy(Enum):
    """Merge conflict resolution strategies"""
    OURS = "ours"
    THEIRS = "theirs"
    MANUAL = "manual"
    SKIP = "skip"


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class GitError:
    """Represents a detected Git error"""
    error_type: ErrorType
    severity: str  # critical, high, medium, low
    description: str
    details: Dict[str, Any]
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class ResolutionResult:
    """Result of an automated resolution attempt"""
    error_type: ErrorType
    status: ResolutionStatus
    message: str
    actions_taken: List[str]
    backup_created: bool
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class RepositoryState:
    """Complete repository state snapshot"""
    branch: str
    is_dirty: bool
    untracked_files: List[str]
    modified_files: List[str]
    staged_files: List[str]
    ahead_count: int
    behind_count: int
    has_conflicts: bool
    detached_head: bool
    submodule_issues: List[str]
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


# ============================================================================
# CONFIGURATION MANAGER
# ============================================================================

class ConfigManager:
    """Manages gitauto configuration"""
    
    DEFAULT_CONFIG = {
        'automation': {
            'enabled': True,
            'dry_run': False,
            'auto_commit': True,
            'auto_push': True,
            'auto_pull': True,
        },
        'commits': {
            'message_template': 'chore: automated commit - {description}',
            'sign_commits': False,
            'gpg_key': '',
        },
        'conflicts': {
            'strategy': 'ours',
            'auto_resolve': True,
        },
        'submodules': {
            'auto_update': True,
            'recursive': True,
        },
        'safety': {
            'create_backups': True,
            'backup_retention_days': 7,
            'require_clean_tree': False,
        },
        'remote': {
            'default_remote': 'origin',
            'default_branch': 'main',
            'push_retries': 3,
            'retry_delay': 5,
        },
        'logging': {
            'level': 'INFO',
            'file': '.gitauto/logs/gitauto.log',
            'json_logs': True,
            'console_output': True,
        },
        'exclusions': {
            'paths': [],
            'patterns': ['*.log', '*.tmp', '__pycache__/'],
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or '.gitauto.yaml'
        self.config = self._load_config()
    
    def _load_config(self) -> Dict:
        """Load configuration from file or use defaults"""
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = yaml.safe_load(f) or {}
                return self._merge_configs(self.DEFAULT_CONFIG, user_config)
            except Exception as e:
                print(f"Warning: Failed to load config from {self.config_path}: {e}")
                return self.DEFAULT_CONFIG.copy()
        return self.DEFAULT_CONFIG.copy()
    
    def _merge_configs(self, default: Dict, user: Dict) -> Dict:
        """Deep merge user config into default config"""
        result = default.copy()
        for key, value in user.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, key_path: str, default=None):
        """Get config value using dot notation (e.g., 'automation.enabled')"""
        keys = key_path.split('.')
        value = self.config
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        return value
    
    def save_default_config(self, path: Optional[str] = None):
        """Save default configuration to file"""
        path = path or self.config_path
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else '.', exist_ok=True)
        with open(path, 'w') as f:
            yaml.dump(self.DEFAULT_CONFIG, f, default_flow_style=False, sort_keys=False)


# ============================================================================
# LOGGER
# ============================================================================

class GitAutoLogger:
    """Comprehensive logging system with JSON and console output"""
    
    def __init__(self, config: ConfigManager, repo_path: str = '.'):
        self.config = config
        self.repo_path = repo_path
        self.console = Console()
        
        # Setup log directory
        log_file = config.get('logging.file', '.gitauto/logs/gitauto.log')
        self.log_dir = os.path.join(repo_path, os.path.dirname(log_file))
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Log files
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.text_log = os.path.join(self.log_dir, f'gitauto_{timestamp}.log')
        self.json_log = os.path.join(self.log_dir, f'gitauto_{timestamp}.json')
        self.error_log = os.path.join(self.log_dir, f'gitauto_errors_{timestamp}.log')
        
        # Audit trail
        self.actions: List[Dict] = []
    
    def _write_log(self, level: str, message: str, data: Optional[Dict] = None):
        """Write to log files"""
        timestamp = datetime.now().isoformat()
        
        # Text log
        with open(self.text_log, 'a') as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")
            if data:
                f.write(f"  Data: {json.dumps(data, indent=2)}\n")
        
        # JSON log
        if self.config.get('logging.json_logs', True):
            log_entry = {
                'timestamp': timestamp,
                'level': level,
                'message': message,
                'data': data or {}
            }
            with open(self.json_log, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        
        # Error log
        if level == 'ERROR':
            with open(self.error_log, 'a') as f:
                f.write(f"[{timestamp}] {message}\n")
                if data:
                    f.write(f"  {json.dumps(data, indent=2)}\n")
    
    def info(self, message: str, data: Optional[Dict] = None):
        """Log info message"""
        if self.config.get('logging.console_output', True):
            self.console.print(f"[blue]ℹ[/blue] {message}")
        self._write_log('INFO', message, data)
    
    def success(self, message: str, data: Optional[Dict] = None):
        """Log success message"""
        if self.config.get('logging.console_output', True):
            self.console.print(f"[green]✓[/green] {message}")
        self._write_log('SUCCESS', message, data)
    
    def warning(self, message: str, data: Optional[Dict] = None):
        """Log warning message"""
        if self.config.get('logging.console_output', True):
            self.console.print(f"[yellow]⚠[/yellow] {message}")
        self._write_log('WARNING', message, data)
    
    def error(self, message: str, data: Optional[Dict] = None):
        """Log error message"""
        if self.config.get('logging.console_output', True):
            self.console.print(f"[red]✗[/red] {message}")
        self._write_log('ERROR', message, data)
    
    def action(self, action: str, details: Optional[Dict] = None):
        """Log and record an action for audit trail"""
        action_entry = {
            'timestamp': datetime.now().isoformat(),
            'action': action,
            'details': details or {}
        }
        self.actions.append(action_entry)
        self.info(f"Action: {action}", details)
    
    def get_audit_trail(self) -> List[Dict]:
        """Get complete audit trail"""
        return self.actions.copy()
    
    def save_audit_report(self, path: Optional[str] = None):
        """Save audit trail to file"""
        path = path or os.path.join(self.log_dir, f'audit_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
        with open(path, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'actions': self.actions,
                'summary': {
                    'total_actions': len(self.actions),
                    'log_files': {
                        'text': self.text_log,
                        'json': self.json_log,
                        'errors': self.error_log
                    }
                }
            }, f, indent=2)


# ============================================================================
# GIT REPOSITORY ANALYZER
# ============================================================================

class GitAnalyzer:
    """Analyzes Git repository state and detects errors"""
    
    def __init__(self, repo_path: str, config: ConfigManager, logger: GitAutoLogger):
        self.repo_path = repo_path
        self.config = config
        self.logger = logger
        
        try:
            self.repo = Repo(repo_path)
        except InvalidGitRepositoryError:
            raise ValueError(f"Not a valid Git repository: {repo_path}")
    
    def get_repository_state(self) -> RepositoryState:
        """Get complete repository state snapshot"""
        self.logger.info("Analyzing repository state...")
        
        # Branch info
        try:
            branch = self.repo.active_branch.name
            detached = False
        except TypeError:
            branch = str(self.repo.head.commit)[:8]
            detached = True
        
        # File status
        untracked = [item.a_path for item in self.repo.untracked_files] if hasattr(self.repo, 'untracked_files') else []
        modified = [item.a_path for item in self.repo.index.diff(None)]
        staged = [item.a_path for item in self.repo.index.diff('HEAD')]
        
        # Remote tracking
        ahead, behind = 0, 0
        try:
            if not detached and self.repo.active_branch.tracking_branch():
                ahead = len(list(self.repo.iter_commits(f'{self.repo.active_branch.tracking_branch()}..{branch}')))
                behind = len(list(self.repo.iter_commits(f'{branch}..{self.repo.active_branch.tracking_branch()}')))
        except Exception as e:
            self.logger.warning(f"Could not determine ahead/behind count: {e}")
        
        # Conflicts
        has_conflicts = any(
            item.a_path for item in self.repo.index.unmerged_blobs()
        ) if hasattr(self.repo.index, 'unmerged_blobs') else False
        
        # Submodules
        submodule_issues = self._check_submodules()
        
        state = RepositoryState(
            branch=branch,
            is_dirty=self.repo.is_dirty(),
            untracked_files=untracked,
            modified_files=modified,
            staged_files=staged,
            ahead_count=ahead,
            behind_count=behind,
            has_conflicts=has_conflicts,
            detached_head=detached,
            submodule_issues=submodule_issues
        )
        
        self.logger.info(f"Repository state: {branch} ({'dirty' if state.is_dirty else 'clean'})")
        return state
    
    def _check_submodules(self) -> List[str]:
        """Check for submodule issues"""
        issues = []
        try:
            for submodule in self.repo.submodules:
                try:
                    # Check if submodule is initialized
                    if not os.path.exists(os.path.join(self.repo_path, submodule.path, '.git')):
                        issues.append(f"{submodule.name}: not initialized")
                        continue
                    
                    # Check for untracked/modified content
                    sub_repo = submodule.module()
                    if sub_repo.is_dirty(untracked_files=True):
                        issues.append(f"{submodule.name}: has uncommitted changes")
                except Exception as e:
                    issues.append(f"{submodule.name}: {str(e)}")
        except Exception as e:
            self.logger.warning(f"Could not check submodules: {e}")
        
        return issues
    
    def detect_errors(self, state: RepositoryState) -> List[GitError]:
        """Detect all Git errors in repository"""
        self.logger.info("Detecting Git errors...")
        errors = []
        
        # Detached HEAD
        if state.detached_head:
            errors.append(GitError(
                error_type=ErrorType.DETACHED_HEAD,
                severity='high',
                description='Repository is in detached HEAD state',
                details={'current_commit': state.branch}
            ))
        
        # Uncommitted changes
        if state.modified_files:
            errors.append(GitError(
                error_type=ErrorType.UNCOMMITTED_CHANGES,
                severity='medium',
                description=f'{len(state.modified_files)} files have uncommitted changes',
                details={'files': state.modified_files}
            ))
        
        # Untracked files
        if state.untracked_files:
            errors.append(GitError(
                error_type=ErrorType.UNTRACKED_FILES,
                severity='low',
                description=f'{len(state.untracked_files)} untracked files',
                details={'files': state.untracked_files}
            ))
        
        # Merge conflicts
        if state.has_conflicts:
            errors.append(GitError(
                error_type=ErrorType.MERGE_CONFLICT,
                severity='critical',
                description='Repository has unresolved merge conflicts',
                details={}
            ))
        
        # Diverged branches
        if state.ahead_count > 0 and state.behind_count > 0:
            errors.append(GitError(
                error_type=ErrorType.DIVERGED_BRANCHES,
                severity='high',
                description=f'Branch has diverged: {state.ahead_count} ahead, {state.behind_count} behind',
                details={'ahead': state.ahead_count, 'behind': state.behind_count}
            ))
        
        # Unpushed commits
        elif state.ahead_count > 0:
            errors.append(GitError(
                error_type=ErrorType.UNPUSHED_COMMITS,
                severity='medium',
                description=f'{state.ahead_count} commits not pushed to remote',
                details={'count': state.ahead_count}
            ))
        
        # Submodule issues
        if state.submodule_issues:
            errors.append(GitError(
                error_type=ErrorType.SUBMODULE_ISSUES,
                severity='medium',
                description=f'{len(state.submodule_issues)} submodule issues detected',
                details={'issues': state.submodule_issues}
            ))
        
        self.logger.info(f"Detected {len(errors)} error(s)")
        return errors


# ============================================================================
# GIT AUTOMATED RESOLVER
# ============================================================================

class GitResolver:
    """Automated Git error resolution engine"""
    
    def __init__(self, repo_path: str, config: ConfigManager, logger: GitAutoLogger):
        self.repo_path = repo_path
        self.config = config
        self.logger = logger
        self.repo = Repo(repo_path)
        self.dry_run = config.get('automation.dry_run', False)
    
    def create_backup(self) -> Optional[str]:
        """Create safety backup using git stash"""
        if not self.config.get('safety.create_backups', True):
            return None
        
        try:
            if self.repo.is_dirty():
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                stash_msg = f"gitauto_backup_{timestamp}"
                
                if not self.dry_run:
                    self.repo.git.stash('save', '--include-untracked', stash_msg)
                    self.logger.success(f"Created backup: {stash_msg}")
                    self.logger.action('create_backup', {'stash_message': stash_msg})
                    return stash_msg
                else:
                    self.logger.info(f"[DRY RUN] Would create backup: {stash_msg}")
                    return stash_msg
        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
        
        return None
    
    def resolve_uncommitted_changes(self, error: GitError) -> ResolutionResult:
        """Auto-commit uncommitted changes"""
        self.logger.info("Resolving uncommitted changes...")
        actions = []
        
        if not self.config.get('automation.auto_commit', True):
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.SKIPPED,
                message="Auto-commit disabled in configuration",
                actions_taken=[],
                backup_created=False
            )
        
        try:
            backup = self.create_backup()
            
            # Generate commit message
            files = error.details.get('files', [])
            description = f"modified {len(files)} file(s)"
            message = self.config.get('commits.message_template', 'chore: automated commit - {description}').format(
                description=description
            )
            
            if not self.dry_run:
                # Stage all changes
                self.repo.git.add('-A')
                actions.append("Staged all changes")
                
                # Commit
                if self.config.get('commits.sign_commits', False):
                    gpg_key = self.config.get('commits.gpg_key', '')
                    self.repo.git.commit('-m', message, '-S' + (gpg_key if gpg_key else ''))
                else:
                    self.repo.git.commit('-m', message)
                
                actions.append(f"Committed changes: {message}")
                self.logger.success(f"Committed changes: {message}")
                self.logger.action('commit_changes', {'message': message, 'files': files})
                
                return ResolutionResult(
                    error_type=error.error_type,
                    status=ResolutionStatus.SUCCESS,
                    message=f"Successfully committed {len(files)} file(s)",
                    actions_taken=actions,
                    backup_created=backup is not None
                )
            else:
                self.logger.info(f"[DRY RUN] Would commit with message: {message}")
                return ResolutionResult(
                    error_type=error.error_type,
                    status=ResolutionStatus.SUCCESS,
                    message=f"[DRY RUN] Would commit {len(files)} file(s)",
                    actions_taken=["[DRY RUN] Stage and commit"],
                    backup_created=False
                )
        
        except Exception as e:
            self.logger.error(f"Failed to resolve uncommitted changes: {e}")
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.FAILED,
                message=str(e),
                actions_taken=actions,
                backup_created=backup is not None if 'backup' in locals() else False
            )
    
    def resolve_untracked_files(self, error: GitError) -> ResolutionResult:
        """Add and commit untracked files"""
        self.logger.info("Resolving untracked files...")
        
        # Apply exclusion patterns
        files = error.details.get('files', [])
        exclusion_patterns = self.config.get('exclusions.patterns', [])
        
        filtered_files = []
        for file in files:
            excluded = False
            for pattern in exclusion_patterns:
                if self._match_pattern(file, pattern):
                    excluded = True
                    break
            if not excluded:
                filtered_files.append(file)
        
        if not filtered_files:
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.SKIPPED,
                message="All untracked files match exclusion patterns",
                actions_taken=[],
                backup_created=False
            )
        
        # Same logic as uncommitted changes
        error.details['files'] = filtered_files
        return self.resolve_uncommitted_changes(error)
    
    def _match_pattern(self, filepath: str, pattern: str) -> bool:
        """Match file against pattern (supports wildcards)"""
        import fnmatch
        return fnmatch.fnmatch(filepath, pattern)
    
    def resolve_detached_head(self, error: GitError) -> ResolutionResult:
        """Recover from detached HEAD state"""
        self.logger.info("Resolving detached HEAD state...")
        actions = []
        
        try:
            backup = self.create_backup()
            current_commit = error.details.get('current_commit', 'unknown')
            
            # Create recovery branch
            branch_name = f"recovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            if not self.dry_run:
                self.repo.git.checkout('-b', branch_name)
                actions.append(f"Created recovery branch: {branch_name}")
                self.logger.success(f"Created recovery branch: {branch_name}")
                self.logger.action('recover_detached_head', {'branch': branch_name, 'commit': current_commit})
                
                return ResolutionResult(
                    error_type=error.error_type,
                    status=ResolutionStatus.SUCCESS,
                    message=f"Recovered to branch: {branch_name}",
                    actions_taken=actions,
                    backup_created=backup is not None
                )
            else:
                self.logger.info(f"[DRY RUN] Would create branch: {branch_name}")
                return ResolutionResult(
                    error_type=error.error_type,
                    status=ResolutionStatus.SUCCESS,
                    message=f"[DRY RUN] Would create branch: {branch_name}",
                    actions_taken=["[DRY RUN] Create recovery branch"],
                    backup_created=False
                )
        
        except Exception as e:
            self.logger.error(f"Failed to resolve detached HEAD: {e}")
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.FAILED,
                message=str(e),
                actions_taken=actions,
                backup_created=backup is not None if 'backup' in locals() else False
            )
    
    def resolve_unpushed_commits(self, error: GitError) -> ResolutionResult:
        """Push commits to remote"""
        self.logger.info("Resolving unpushed commits...")
        actions = []
        
        if not self.config.get('automation.auto_push', True):
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.SKIPPED,
                message="Auto-push disabled in configuration",
                actions_taken=[],
                backup_created=False
            )
        
        remote_name = self.config.get('remote.default_remote', 'origin')
        retries = self.config.get('remote.push_retries', 3)
        retry_delay = self.config.get('remote.retry_delay', 5)
        
        for attempt in range(retries):
            try:
                if not self.dry_run:
                    # Get current branch
                    branch = self.repo.active_branch.name
                    
                    # Push
                    self.repo.git.push(remote_name, branch)
                    actions.append(f"Pushed to {remote_name}/{branch}")
                    self.logger.success(f"Pushed commits to {remote_name}/{branch}")
                    self.logger.action('push_commits', {'remote': remote_name, 'branch': branch})
                    
                    return ResolutionResult(
                        error_type=error.error_type,
                        status=ResolutionStatus.SUCCESS,
                        message=f"Successfully pushed to {remote_name}/{branch}",
                        actions_taken=actions,
                        backup_created=False
                    )
                else:
                    branch = self.repo.active_branch.name
                    self.logger.info(f"[DRY RUN] Would push to {remote_name}/{branch}")
                    return ResolutionResult(
                        error_type=error.error_type,
                        status=ResolutionStatus.SUCCESS,
                        message=f"[DRY RUN] Would push to {remote_name}/{branch}",
                        actions_taken=["[DRY RUN] Push commits"],
                        backup_created=False
                    )
            
            except GitCommandError as e:
                if attempt < retries - 1:
                    self.logger.warning(f"Push failed (attempt {attempt + 1}/{retries}), retrying in {retry_delay}s...")
                    import time
                    time.sleep(retry_delay)
                else:
                    self.logger.error(f"Failed to push after {retries} attempts: {e}")
                    return ResolutionResult(
                        error_type=error.error_type,
                        status=ResolutionStatus.FAILED,
                        message=f"Push failed: {str(e)}",
                        actions_taken=actions,
                        backup_created=False
                    )
        
        return ResolutionResult(
            error_type=error.error_type,
            status=ResolutionStatus.FAILED,
            message="Push failed unexpectedly",
            actions_taken=actions,
            backup_created=False
        )
    
    def resolve_submodule_issues(self, error: GitError) -> ResolutionResult:
        """Resolve submodule problems"""
        self.logger.info("Resolving submodule issues...")
        actions = []
        
        if not self.config.get('submodules.auto_update', True):
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.SKIPPED,
                message="Submodule auto-update disabled",
                actions_taken=[],
                backup_created=False
            )
        
        try:
            backup = self.create_backup()
            recursive = self.config.get('submodules.recursive', True)
            
            if not self.dry_run:
                # Initialize submodules
                self.repo.git.submodule('update', '--init', '--recursive' if recursive else '')
                actions.append("Initialized submodules")
                
                # Update submodules
                self.repo.git.submodule('update', '--remote', '--recursive' if recursive else '')
                actions.append("Updated submodules")
                
                # Commit submodule updates
                if self.repo.is_dirty():
                    message = "chore: update submodules"
                    self.repo.git.add('-A')
                    self.repo.git.commit('-m', message)
                    actions.append(f"Committed submodule updates")
                
                self.logger.success("Resolved submodule issues")
                self.logger.action('update_submodules', {'recursive': recursive})
                
                return ResolutionResult(
                    error_type=error.error_type,
                    status=ResolutionStatus.SUCCESS,
                    message="Submodules updated successfully",
                    actions_taken=actions,
                    backup_created=backup is not None
                )
            else:
                self.logger.info("[DRY RUN] Would update submodules")
                return ResolutionResult(
                    error_type=error.error_type,
                    status=ResolutionStatus.SUCCESS,
                    message="[DRY RUN] Would update submodules",
                    actions_taken=["[DRY RUN] Update submodules"],
                    backup_created=False
                )
        
        except Exception as e:
            self.logger.error(f"Failed to resolve submodule issues: {e}")
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.FAILED,
                message=str(e),
                actions_taken=actions,
                backup_created=backup is not None if 'backup' in locals() else False
            )
    
    def resolve_diverged_branches(self, error: GitError) -> ResolutionResult:
        """Resolve diverged branches by pulling with rebase"""
        self.logger.info("Resolving diverged branches...")
        actions = []
        
        try:
            backup = self.create_backup()
            
            if not self.dry_run:
                # Pull with rebase
                self.repo.git.pull('--rebase')
                actions.append("Pulled with rebase")
                
                self.logger.success("Resolved branch divergence")
                self.logger.action('rebase_pull', {})
                
                return ResolutionResult(
                    error_type=error.error_type,
                    status=ResolutionStatus.SUCCESS,
                    message="Branch divergence resolved with rebase",
                    actions_taken=actions,
                    backup_created=backup is not None
                )
            else:
                self.logger.info("[DRY RUN] Would pull with rebase")
                return ResolutionResult(
                    error_type=error.error_type,
                    status=ResolutionStatus.SUCCESS,
                    message="[DRY RUN] Would rebase",
                    actions_taken=["[DRY RUN] Pull with rebase"],
                    backup_created=False
                )
        
        except Exception as e:
            self.logger.error(f"Failed to resolve diverged branches: {e}")
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.FAILED,
                message=str(e),
                actions_taken=actions,
                backup_created=backup is not None if 'backup' in locals() else False
            )
    
    def resolve_merge_conflict(self, error: GitError) -> ResolutionResult:
        """Resolve merge conflicts using configured strategy"""
        self.logger.info("Resolving merge conflicts...")
        
        if not self.config.get('conflicts.auto_resolve', True):
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.SKIPPED,
                message="Auto conflict resolution disabled",
                actions_taken=[],
                backup_created=False
            )
        
        strategy = self.config.get('conflicts.strategy', 'ours')
        if strategy == 'skip':
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.SKIPPED,
                message="Conflict strategy set to 'skip'",
                actions_taken=[],
                backup_created=False
            )
        
        # This is a simplified implementation
        # Production use would need more sophisticated conflict resolution
        self.logger.warning("Merge conflict resolution not fully implemented - requires manual intervention")
        return ResolutionResult(
            error_type=error.error_type,
            status=ResolutionStatus.FAILED,
            message="Merge conflicts require manual resolution",
            actions_taken=[],
            backup_created=False
        )
    
    def resolve_error(self, error: GitError) -> ResolutionResult:
        """Route error to appropriate resolver"""
        resolvers = {
            ErrorType.UNCOMMITTED_CHANGES: self.resolve_uncommitted_changes,
            ErrorType.UNTRACKED_FILES: self.resolve_untracked_files,
            ErrorType.DETACHED_HEAD: self.resolve_detached_head,
            ErrorType.UNPUSHED_COMMITS: self.resolve_unpushed_commits,
            ErrorType.SUBMODULE_ISSUES: self.resolve_submodule_issues,
            ErrorType.DIVERGED_BRANCHES: self.resolve_diverged_branches,
            ErrorType.MERGE_CONFLICT: self.resolve_merge_conflict,
        }
        
        resolver = resolvers.get(error.error_type)
        if resolver:
            return resolver(error)
        else:
            return ResolutionResult(
                error_type=error.error_type,
                status=ResolutionStatus.SKIPPED,
                message=f"No resolver available for {error.error_type.value}",
                actions_taken=[],
                backup_created=False
            )


# ============================================================================
# MAIN AUTOMATION ENGINE
# ============================================================================

class GitAutoEngine:
    """Main Git automation orchestration engine"""
    
    def __init__(self, repo_path: str = '.', config_path: Optional[str] = None, dry_run: bool = False):
        self.repo_path = os.path.abspath(repo_path)
        self.config = ConfigManager(config_path)
        
        # Override dry_run if specified
        if dry_run:
            self.config.config['automation']['dry_run'] = True
        
        self.logger = GitAutoLogger(self.config, self.repo_path)
        self.analyzer = GitAnalyzer(self.repo_path, self.config, self.logger)
        self.resolver = GitResolver(self.repo_path, self.config, self.logger)
        
        self.logger.info("=" * 60)
        self.logger.info("GitAuto - Automated Git Management System")
        self.logger.info("=" * 60)
        if self.config.get('automation.dry_run', False):
            self.logger.warning("DRY RUN MODE - No changes will be made")
        self.logger.info(f"Repository: {self.repo_path}")
    
    def check(self) -> Tuple[RepositoryState, List[GitError]]:
        """Check repository and detect errors"""
        state = self.analyzer.get_repository_state()
        errors = self.analyzer.detect_errors(state)
        return state, errors
    
    def fix(self) -> List[ResolutionResult]:
        """Run automated error resolution"""
        if not self.config.get('automation.enabled', True):
            self.logger.warning("Automation is disabled in configuration")
            return []
        
        state, errors = self.check()
        
        if not errors:
            self.logger.success("No errors detected - repository is clean!")
            return []
        
        self.logger.info(f"Found {len(errors)} error(s) to resolve")
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        errors.sort(key=lambda e: severity_order.get(e.severity, 99))
        
        results = []
        for error in errors:
            self.logger.info(f"\n{'=' * 60}")
            self.logger.info(f"Resolving: {error.description}")
            self.logger.info(f"Type: {error.error_type.value} | Severity: {error.severity}")
            
            result = self.resolver.resolve_error(error)
            results.append(result)
            
            if result.status == ResolutionStatus.SUCCESS:
                self.logger.success(result.message)
            elif result.status == ResolutionStatus.FAILED:
                self.logger.error(result.message)
            elif result.status == ResolutionStatus.SKIPPED:
                self.logger.warning(f"Skipped: {result.message}")
        
        return results
    
    def status(self) -> Dict[str, Any]:
        """Get detailed repository status"""
        state, errors = self.check()
        
        return {
            'repository': self.repo_path,
            'timestamp': datetime.now().isoformat(),
            'state': asdict(state),
            'errors': [asdict(e) for e in errors],
            'error_count': len(errors),
            'is_clean': len(errors) == 0
        }
    
    def generate_report(self, results: List[ResolutionResult]) -> str:
        """Generate execution report"""
        console = Console()
        
        # Summary table
        table = Table(title="GitAuto Execution Report")
        table.add_column("Error Type", style="cyan")
        table.add_column("Status", style="magenta")
        table.add_column("Message", style="white")
        
        for result in results:
            status_color = {
                ResolutionStatus.SUCCESS: "green",
                ResolutionStatus.FAILED: "red",
                ResolutionStatus.SKIPPED: "yellow",
            }.get(result.status, "white")
            
            table.add_row(
                result.error_type.value,
                f"[{status_color}]{result.status.value}[/{status_color}]",
                result.message
            )
        
        console.print(table)
        
        # Statistics
        success_count = sum(1 for r in results if r.status == ResolutionStatus.SUCCESS)
        failed_count = sum(1 for r in results if r.status == ResolutionStatus.FAILED)
        skipped_count = sum(1 for r in results if r.status == ResolutionStatus.SKIPPED)
        
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"  ✓ Success: {success_count}")
        console.print(f"  ✗ Failed: {failed_count}")
        console.print(f"  ⊘ Skipped: {skipped_count}")
        console.print(f"  Total: {len(results)}")
        
        # Audit trail
        audit = self.logger.get_audit_trail()
        if audit:
            console.print(f"\n[bold]Actions Taken:[/bold]")
            for action in audit:
                console.print(f"  [{action['timestamp']}] {action['action']}")
        
        return "Report generated"


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='GitAuto - Automated Git Error Detection and Resolution',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s check                 # Analyze repository and detect errors
  %(prog)s fix                   # Automatically resolve detected errors
  %(prog)s status                # Show detailed repository status
  %(prog)s fix --dry-run         # Test resolution without making changes
  %(prog)s --repo /path/to/repo fix  # Run on specific repository
        """
    )
    
    parser.add_argument('command', choices=['check', 'fix', 'status', 'init-config'],
                       help='Command to execute')
    parser.add_argument('--repo', default='.', help='Repository path (default: current directory)')
    parser.add_argument('--config', help='Configuration file path (default: .gitauto.yaml)')
    parser.add_argument('--dry-run', action='store_true', help='Test mode - no changes will be made')
    parser.add_argument('--json', action='store_true', help='Output in JSON format')
    
    args = parser.parse_args()
    
    try:
        if args.command == 'init-config':
            config = ConfigManager()
            config_path = args.config or '.gitauto.yaml'
            config.save_default_config(config_path)
            print(f"✓ Created default configuration: {config_path}")
            return 0
        
        engine = GitAutoEngine(args.repo, args.config, args.dry_run)
        
        if args.command == 'check':
            state, errors = engine.check()
            
            if args.json:
                print(json.dumps({
                    'state': asdict(state),
                    'errors': [asdict(e) for e in errors]
                }, indent=2))
            else:
                if errors:
                    engine.logger.warning(f"Found {len(errors)} error(s):")
                    for error in errors:
                        engine.logger.error(f"  [{error.severity}] {error.description}")
                else:
                    engine.logger.success("Repository is clean - no errors detected!")
            
            return 1 if errors else 0
        
        elif args.command == 'fix':
            results = engine.fix()
            
            if args.json:
                print(json.dumps([asdict(r) for r in results], indent=2))
            else:
                engine.generate_report(results)
            
            # Save audit report
            engine.logger.save_audit_report()
            
            failed = any(r.status == ResolutionStatus.FAILED for r in results)
            return 1 if failed else 0
        
        elif args.command == 'status':
            status = engine.status()
            
            if args.json:
                print(json.dumps(status, indent=2))
            else:
                console = Console()
                console.print(Panel(f"[bold]Repository Status[/bold]\n\n"
                                   f"Path: {status['repository']}\n"
                                   f"Branch: {status['state']['branch']}\n"
                                   f"Status: {'[green]Clean[/green]' if status['is_clean'] else '[red]Has Issues[/red]'}\n"
                                   f"Errors: {status['error_count']}"))
            
            return 0
    
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
