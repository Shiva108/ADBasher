#!/usr/bin/env python3
import os
import subprocess
import sys
import time
import logging
import datetime
import argparse
from pathlib import Path

# Configure Logging
LOG_FILE = "git_healer.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class GitHealer:
    def __init__(self, repo_path=".", dry_run=False, branch="main"):
        self.repo_path = os.path.abspath(repo_path)
        self.dry_run = dry_run
        self.target_branch = branch
        self.git_cmd = ["git"]
        
        if not os.path.isdir(os.path.join(self.repo_path, ".git")):
            logger.error(f"Not a valid git repository: {self.repo_path}")
            sys.exit(1)
            
    def _run_git(self, args, check=False):
        """Executes a git command in the repo directory."""
        cmd = self.git_cmd + args
        try:
            result = subprocess.run(
                cmd, 
                cwd=self.repo_path, 
                capture_output=True, 
                text=True, 
                check=check
            )
            return result
        except subprocess.CalledProcessError as e:
            logger.debug(f"Command failed: {' '.join(cmd)}\nStderr: {e.stderr}")
            if check:
                raise
            return e

    def check_lock_file(self):
        """Checks for and removes stale git lock files."""
        lock_file = Path(self.repo_path) / ".git" / "index.lock"
        if lock_file.exists():
            # Check age
            age_seconds = time.time() - lock_file.stat().st_mtime
            if age_seconds > 600: # 10 minutes stale
                logger.warning(f"Found stale index.lock file ({age_seconds:.0f}s old).")
                if not self.dry_run:
                    try:
                        lock_file.unlink()
                        logger.info("Removed stale index.lock file.")
                        return True
                    except Exception as e:
                        logger.error(f"Failed to remove lock file: {e}")
                else:
                    logger.info("[DRY RUN] Would remove stale index.lock file.")
            else:
                logger.info("Found index.lock but it is recent. Waiting...")
        return False

    def check_status(self):
        """Analyzes git status for issues."""
        res = self._run_git(["status"])
        output = res.stdout
        
        issues = []
        
        if "HEAD detached" in output:
            issues.append("DETACHED_HEAD")
        if "You have unmerged paths" in output or "fix conflicts" in output:
            issues.append("MERGE_CONFLICT")
        if "rebase in progress" in output:
            issues.append("REBASE_IN_PROGRESS")
        if "Your branch is ahead of" in output:
            issues.append("UNPUSHED_CHANGES")
        if "Your branch and 'origin/main' have diverged" in output: # simplistic branch check
             issues.append("DIVERGED_BRANCH")
             
        return issues

    def fix_detached_head(self):
        """Fixes detached HEAD by banking changes and checking out target branch."""
        logger.warning(f"Detected Detached HEAD state.")
        
        # identifying current commit
        res = self._run_git(["rev-parse", "--short", "HEAD"])
        current_commit = res.stdout.strip()
        
        backup_branch = f"backup/detached-{current_commit}-{int(time.time())}"
        
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create backup branch '{backup_branch}' and checkout '{self.target_branch}'.")
            return

        # Create backup branch
        logger.info(f"Creating backup branch: {backup_branch}")
        self._run_git(["branch", backup_branch])
        
        # Checkout target
        logger.info(f"Checking out {self.target_branch}...")
        res = self._run_git(["checkout", self.target_branch])
        if res.returncode == 0:
            logger.info(f"Successfully returned to {self.target_branch}.")
        else:
            logger.error(f"Failed to checkout {self.target_branch}: {res.stderr}")

    def abort_stuck_ops(self, op_type):
        """Aborts stuck merges or rebases."""
        logger.warning(f"Detected stuck {op_type}.")
        
        if self.dry_run:
            logger.info(f"[DRY RUN] Would abort {op_type}.")
            return

        cmd = []
        if op_type == "MERGE_CONFLICT":
            cmd = ["merge", "--abort"]
        elif op_type == "REBASE_IN_PROGRESS":
            cmd = ["rebase", "--abort"]
            
        logger.info(f"Aborting {op_type}...")
        res = self._run_git(cmd)
        if res.returncode == 0:
            logger.info("Successfully aborted stuck operation.")
        else:
            logger.error(f"Failed to abort operation: {res.stderr}")

    def sync_upstream(self):
        """Pulls latest changes with rebase."""
        logger.info("Attempting to sync with upstream...")
        if self.dry_run:
            logger.info("[DRY RUN] Would run 'git pull --rebase'.")
            return

        res = self._run_git(["pull", "--rebase"])
        if res.returncode != 0:
            logger.error(f"Pull failed: {res.stderr}")
            # Identify failure reason?
            if "conflict" in res.stderr.lower():
                logger.warning("Pull caused conflict. Aborting rebase to restore state.")
                self._run_git(["rebase", "--abort"])
        else:
            logger.info("Successfully synced with upstream.")

    def push_changes(self):
        """Pushes committed changes to remote."""
        logger.info("Attempting to push changes...")
        if self.dry_run:
            logger.info("[DRY RUN] Would run 'git push'.")
            return
            
        res = self._run_git(["push"])
        if res.returncode == 0:
            logger.info("Push successful.")
        else:
            logger.error(f"Push failed: {res.stderr}")
            if "fetch first" in res.stderr:
                 logger.info("Remote contains work that you do not have. Attempting sync...")
                 self.sync_upstream()
                 # Retry push? Maybe once.
                 
    def fix_submodules(self):
        """Initializes and updates submodules."""
        logger.info("Updating submodules...")
        if self.dry_run:
            logger.info("[DRY RUN] Would update submodules recursively.")
            return

        res = self._run_git(["submodule", "update", "--init", "--recursive"])
        if res.returncode == 0:
            logger.info("Submodules updated successfully.")
        else:
            logger.error(f"Failed to update submodules: {res.stderr}")

    def heal(self):
        """Main execution flow."""
        logger.info("Starting Git Auto-Healer scan...")
        
        # 1. Check Locks
        self.check_lock_file()
        
        # 2. Analyze Status
        issues = self.check_status()
        
        if not issues:
            logger.info("No critical state issues detected.")
            # Even if "healthy", we might want to sync/push?
            # For "Self-healing", we usually only act on problems, but 
            # ensuring we are up to date is part of "consistency".
            self.sync_upstream()
        
        for issue in issues:
            if issue == "DETACHED_HEAD":
                self.fix_detached_head()
            elif issue == "MERGE_CONFLICT":
                self.abort_stuck_ops("MERGE_CONFLICT")
            elif issue == "REBASE_IN_PROGRESS":
                self.abort_stuck_ops("REBASE_IN_PROGRESS")
            elif issue == "UNPUSHED_CHANGES":
                self.push_changes()
            elif issue == "DIVERGED_BRANCH":
                # Diverged usually means we need to pull --rebase
                self.sync_upstream()
        
        # 3. Always check submodules (often neglected)
        self.fix_submodules()
        
        logger.info("Heal cycle completed.")

def main():
    parser = argparse.ArgumentParser(description="Git Auto-Healer: Unattended Git Resolution Tool")
    parser.add_argument("--path", default=".", help="Path to git repository")
    parser.add_argument("--branch", default="main", help="Target main branch name")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without making changes")
    
    args = parser.parse_args()
    
    healer = GitHealer(repo_path=args.path, dry_run=args.dry_run, branch=args.branch)
    healer.heal()

if __name__ == "__main__":
    main()
