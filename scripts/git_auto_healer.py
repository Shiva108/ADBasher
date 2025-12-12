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
    def __init__(self, repo_path=".", dry_run=False, branch="main", auto_commit=False):
        self.repo_path = os.path.abspath(repo_path)
        self.dry_run = dry_run
        self.target_branch = branch
        self.auto_commit = auto_commit
        self.git_cmd = ["git"]
        
        if not os.path.isdir(os.path.join(self.repo_path, ".git")):
            logger.error(f"Not a valid git repository: {self.repo_path}")
            sys.exit(1)
            
    def _run_git(self, args, check=False, retries=3):
        """Executes a git command in the repo directory with retry logic for network issues."""
        cmd = self.git_cmd + args
        attempt = 0
        
        while attempt < retries:
            try:
                result = subprocess.run(
                    cmd, 
                    cwd=self.repo_path, 
                    capture_output=True, 
                    text=True, 
                    check=check
                )
                
                # Check for specific failure patterns that warrant a retry
                if result.returncode != 0:
                    err = result.stderr.lower()
                    if "could not resolve host" in err or "connection timed out" in err or "temporary failure" in err:
                        logger.warning(f"Network error detected (Updated attempt {attempt+1}/{retries}). Retrying...")
                        time.sleep(2 ** attempt) # Exponential backoff
                        attempt += 1
                        continue
                    
                    # Check for fatal auth errors
                    if "permission denied" in err or "authentication failed" in err:
                        logger.critical("Authentication failure detected. Cannot proceed autonomously. Please update credentials.")
                        return result # Return the failure so logic can halt if needed

                return result
            except subprocess.CalledProcessError as e:
                logger.debug(f"Command failed: {' '.join(cmd)}\nStderr: {e.stderr}")
                if check:
                    raise
                return e
            except Exception as e:
                logger.error(f"Unexpected error executing {cmd}: {e}")
                return None
                
        return result

    def check_lock_file(self):
        """Checks for and removes stale git lock files."""
        lock_file = Path(self.repo_path) / ".git" / "index.lock"
        if lock_file.exists():
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
        if "Your branch and 'origin/main' have diverged" in output:
             issues.append("DIVERGED_BRANCH")
        if "Changes not staged for commit" in output or "Untracked files" in output:
            issues.append("DIRTY_WORKTREE")
             
        return issues

    def handle_uncommitted_changes(self):
        """Automatically stages and commits uncommitted changes."""
        if not self.auto_commit:
            logger.info("Uncommitted changes detected, but --auto-commit is not enabled. Skipping.")
            return

        logger.info("Handling uncommitted changes...")
        if self.dry_run:
            logger.info("[DRY RUN] Would stage and commit all changes.")
            return

        # Stage all
        self._run_git(["add", "."])
        
        # Commit
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msg = f"chore(auto): Auto-save uncommitted work at {ts}"
        res = self._run_git(["commit", "-m", msg])
        
        if res.returncode == 0:
            logger.info(f"Successfully committed changes: '{msg}'")
        else:
            logger.error(f"Failed to commit changes: {res.stderr}")

    def fix_detached_head(self):
        """Fixes detached HEAD by banking changes and checking out target branch."""
        logger.warning(f"Detected Detached HEAD state.")
        res = self._run_git(["rev-parse", "--short", "HEAD"])
        current_commit = res.stdout.strip()
        
        backup_branch = f"backup/detached-{current_commit}-{int(time.time())}"
        
        if self.dry_run:
            logger.info(f"[DRY RUN] Would create backup branch '{backup_branch}' and checkout '{self.target_branch}'.")
            return

        logger.info(f"Creating backup branch: {backup_branch}")
        self._run_git(["branch", backup_branch])
        
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
        
        self.check_lock_file()
        issues = self.check_status()
        
        # Priority 1: Commit work if dirty (so we don't lose it during aborts/checkouts)
        if "DIRTY_WORKTREE" in issues:
            self.handle_uncommitted_changes()
            # refetch status since it changed
            issues = self.check_status() 
        
        if not issues:
            logger.info("No critical state issues detected. Ensuring sync.")
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
                self.sync_upstream()
        
        self.fix_submodules()
        logger.info("Heal cycle completed.")

def main():
    parser = argparse.ArgumentParser(description="Git Auto-Healer: Unattended Git Resolution Tool")
    parser.add_argument("--path", default=".", help="Path to git repository")
    parser.add_argument("--branch", default="main", help="Target main branch name")
    parser.add_argument("--auto-commit", action="store_true", help="Automatically commit uncommitted changes")
    parser.add_argument("--dry-run", action="store_true", help="Simulate actions without making changes")
    
    args = parser.parse_args()
    
    healer = GitHealer(
        repo_path=args.path, 
        dry_run=args.dry_run, 
        branch=args.branch,
        auto_commit=args.auto_commit
    )
    healer.heal()

if __name__ == "__main__":
    main()
