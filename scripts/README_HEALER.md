# Git Auto-Healer

Git Auto-Healer is a production-ready Python tool designed to proactively detect, diagnose, and resolve common Git errors in an unattended manner. It is built to ensure repository consistency in automated environments (CI/CD, cron jobs, background workers).

## Features

- **Automated Conflict Handling**: Safely aborts stuck merges or rebases to restore repository availability.
- **Detached HEAD Recovery**: Automatically backs up the detached state to a new branch and checks out the main branch.
- **Lock File Cleanup**: Detects and removes stale `index.lock` files that block git operations.
- **Synchronization**: Handles upstream syncs using `pull --rebase` and retries on failure.
- **Auto-Commit Strategy**: Optionally detects and commits uncommitted work to prevent data loss or blocking.
- **Network Resilience**: Implements exponential backoff retries for transient network errors.
- **Submodule Management**: Ensures submodules are initialized and updated recursively.
- **Safety First**: "Dry Run" mode available for testing. Critical errors (like Auth failures) halt execution safely.

## Usage

The tool is a single Python script. No external dependencies beyond the Python standard library (Python 3.6+).

### Basic Command

Run the healer on the current directory:

```bash
python3 scripts/git_auto_healer.py
```

### Options

| Argument        | Description                                                           | Default                 |
| :-------------- | :-------------------------------------------------------------------- | :---------------------- |
| `--path`        | Path to the git repository to heal.                                   | Current Directory (`.`) |
| `--branch`      | The target "main" branch to restore to (e.g., master, main, develop). | `main`                  |
| `--auto-commit` | **[NEW]** Automatically stage and commit uncommitted changes.         | `False`                 |
| `--dry-run`     | Enable simulation mode. Logs actions but does not execute them.       | `False`                 |

### Examples

**Dry run to see what would happen:**

```bash
python3 scripts/git_auto_healer.py --dry-run
```

**Run continuously (cron) with auto-save for uncommitted work:**

```bash
python3 scripts/git_auto_healer.py --auto-commit
```

## Scheduling (Cron)

To ensure your repo stays healthy, adds a cron job to run every 30 minutes:

```bash
*/30 * * * * /usr/bin/python3 /home/e/ADBasher/scripts/git_auto_healer.py --auto-commit >> /home/e/ADBasher/git_healer_cron.log 2>&1
```

## Logic & Strategy

1.  **Stale Locks**: If `index.lock` is > 10 minutes old, it is deleted.
2.  **Dirty Worktree**: If `--auto-commit` is set, uncommitted changes are staged and committed with a timestamped message (e.g., `chore(auto): Auto-save...`) to ensure a clean state for synchronization.
3.  **Detached HEAD**: If detected, a backup branch `backup/detached-<commit>-<timestamp>` is created, and `main` is checked out.
4.  **Merge/Rebase Conflicts**: If the repo is stuck in a conflict state, the operation is **Aborted**.
5.  **Sync**: Performs `git pull --rebase`. Retries up to 3 times for transient network issues. If credentials fail, it logs a critical error and exits.

## Logs

Logs are written to `git_healer.log` in the working directory and printed to stdout.
