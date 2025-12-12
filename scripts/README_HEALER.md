# Git Auto-Healer

Git Auto-Healer is a production-ready Python tool designed to proactively detect, diagnose, and resolve common Git errors in an unattended manner. It is built to ensure repository consistency in automated environments (CI/CD, cron jobs, background workers).

## Features

- **Automated Conflict Handling**: Safely aborts stuck merges or rebases to restore repository availability.
- **Detached HEAD Recovery**: Automatically backs up the detached state to a new branch and checks out the main branch.
- **Lock File Cleanup**: Detects and removes stale `index.lock` files that block git operations.
- **Synchronization**: Handles upstream syncs using `pull --rebase` and retries on failure.
- **Submodule Management**: Ensures submodules are initialized and updated recursively.
- **Divergence Resolution**: Detects diverged branches and attempts to align with upstream.
- **Safety First**: "Dry Run" mode available for testing. Critical operations log extensively.

## Usage

The tool is a single Python script. No external dependencies beyond the Python standard library (Python 3.6+).

### Basic Command

Run the healer on the current directory:

```bash
python3 scripts/git_auto_healer.py
```

### Options

| Argument    | Description                                                           | Default                 |
| :---------- | :-------------------------------------------------------------------- | :---------------------- |
| `--path`    | Path to the git repository to heal.                                   | Current Directory (`.`) |
| `--branch`  | The target "main" branch to restore to (e.g., master, main, develop). | `main`                  |
| `--dry-run` | Enable simulation mode. Logs actions but does not execute them.       | `False`                 |

### Examples

**Dry run to see what would happen:**

```bash
python3 scripts/git_auto_healer.py --dry-run
```

**Heal a specific request running on 'master' branch:**

```bash
python3 scripts/git_auto_healer.py --path /path/to/repo --branch master
```

## Scheduling (Cron)

To ensure your repo stays healthy, adds a cron job to run every 30 minutes:

```bash
*/30 * * * * /usr/bin/python3 /home/e/ADBasher/scripts/git_auto_healer.py >> /home/e/ADBasher/git_healer_cron.log 2>&1
```

## Logic & Strategy

1.  **Stale Locks**: If `index.lock` is > 10 minutes old, it is deleted.
2.  **Detached HEAD**: If detected, a backup branch `backup/detached-<commit>-<timestamp>` is created, and `main` is checked out.
3.  **Merge/Rebase Conflicts**: If the repo is stuck in a conflict state (e.g., from a failed manual pull), the operation is **Aborted** to return the repo to a clean, usable state. The script assumes "availability" is higher priority than partially merged code in an automated context.
4.  **Sync**: It performs `git pull --rebase`. If this fails due to conflict, it aborts the rebase to avoid leaving the repo in a broken state.

## Logs

Logs are written to `git_healer.log` in the working directory and printed to stdout.
