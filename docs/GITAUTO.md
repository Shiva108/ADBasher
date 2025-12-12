# GitAuto - Automated Git Error Detection and Resolution

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.10+-green)
![License](https://img.shields.io/badge/license-MIT-blue)

**GitAuto** is a production-ready, unattended Git automation system that autonomously detects, diagnoses, and resolves common Git errors without manual intervention. Designed for DevOps workflows, CI/CD pipelines, and automated repository maintenance.

---

## 🎯 Features

### Error Detection

- ✅ **Uncommitted Changes** - Detects modified files not staged for commit
- ✅ **Untracked Files** - Identifies new files not in version control
- ✅ **Detached HEAD** - Recognizes detached HEAD state
- ✅ **Merge Conflicts** - Detects unresolved merge conflicts
- ✅ **Diverged Branches** - Identifies when local/remote have diverged
- ✅ **Unpushed Commits** - Finds commits waiting to be pushed
- ✅ **Submodule Issues** - Detects uninitialized or modified submodules
- ✅ **Authentication Failures** - Identifies credential issues

### Automated Resolution

- 🤖 **Auto-commit** - Automatically stage and commit changes with descriptive messages
- 🤖 **Auto-push** - Push commits to remote with retry logic
- 🤖 **HEAD Recovery** - Create recovery branches from detached HEAD
- 🤖 **Submodule Updates** - Initialize and update submodules automatically
- 🤖 **Divergence Resolution** - Rebase or merge to resolve branch divergence
- 🤖 **Conflict Resolution** - Strategy-based conflict handling (ours/theirs)

### Safety Features

- 🛡️ **Automatic Backups** - Creates stash backups before major operations
- 🛡️ **Dry-run Mode** - Test operations without making changes
- 🛡️ **Rollback Support** - Undo automated operations
- 🛡️ **Exclusion Patterns** - Skip sensitive files/directories
- 🛡️ **Validation Checks** - Pre-operation safety validations

### Logging & Reporting

- 📊 **Structured Logs** - JSON logs for machine parsing
- 📊 **Audit Trail** - Complete record of all actions taken
- 📊 **Console Output** - Rich, colorized terminal output
- 📊 **Error Tracking** - Separate error logs for troubleshooting

---

## 📦 Installation

### Prerequisites

- **Python 3.10+**
- **Git 2.0+**
- **Pip** (Python package manager)

### Install Dependencies

```bash
# Install Python dependencies
pip3 install GitPython PyYAML rich

# Or using requirements file
pip3 install -r requirements.txt
```

### Setup GitAuto

```bash
# Navigate to your repository
cd /path/to/your/repo

# Copy gitauto scripts (if not already present)
cp /path/to/ADBasher/scripts/gitauto* ./scripts/

# Make executable
chmod +x scripts/gitauto*.sh scripts/gitauto.py

# Initialize configuration
./scripts/gitauto-cli.sh init
```

---

## 🚀 Quick Start

### Basic Usage

```bash
# Check for Git errors
./scripts/gitauto-cli.sh check

# Automatically fix errors
./scripts/gitauto-cli.sh fix

# Test fixes without applying (dry-run)
./scripts/gitauto-cli.sh fix --dry-run

# Show repository status
./scripts/gitauto-cli.sh status

# Rollback last operation
./scripts/gitauto-cli.sh rollback
```

### Python API

```python
from scripts.gitauto import GitAutoEngine

# Create engine instance
engine = GitAutoEngine(repo_path='/path/to/repo')

# Check for errors
state, errors = engine.check()
print(f"Found {len(errors)} errors")

# Fix errors
results = engine.fix()

# Get status
status = engine.status()
```

---

## 📖 Configuration

GitAuto uses a YAML configuration file (`.gitauto.yaml`) to control behavior.

### Create Default Configuration

```bash
./scripts/gitauto-cli.sh init
```

This creates `.gitauto.yaml` in your repository root.

### Configuration Options

```yaml
automation:
  enabled: true # Enable/disable automation
  dry_run: false # Test mode
  auto_commit: true # Auto-commit changes
  auto_push: true # Auto-push commits
  auto_pull: true # Auto-pull before operations

commits:
  message_template: "chore: automated commit - {description}"
  sign_commits: false # GPG sign commits
  gpg_key: "" # GPG key ID

conflicts:
  strategy: "ours" # ours | theirs | manual | skip
  auto_resolve: true # Enable auto-resolution

submodules:
  auto_update: true # Update submodules
  recursive: true # Recursive update

safety:
  create_backups: true # Stash before operations
  backup_retention_days: 7
  require_clean_tree: false

remote:
  default_remote: "origin"
  default_branch: "main"
  push_retries: 3
  retry_delay: 5

logging:
  level: "INFO"
  file: ".gitauto/logs/gitauto.log"
  json_logs: true
  console_output: true

exclusions:
  patterns:
    - "*.log"
    - "*.tmp"
    - ".env"
```

---

## 🔧 Usage Guide

### Command-Line Interface

#### Check Command

Analyze repository and detect errors without making changes.

```bash
./scripts/gitauto-cli.sh check
./scripts/gitauto-cli.sh check --json  # JSON output
```

**Output:**

```text
ℹ Analyzing repository for Git errors...
✓ Repository state: main (dirty)
⚠ Found 3 error(s):
  [medium] 2 files have uncommitted changes
  [medium] 1 commits not pushed to remote
  [medium] 2 submodule issues detected
```

#### Fix Command

Automatically resolve detected errors.

```bash
./scripts/gitauto-cli.sh fix
./scripts/gitauto-cli.sh fix --dry-run  # Test mode
```

**Output:**

```text
ℹ Running automated error resolution...
✓ Created backup: gitauto_backup_20241212_143000
✓ Committed changes: chore: automated commit - modified 2 file(s)
✓ Pushed commits to origin/main
✓ Submodules updated successfully

Summary:
  ✓ Success: 3
  ✗ Failed: 0
  ⊘ Skipped: 0
```

#### Status Command

Show detailed repository status.

```bash
./scripts/gitauto-cli.sh status
```

#### Rollback Command

Undo last automated operation by restoring from backup stash.

```bash
./scripts/gitauto-cli.sh rollback
```

**Output:**

```text
Found backup: stash@{0}: gitauto_backup_20241212_143000
⚠ Warning: This will restore the repository to the backup state.
Continue? [y/N] y
✓ Rollback complete
```

#### Clean Command

Clean up old logs and backup stashes.

```bash
./scripts/gitauto-cli.sh clean
```

---

## 🤖 Scheduled Automation (Cron)

### Setup Cron Job

```bash
# Edit crontab
crontab -e

# Add entry (runs every 30 minutes)
*/30 * * * * /path/to/ADBasher/scripts/gitauto-cron.sh /path/to/repo

# With email notifications
GITAUTO_NOTIFY_EMAIL=admin@example.com
*/30 * * * * /path/to/ADBasher/scripts/gitauto-cron.sh /path/to/repo
```

### Features

- **Lock File Management** - Prevents concurrent runs
- **Syslog Integration** - Logs to system logs
- **Email Notifications** - Optional email alerts
- **Error Handling** - Graceful failure handling

---

## 🛡️ Safety & Best Practices

### Automatic Backups

GitAuto creates stash backups before major operations:

```bash
# List backups
git stash list | grep gitauto_backup

# View backup contents
git stash show stash@{0}

# Manually restore a backup
git stash pop stash@{0}
```

### Dry-Run Mode

Always test in dry-run mode first:

```bash
# Test on production repositories
./scripts/gitauto-cli.sh fix --dry-run
```

### Exclusion Patterns

Prevent automation on sensitive files:

```yaml
exclusions:
  paths:
    - "config/secrets.yml"
    - "private/"
  patterns:
    - ".env*"
    - "*.key"
    - "*.pem"
```

### Rollback Capabilities

All operations can be rolled back:

```bash
# Immediate rollback
./scripts/gitauto-cli.sh rollback

# Manual rollback from specific stash
git stash list
git stash pop stash@{N}
```

---

## 📊 Resolution Strategies

### Error Type Matrix

| Error Type          | Default Action         | Customizable | Backup Created |
| ------------------- | ---------------------- | ------------ | -------------- |
| Uncommitted Changes | Auto-commit            | ✅           | ✅             |
| Untracked Files     | Auto-add & commit      | ✅           | ✅             |
| Detached HEAD       | Create recovery branch | ❌           | ✅             |
| Unpushed Commits    | Auto-push with retry   | ✅           | ❌             |
| Submodule Issues    | Update & commit        | ✅           | ✅             |
| Diverged Branches   | Rebase                 | ✅           | ✅             |
| Merge Conflicts     | Strategy-based         | ✅           | ✅             |

### Conflict Resolution Strategies

Configure in `.gitauto.yaml`:

```yaml
conflicts:
  strategy: "ours" # Options: ours, theirs, manual, skip
  auto_resolve: true
```

- **ours**: Keep local changes
- **theirs**: Keep remote changes
- **manual**: Skip (requires manual resolution)
- **skip**: Do not attempt resolution

---

## 📝 Logging

### Log Files

GitAuto creates timestamped logs in `.gitauto/logs/`:

```text
.gitauto/logs/
├── gitauto_20241212_143000.log       # Human-readable log
├── gitauto_20241212_143000.json      # Structured JSON log
├── gitauto_errors_20241212_143000.log # Errors only
└── audit_20241212_143000.json        # Audit trail
```

### Viewing Logs

```bash
# Latest human-readable log
cat .gitauto/logs/gitauto_*.log | tail -n 50

# Parse JSON logs
cat .gitauto/logs/gitauto_*.json | jq '.[] | select(.level=="ERROR")'

# View audit trail
cat .gitauto/logs/audit_*.json | jq .
```

### Log Levels

Configure in `.gitauto.yaml`:

```yaml
logging:
  level: "INFO" # DEBUG | INFO | WARNING | ERROR
```

---

## 🔌 Integration Examples

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Git Automation

on:
  schedule:
    - cron: "0 */6 * * *" # Every 6 hours

jobs:
  gitauto:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: "3.10"

      - name: Install Dependencies
        run: pip install GitPython PyYAML rich

      - name: Run GitAuto
        run: ./scripts/gitauto-cli.sh fix
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Run gitauto check before allowing commit
./scripts/gitauto-cli.sh check --dry-run
```

### Docker Container

```dockerfile
FROM python:3.10-slim

RUN apt-get update && apt-get install -y git
RUN pip install GitPython PyYAML rich

COPY scripts/gitauto.py /usr/local/bin/
COPY scripts/gitauto-cli.sh /usr/local/bin/gitauto

WORKDIR /repo
CMD ["gitauto", "fix"]
```

---

## ❓ Troubleshooting

### Common Issues

#### "Not a valid Git repository"

```bash
# Ensure you're in a Git repository
git rev-parse --git-dir

# Initialize if needed
git init
```

#### "Permission denied"

```bash
# Make scripts executable
chmod +x scripts/gitauto*.sh scripts/gitauto.py
```

#### "Module not found: GitPython"

```bash
# Install dependencies
pip3 install GitPython PyYAML rich
```

#### "Failed to push: authentication failed"

```bash
# Setup SSH keys or credential helper
git config --global credential.helper cache

# Or use SSH instead of HTTPS
git remote set-url origin git@github.com:user/repo.git
```

### Debug Mode

Enable debug logging:

```yaml
# .gitauto.yaml
logging:
  level: "DEBUG"
```

### Manual Recovery

If automation fails:

```bash
# 1. Check for backups
git stash list | grep gitauto_backup

# 2. Restore from backup
git stash pop stash@{0}

# 3. Check git status
git status

# 4. Manual resolution
git add .
git commit -m "manual fix"
```

---

## 🤝 Contributing

Contributions welcome! Areas for improvement:

- Additional error detection scenarios
- Enhanced conflict resolution strategies
- Integration with more CI/CD platforms
- Performance optimizations
- Test coverage expansion

---

## 📄 License

MIT License - See [LICENSE](../LICENSE) file

---

## 🙏 Acknowledgments

- **GitPython** - Python Git library
- **Rich** - Terminal formatting
- **PyYAML** - YAML parsing

---

## 📞 Support

- **Documentation**: [ADBasher Docs](../README.md)
- **Issues**: Report bugs or request features via GitHub Issues
- **Email**: <security@example.com> (for security issues)

---

## Made with ❤️ for DevOps automation
