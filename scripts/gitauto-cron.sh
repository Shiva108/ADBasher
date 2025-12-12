#!/bin/bash
#
# gitauto-cron.sh - Cron-friendly wrapper for scheduled GitAuto execution
#
# Usage in crontab:
#   */30 * * * * /path/to/gitauto-cron.sh /path/to/repo
#
# Features:
#   - Lock file to prevent concurrent runs
#   - Syslog integration
#   - Email notifications (optional)
#   - Exit code handling
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GITAUTO_CLI="${SCRIPT_DIR}/gitauto-cli.sh"

# Configuration
REPO_PATH="${1:-.}"
LOCK_FILE="/tmp/gitauto_${USER}_$(echo "$REPO_PATH" | md5sum | cut -d' ' -f1).lock"
LOG_TAG="gitauto"
NOTIFY_EMAIL="${GITAUTO_NOTIFY_EMAIL:-}"

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    
    # Log to syslog if available
    if command -v logger &> /dev/null; then
        logger -t "$LOG_TAG" -p "user.${level}" "$message"
    fi
    
    # Also log to stderr for cron email
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [$level] $message" >&2
}

# Send email notification (if configured)
send_notification() {
    local subject="$1"
    local body="$2"
    
    if [[ -n "$NOTIFY_EMAIL" ]] && command -v mail &> /dev/null; then
        echo "$body" | mail -s "$subject" "$NOTIFY_EMAIL"
    fi
}

# Acquire lock
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
        
        # Check if process is still running
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            log "info" "Another instance is running (PID: $lock_pid), exiting"
            exit 0
        else
            log "warning" "Removing stale lock file"
            rm -f "$LOCK_FILE"
        fi
    fi
    
    echo $$ > "$LOCK_FILE"
    log "info" "Acquired lock"
}

# Release lock
release_lock() {
    rm -f "$LOCK_FILE"
    log "info" "Released lock"
}

# Cleanup on exit
cleanup() {
    release_lock
}

trap cleanup EXIT INT TERM

# Main execution
main() {
    log "info" "Starting GitAuto for repository: $REPO_PATH"
    
    # Acquire lock
    acquire_lock
    
    # Change to repository directory
    if [[ ! -d "$REPO_PATH" ]]; then
        log "error" "Repository path does not exist: $REPO_PATH"
        send_notification "GitAuto Error" "Repository not found: $REPO_PATH"
        exit 1
    fi
    
    cd "$REPO_PATH"
    
    # Check if it's a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        log "error" "Not a Git repository: $REPO_PATH"
        send_notification "GitAuto Error" "Not a Git repository: $REPO_PATH"
        exit 1
    fi
    
    # Run gitauto check first
    log "info" "Checking for Git errors..."
    if "$GITAUTO_CLI" check --json > /tmp/gitauto_check_$$.json 2>&1; then
        log "info" "No errors detected"
        rm -f /tmp/gitauto_check_$$.json
        exit 0
    else
        check_exit_code=$?
        log "warning" "Errors detected (exit code: $check_exit_code)"
    fi
    
    # Run gitauto fix
    log "info" "Running automated resolution..."
    if "$GITAUTO_CLI" fix --json > /tmp/gitauto_fix_$$.json 2>&1; then
        log "info" "Automated resolution completed successfully"
        
        # Parse results for notification
        if [[ -n "$NOTIFY_EMAIL" ]]; then
            result_summary=$(cat /tmp/gitauto_fix_$$.json | python3 -c "
import sys, json
data = json.load(sys.stdin)
success = sum(1 for r in data if r.get('status') == 'success')
failed = sum(1 for r in data if r.get('status') == 'failed')
print(f'Success: {success}, Failed: {failed}, Total: {len(data)}')
" 2>/dev/null || echo "Results available in logs")
            
            send_notification "GitAuto Success" "Repository: $REPO_PATH\n\n$result_summary"
        fi
        
        rm -f /tmp/gitauto_fix_$$.json
        exit 0
    else
        fix_exit_code=$?
        log "error" "Automated resolution failed (exit code: $fix_exit_code)"
        
        # Send failure notification
        send_notification "GitAuto Failure" "Repository: $REPO_PATH\nExit code: $fix_exit_code\n\nCheck logs for details"
        
        rm -f /tmp/gitauto_fix_$$.json
        exit 1
    fi
}

# Cleanup temp files
rm -f /tmp/gitauto_check_$$.json /tmp/gitauto_fix_$$.json 2>/dev/null || true

main "$@"
