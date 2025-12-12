#!/bin/bash
#
# gitauto-cli.sh - User-friendly CLI wrapper for GitAuto
# 
# Usage:
#   gitauto check           - Analyze repository for errors
#   gitauto fix             - Automatically fix detected errors
#   gitauto status          - Show detailed repository status
#   gitauto rollback        - Undo last automated operation
#   gitauto clean           - Clean up automation artifacts
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GITAUTO_PY="${SCRIPT_DIR}/gitauto.py"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
error() {
    echo -e "${RED}✗ Error:${NC} $1" >&2
    exit 1
}

success() {
    echo -e "${GREEN}✓${NC} $1"
}

info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Check if gitauto.py exists
if [[ ! -f "$GITAUTO_PY" ]]; then
    error "gitauto.py not found at: $GITAUTO_PY"
fi

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    error "Not in a Git repository"
fi

# Command implementations
cmd_check() {
    info "Analyzing repository for Git errors..."
    python3 "$GITAUTO_PY" check --repo "$REPO_ROOT" "$@"
}

cmd_fix() {
    info "Running automated error resolution..."
    python3 "$GITAUTO_PY" fix --repo "$REPO_ROOT" "$@"
}

cmd_status() {
    info "Retrieving repository status..."
    python3 "$GITAUTO_PY" status --repo "$REPO_ROOT" "$@"
}

cmd_rollback() {
    info "Rolling back last automated operation..."
    
    # Check for stashed backups
    stash_list=$(git stash list | grep "gitauto_backup" || true)
    
    if [[ -z "$stash_list" ]]; then
        warning "No GitAuto backups found in stash"
        exit 0
    fi
    
    # Get most recent backup
    latest_stash=$(echo "$stash_list" | head -n 1 | cut -d: -f1)
    
    echo -e "\nFound backup: $latest_stash"
    git stash show "$latest_stash"
    
    echo -e "\n${YELLOW}⚠ Warning:${NC} This will restore the repository to the backup state."
    read -p "Continue? [y/N] " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        git stash pop "$latest_stash"
        success "Rollback complete"
    else
        info "Rollback cancelled"
    fi
}

cmd_clean() {
    info "Cleaning up GitAuto artifacts..."
    
    local gitauto_dir="${REPO_ROOT}/.gitauto"
    local retention_days=7
    
    if [[ -d "$gitauto_dir" ]]; then
        # Clean old logs
        find "$gitauto_dir/logs" -type f -mtime +${retention_days} -delete 2>/dev/null || true
        success "Cleaned logs older than ${retention_days} days"
        
        # Show current usage
        local size=$(du -sh "$gitauto_dir" 2>/dev/null | cut -f1)
        info "Current .gitauto directory size: $size"
    else
        info "No .gitauto directory found"
    fi
    
    # Clean old stash backups
    local old_backups=$(git stash list | grep "gitauto_backup" | tail -n +5 || true)
    if [[ -n "$old_backups" ]]; then
        warning "Found old backup stashes (keeping 5 most recent)"
        echo "$old_backups" | while read -r line; do
            stash_ref=$(echo "$line" | cut -d: -f1)
            git stash drop "$stash_ref" 2>/dev/null || true
        done
        success "Cleaned old backup stashes"
    fi
}

cmd_init() {
    info "Initializing GitAuto configuration..."
    python3 "$GITAUTO_PY" init-config --repo "$REPO_ROOT"
    
    if [[ -f "${REPO_ROOT}/.gitauto.yaml" ]]; then
        success "Configuration created: .gitauto.yaml"
        info "Edit this file to customize automation behavior"
    fi
}

cmd_help() {
    cat << EOF
GitAuto - Automated Git Error Detection and Resolution

Usage:
  gitauto <command> [options]

Commands:
  check          Analyze repository and detect Git errors
  fix            Automatically resolve detected errors
  status         Show detailed repository status
  rollback       Undo last automated operation (restore from backup)
  clean          Clean up old logs and backup stashes
  init           Create default configuration file
  help           Show this help message

Options:
  --dry-run      Test mode - show what would be done without making changes
  --json         Output in JSON format
  --config FILE  Use specific configuration file

Examples:
  gitauto check                  # Check for errors
  gitauto fix --dry-run          # Test fixes without applying
  gitauto fix                    # Apply automated fixes
  gitauto rollback               # Undo last operation
  gitauto clean                  # Clean up old artifacts

For more information, see: docs/GITAUTO.md
EOF
}

# Main command router
main() {
    if [[ $# -eq 0 ]]; then
        cmd_help
        exit 0
    fi
    
    local command="$1"
    shift
    
    case "$command" in
        check)
            cmd_check "$@"
            ;;
        fix)
            cmd_fix "$@"
            ;;
        status)
            cmd_status "$@"
            ;;
        rollback)
            cmd_rollback "$@"
            ;;
        clean)
            cmd_clean "$@"
            ;;
        init)
            cmd_init "$@"
            ;;
        help|--help|-h)
            cmd_help
            ;;
        *)
            error "Unknown command: $command (try 'gitauto help')"
            ;;
    esac
}

main "$@"
