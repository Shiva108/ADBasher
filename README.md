# ADBasher

**Version 1.0.0 - Fully Automated AD Penetration Testing Framework**

<div align="center">
    <img src="/resources/ADBasherlogo.png" alt="Logo" width="300">
</div>

An **unattended** Active Directory penetration testing framework written in Python and shell script.

This repo is an **automated implementation** of the "Active Directory pentesting mind map" found here:
<https://github.com/esidate/pentesting-active-directory>

![Orange Pentesting AD](/resources/pentest_ad_dark_2022_11.svg "Orange Pentesting AD")

---

## 🆕 What's New in V1.0

### Core Infrastructure

- **Orchestration Engine** (`core/orchestrator.py`): State machine-driven execution
- **Central Database** (SQLite): Persistent storage of targets, credentials, and findings
- **Structured Logging**: JSON logs for SIEM integration
- **Configuration Management**: YAML-based settings for scope and evasion

### Attack Lifecycle Automation

1. **Phase 1: Reconnaissance**

   - DNS domain discovery (`discover_domain.py`)
   - LDAP anonymous enumeration (`ldap_anonymous_bind.py`)

2. **Phase 2: Post-Exploitation Enumeration**

   - BloodHound data collection (`bloodhound_collect.py`)
   - Credential dumping with secretsdump (`secretsdump_auto.py`)

3. **Phase 3: Credential Attacks**

   - Password spraying with lockout protection (`password_spray.py`)
   - Kerberoasting (`kerberoast.py`)
   - Admin privilege detection (`check_admin.py`)

4. **Phase 4: Lateral Movement**

   - Pass-the-Hash attacks via CrackMapExec

5. **Phase 5: Reporting**
   - Automated markdown report generation
   - Credential compromise tables
   - Remediation recommendations

### Unattended Features

- **Credential Cascading**: Automatically re-runs modules when admin creds are found
- **Error Handling**: Graceful degradation (continues on non-critical failures)
- **Progress Tracking**: Rich progress bars and console output

---

## Installation

```bash
# Clone repository
git clone https://github.com/Shiva108/ADBasher.git
cd ADBasher

# Install dependencies (Debian/Kali)
sudo ./install.sh

# Install Python requirements
pip3 install -r requirements.txt
```

### Required Tools

- **CrackMapExec**: `apt install crackmapexec`
- **Impacket**: `pip3 install impacket`
- **BloodHound Python**: `pip3 install bloodhound`
- **DNSPython**: `pip3 install dnspython`

---

## Usage

### Basic Usage

```bash
# Target a domain
./adbasher.py --target example.local

# Target multiple IPs/domains
./adbasher.py --target 192.168.1.0/24 example.local

# OpSec mode
./adbasher.py --target example.local --opsec stealth
```

### Configuration

Edit `core/config.yaml` to customize:

- Target scope (CIDR ranges, exclusions)
- Evasion settings (jitter timing, MAC randomization)
- Module enablement
- Reporting preferences

### Session Management

All output is stored in `~/.adbasher/sessions/<SESSION_ID>/`:

- `session.db`: SQLite database with all findings
- `session_*.log`: Execution logs
- `bloodhound_data/`: BloodHound ZIP files
- `report.md`: Final penetration test report

---

## Tested With

- PowerShell 7.2.1 (for Linux)
- zsh 5.8 (x86_64-debian-linux-gnu)
- GNU bash, version 5.1.4(1)-release
- Parrot OS 5.1 (Electro Ara) x86_64
- Kali Rolling (2024.4) x64

---

## Workflow

```
ADBasher Orchestrator
       ↓
[Phase 1] Reconnaissance
  ├─ discover_domain.py → Finds DCs via DNS
  └─ ldap_anonymous_bind.py → Enumerates users
       ↓
[Phase 2] Credential Attacks
  ├─ password_spray.py → Tests common passwords
  ├─ kerberoast.py → Extracts TGS tickets
  └─ check_admin.py → Identifies admin accounts
       ↓ (if admin creds found)
[Phase 3] Post-Exploitation
  ├─ bloodhound_collect.py → AD attack paths
  └─ secretsdump_auto.py → Dumps NTDS.dit
       ↓
[Phase 4] Lateral Movement
  └─ Pass-the-Hash via CrackMapExec
       ↓
[Phase 5] Reporting
  └─ Generates report.md
```

---

## Ethical Use Warning

⚠️ **This tool is for authorized security testing only.** Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

**Always obtain written authorization before use.**

---

## License

ADBasher is released under the [Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)](https://creativecommons.org/licenses/by-nc/4.0/).
