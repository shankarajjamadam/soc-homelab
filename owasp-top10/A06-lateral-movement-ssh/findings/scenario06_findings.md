# Scenario 06 — Lateral Movement SSH — Findings Summary

## Path A — Hydra SSH Brute Force Results

| Metric | Value |
|--------|-------|
| Target | 10.10.10.20 (Ubuntu Server) |
| Account cracked | testuser |
| Password | password123! |
| Time to crack | 11 seconds |
| Wordlist | rockyou.txt |
| Hydra threads | 4 |
| Detection method | Zeek ssh.log — libssh_0.12.0 fingerprint |

## Path B — Meterpreter SOCKS5 Pivot Results

| Metric | Value |
|--------|-------|
| Pivot host | Ubuntu Server 10.10.10.20 |
| VLAN20 access gained | 10.10.20.10 |
| Proxy port | 1080 (SOCKS5) |
| Detection method | Sysmon EID 3 — port 4444 + port 1080 |

## Zeek ssh.log Key Fields

| Field | Value | Significance |
|-------|-------|-------------|
| client | libssh_0.12.0 | Definitive Hydra fingerprint |
| auth_attempts | 50+ | Brute force volume |
| auth_success | true | Successful login after failures |
| id.orig_h | 10.10.10.5 | Kali attacker |
| id.resp_h | 10.10.10.20 | Ubuntu Server victim |
| id.resp_p | 22 | SSH port |

## Detection Gaps (Pre-Fix)

- **auth.log NOT in Splunk before this session** — SSH brute force and successful login invisible to SIEM in real time — **P1 gap**
- **FIXED:** Splunk UF installed on Ubuntu Server (5 June 2026) — auth.log + syslog now forwarding to Splunk main index
- **fail2ban NOT installed** — Hydra completed brute force without lockout — P2 gap pending (needs internet route for apt install)

## CVSS v4.0 Score

**Base Score: 8.1 (High)**
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- Confidentiality: High (VLAN20 access)
- Integrity: High
- Availability: Low

## IOC Summary

| IOC | Value | Confidence |
|-----|-------|------------|
| SSH client string | libssh_0.12.0 | High — Hydra fingerprint |
| Failed auth volume | >10 from same IP | High — brute force |
| Successful auth after failures | testuser from 10.10.10.5 | Critical |
| SOCKS proxy port | 1080 outbound | High — pivot indicator |
| Cross-VLAN connection | 10.10.10.x → 10.10.20.x | High — VLAN boundary crossing |
