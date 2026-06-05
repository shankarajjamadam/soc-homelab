# A04 — Directory Traversal / Local File Inclusion (LFI)

## Overview

This scenario simulates a path traversal and Local File Inclusion (LFI) attack against OWASP Juice Shop hosted behind an nginx reverse proxy on Ubuntu (10.10.10.50). The attacker uses `../` sequences to escape the web root and read sensitive system files. Detection is achieved via Splunk nginx access log analysis and Zeek http.log URI pattern matching.

**OWASP Category:** A01:2021 — Broken Access Control (Path Traversal)  
**MITRE ATT&CK:** T1083 (File and Directory Discovery), T1005 (Data from Local System), T1190 (Exploit Public-Facing Application)  
**Lab Date:** May 2026  
**Target:** Ubuntu JuiceShop — 10.10.10.50 (nginx port 80 → Juice Shop port 3000)  
**Attacker:** Kali Linux — 10.10.10.5  
**SIEM:** Splunk Enterprise — juiceshop index  
**Network:** Zeek 8.0.8 — http.log  

---

## What is Directory Traversal / LFI?

Path traversal exploits insufficient input validation to access files outside the intended web root. By injecting `../` sequences into file path parameters, an attacker can read arbitrary files on the server — configuration files, credentials, `/etc/passwd`, private keys.

LFI (Local File Inclusion) extends this by including and potentially executing local files in the web application context.

---

## Attack Chain

| Phase | Action | MITRE | Tool |
|-------|--------|-------|------|
| 1 — Recon | Identify file path parameters in Juice Shop | T1190 | Browser / Burp Suite |
| 2 — Basic traversal | `../../../../etc/passwd` in URL parameter | T1083 | Browser |
| 3 — Encoded traversal | URL-encode `../` as `%2e%2e%2f` to bypass filters | T1027 | Browser |
| 4 — Double encoding | `%252e%252e%252f` — bypass double-decode filters | T1027 | Browser |
| 5 — Sensitive file read | Target `/etc/shadow`, `/etc/hosts`, app config files | T1005 | Browser |
| 6 — App config access | Read Juice Shop config — DB credentials, secrets | T1552 | Browser |
| 7 — Log poisoning (optional) | Inject payload into log file, include via LFI | T1505 | Browser |

---

## Key Payloads

```
# Basic traversal
GET /assets/public/../../../../etc/passwd

# URL encoded
GET /assets/public/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd

# Double encoded
GET /assets/public/%252e%252e%252f%252e%252e%252fetc%252fpasswd

# Null byte (legacy PHP bypass)
GET /assets/public/../../../../etc/passwd%00.jpg

# Juice Shop specific — ftp directory traversal
GET /ftp/../../etc/passwd
GET /ftp/acquisitions.md
GET /ftp/eastere.gg%2500.md
```

---

## Detection — Splunk (nginx access logs)

**Index:** juiceshop | **Sourcetype:** nginx:juice-shop:json

### Primary Detection — Path Traversal Pattern

```spl
index=juiceshop sourcetype="nginx:juice-shop:json"
| search uri="*../*" OR uri="*%2e%2e%2f*" OR uri="*%252e*" OR uri="*etc/passwd*"
| table _time, remote_addr, method, uri, status, bytes_sent
```

### Suspicious 200 Responses to Traversal Attempts

```spl
index=juiceshop sourcetype="nginx:juice-shop:json"
| search uri="*../*" OR uri="*%2e%2e%2f*" OR uri="*etc*"
| where status=200
| table _time, remote_addr, uri, status, bytes_sent
| sort -bytes_sent
```

### High Response Volume — Successful File Read

```spl
index=juiceshop sourcetype="nginx:juice-shop:json"
| where bytes_sent > 1000
| search uri="*ftp*" OR uri="*assets*"
| table _time, remote_addr, uri, status, bytes_sent, request_time
```

**Saved Alert:** `Directory Traversal - Path Traversal Pattern Detected` — High, real-time

---

## Detection — Zeek (http.log)

**Zeek query (Kibana):**
```
uri: *../* OR uri: *%2e%2e* OR uri: *etc*
```

Fields of interest: `uri`, `method`, `status_code`, `response_body_len`, `user_agent`

Successful traversal produces larger `response_body_len` — file content returned in HTTP response body.

---

## Key Findings

- **Juice Shop /ftp/ endpoint** exposes internal files — `/ftp/acquisitions.md` accessible without authentication
- **Null byte bypass** (`%2500`) works against Juice Shop's file extension filter — LFI challenge completed
- **nginx access log captures URI** but not response body — cannot confirm what file was returned without response body logging
- **Status 200 + large bytes_sent** is the behavioural indicator when URI-based detection is evaded via encoding
- **ModSecurity + OWASP CRS 3.3.8** installed post-scenario — blocks basic traversal patterns in subsequent tests

## CVSS v4.0 Score

**Base Score: 7.5 (High)**
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None
- User Interaction: None
- Confidentiality: High (arbitrary file read)
- Integrity: None
- Availability: None

---

## Regulatory Mapping

| Framework | Control | Relevance |
|-----------|---------|-----------|
| NIST CSF | PR.AC-4 | Access permissions — web root isolation |
| ISO 27001 | A.8.3 | Information access restriction |
| OWASP WSTG | WSTG-AUTH-01 | Path traversal testing methodology |
| ACSC Essential Eight | Patch Applications | Juice Shop vulnerable endpoint — unpatched |

---

## Files

- `detections/scenario04_lfi.spl` — All Splunk detection queries
- `findings/scenario04_findings.md` — Detailed findings and evidence
- `Scenario04_LFI_Playbook.docx` — Full playbook (local)
