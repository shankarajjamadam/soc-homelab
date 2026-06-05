# Scenario 05 — Command Injection — Findings Summary

## Detection Results

| Phase | Action | Detected | Detection Method |
|-------|--------|----------|-----------------|
| 1 | DVWA recon | N/A | Reconnaissance only |
| 2 | `whoami` via injection | YES | Sysmon EID 1 — httpd.exe->cmd.exe |
| 3 | `net user` enumeration | YES | Sysmon EID 1 — CommandLine match |
| 4 | `whoami /priv` | YES | Sysmon EID 1 |
| 5 | `dir C:\` | YES | Sysmon EID 1 |
| 6 | `type passwords.txt` | YES | Sysmon EID 1 — credential keyword |
| 7 | Web shell write | YES (blocked) | Sysmon EID 1 + MariaDB secure_file_priv |
| 8 | Persistence check | YES | Sysmon EID 1 |
| 9 | Lateral prep | YES | Sysmon EID 3 |
| 10 | Exfil simulation | YES | Sysmon EID 1 |

**Detection rate: 100%**

## Key Evidence

- **Process chain:** `httpd.exe` -> `cmd.exe` — definitive indicator, zero false positives in lab
- **Defence in depth worked:** MariaDB `secure_file_priv` prevented web shell write outside htdocs
- **POST body blind spot:** nginx access logs capture URI but not POST body — payload regex detection not possible

## CVSS v4.0 Score

**Base Score: 9.3 (Critical)**
- Attack Vector: Network
- Attack Complexity: Low
- Privileges Required: None (DVWA low security)
- User Interaction: None
- Scope: Changed (web process to OS)
- Confidentiality: High
- Integrity: High
- Availability: High
