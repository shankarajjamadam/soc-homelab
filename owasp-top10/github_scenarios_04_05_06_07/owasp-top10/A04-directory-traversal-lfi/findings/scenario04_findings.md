# Scenario 04 — Directory Traversal / LFI — Findings Summary

## Detection Results

| Attack Vector | Detected | Method | Status Code |
|---------------|----------|--------|-------------|
| Basic `../` traversal | YES | Splunk URI pattern + Zeek http.log | 400/200 |
| URL encoded `%2e%2e%2f` | YES | Splunk encoding detection | 200 |
| Double encoded `%252e%252e%252f` | YES | Splunk `%25` pattern | 200 |
| Null byte `%2500` bypass | YES | Splunk + Zeek | 200 (Juice Shop LFI challenge) |
| `/ftp/acquisitions.md` direct access | YES | Splunk FTP exposure rule | 200 |
| `/ftp/eastere.gg%2500.md` null byte | YES | Splunk encoding rule | 200 |

## Key Evidence

- **Juice Shop /ftp/ endpoint** accessible without authentication — internal business documents exposed
- **Null byte bypass** (`%2500`) successfully bypassed Juice Shop file extension filter — LFI challenge solved
- **bytes_sent > 1000 on traversal URIs** — file content returned, confirms successful read
- **ModSecurity deployed post-scenario** — CRS 3.3.8 rules block basic and encoded traversal in subsequent tests

## Blind Spot Identified

nginx `nginx:juice-shop:json` sourcetype captures:
- `remote_addr`, `method`, `uri`, `status`, `bytes_sent`, `request_time`, `user_agent`

**NOT captured:** response body content — cannot confirm which file was read from logs alone. Response body size (`bytes_sent`) used as proxy indicator.

## CVSS v4.0 Score

**Base Score: 7.5 (High)**  
- Attack Vector: Network  
- Privileges Required: None  
- Confidentiality Impact: High (arbitrary file read confirmed)  
- Integrity Impact: None  
- Availability Impact: None  
