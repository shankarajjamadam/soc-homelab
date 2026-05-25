# Phase 1 — Reconnaissance

**MITRE ATT&CK:** T1595.003 (Active Scanning: Wordlist Scanning), T1592 (Gather Victim Host Information)
**OWASP Category:** Pre-attack discovery (no specific A-category)

---

## Objective

Enumerate the application's attack surface — endpoints, file paths, and exposed administrative interfaces — using passive browsing through Burp Suite. The goal is to identify injection-vulnerable endpoints before launching targeted payloads in subsequent phases.

---

## Technique

### Passive Discovery via Burp Site Map

The simplest reconnaissance approach is to browse the target application through Burp's proxy. Every request — including JavaScript chunks, API calls, and static resources — populates the Burp Site Map automatically.

**Procedure:**

1. Launch Burp Suite, open the built-in browser
2. Navigate to `http://10.10.10.50`
3. Interact with the application as a normal user would:
   - Browse the product catalog
   - Click individual product detail pages
   - Open the login form (without authenticating)
   - Open the contact/feedback form
   - Perform a product search
   - Open the About Us page
4. Review the populated tree in **Target → Site map**

### Key Endpoints Identified

After two minutes of casual browsing, the following injection-relevant endpoints were discovered:

| Endpoint | Method | Phase Target | OWASP Mapping |
|----------|--------|--------------|---------------|
| `/rest/user/login` | POST | Phase 2 — SQLi auth bypass | A03 Injection |
| `/rest/products/search` | GET | Phase 7 — UNION SQLi | A03 Injection |
| `/api/Feedbacks/` | POST | Phase 4 — Stored XSS | A03 Injection |
| `/rest/products/reviews` | PATCH | Phase 3 — NoSQL injection | A03 Injection |
| `/ftp/` | GET | Phase 6 — Path traversal | A01 Access Control |
| `/rest/admin/application-version` | GET | Information disclosure | A05 Misconfiguration |
| `/rest/admin/application-configuration` | GET | Admin endpoint exposure | A05 Misconfiguration |
| `/api/Challenges/` | GET | Score Board (Juice Shop meta) | — |

---

## Detection

### Detection 1: 404 Burst (Directory Enumeration)

While passive browsing generates few 404s, **active scanning** with tools like `gobuster` or `ffuf` generates large bursts of 404 responses as the scanner probes nonexistent paths. This is a high-fidelity recon signal.

**Splunk search:**

```spl
index=main sourcetype="nginx:juice-shop:json" status=404
| bucket _time span=1m
| stats count dc(uri) as unique_404_uris by _time, remote_addr
| where count > 50 AND unique_404_uris > 30
| eval detection_name = "Recon: directory enumeration (404 burst)"
| eval severity = "medium"
| table _time, remote_addr, count, unique_404_uris, detection_name, severity
```

**Logic:** A source IP generating 50+ requests with 30+ unique 404 URIs within one minute is statistically incompatible with legitimate user browsing. Real users do not request thirty different non-existent paths in sixty seconds.

### Detection 2: Endpoint Diversity (Forced Browsing)

Tools like `dirb`, `ffuf`, and Burp's Engagement Tools fire requests against wordlists. Even when paths exist (returning 200/304), the *diversity* of paths requested is anomalous.

```spl
index=main sourcetype="nginx:juice-shop:json"
| bucket _time span=5m
| stats dc(path) as unique_paths count as total_requests by _time, remote_addr
| where unique_paths > 100 AND total_requests > 200
| eval detection_name = "Recon: high endpoint diversity (possible forced browsing)"
| eval severity = "low"
| table _time, remote_addr, unique_paths, total_requests, detection_name, severity
```

**Logic:** Most legitimate users interact with a small number of pages. Hitting 100+ unique paths in 5 minutes indicates automated discovery.

### Detection 3: User-Agent Anomaly

Default scanner user-agents are easily spotted. Even when not blocked, they should generate alerts.

```spl
index=main sourcetype="nginx:juice-shop:json"
| eval is_scanner = case(
    match(user_agent, "(?i)gobuster|ffuf|dirb|nikto|sqlmap|nmap|burp|nuclei|wfuzz|w3af"), 1,
    true(), 0
)
| where is_scanner = 1
| stats count by remote_addr, user_agent
| eval detection_name = "Recon: known scanner user-agent"
| eval severity = "medium"
```

> ⚠️ **Limitation:** Trivially bypassed by setting a custom UA. Treat as a high-confidence, low-coverage detection — when it fires, the attacker is unskilled or careless.

---

## Detection Validation

In the lab, passive browsing through Burp produced **59 unique URIs across 203 events** within a 5-minute window. This does not trigger any of the three detections above, which is correct behaviour — passive browsing is not the threat being detected.

Validation of the detections requires running an active scanner:

```bash
# From Kali — example only, not executed in this phase
gobuster dir -u http://10.10.10.50 -w /usr/share/wordlists/dirb/common.txt -t 50
```

This would generate hundreds of 404s in under a minute and trip Detection 1 within one search interval.

---

## SOC Analyst Notes

- Recon is the **noisiest** phase of an attack and offers the highest detection probability — but only against unskilled or automated adversaries. Skilled attackers reconnoitre via OSINT and never touch the target until they have a specific vulnerability in mind.
- The recon detections above complement, rather than replace, signature-based WAF rules. WAFs catch known scanner signatures; behavioural detections catch unknown scanners.
- Alert fatigue is a real risk on Detection 1 if the threshold is too low. Tune to your environment's baseline by first running:

  ```spl
  index=main sourcetype="nginx:juice-shop:json" status=404
  | bucket _time span=1m
  | stats count by _time, remote_addr
  | stats avg(count) as avg_404_per_min p95(count) as p95_404_per_min
  ```

  Set thresholds at p95 + reasonable buffer.

---

## Mapping

| Framework | Control / Reference |
|-----------|---------------------|
| MITRE ATT&CK | T1595.003 (Wordlist Scanning), T1592 (Gather Victim Host Information) |
| NIST CSF 2.0 | DE.CM-01 (Network monitoring), DE.AE-03 (Event correlation) |
| NIST SP 800-53 | SI-4(2) (Automated tools for real-time analysis), AU-6 (Audit review) |
| ISO 27001:2022 | A.8.16 (Monitoring activities) |
| ACSC Essential Eight | Application Hardening (web server logging baseline) |
