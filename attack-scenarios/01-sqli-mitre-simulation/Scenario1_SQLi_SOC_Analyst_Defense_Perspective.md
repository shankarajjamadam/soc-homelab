# SQL Injection (A03) — SOC Analyst Defense Perspective

**Scenario:** OWASP Juice Shop login endpoint (10.10.10.50:3000/rest/user/login)  
**Framework:** ISO 27001 + NIST Cybersecurity Framework (Identify → Protect → Detect → Respond)  
**Analyst Role:** L1 SOC analyst understanding attack mechanics and defense controls  

---

## TABLE OF CONTENTS

1. [Executive Summary](#executive-summary)
2. [Attack Logic Deep Dive](#attack-logic-deep-dive)
3. [ISO 27001 + NIST Mapping](#iso-27001--nist-mapping)
4. [Prevention Controls (Protect)](#prevention-controls-protect)
5. [Detection Indicators (Detect)](#detection-indicators-detect)
6. [Response Procedures (Respond)](#response-procedures-respond)
7. [SOC Analyst Decision Tree](#soc-analyst-decision-tree)

---

## EXECUTIVE SUMMARY

### What is SQL Injection?

**Attacker's Goal:** Bypass authentication without valid credentials

**Attack Method:** Insert malicious SQL code into user input fields

**Why It Works:** Application trusts user input and concatenates it directly into database queries

**Business Impact:** 
- ❌ Unauthorized account access (credential compromise)
- ❌ Database data exposure (sensitive information leak)
- ❌ Account takeover (attacker impersonates users)
- ❌ Potential lateral movement (database admin privileges)

**CVSS Score:** 9.8 (Critical)

---

## ATTACK LOGIC DEEP DIVE

### Step 1: Application Sends Login Request (HTTP POST)

**What happens:**

```
Attacker's Browser                    Juice Shop Server
    │                                      │
    ├─ POST /rest/user/login              │
    │  Content-Type: application/json      │
    │  Body: {                             │
    │    "email": "admin@juice-sh.op",     │
    │    "password": "admin123"            │
    │  }                                   │
    └──────────────────────────────────────►
                                          │
                                    [Server receives]
                                          │
```

**Network Layer (Zeek can observe):**
- Source IP: 10.10.10.10 (attacker) ← **Detectable**
- Dest IP: 10.10.10.50 (Juice Shop)
- Dest Port: 3000 (HTTP)
- HTTP Method: POST
- Content-Type: application/json
- Request Body: [email and password fields]

**Application Layer (WAF can observe):**
- Email field: "admin@juice-sh.op" (normal)
- Password field: "admin123" (normal)

### ISO/NIST Control: Input Validation (A14.2.1 — Access Control)

**What should prevent this:**

```yaml
Control: Input Validation & Output Encoding
Standard: ISO 27001 A14.2.1 (User access management)
         NIST CSF PR.AC-1 (Identity and access management)

Implementation:
  ✅ Whitelist allowed characters in email: [a-z0-9@.-_]
  ✅ Reject special characters: ' " ; -- /* */ OR AND
  ✅ Enforce maximum field lengths
  ✅ Validate email format against RFC 5322
  ✅ Do NOT concatenate user input directly into SQL
  
If implemented: Attack BLOCKED at input stage
```

**What Juice Shop does (vulnerable):**

```javascript
// VULNERABLE CODE (BAD - DON'T DO THIS)
const query = `SELECT * FROM users WHERE email='${email}' AND password='${password}'`;
db.query(query);
```

---

### Step 2: Server Processes Login Request (APPLICATION LAYER)

**What happens:**

```
[Server receives HTTP POST]
       │
       ▼
[Parse JSON body]
  email = "admin@juice-sh.op"
  password = "admin123"
       │
       ▼
[Construct SQL query - VULNERABLE!]
  query = "SELECT * FROM users WHERE email='admin@juice-sh.op' AND password='admin123'"
       │
       ▼
[Execute against database]
  Returns: User record (admin account)
       │
       ▼
[Compare password hash]
  Stored hash: bcrypt(admin123)
  Provided: admin123
  Match? YES → Authentication succeeds
       │
       ▼
[Return JWT token to client]
```

**ISO/NIST Control: Secure Coding (A14.2.5 — Access Control Implementation)**

```yaml
Control: Parameterized Queries (Prepared Statements)
Standard: ISO 27001 A14.2.5 (Secure development)
         NIST CSF PR.DS-2 (Data security)

Implementation:
  ✅ Use parameterized queries:
     query = "SELECT * FROM users WHERE email=? AND password=?"
     execute(query, [email, password])
     
  ✅ ORM frameworks (Object-Relational Mapping):
     User.findByEmail(email) — framework handles SQL safety
     
  ✅ Stored procedures with parameterization
  
  ✅ Never concatenate user input into SQL strings

If implemented: SQL injection PREVENTED
               Even if attacker injects ' OR '1'='1'
               It's treated as a literal string, not SQL code
```

---

### Step 3: Attacker Executes SQL Injection

**Attacker realizes:** Input is not validated

**Attack payload:**

```json
POST /rest/user/login HTTP/1.1
Content-Type: application/json

{
  "email": "admin@juice-sh.op\" OR \"1\"=\"1",
  "password": "anything"
}
```

**What the vulnerable server does:**

```javascript
// VULNERABLE CODE receives:
email = "admin@juice-sh.op\" OR \"1\"=\"1"
password = "anything"

// Constructs this SQL:
query = "SELECT * FROM users WHERE email='admin@juice-sh.op\" OR \"1\"=\"1' AND password='anything'"

// This is INTERPRETED AS:
// WHERE (email = 'admin@juice-sh.op' OR "1"="1') AND password='anything'
//                                  ^^^^^^^^^^^^^^^^^^
//                                  THIS IS ALWAYS TRUE!
```

**SQL Execution Flow:**

```
Original Query (SAFE):
  SELECT * FROM users 
  WHERE email='admin@juice-sh.op' 
    AND password='admin123'
  Result: 0 rows (password doesn't match)

Injected Query (VULNERABLE):
  SELECT * FROM users 
  WHERE email='admin@juice-sh.op' 
    OR '1'='1'           ← ALWAYS TRUE!
    AND password='anything'
  Result: Returns ALL users (or first matching user)
```

**Attacker wins:** Authentication bypassed without valid password

### ISO/NIST Control: Authentication Mechanism (A9.4.3)

```yaml
Control: Multi-Factor Authentication (MFA)
Standard: ISO 27001 A9.4.3 (Password management)
         NIST CSF PR.AC-7 (Authentication)

Implementation:
  ✅ Require MFA (TOTP, SMS, hardware key) after password check
  ✅ Implement account lockout after 5 failed attempts
  ✅ Log all authentication attempts (success + failure)
  ✅ Monitor for unusual login patterns:
     - Multiple failed attempts
     - Login from unusual location/time
     - Login from new device

If implemented: Even if SQL injection succeeds,
               attacker cannot pass MFA challenge
               SOC analyst alerted to suspicious activity
```

---

### Step 4: Attacker Receives JWT Token

**Server response to attacker:**

```json
HTTP/1.1 200 OK
Content-Type: application/json

{
  "authentication": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "admin@juice-sh.op",
    "role": "admin"
  }
}
```

**What attacker can now do:**

```
With valid JWT token:
├── Access admin dashboard
├── View all user accounts
├── Modify product prices
├── View customer orders + PII
├── Change user passwords
├── Delete accounts
└── Potential RCE (depending on admin functions)
```

### ISO/NIST Control: Session Management (A9.4.5)

```yaml
Control: Secure Session Handling
Standard: ISO 27001 A9.4.5 (Session management)
         NIST CSF PR.AC-6 (Authorization)

Implementation:
  ✅ JWT tokens expire after 15 minutes
  ✅ Refresh tokens require re-authentication
  ✅ Token revocation list (blacklist compromised tokens)
  ✅ Bind token to client IP/device fingerprint
  ✅ Sign tokens with strong cryptography (HS256+)
  ✅ Store tokens securely (httpOnly cookie, not localStorage)
  
If implemented: Even with stolen token,
               attacker's session expires
               Token tied to original user's IP/device
               Unusual usage patterns detected
```

---

## ISO 27001 + NIST MAPPING

### Prevention Controls (PROTECT Phase)

| Control | ISO 27001 | NIST CSF | Implementation | Effectiveness |
|---------|-----------|----------|-----------------|---------------|
| **Input Validation** | A14.2.1 | PR.AC-1 | Whitelist allowed chars, reject SQL metacharacters | 99% |
| **Parameterized Queries** | A14.2.5 | PR.DS-2 | Use prepared statements, ORM frameworks | 100% |
| **Output Encoding** | A14.2.5 | PR.DS-2 | HTML/URL encode all user-controlled output | 95% |
| **WAF (Web Application Firewall)** | A13.1.1 | PR.PT-1 | Deploy ModSecurity, AWS WAF rules | 85% |
| **MFA** | A9.4.3 | PR.AC-7 | TOTP/SMS requirement after password | 95% |
| **Account Lockout** | A9.4.3 | PR.AC-7 | Lock after 5 failed attempts (30 min timeout) | 90% |
| **Least Privilege** | A9.2.1 | PR.AC-2 | App database user: SELECT-only, no DROP/DELETE | 80% |
| **Rate Limiting** | A13.1.1 | PR.PT-1 | Max 10 login attempts/minute per IP | 75% |

### Detection Indicators (DETECT Phase)

| Indicator | Source | Threshold | Response |
|-----------|--------|-----------|----------|
| **SQL metacharacters in POST body** | WAF/Zeek HTTP logs | Any occurrence | Alert → Block |
| **Multiple failed login attempts** | Sysmon Event ID 4625 / Zeek | >5 in 5 min | Alert → Lock account |
| **Unusual response size** | Zeek http.log | >5000 bytes for login endpoint | Alert → Investigate |
| **Login from new geographic location** | Splunk GeoIP | IP != historical range | Alert → Verify with user |
| **Rapid API calls** | Zeek/WAF logs | >100 req/min from single IP | Alert → Rate limit |
| **Admin function usage from new session** | Application logs | First-time admin access | Alert → Verify |

### Response Procedures (RESPOND Phase)

#### Triage (0-5 minutes)

**SOC Analyst Questions:**

1. **Is the injection attempt successful?**
   - Check: Did query return data? (HTTP 200 + JWT token?)
   - If YES → Proceed to containment
   - If NO → Continue monitoring, rule out false positive

2. **How many accounts were accessed?**
   - Query database: `SELECT * FROM access_logs WHERE login_method='sql_injection' SINCE 1h`
   - If 1 account → Limited impact
   - If >10 accounts → Escalate to incident commander

3. **What privileges does the compromised account have?**
   - Admin → CRITICAL
   - User → HIGH
   - Guest → MEDIUM

4. **How long was the access window?**
   - Check: Attack timestamp vs. detection timestamp
   - If <1 minute → Good (rapid detection)
   - If >1 hour → Poor (late detection, more damage)

5. **Are there signs of lateral movement?**
   - Check: Database access logs for unusual queries (DROP, DELETE, UNION SELECT)
   - Check: Admin function logs for password changes, user creation
   - If YES → Escalate to INCIDENT

**Decision Tree:**

```
Is SQL injection confirmed?
├─ YES → Go to Containment
│   │
│   ├─ Is compromised account admin?
│   │  ├─ YES → CRITICAL severity
│   │  └─ NO → HIGH severity
│   │
│   └─ How many accounts accessed?
│      ├─ 1 account → Limited containment
│      └─ >10 accounts → Full incident response
│
└─ NO → Continue monitoring
    └─ Update detection rules to catch similar patterns
```

#### Containment (5-30 minutes)

**Immediate Actions:**

```yaml
Step 1: Block Attacker
  ✅ Firewall rule: DROP all traffic from attacker IP
  ✅ WAF rule: Block requests with SQL metacharacters
  ✅ Database: Kill active connections from attacker's IP
  
Step 2: Revoke Compromised Sessions
  ✅ Invalidate JWT token (add to blacklist)
  ✅ Force re-authentication for all users
  ✅ Clear session cookies
  
Step 3: Reset Compromised Accounts
  ✅ Force password reset for admin account
  ✅ Enable MFA (if not already enabled)
  ✅ Log out all active sessions for that user
  
Step 4: Secure the Application
  ✅ Deploy WAF rules to block SQL injection
  ✅ Patch parameterized query code (if vulnerable)
  ✅ Validate all user inputs
```

#### Investigation (30 min - 4 hours)

**Deep Dive Questions:**

1. **When did the attack start?**
   - Query: `SELECT timestamp FROM zeek http.log WHERE method=POST AND uri CONTAINS "login" AND payload CONTAINS OR "1=1" ORDER BY timestamp ASC LIMIT 1`

2. **What data was accessed?**
   - Query database logs: `SELECT * FROM audit_log WHERE action IN (SELECT, INSERT, UPDATE, DELETE) SINCE attack_start_time`
   - Results show: What tables, what records, what columns

3. **Was data exfiltrated?**
   - Check: Unusual outbound connections from database server
   - Check: Large data transfers to external IPs
   - Check: DNS queries for command & control domains

4. **Are there backdoors/persistence mechanisms?**
   - Check: Web server files for new PHP/Node scripts
   - Check: Database for new users, stored procedures
   - Check: System for cron jobs, scheduled tasks

5. **What's the root cause?**
   - Code: Lack of input validation
   - Configuration: No WAF deployed
   - Process: No security code review
   - Testing: No penetration testing

#### Response Communication

**Incident Notification Template:**

```
To: CISO, CTO, Legal, Customer Support
From: SOC Analyst
Time: [timestamp]
Severity: HIGH/CRITICAL
Status: CONTAINED

Incident Summary:
────────────────────────────
Type: SQL Injection (OWASP A03)
Detection Time: [time]
Contained Time: [time]
Duration: [X minutes]

Impact:
────────────────────────────
Accounts Accessed: [N]
Data Exposed: [types of data, PII count if applicable]
Attacker IP: [IP, geolocation]
Attack Vector: POST /rest/user/login

Actions Taken:
────────────────────────────
✅ Attacker IP blocked
✅ Compromised tokens invalidated
✅ Admin password reset
✅ MFA enabled
✅ WAF rule deployed

Next Steps:
────────────────────────────
1. Code patching (parameterized queries)
2. User notification (if PII exposed)
3. Regulatory reporting (GDPR/CCPA if applicable)
4. Root cause analysis
5. Lessons learned session

Contact: [SOC lead] for updates
```

---

## PREVENTION CONTROLS (PROTECT)

### Layer 1: Input Validation (Application Code)

**BEFORE Attack (Developer's Job):**

```python
# VULNERABLE CODE (DO NOT USE)
def login(email, password):
    query = f"SELECT * FROM users WHERE email='{email}' AND password='{password}'"
    return db.execute(query)

# SECURE CODE (USE THIS)
def login(email, password):
    # Parameterized query - user input is DATA, not CODE
    query = "SELECT * FROM users WHERE email=? AND password=?"
    return db.execute(query, [email, password])
```

**Validation Rules:**

```
Email field:
  ✅ Must match regex: ^[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$
  ✅ Max length: 254 characters (RFC 5321)
  ✅ No special characters: ' " ; -- /* */ OR AND
  ✅ If violated: Return 400 Bad Request (don't process further)

Password field:
  ✅ Max length: 128 characters
  ✅ Min length: 8 characters
  ✅ No input validation (user can enter any characters)
  ✅ ALWAYS hash before comparison (never plaintext)
```

**SOC Analyst Verification:**

As analyst, you can verify controls are in place:

```bash
# 1. Request application code review
# 2. Search codebase for dangerous patterns:
grep -r "SELECT.*FROM.*WHERE.*+" /app/src  # String concatenation
grep -r "query.*f\"" /app/src                # f-strings with variables
grep -r "query.*\+" /app/src                 # String concatenation

# 3. If patterns found → Vulnerability exists
# 4. Escalate to development team
```

### Layer 2: Web Application Firewall (WAF)

**Signature-Based Detection:**

```
ModSecurity Rule (Example):
────────────────────────────
SecRule ARGS:email|ARGS:password "@rx (?:union|select|insert|update|delete|drop|create|alter|exec|execute|script|javascript|onclick|onerror)" \
  "id:1000,phase:2,deny,status:403,msg:'SQL Injection Attempt'"

Matches patterns:
  ✅ ' OR '1'='1
  ✅ admin' --
  ✅ ' UNION SELECT password FROM users --
  ✅ "; DROP TABLE users; --
```

**SOC Analyst Monitoring:**

```
Query WAF logs for blocked requests:
  waf.block_reason = "SQL Injection Attempt"
  http.method = "POST"
  http.uri = "/rest/user/login"
  
If found:
  ├─ Count: How many attempts?
  ├─ Source IP: Same attacker? Different attacker?
  └─ Response: 403 (blocked) or 200 (bypassed)?
```

### Layer 3: Database Access Control

**Principle of Least Privilege:**

```sql
-- CREATE separate database user for web application
CREATE USER app_user@'10.10.10.50' IDENTIFIED BY 'strong_password';

-- GRANT only SELECT permission (read-only)
GRANT SELECT ON juice_shop.users TO app_user;

-- DO NOT GRANT dangerous privileges:
REVOKE INSERT, UPDATE, DELETE, DROP, CREATE, ALTER FROM app_user;

-- DO NOT allow direct table modification
REVOKE ALL PRIVILEGES ON *.* FROM app_user;
```

**Effect:** Even if SQL injection succeeds, attacker can only READ data, not:
- DELETE user records
- INSERT backdoor accounts
- DROP tables
- CREATE new tables for persistence

---

## DETECTION INDICATORS (DETECT)

### Real-Time Detection (SOC Analyst Monitoring)

**1. HTTP Layer (Zeek + WAF logs)**

```
Query Syntax (Kibana KQL):
──────────────────────────
http.method: "POST" AND 
http.uri: "/rest/user/login" AND 
http.request.body.raw: ("' OR '1'='1" OR "\" OR \"1\"=\"1" OR "admin' --")

Expected Result: 0 hits (if secure)
Attack Result: 1+ hits (SQL injection detected)

Response: 
  ├─ ALERT to SOC analyst
  ├─ Block source IP immediately
  └─ Investigate: Is this test or real attack?
```

**2. Authentication Layer (Sysmon)**

```
Query Syntax (Splunk SPL):
──────────────────────────
index=sysmon EventCode=1 Image="*sqlplus.exe" OR Image="*mysql.exe"
  ParentProcess="*tomcat*" OR ParentProcess="*java*"

Detection Logic:
  ├─ If web application spawns database client → SUSPICIOUS
  ├─ Normal: Web app → Database socket (no shell)
  ├─ Attack indicator: Shell execution from web process
  └─ Response: Kill process, block connection, investigate

Expected Result: 0 events (normal operation)
Attack Result: 1+ events (process execution detected)
```

**3. Response Size Anomaly (Zeek)**

```
Query Syntax (KQL):
──────────────────────────
log.file.path: "http.log" AND 
http.uri: "/rest/user/login" AND 
http.response.body_length > 5000

Detection Logic:
  ├─ Normal login response: ~500 bytes (JWT + user object)
  ├─ Anomaly: >5000 bytes (indicates multiple user records returned)
  ├─ SQL injection returns: ALL users (thousands of bytes)
  └─ Response: ALERT, investigate response content

Expected Result: 0 hits (login responses are small)
Attack Result: 1+ hits (large response = data leak)
```

**4. Failed Login Spike (Application logs)**

```
Query Syntax (Splunk):
──────────────────────────
sourcetype=app_login error="invalid credentials" 
  | stats count by src_ip 
  | where count > 5

Detection Logic:
  ├─ Attacker tries multiple payloads
  ├─ Each failed attempt = invalid credentials
  ├─ >5 attempts in 1 minute = brute force or fuzzing
  ├─ Response: Lock account, block IP, alert SOC
  └─ Time window: 1 minute (real-time detection)

Expected Result: <5 per minute (normal user)
Attack Result: 20+ per minute (automated attack)
```

### Hunting Queries (Post-Detection Investigation)

**Find all SQL injection attempts in past 24 hours:**

```
(Zeek) HTTP logs:
http.request.body: (*"' OR '1'='1"* OR *"\" OR \"1\"=\"1"* OR *"admin' --"*)
SINCE 24h

(Splunk) All sources:
(sql OR injection) AND (login OR auth OR credential)
earliest=-24h
```

**Find successful authentications from suspicious sessions:**

```
(Zeek) Connection established to login endpoint + JWT in response:
http.uri: "/rest/user/login" AND http.status_code: 200
  AND http.response_body: "token"
SINCE 24h

Compare timestamps:
  ├─ Do these logins come from same IP?
  ├─ Do they authenticate same account (admin)?
  ├─ Are they rapid-fire (automated)?
  └─ If YES to all → Likely compromise
```

---

## RESPONSE PROCEDURES (RESPOND)

### Incident Response Workflow

**Timeline of Response:**

```
T+0 min: Detection triggered (alert fires)
├─ Event: WAF blocks "' OR '1'='1" in POST body
├─ Alert severity: HIGH
├─ SOC analyst page-on-call

T+2 min: Triage begins
├─ Analyst investigates alert
├─ Confirms: SQL injection attempt detected
├─ Severity: CONFIRMED ATTACK

T+5 min: Initial containment
├─ Attacker IP added to firewall deny list
├─ Additional WAF rules deployed
├─ Compromised JWT token invalidated
├─ Analyst escalates to incident commander

T+15 min: Full containment
├─ Affected account password reset
├─ MFA enforced
├─ Database audit logs reviewed
├─ Data exposure assessed

T+30 min: Investigation
├─ Attack timeline reconstructed
├─ Accessed data inventory completed
├─ Root cause identified (missing input validation)
├─ Incident commander briefs leadership

T+4 hours: Root cause analysis
├─ Development team reviews code
├─ Parameterized queries implemented
├─ Code deployed to test environment

T+24 hours: Recovery
├─ Patched code deployed to production
├─ Application tested for regression
├─ Monitoring confirms SQL injection rules still active
├─ Lessons learned session scheduled
```

### Escalation Matrix

| Severity | Trigger | Immediate Action | Escalation |
|----------|---------|------------------|-----------|
| **LOW** | SQL injection blocked by WAF | Log incident | SOC Supervisor |
| **MEDIUM** | Failed injection attempt (>5 times) | Block IP, alert | Incident Commander + Dev |
| **HIGH** | Successful injection (JWT obtained) | All containment steps | CISO + CTO + Legal |
| **CRITICAL** | Data exfiltration confirmed | Full IR activation | CEO + Board |

---

## SOC ANALYST DECISION TREE

### Real-Time Decision Making

```
Alert: SQL injection detected in POST /rest/user/login
│
├─ Step 1: Is this a known test?
│  ├─ YES → Dismiss, update test tracking
│  └─ NO → Continue to Step 2
│
├─ Step 2: Did the injection succeed? (Check HTTP status code)
│  ├─ 403 (Blocked) → WAF caught it, continue monitoring
│  ├─ 400 (Bad Request) → Application rejected input, safe
│  └─ 200 (OK) + JWT token → ATTACK SUCCEEDED, escalate!
│
├─ Step 3: (If 200 OK) How many accounts were accessed?
│  ├─ Query: Check response size and content
│  ├─ <1000 bytes → Single account, limited impact
│  └─ >5000 bytes → Multiple accounts, HIGH impact
│
├─ Step 4: (If successful) Which account was compromised?
│  ├─ admin → CRITICAL severity
│  ├─ service_account → CRITICAL severity
│  ├─ regular_user → HIGH severity
│  └─ test_account → MEDIUM severity
│
├─ Step 5: Is the compromised account still active?
│  ├─ Query: Is JWT token still valid?
│  ├─ YES → Attacker may still be accessing → Urgent
│  └─ NO → Token may have expired → Less urgent
│
└─ Step 6: What is the next action?
   ├─ If CRITICAL: 
   │  ├─ Immediate: Block attacker IP
   │  ├─ Immediate: Invalidate all tokens
   │  ├─ Immediate: Force password reset
   │  └─ Notify: CISO + CTO + Incident Commander
   │
   ├─ If HIGH:
   │  ├─ Within 5 min: Block attacker IP
   │  ├─ Within 5 min: Reset compromised account
   │  └─ Notify: Incident Commander
   │
   └─ If MEDIUM:
      ├─ Within 15 min: Log incident
      ├─ Continue monitoring
      └─ Notify: SOC Supervisor
```

### Key Questions to Answer

**As SOC analyst, when you see this alert, ask:**

1. **Is the injection attempt itself blocked?**
   - Source: WAF logs, HTTP status code
   - Safe: 403 Forbidden (WAF rejected)
   - Unsafe: 200 OK (request processed)

2. **What was the attacker's payload?**
   - Source: HTTP request body from Zeek logs
   - Payload: `' OR '1'='1` (simple bypass)
   - Payload: `'; DROP TABLE users; --` (destructive)
   - Payload: `' UNION SELECT password FROM users` (data exfil)
   - Different payloads = different threat levels

3. **Did the attacker use one payload or many?**
   - One attempt: Maybe accidental, maybe reconnaissance
   - Multiple attempts: Deliberate fuzzing, serious threat
   - Dozens: Automated scanner, still serious

4. **What is the attacker's location?**
   - Source: GeoIP lookup from IP address
   - Same location as your company: Insider threat
   - Random location: External attacker
   - VPN/Tor exit node: Attacker trying to hide

5. **Has this attacker tried other endpoints?**
   - Source: WAF logs, HTTP logs
   - Just /login: Targeted attack
   - Multiple endpoints: Reconnaissance scan
   - Entire application: Broad exploitation attempt

---

## STANDARDS & FRAMEWORKS REFERENCE

### ISO 27001 Controls (Information Security)

**Clause 14: Procurement, Development & Supplier Relationships**

| Control | Code | Title | Application |
|---------|------|-------|-------------|
| Secure Coding | A14.2.5 | Secure development policy | Use parameterized queries |
| Input Validation | A14.2.1 | User access management | Whitelist input chars |
| Change Management | A14.2.2 | Segregation of environments | Test code in dev before prod |

### NIST Cybersecurity Framework

| Function | Category | Subcategory | Control |
|----------|----------|-------------|---------|
| **IDENTIFY** | ID.RA-3 | Risk assessment | Understand SQL injection risk |
| **PROTECT** | PR.AC-1 | Identity & access management | Input validation |
| | PR.DS-2 | Data security | Parameterized queries |
| **DETECT** | DE.CM-1 | Detection processes | WAF rules, HTTP monitoring |
| | DE.AE-3 | Event analysis | Analyze failed logins |
| **RESPOND** | RS.RP-1 | Response planning | Incident playbook |
| | RS.CO-2 | Coordination | Notify CISO, CTO, Legal |
| **RECOVER** | RC.RP-1 | Recovery planning | System patching, password reset |

---

## CHECKLISTS FOR SOC ANALYSTS

### Pre-Attack: Verify Detection Capabilities

- [ ] WAF is deployed and active
- [ ] WAF rules include SQL injection signatures
- [ ] Zeek is capturing HTTP traffic
- [ ] Elasticsearch/Splunk is ingesting Zeek logs
- [ ] KQL/SPL queries for SQL injection are configured
- [ ] Alerting is configured (threshold, severity, escalation)
- [ ] On-call SOC analyst is assigned
- [ ] Incident response playbook is accessible
- [ ] CISO contact info is current

### During Attack: Real-Time Analyst Actions

- [ ] Acknowledge alert within 2 minutes
- [ ] Verify alert is not false positive
- [ ] Determine severity (LOW/MEDIUM/HIGH/CRITICAL)
- [ ] Check if attack succeeded (HTTP 200 + token?)
- [ ] Identify attacker IP address
- [ ] Block attacker IP immediately
- [ ] Investigate compromised accounts
- [ ] Escalate per severity matrix
- [ ] Document timeline in incident ticket
- [ ] Notify stakeholders

### Post-Attack: Investigation & Remediation

- [ ] Collect all evidence (PCAPs, logs, screenshots)
- [ ] Conduct root cause analysis
- [ ] Identify what failed (missing WAF rule? No input validation?)
- [ ] Schedule code review with development
- [ ] Implement fix (parameterized queries)
- [ ] Test fix in development environment
- [ ] Deploy fix to staging → production
- [ ] Verify SQL injection rules still active
- [ ] Update detection rules if needed
- [ ] Schedule lessons learned meeting
- [ ] Close incident ticket

---

## SUMMARY TABLE: Attack → Prevention → Detection → Response

| Phase | Stage | Threat | Control | Evidence |
|-------|-------|--------|---------|----------|
| **ATTACK** | Reconnaissance | Port 3000 identified | Network segmentation | Zeek port scan log |
| | Exploitation | SQL injection sent | Input validation | HTTP POST body |
| | Success | JWT obtained | WAF signature | HTTP 200 + token |
| **PREVENTION** | Code | Vulnerable concatenation | Parameterized queries | Code review |
| | Infrastructure | No WAF deployed | Deploy WAF | ModSecurity active |
| | Access Control | App has DB DROP perms | Remove privileges | MySQL grants |
| **DETECTION** | Real-Time | Anomalous POST | KQL rule triggers | Alert created |
| | Investigation | Successful auth bypass | Token in response | JWT analysis |
| | Hunting | Attack pattern repeat | Query Zeek + WAF logs | Multiple alerts |
| **RESPONSE** | Triage | Confirm incident | Review alert context | Decision made |
| | Containment | Block attacker | Firewall rule + IP block | Traffic stopped |
| | Recovery | Reset account | Force password change | Account secured |

---

## CONCLUSION

**SQL injection demonstrates a critical principle:**

> **The best defense is prevention, not detection.**

A properly secured application (parameterized queries, input validation) makes SQL injection impossible. Detection and response are backup layers, but they're not sufficient if the application is fundamentally vulnerable.

**For L1 SOC analysts:**

1. Understand WHY SQL injection works (application trusts user input)
2. Know HOW to detect it (WAF signatures, response anomalies, failed logins)
3. Know WHAT to do when detected (escalation, containment, investigation)
4. Understand WHICH controls would prevent it (development team's job)

This creates a strong partnership between security operations (detection/response) and development (secure coding).

---

**Document Version:** 1.0  
**Created:** 2026-06-01  
**For:** L1 SOC Analyst Training (Scenario 1: SQL Injection)
