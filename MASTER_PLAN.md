# SOC Home Lab — Master Plan & Detection Engineering Roadmap

**Version:** 1.0  
**Date:** 2026-06-01  
**Author:** Shankar (Lab Operator) / Claude (Anthropic)  
**Status:** Active Development  
**Platform:** VMware Workstation (VMnet10 isolated network)  

---

## TABLE OF CONTENTS

1. [Overview](#overview)
2. [Methodology](#methodology)
3. [Lab Architecture](#lab-architecture)
4. [Scenario Framework](#scenario-framework)
5. [Scenario Roadmap](#scenario-roadmap)
6. [Execution Template](#execution-template)
7. [Portfolio Structure](#portfolio-structure)
8. [Success Criteria](#success-criteria)

---

## OVERVIEW

This master plan documents a systematic approach to building L1 SOC analyst skills through simulated attack scenarios. Each scenario integrates:

- **MITRE ATT&CK** — industry-standard adversary tactics & techniques
- **OWASP Top 10** — web application security (where applicable)
- **OSI Layer Analysis** — network architecture understanding
- **Detection Engineering** — Zeek rules + KQL queries
- **Incident Response** — playbooks & containment procedures
- **Security Hardening** — technical controls & baselines

**Output:** GitHub-ready portfolio demonstrating full SOC workflow (attack → detection → response → hardening).

---

## METHODOLOGY

### Per-Scenario Delivery Pipeline

Each scenario follows this 6-stage workflow:

```
1. MITRE/OWASP Analysis
   ↓
2. Lab Execution & Capture
   ↓
3. Detection Engineering
   ↓
4. Incident Response Planning
   ↓
5. Security Hardening
   ↓
6. Documentation & Portfolio
```

### Quality Gates

- ✅ Attack successfully replicated & captured in PCAP
- ✅ Logs processed through Zeek without errors
- ✅ Detection rules tested against captured traffic
- ✅ Incident response playbook validated (dry-run)
- ✅ Hardening controls documented with implementation steps
- ✅ Professional markdown report published to GitHub

---

## LAB ARCHITECTURE

### Physical Layout

```
Host Machine (VMware Workstation)
│
└── VMnet10 (10.10.10.0/24) — Isolated lab network
    ├── Kali Linux (10.10.10.5) — Attacker / Tools
    ├── Windows 10 (10.10.10.10) — Victim / Splunk SIEM
    ├── Ubuntu Web (10.10.10.50) — OWASP Juice Shop (target)
    ├── Ubuntu ELK (10.10.10.30) — Zeek NSM / Elasticsearch / Kibana
    └── FortiGate (10.10.10.1) — Firewall / Syslog
```

### Detection & Observability Stack

| Component | Role | Version | Index/Log |
|---|---|---|---|
| **Zeek** | Network Security Monitoring | 8.0.8 | conn.log, http.log, dns.log, arp.log, ssl.log, notice.log |
| **Sysmon** | Host-based monitoring (Windows) | Latest | Event ID 1,3,7,13, etc. |
| **FortiGate** | Network firewall + syslog | VM eval | Syslog stream |
| **Elasticsearch** | Log aggregation | 8.19.15 | filebeat-8.19.15 index |
| **Kibana** | SIEM visualization | 8.19.15 | Dashboards, Discover, Alerts |
| **Filebeat** | Log shipper | 8.19.15 | Parses Zeek JSON + Windows logs |

### Detection Visibility Matrix

```
           | Sysmon | FortiGate | Zeek |
-----------|--------|-----------|------|
Layer 2    |   ❌   |     ❌    |  ✅  |
Layer 3-4  |   ❌   |     ✅    |  ✅  |
Layer 5-6  |   ❌   |     ❌    |  ✅  |
Layer 7    |   ❌   |     ✅    |  ✅  |
Host Proc  |   ✅   |     ❌    |  ❌  |
```

**Lesson:** NSM (Zeek) is essential for network-layer attacks; host tools (Sysmon) are essential for process attacks.

---

## SCENARIO FRAMEWORK

### Standard Template (All Scenarios)

```markdown
# Scenario: [Name]

## Executive Summary
- Attack Type: [Description]
- MITRE Techniques: T#### | T#### | ....
- OWASP Category: A## (if applicable)
- OSI Layer(s): [1-7 range]
- Threat Level: 🔴 CRITICAL / 🟠 HIGH / 🟡 MEDIUM / 🟢 LOW
- Expected Detection Time: [minutes/hours]

## OSI Layer Analysis

| Layer | Attack Component | Observable | Detection Tool | Blind Spot |
|-------|------------------|-----------|-----------------|-----------|
| 1 | Physical | ... | ... | ... |
| 2 | Data Link | ... | ... | ... |
| 3 | Network | ... | ... | ... |
| 4 | Transport | ... | ... | ... |
| 5 | Session | ... | ... | ... |
| 6 | Presentation | ... | ... | ... |
| 7 | Application | ... | ... | ... |

## MITRE ATT&CK Mapping

**Techniques Used:**
- [T####] — [Name] ([Tactic])
  - Expected Observable: [log type, field]
  - Detection: Zeek rule, KQL query
  - Mitigation: [Control]

## Attack Chain

```
Reconnaissance
  ↓
Exploitation
  ↓
Privilege Escalation (if applicable)
  ↓
Persistence (if applicable)
  ↓
Defense Evasion (if applicable)
  ↓
Credential Access
  ↓
Lateral Movement (if applicable)
  ↓
Impact/Exfiltration
```

## Lab Setup

**Prerequisites:**
- [List VMs needed, network config, services]

**Configuration:**
- [Step-by-step setup]

## Execution Steps

1. [Step 1]
2. [Step 2]
3. ...

## Evidence Captured

### PCAP Analysis
- File: `[scenario]_attack.pcap`
- Packets: [count]
- Duration: [time window]
- Key packets: [timestamps + descriptions]

### Zeek Logs Generated
- conn.log: [count] records
- http.log: [count] records
- dns.log: [count] records
- notice.log: [count] alerts

### Sysmon Events (Windows)
- Event ID 1: [count] process creations
- Event ID 3: [count] network connections
- Event ID 7: [count] DLL loads
- [etc.]

## Detection Engineering

### Rule 1: [Name]
**Objective:** Detect [attack phase]
**Detection Method:** Zeek / KQL
**Logic:** [Query/rule]
**Expected Hits:** [count]
**False Positive Rate:** [estimated %]

### Rule 2: [Name]
**Objective:** Detect [attack phase]
**Detection Method:** Zeek / KQL
**Logic:** [Query/rule]
**Expected Hits:** [count]
**False Positive Rate:** [estimated %]

### Rule 3: [Name]
**Objective:** Detect [attack phase]
**Detection Method:** Zeek / KQL
**Logic:** [Query/rule]
**Expected Hits:** [count]
**False Positive Rate:** [estimated %]

### Kibana Dashboard
**Name:** `SOC Lab — [Scenario] Detection Dashboard`
**Panels:**
1. [Panel name] — [visualization type]
2. [Panel name] — [visualization type]
3. [Panel name] — [visualization type]

## Incident Response Playbook

### Triage (0-5 minutes)
**5 Questions:**
1. [Question 1?]
2. [Question 2?]
3. [Question 3?]
4. [Question 4?]
5. [Question 5?]

**Actions:**
- [ ] [Action 1]
- [ ] [Action 2]
- [ ] [Action 3]

### Containment (5-30 minutes)
- [ ] [Containment step 1]
- [ ] [Containment step 2]
- [ ] [Containment step 3]

### Investigation (30 min - 4 hours)
- [ ] [Investigation step 1]
- [ ] [Investigation step 2]
- [ ] [Investigation step 3]

### Recovery (varies)
- [ ] [Recovery step 1]
- [ ] [Recovery step 2]
- [ ] [Recovery step 3]

## Security Hardening

### Layer 2 (Data Link) Hardening
- Control: [Description]
- Implementation: [Steps]
- Validation: [How to test]

### Layer 3 (Network) Hardening
- Control: [Description]
- Implementation: [Steps]
- Validation: [How to test]

### Layer 4 (Transport) Hardening
- Control: [Description]
- Implementation: [Steps]
- Validation: [How to test]

### Layer 7 (Application) Hardening
- Control: [Description]
- Implementation: [Steps]
- Validation: [How to test]

## Portfolio Evidence

### Files Delivered
- `[scenario]_attack.pcap` — Raw network capture
- `[scenario]_zeek_logs.tar.gz` — Processed logs
- `[scenario]_detection_rules.zeek` — Zeek rules
- `[scenario]_detection_queries.kql` — Kibana queries
- `[scenario]_incident_response_playbook.md` — IR steps
- `[scenario]_detection_report.md` — Complete analysis
- `[scenario]_kibana_dashboard.json` — Dashboard export

### Learning Outcomes
- ✅ Understands [attack technique]
- ✅ Can detect [attack pattern] using [tool]
- ✅ Knows how to respond to [incident type]
- ✅ Understands hardening controls for [OSI layer]

---

## SCENARIO ROADMAP

### Phase 1: Web Application Security (OWASP Top 10)

#### Scenario 1: SQL Injection (A03)
- **MITRE:** T1190 (Exploit Public-Facing Application)
- **OWASP:** A03 Injection
- **OSI Layers:** 7 (Application), 6 (Presentation), 4 (Transport visibility)
- **Status:** 🔄 NEXT
- **Target:** OWASP Juice Shop API endpoint
- **Expected Detection:** Zeek HTTP logs + KQL query
- **Estimated Duration:** 2 hours

#### Scenario 2: Broken Authentication (A07)
- **MITRE:** T1110 (Brute Force)
- **OWASP:** A07 Broken Authentication
- **OSI Layers:** 7 (Application), 5 (Session)
- **Status:** 📋 PLANNED
- **Target:** Juice Shop login endpoint
- **Expected Detection:** Failed login pattern + rate anomaly
- **Estimated Duration:** 2 hours

#### Scenario 3: Sensitive Data Exposure (A02)
- **MITRE:** T1040 (Network Sniffing)
- **OWASP:** A02 Cryptographic Failures
- **OSI Layers:** 6 (Presentation), 1-4 (Network capture)
- **Status:** 📋 PLANNED
- **Target:** HTTP vs HTTPS comparison
- **Expected Detection:** Cleartext protocol usage
- **Estimated Duration:** 1.5 hours

### Phase 2: Network & System Attacks (MITRE)

#### Scenario 4: Lateral Movement (T1570)
- **MITRE:** T1570 (Lateral Tool Transfer)
- **OWASP:** N/A
- **OSI Layers:** 3-4 (Network), 7 (Application)
- **Status:** 📋 PLANNED
- **Target:** SMB file share enumeration + file transfer
- **Expected Detection:** Unusual file access patterns
- **Estimated Duration:** 2 hours

#### Scenario 5: Privilege Escalation (T1548)
- **MITRE:** T1548 (Abuse Elevation Control Mechanism)
- **OWASP:** N/A
- **OSI Layers:** 7 (Application), 5 (Session)
- **Status:** 📋 PLANNED
- **Target:** Windows UAC bypass or sudoeers exploit
- **Expected Detection:** Sysmon process monitoring + privilege changes
- **Estimated Duration:** 2 hours

#### Scenario 6: Data Exfiltration (T1041)
- **MITRE:** T1041 (Exfiltration Over C2 Channel)
- **OWASP:** N/A
- **OSI Layers:** 4-7 (Transport + Application)
- **Status:** 📋 PLANNED
- **Target:** Reverse shell + data transfer
- **Expected Detection:** Unusual outbound traffic patterns
- **Estimated Duration:** 2.5 hours

### Phase 3: Advanced Scenarios (Bonus)

#### Scenario 7: VLAN Hopping
- **MITRE:** T1557 (Man-in-the-Middle)
- **OWASP:** N/A
- **OSI Layers:** 2 (Data Link)
- **Status:** 📋 BONUS
- **Target:** Cross-VLAN traffic injection
- **Expected Detection:** Unexpected VLAN membership
- **Estimated Duration:** 3 hours

#### Scenario 8: Supply Chain Attack (Software Composition Analysis)
- **MITRE:** T1195 (Supply Chain Compromise)
- **OWASP:** A06 Vulnerable & Outdated Components
- **OSI Layers:** 7 (Application dependencies)
- **Status:** 📋 BONUS
- **Target:** Juice Shop vulnerable npm packages
- **Expected Detection:** Known CVE signatures
- **Estimated Duration:** 2 hours

---

## EXECUTION TEMPLATE

### Per-Scenario Checklist

**Week N — Scenario X: [Name]**

- [ ] **Monday:** MITRE/OWASP research + OSI analysis
- [ ] **Tuesday:** Lab setup + attack simulation
- [ ] **Wednesday:** Evidence capture + log processing
- [ ] **Thursday:** Detection rule writing + Kibana dashboard
- [ ] **Friday:** IR playbook + hardening documentation

**Deliverables:**
- [ ] PCAP file
- [ ] Zeek logs (JSON)
- [ ] Detection rules (3 Zeek + 3 KQL)
- [ ] Incident response playbook
- [ ] Security hardening guide
- [ ] Final markdown report
- [ ] Screenshots/evidence

---

## PORTFOLIO STRUCTURE

### GitHub Repository Layout

```
soc-lab/
├── README.md (master overview)
├── MASTER_PLAN.md (this file)
├── METHODOLOGY.md (detection engineering guide)
│
├── scenarios/
│   ├── scenario-01-sql-injection/
│   │   ├── README.md (complete scenario report)
│   │   ├── pcap/
│   │   │   └── sql_injection_attack.pcap
│   │   ├── zeek-logs/
│   │   │   ├── http.log
│   │   │   ├── conn.log
│   │   │   └── notice.log
│   │   ├── detection/
│   │   │   ├── sql_injection_detection.zeek
│   │   │   ├── sql_injection_queries.kql
│   │   │   └── kibana_dashboard.json
│   │   ├── incident-response/
│   │   │   ├── playbook.md
│   │   │   └── triage_checklist.txt
│   │   └── hardening/
│   │       ├── controls.md
│   │       └── implementation_guide.md
│   │
│   ├── scenario-02-brute-force/
│   │   └── [same structure]
│   │
│   └── scenario-03-...
│
├── tools/
│   ├── zeek_rule_template.zeek
│   ├── kql_query_generator.py
│   └── pcap_processor.sh
│
├── documentation/
│   ├── ZEEK_RULES_GUIDE.md
│   ├── KQL_QUERIES_GUIDE.md
│   ├── OSI_LAYER_MAPPING.md
│   └── MITRE_MAPPING.md
│
└── assets/
    ├── lab-architecture.png
    ├── detection-matrix.png
    └── incident-response-workflow.png
```

### README Content (High-Level)

```markdown
# SOC Home Lab — Detection Engineering Portfolio

Complete L1 SOC analyst training through simulated attack scenarios.

## At a Glance

- **8 scenarios** (SQL injection → Supply chain)
- **3 detection rules per scenario** (Zeek + KQL)
- **Complete incident response playbooks**
- **Security hardening for each OSI layer**
- **Professional markdown documentation**

## What You'll Learn

- ✅ MITRE ATT&CK framework application
- ✅ Network security monitoring (Zeek)
- ✅ SIEM query language (Kibana KQL)
- ✅ Incident response procedures
- ✅ Security controls implementation
- ✅ OSI layer architecture

## Scenarios

1. [SQL Injection](#scenario-1-sql-injection) — A03 Injection
2. [Brute Force](#scenario-2-brute-force) — A07 Authentication
3. [Data Exposure](#scenario-3-data-exposure) — A02 Cryptography
4. [Lateral Movement](#scenario-4-lateral-movement) — T1570
5. [Privilege Escalation](#scenario-5-privilege-escalation) — T1548
6. [Data Exfiltration](#scenario-6-exfiltration) — T1041
7. [VLAN Hopping](#scenario-7-vlan-hopping) — T1557
8. [Supply Chain](#scenario-8-supply-chain) — T1195 (Bonus)

## Lab Architecture

[Diagram of VMware setup, VMs, network]

## Getting Started

See `MASTER_PLAN.md` for complete roadmap and setup instructions.

## Portfolio Evidence

Each scenario includes:
- PCAP capture
- Zeek detection rules
- KQL queries
- Incident response playbook
- Hardening documentation
- Professional report

---

**Status:** Active development  
**Next Scenario:** SQL Injection (Scenario 1)  
**Expected Completion:** [Date]
```

---

## SUCCESS CRITERIA

### Per-Scenario Success

- ✅ Attack replicated successfully (PCAP captured)
- ✅ Zeek processes logs without errors
- ✅ 3 detection rules written & tested
- ✅ 3 KQL queries working in Kibana
- ✅ Detection dashboard created
- ✅ Incident response playbook complete
- ✅ Hardening controls documented
- ✅ Professional markdown report published

### Overall Portfolio Success

- ✅ 8 scenarios completed
- ✅ 24 detection rules (3 per scenario)
- ✅ 24 KQL queries (3 per scenario)
- ✅ 8 IR playbooks
- ✅ 8 hardening guides
- ✅ 8+ GitHub commits (one per scenario)
- ✅ Professional README + master plan
- ✅ Ready for L1 SOC analyst interviews

---

## QUICK START

### Session 1 (THIS SESSION)

**Objective:** Complete Scenario 1 (SQL Injection)

**Timeline:**
1. **Hour 1:** MITRE analysis + OSI mapping
2. **Hour 2:** Lab setup + attack execution
3. **Hour 3:** Zeek log processing + dashboard
4. **Hour 4:** Detection rules + incident response
5. **Hour 5:** Hardening documentation + GitHub publish

**Deliverable:** Scenario 1 folder ready for GitHub

---

## REFERENCES

- MITRE ATT&CK Framework: https://attack.mitre.org
- OWASP Top 10 2021: https://owasp.org/Top10/
- OSI Model: https://en.wikipedia.org/wiki/OSI_model
- Zeek Documentation: https://docs.zeek.org
- Kibana KQL: https://www.elastic.co/guide/en/kibana/current/kuery-query.html

---

**Document Version:** 1.0  
**Last Updated:** 2026-06-01  
**Status:** APPROVED FOR EXECUTION  
**Next Review:** After Scenario 1 completion
