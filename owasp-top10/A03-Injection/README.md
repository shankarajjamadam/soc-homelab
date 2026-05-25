# Operation Citrus Squeeze — OWASP A03:2021 Injection Detection Lab

**SOC analyst portfolio project — detecting web application injection attacks against OWASP Juice Shop**

![Status](https://img.shields.io/badge/status-in_progress-yellow)
![OWASP](https://img.shields.io/badge/OWASP-A03%3A2021-orange)
![MITRE](https://img.shields.io/badge/MITRE-T1190-red)
![Splunk](https://img.shields.io/badge/Splunk-Enterprise-blue)

---

## Overview

This project demonstrates end-to-end detection engineering against OWASP Top 10 **A03:2021 — Injection** vulnerabilities, using OWASP Juice Shop as a deliberately vulnerable target. Attacks are executed via Burp Suite from a Kali Linux host; detection logic is implemented in Splunk Enterprise against nginx access logs forwarded via Splunk Universal Forwarder.

The project's focus is **detection engineering** rather than offensive technique — every attack phase pairs the offensive action with a corresponding Splunk detection search, including discussion of detection gaps and how a real SOC would address them.

---

## Lab Architecture

```
┌────────────────────┐         ┌──────────────────────┐         ┌───────────────────┐
│   Kali Linux       │  HTTP   │  Ubuntu Server       │ syslog  │   Splunk          │
│   10.10.10.5       ├────────►│  10.10.10.50         ├────────►│   Enterprise      │
│                    │  :80    │                      │  :9997  │   (on Kali)       │
│   • Burp Suite     │         │   • nginx (port 80)  │         │   • index=main    │
│   • Attacker       │         │   • Juice Shop:3000  │         │   • Detections    │
└────────────────────┘         │   • Splunk UF        │         └───────────────────┘
                               └──────────────────────┘
```

**Key components:**

| Component | Purpose | Notes |
|-----------|---------|-------|
| OWASP Juice Shop | Vulnerable target application | Hosted on Ubuntu, listening on `localhost:3000` |
| nginx | Reverse proxy + access logging | Custom JSON log format `juiceshop_json` |
| Splunk Universal Forwarder | Log shipping | Monitors `/var/log/nginx/juice-shop-access.log` |
| Splunk Enterprise | SIEM and detection platform | Index: `main`, sourcetype: `nginx:juice-shop:json` |
| Burp Suite | Attack tooling | Proxy + Repeater + Intruder |

---

## Repository Structure

```
.
├── README.md                          # This file
├── 01-lab-setup.md                    # Environment configuration and gotchas
├── phases/
│   ├── phase-01-recon.md              # Reconnaissance and endpoint enumeration
│   ├── phase-02-sqli-auth-bypass.md   # SQL injection authentication bypass
│   └── (future phases as completed)
├── detections/
│   ├── A02-null-byte-filter-bypass.spl
│   ├── A03-sqli-credential-bypass-behavioural.spl
│   └── (additional detection searches)
└── findings/
    └── detection-gaps.md              # SOC blind spots identified during testing
```

---

## Attack Phases — Status

| Phase | Technique | OWASP Challenge | Detection Method | Status |
|-------|-----------|-----------------|-------------------|--------|
| 1 | Reconnaissance | — | 404 burst, endpoint enumeration | ✅ Documented |
| 2 | SQLi Auth Bypass | Login Admin | Behavioural (fail→success) | ✅ Complete |
| 3 | NoSQL Injection | NoSQL Manipulation | Operator pattern (`$ne`, `$where`) | ⏳ Planned |
| 4 | XSS (Stored/Reflected) | DOM XSS, Persisted XSS | Pattern + URL decoding | ⏳ Planned |
| 5 | Command Injection | Application-version | Sysmon parent-child chain | ⏳ Planned |
| 6 | Path Traversal | Access Log, Confidential Document | Null byte, `../` patterns | ✅ Detection exists (A02) |
| 7 | UNION-based Data Exfil | Database Schema | Pattern + response size anomaly | ⏳ Planned |

---

## Frameworks and Standards Applied

This work maps to multiple security frameworks for portfolio credibility:

- **OWASP Top 10 2021:** A03 — Injection (primary focus)
- **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter), T1083 (File and Directory Discovery), T1005 (Data from Local System)
- **NIST CSF 2.0:** DE.CM-01 (Network monitoring), DE.AE-02 (Event analysis), PR.DS-02 (Data-in-transit)
- **NIST SP 800-53 Rev. 5:** SI-10 (Information Input Validation), AU-6 (Audit Review/Analysis), SI-4 (System Monitoring)
- **ISO 27001:2022 Annex A:** A.8.26 (Application security requirements), A.8.16 (Monitoring activities)
- **ACSC Essential Eight:** Application Hardening, Application Control
- **APRA CPS 234:** Para 35–37 (Testing of information security controls)
- **Privacy Act 1988 / NDB Scheme:** Relevance to credential compromise and data exfiltration scenarios

---

## Key Findings Summary

1. **Behavioural detection compensates for payload visibility gaps.** nginx access logs do not capture POST request bodies by default, making payload-based regex detection ineffective against JSON API injection attacks. Behavioural patterns (failed-then-successful authentication, response size anomalies, request velocity) reliably detect injection without payload visibility.

2. **Reverse proxy logging architecture matters.** Hitting Juice Shop directly on its application port bypasses all reverse-proxy logging. nginx must be the only ingress path for logging to be reliable — application ports should be firewalled off from attacker networks.

3. **Same-subnet traffic is invisible to gateway firewalls.** FortiGate does not see attacker-to-target traffic on the same VLAN, so same-subnet attacks must be detected through application-tier and endpoint-tier telemetry. This justifies VLAN segmentation in production environments.

4. **Detection engineering benefits from layered visibility.** The most robust detection combines (a) application access logs, (b) endpoint process telemetry (Sysmon for hosted apps), (c) network IDS (Suricata for body inspection), and (d) WAF decisions. No single layer is sufficient.

---

## Tools Used

| Tool | Version | Purpose |
|------|---------|---------|
| Kali Linux | Rolling | Attacker platform |
| Burp Suite Community | 2024.x | HTTP proxy, Repeater, Intruder |
| OWASP Juice Shop | Latest | Vulnerable target |
| nginx | 1.28.3 | Reverse proxy with JSON access logging |
| Splunk Enterprise | 10.2.1 | SIEM platform |
| Splunk Universal Forwarder | 9.x | Log shipping agent |
| Ubuntu Server | 24.04 LTS | Target host |

---

## How to Use This Repository

1. Read `01-lab-setup.md` to understand the environment.
2. Walk through each `phases/phase-XX-*.md` file for offensive technique and detection logic.
3. Import detection searches from `detections/*.spl` into your own Splunk instance.
4. Review `findings/detection-gaps.md` for a SOC-perspective summary of what was learned.

---

## Disclaimer

This work was performed in an isolated home lab against an intentionally vulnerable application (OWASP Juice Shop). All techniques shown are for educational purposes and authorised SOC training only. Do not apply these techniques against any system you do not own or have explicit written authorisation to test.

---

## Author

SOC analyst portfolio project — Australian cybersecurity context.

References to APRA CPS 234, Privacy Act 1988, and ACSC Essential Eight reflect the regulatory environment for which this work is being prepared.
