\# OWASP Top 10 — Practical Exploitation in the SOC Home Lab



Working through the OWASP Top 10 (2021) by exploiting OWASP Juice Shop in

the isolated lab. Each entry covers attack methodology, captured evidence,

root cause analysis, remediation, and SOC detection opportunities.



\## Lab environment



\- Attacker: Kali Linux on VMnet10 (10.10.10.5)

\- Target: OWASP Juice Shop 20.0.0 on Ubuntu (10.10.10.50)

\- Monitoring: parallel ELK + Splunk SIEM

\- Network: FortiGate VM as gateway/firewall, fully isolated lab segment



\## Progress



| OWASP | Title | Status |

|---|---|---|

| \[A01](./A01-broken-access-control/) | Broken Access Control | ✅ Complete |

| A02 | Cryptographic Failures | Planned |

| A03 | Injection | Planned |

| A04 | Insecure Design | Planned |

| A05 | Security Misconfiguration | Planned |

| A06 | Vulnerable and Outdated Components | Planned |

| A07 | Identification and Authentication Failures | Planned |

| A08 | Software and Data Integrity Failures | Planned |

| A09 | Security Logging and Monitoring Failures | Planned |

| A10 | Server-Side Request Forgery (SSRF) | Planned |

