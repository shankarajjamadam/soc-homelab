---
title: "SOC Home Lab — 3-Lens Attack Analysis: ARP Poisoning (Variant A)"
scenario: "A1 — Ettercap MITM / ARP Cache Poisoning"
author: Claude (Anthropic)
lab_operator: Shankar
date: 2026-06-01
lab: SOC Home Lab — VMware Workstation / VMnet10
phase: "L1 Analyst Learn Phase — Session 1b"
mitre_technique: "T1557.002 — ARP Cache Poisoning"
tags: [arp-poisoning, mitm, zeek, sysmon, fortigate, elk, pcap-analysis, detection-gap]
---

# SOC Home Lab — 3-Lens Attack Analysis
## Scenario A1: ARP Poisoning (Variant A — Ettercap MITM)

| Field | Value |
|---|---|
| **Date** | 2026-06-01 |
| **Author** | Claude (Anthropic) |
| **Lab Operator** | Shankar |
| **Lab Environment** | VMware Workstation — VMnet10 (10.10.10.0/24) |
| **MITRE Technique** | [T1557.002 — ARP Cache Poisoning](https://attack.mitre.org/techniques/T1557/002/) |
| **PCAP** | `arp_variantA.pcap` (2.2 MB, 4,691 packets) |
| **Phase** | L1 Analyst Learn Phase — Session 1b |

---

## Lab Network Reference

| Host | Role | IP | MAC |
|---|---|---|---|
| Kali Linux | Attacker | `10.10.10.5` | `00:0c:29:27:a1:f2` |
| Windows 10 | Victim / SIEM host | `10.10.10.10` | `00:0c:29:84:87:87` |
| Ubuntu Web | Target (Juice Shop) | `10.10.10.50` | `00:0c:29:f4:2b:c7` |
| Ubuntu ELK | NSM observer | `10.10.10.30` | `00:0c:29:67:c7:0a` |
| FortiGate | Perimeter firewall | `10.10.10.1` | `00:0c:29:2c:d6:fc` |

---

## 1. Attack Summary

Kali performed an ARP cache poisoning attack using Ettercap, positioning itself as a man-in-the-middle (MITM) between the Windows 10 victim and the Ubuntu Web server running OWASP Juice Shop. With MITM established, cleartext HTTP traffic was intercepted — including a POST login request to `/rest/user/login`. The response contained a JWT token from which the admin credentials (`admin@juice-sh.op`, `role=admin`) were decoded.

**Attack chain:**

```
Kali sends gratuitous ARP → Windows 10 caches Kali MAC for 10.10.10.50
Kali sends gratuitous ARP → Ubuntu Web caches Kali MAC for 10.10.10.10
Windows 10 POSTs login to Juice Shop → traffic flows through Kali
Kali captures cleartext HTTP + JWT → forwards traffic (transparent MITM)
```

---

## 2. Three-Lens Detection Table

| # | Observable | Lens | Platform | Visibility | Detail |
|---|---|---|---|---|---|
| 1 | Gratuitous ARP from Kali claiming 10.10.10.10 and 10.10.10.50 | Network | Zeek `arp.log` | ✅ Full | Kali MAC `00:0c:29:27:a1:f2` sent ARP replies for both victim IPs |
| 2 | Duplicate MAC-to-IP mapping (MAC conflict) | Network | Zeek `arp.log` | ✅ Full | Zeek ARP script flagged same MAC claiming multiple IPs |
| 3 | HTTP POST `/rest/user/login` in cleartext | Network | Zeek `http.log` | ✅ Full | `id.orig_h=10.10.10.10`, `id.resp_h=10.10.10.50`, status 200 |
| 4 | JWT token in HTTP response body | Network | Zeek `http.log` | ✅ Partial | Response captured; JWT decoded offline (base64) |
| 5 | Admin credential exposure (`admin@juice-sh.op`) | Network | Zeek `http.log` | ✅ Full | Extracted from decoded JWT payload |
| 6 | Unusual traffic flow through Kali (unexpected hop) | Network | Zeek `conn.log` | ✅ Full | Conn records show Kali forwarding flows between 10.10.10.10 and 10.10.10.50 |
| 7 | Ettercap process execution on Kali | Host | Sysmon | ❌ None | Sysmon monitors Windows 10 only — Kali attacker is outside scope |
| 8 | ARP poisoning tool network activity | Host | Sysmon | ❌ None | No Sysmon visibility on Linux hosts |
| 9 | Outbound HTTP from Windows 10 to Juice Shop | Host | Sysmon Event ID 3 | ✅ Partial | Network connection logged (source/dest/port) — no payload content |
| 10 | Browser process initiating connection | Host | Sysmon Event ID 1 | ✅ Full | Process creation visible if browser was used |
| 11 | Inbound/outbound flows on VMnet10 | Perimeter | FortiGate | ⚠️ Limited | FortiGate sees layer 3 flows — ARP operates at layer 2, invisible to firewall |
| 12 | HTTP session between 10.10.10.10 and 10.10.10.50 | Perimeter | FortiGate | ✅ Partial | Flow logged but no content inspection at this config level |
| 13 | Anomalous routing (traffic via unexpected IP) | Perimeter | FortiGate | ❌ None | MITM traffic stays within VMnet10 subnet — does not cross FortiGate |

---

## 3. Per-Lens Narrative

### 3.1 Lens 1 — Host (Sysmon on Windows 10)

**What Sysmon saw:** Limited.

Sysmon on Windows 10 (`10.10.10.10`) logged network connections (Event ID 3) when the browser initiated the HTTP session to Juice Shop on port 3000. If a browser process was used, Event ID 1 (process creation) would also show the parent-child chain. However, Sysmon has no visibility into:

- ARP table manipulation (layer 2 — below OS logging scope without specialist tooling)
- The fact that traffic was being intercepted by a third party
- Payload content of HTTP requests or responses

From a Sysmon perspective, this attack is **nearly invisible**. The victim's host behaved normally — it sent traffic believing it was going directly to Juice Shop. The deception happened at the network layer, entirely outside Sysmon's event model.

**Key gap:** Sysmon cannot detect ARP poisoning. Detection at the host would require monitoring the ARP cache directly (e.g., `arp -a` baseline + diff) or using an endpoint agent with network stack visibility.

---

### 3.2 Lens 2 — Perimeter (FortiGate Firewall)

**What FortiGate saw:** Minimal.

FortiGate operates at layer 3 and above. ARP is a layer 2 protocol — it never reaches the firewall. The MITM attack was entirely contained within VMnet10, meaning:

- FortiGate received no ARP traffic to inspect
- The HTTP flows between 10.10.10.10 and 10.10.10.50 appeared normal at the firewall level
- No anomalous routing was visible because Kali forwarded traffic transparently

FortiGate *would* log the HTTP session in `index=main` (forward traffic), but the source and destination IPs would appear legitimate — no indicator that Kali was an intermediary.

**Key gap:** A perimeter firewall provides zero detection capability against intra-subnet MITM attacks. The attack never crossed a routed boundary. Detection would require inline IDS/IPS with ARP inspection enabled, or 802.1X port-level authentication to prevent rogue ARP replies.

---

### 3.3 Lens 3 — Network (Zeek NSM on Ubuntu ELK)

**What Zeek saw:** Full detection.

Zeek running offline against `arp_variantA.pcap` provided the most complete picture of all three lenses:

**`arp.log` — ARP poisoning detected:**
- Kali MAC `00:0c:29:27:a1:f2` sent gratuitous ARP replies claiming both `10.10.10.10` and `10.10.10.50`
- Zeek ARP script flagged the MAC-to-IP conflict — one MAC address announcing ownership of two IPs is a definitive indicator of ARP spoofing

**`conn.log` — MITM traffic flow confirmed:**
- Connection records showed traffic flowing through Kali as an intermediary
- Unusual connection patterns between hosts visible in flow metadata

**`http.log` — Credential interception confirmed:**
- `POST /rest/user/login` HTTP 200 captured
- Source: `10.10.10.10` → Destination: `10.10.10.50:3000`
- JWT token in response decoded to reveal: `admin@juice-sh.op`, `role=admin`
- User-agent: Windows 10 / Chrome browser fingerprint visible in cleartext

**Key strength:** Zeek is the only platform in this lab that detected all phases of the attack — the ARP poisoning itself, the traffic interception, and the credential exposure. This validates the NSM platform decision and the "Sysmon blind, Zeek visible" design principle underpinning the lab architecture.

---

## 4. Indicators of Compromise (IOCs)

| IOC Type | Value | Source |
|---|---|---|
| Attacker IP | `10.10.10.5` | Zeek conn.log |
| Attacker MAC | `00:0c:29:27:a1:f2` | Zeek arp.log |
| Spoofed IP (victim) | `10.10.10.10` | Zeek arp.log |
| Spoofed IP (target) | `10.10.10.50` | Zeek arp.log |
| Intercepted endpoint | `POST /rest/user/login` | Zeek http.log |
| Compromised account | `admin@juice-sh.op` | JWT decode |
| JWT role claim | `role=admin` | JWT decode |
| HTTP status | `200 OK` (successful auth) | Zeek http.log |
| Juice Shop port | `3000/tcp` | Zeek conn.log |

---

## 5. Detection Gap Summary

| Platform | Detects ARP Poisoning | Detects MITM Traffic | Detects Credential Theft | Notes |
|---|---|---|---|---|
| Sysmon (Windows 10) | ❌ | ❌ | ❌ | Layer 2 blind; payload blind |
| FortiGate | ❌ | ❌ | ❌ | Intra-subnet attack; never crossed firewall |
| Zeek (NSM) | ✅ | ✅ | ✅ | Full visibility via PCAP analysis |

**Conclusion:** This scenario demonstrates a critical detection gap in host-only and perimeter-only monitoring strategies. ARP poisoning attacks operating within a subnet are invisible to both Sysmon and traditional firewalls. Network Security Monitoring (NSM) via Zeek is the essential compensating control.

---

## 6. Defensive Recommendations

| Recommendation | Mitigates | Complexity |
|---|---|---|
| Enable Dynamic ARP Inspection (DAI) on managed switches | ARP poisoning | Medium |
| Deploy 802.1X port authentication | Rogue device MITM | High |
| Enforce HTTPS/TLS on all internal web services | Credential exposure via MITM | Low |
| Implement ARP cache monitoring (baseline + alert on change) | ARP poisoning detection at host | Medium |
| Deploy Zeek or equivalent NSM in inline/tap mode | All MITM variants | Medium |
| Network segmentation (VLANs) to limit blast radius | Lateral movement | Medium |

---

## 7. Lab Artefacts

| Artefact | Location | Notes |
|---|---|---|
| Raw PCAP | `/home/shankar/arp_variantA.pcap` | 2.2 MB, 4,691 packets |
| Zeek output (TSV) | `/home/shankar/zeek-output/arp_variantA/` | conn.log, http.log, arp.log |
| Zeek conn (JSON) | `/home/shankar/zeek-output/conn_arp_variantA_json.log` | Filebeat-ingested |
| Zeek http (JSON) | `/home/shankar/zeek-output/http_arp_variantA_json.log` | Filebeat-ingested; 201 docs in ES |
| Kibana index | `filebeat-8.19.15` | 266,080 total docs |
| Scenario document | `SOC_Lab_Scenario_A1_ARP_Poisoning.docx` | Full scenario write-up |

---

## 8. References

- Zeek Documentation — ARP log format: https://docs.zeek.org/en/master/scripts/base/protocols/arp/
- MITRE ATT&CK — T1557.002 ARP Cache Poisoning: https://attack.mitre.org/techniques/T1557/002/
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
- ASD Essential Eight — Network Segmentation (Mitigation)
- NIST SP 800-94 — Guide to Intrusion Detection and Prevention Systems

---

## 9. Attribution

| Role | Name |
|---|---|
| **Document Author** | Claude (Anthropic) |
| **Lab Operator / Analyst** | Shankar |
| **Lab Platform** | VMware Workstation — VMnet10 isolated segment |
| **Generated** | 2026-06-01 |
| **Lab Phase** | L1 SOC Analyst Learn Phase — Session 1b (3-Lens Analysis) |

---

*This document is part of the SOC Home Lab portfolio — a structured curriculum for L1 SOC analyst skill development in the Australian cybersecurity context.*
