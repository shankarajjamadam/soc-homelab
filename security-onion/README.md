# Security Onion Lab

This folder documents the Security Onion 3.1.0 deployment in the SOC home lab, used as a secondary detection platform alongside the primary Splunk + Zeek + ELK stack.

## Platform Overview

| Item | Detail |
|---|---|
| **Version** | Security Onion 3.1.0 |
| **Role** | Evaluation (single-node) |
| **Management IP** | 192.168.134.134 |
| **Hypervisor** | VMware Workstation |
| **Network** | VMnet8 (NAT) |
| **RAM allocated** | 12.2 GB |

## Architecture

```
Windows Host (192.168.134.1)
        │
        │ SSH / HTTPS (management)
        ▼
Security Onion VM (192.168.134.134)
        │
        ├── ens160   → Management NIC (SSH, web UI)
        ├── ens192   → Capture NIC (PROMISC, bonded)
        └── bond0    → Suricata monitoring interface
```

### Services Confirmed Running

| Service | Status |
|---|---|
| so-elasticsearch | running |
| so-suricata | running |
| so-zeek | running |
| so-kibana | running |
| so-elastic-fleet | running |
| so-nginx | running |
| so-soc | running |
| so-strelka (all) | running |

## Detection Rulesets Loaded

| Type | Count | Ruleset |
|---|---|---|
| Suricata | 65,217 | ETOPEN (49,273 enabled) |
| YARA | 4,321 | securityonion-yara |
| Sigma | 1,854 | Various |
| **Total** | **71,392** | |

## Lab Constraints

Security Onion cannot run simultaneously with the primary lab stack (OPNsense + Kali + Windows + Splunk + Ubuntu ELK) due to the 16GB RAM ceiling on the host machine (Acer Swift Go 14, on-package LPDDR5X non-upgradeable).

**Workflow adopted:**
1. Run attack sessions with primary lab stack → capture PCAP
2. Shut down primary lab VMs
3. Boot Security Onion
4. Import PCAP via `sudo so-import-pcap /path/to/file.pcap`
5. Analyse alerts in SO web UI

## Detection Validation — Session 1 (2026-06-07)

### Objective
Confirm the SO detection pipeline is functional using `so-import-pcap` with HTTP traffic targeting a known Suricata test endpoint.

### Method
1. Captured live HTTP traffic on `ens160` using `tcpdump`
2. Generated traffic to `testmynids.org` — a site specifically designed to trigger Suricata ET rules
3. Imported PCAP via `so-import-pcap`
4. Verified Suricata alert in `/nsm/import/<id>/suricata/eve.json`

### Capture Command
```bash
sudo tcpdump -i ens160 -w /tmp/test2.pcap host 18.67.93.123 &
curl http://testmynids.org/uid/index.html
curl -A "BlackSun" http://testmynids.org/uid/index.html
sudo pkill tcpdump
sudo so-import-pcap /tmp/test2.pcap
```

### Suricata Alert Confirmed

| Field | Value |
|---|---|
| **Rule** | GPL ATTACK_RESPONSE id check returned root |
| **Signature ID** | 2100498 |
| **Category** | Potentially Bad Traffic |
| **Severity** | 2 (Medium) |
| **Source IP** | 18.67.93.123 (testmynids.org) |
| **Destination IP** | 192.168.134.134 |
| **Protocol** | TCP / HTTP port 80 |
| **Payload** | `uid=0(root) gid=0(root) groups=0(root)` |
| **MITRE ATT&CK** | T1059 — Command and Scripting Interpreter |

### Why This Rule Fired
The GPL rule `sid:2100498` matches on the string `uid=0|28|root|29|` in HTTP response payloads — a pattern indicative of command injection responses returning root shell output. The testmynids.org endpoint deliberately returns this string to validate IDS/IPS rule coverage.

### Zeek Logs Generated
Zeek also processed the PCAP and produced:
- `conn.log` — TCP connection metadata
- `dns.log` — DNS resolution records
- `notice.log` — Zeek notices
- `capture_loss.log`

## Upcoming Sessions

| Session | Objective |
|---|---|
| Session 2 | Import 5-phase attack chain PCAP (Nmap → SMB brute → smbexec → Meterpreter → persistence) |
| Session 3 | Import OWASP scenario PCAPs (SQL injection, XSS, C2 beaconing) |
| Session 4 | Hunt workflow — pivot from alert to Zeek conn.log |
| Session 5 | Cases — create and manage a SOC case from an alert |
| Session 6 | Detections — write a custom Suricata rule |

## Key Commands Reference

```bash
# Import a PCAP
sudo so-import-pcap /path/to/file.pcap

# Check service status
sudo so-status

# View Suricata alerts from import
cat /nsm/import/<import-id>/suricata/eve*.json | python3 -m json.tool

# View Zeek logs from import
ls /nsm/import/<import-id>/zeek/logs/

# Capture traffic for import (during attack sessions)
sudo tcpdump -i <interface> -w /path/to/output.pcap
```

## Related Lab Documentation

- [Main Lab README](../README.md)
- [OWASP Scenarios](../owasp-top10/)
- Primary stack: Splunk + Zeek + OPNsense + Sysmon
