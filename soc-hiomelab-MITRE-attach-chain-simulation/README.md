# SOC Lab — MITRE ATT&CK Chain Detection

End-to-end simulation and detection of an 11-phase MITRE ATT&CK kill chain in a home lab environment using Sysmon, Splunk, and FortiGate.

## Overview

This project documents a complete attack simulation spanning reconnaissance through impact, with Splunk-based threat detection for each phase. The lab uses real-world tools (Nmap, Metasploit, PowerShell) and detection techniques (Sysmon event correlation, Windows Security logs, FortiGate syslog).

**Lab Status:** Phases 1–10 fully operational with working detections. Phase 11 requires Sysmon config enhancement.

## Attack Chain

| Phase | Technique | Tool | Detection | Status |
|-------|-----------|------|-----------|--------|
| 1 | Reconnaissance | Nmap (SYN scan) | Sysmon EID 3 (network connection burst) | ✅ Working |
| 2 | Initial Access | SMB brute force (Hydra) | Windows Event ID 4625 (failed logons) | ✅ Working |
| 3 | Execution | PowerShell IEX + Meterpreter | Sysmon EID 1 (process creation) | ✅ Working |
| 4 | Privilege Escalation | fodhelper UAC bypass | Sysmon EID 13 (registry write) | ✅ Working |
| 5 | Credential Access | LSASS memory dump | Sysmon EID 10 (process access) | ✅ Working |
| 6 | Persistence | Run registry key + Scheduled task | Sysmon EID 13 (registry) | ✅ Working |
| 7 | Defense Evasion | Windows Defender disable + event log clear | Sysmon EID 1 + Win Event 1102 | ✅ Working |
| 8 | Discovery | LOLBin enumeration (net, tasklist, whoami) | Sysmon EID 1 burst | ✅ Working |
| 9 | Collection | Archive sensitive files (Compress-Archive) | Sysmon EID 11 (file creation) | ⚠️ Config limited |
| 10 | Exfiltration | HTTP POST to attacker listener | Sysmon EID 3 (outbound connection) | ✅ Working |
| 11 | Impact | VSS deletion + file rename (.LOCKED) | Sysmon EID 1 (vssadmin) + EID 11 | ⚠️ Partial |

## Lab Infrastructure

### Network
- **VMnet10:** 10.10.10.0/24 (isolated lab network)
- **Kali Linux:** 10.10.10.5 (attacker)
- **Windows 10:** 10.10.10.10 (target, password: `Password123!`)
- **FortiGate VM:** 10.10.10.1 (gateway, syslog forwarding)

### Security Tools
- **Sysmon v15.20** — Windows process, network, and file monitoring
- **Splunk Enterprise 10.2.1** — Log aggregation and correlation
- **Splunk Universal Forwarder** — Windows event forwarding
- **FortiGate VM64** — Network-level traffic logging

### Detection Platform
- **Splunk Indexes:**
  - `sysmon` — Sysmon events (EID 1, 3, 10, 11, 13)
  - `wineventlog` — Windows Security/System logs
  - `main` — FortiGate syslog

## Execution Guide

### Prerequisites
1. VMware Workstation with three VMs (Kali, Windows 10, FortiGate)
2. Sysmon v15.20 installed on Windows with monitoring enabled
3. Splunk Enterprise configured with Universal Forwarder
4. FortiGate syslog configured to forward to Splunk on port 514

### Running the Attack Chain

Each phase includes:
1. **Attack command** — Execute on Kali or via Meterpreter shell
2. **Detection query** — Splunk SPL to identify the technique
3. **Expected telemetry** — Event IDs and field values to look for

#### Phase 1: Reconnaissance
```bash
# Kali terminal
nmap -sS 10.10.10.0/24
```
**Detection (Splunk):**
```spl
index=sysmon host=DESKTOP-LGU5NRB EventCode=3 SourceIp=10.10.10.5 
DestinationIp=10.10.10.10 DestinationPort=22 DestinationPort=445
| stats count by SourceIp, DestinationPort
```

#### Phase 2: Initial Access
```bash
# Kali terminal
hydra -l administrator -P /path/to/wordlist.txt smb://10.10.10.10
```
**Detection (Splunk):**
```spl
index=wineventlog host=DESKTOP-LGU5NRB EventCode=4625 
| regex _raw="<EventID>4625</EventID>"
| stats count by _raw
```

#### Phase 3–11: See playbook document for full commands

### Known Limitations

**Sysmon Configuration:**
- FileCreate (EID 11) monitoring limited to `.exe`, `.dll`, `.bat`, `.cmd`, `.ps1` extensions
- **Impact:** Phase 9 (`.zip` files) and Phase 11 (`.LOCKED` files) require config enhancement
- **Fix:** Add to FileCreate include rules:
  ```xml
  <TargetFilename condition="end with">.zip</TargetFilename>
  <TargetFilename condition="end with">.LOCKED</TargetFilename>
  ```

**Splunk Universal Forwarder:**
- PowerShell CommandLine field not always extracted from Sysmon EID 1 events
- **Impact:** Phase 11 (Rename-Item detection) limited
- **Workaround:** Use process creation (vssadmin.exe) as Phase 11 indicator instead

**FortiGate Logging:**
- Syslog filter must be reconfigured after each FortiGate reboot
- **Command:** `config log syslogd filter / set severity information / set forward-traffic enable / end`

## Detection Queries

### Master Correlation Search (All Phases)

```spl
index=sysmon OR index=wineventlog OR index=main
| eval stage=case(
    (index="sysmon" AND EventCode=3 AND SourceIp="10.10.10.5"), "01_recon",
    (index="wineventlog" AND match(_raw, "<EventID>4625</EventID>")), "02_initial_access",
    (index="sysmon" AND EventCode=1 AND match(Image, "powershell") AND match(CommandLine, "IEX")), "03_execution",
    (index="sysmon" AND EventCode=13 AND match(TargetObject, "ms-settings")), "04_priv_esc",
    (index="sysmon" AND EventCode=10 AND match(TargetImage, "lsass")), "05_cred_access",
    (index="sysmon" AND EventCode=13 AND match(TargetObject, "Run")), "06_persistence",
    (index="wineventlog" AND match(_raw, "<EventID>1102</EventID>")), "07_defense_evasion",
    (index="sysmon" AND EventCode=11 AND match(TargetFilename, "backup.zip")), "09_collection",
    (index="sysmon" AND EventCode=3 AND DestinationPort=8444), "10_exfil",
    (index="sysmon" AND EventCode=1 AND match(Image, "vssadmin")), "11_impact",
    true(), "noise")
| where stage != "noise"
| stats dc(stage) as stages_hit values(stage) as stages by host
| where stages_hit >= 5
| eval detection_name="Multi-Stage MITRE Attack Chain"
| eval severity="critical"
```

## Test Results

### Run 1 — May 26, 2026
- **Phases Executed:** 1–11
- **Phases Detected:** 1–10 (Phase 11 partial due to config limitations)
- **Key Findings:**
  - Sysmon EID 11 monitoring excludes `.zip` and `.LOCKED` extensions
  - FortiGate syslog successfully captured outbound exfiltration (Phase 10)
  - Windows Security logs captured SMB brute force accurately (Phase 2)
  - Master correlation search identified 8+ attack phases

## Next Steps

1. **Enhance Sysmon Config** — Add `.zip` and `.LOCKED` to FileCreate monitoring
2. **VLAN Segmentation** — Implement port1.10 (Windows) and port1.20 (Kali) on FortiGate
3. **Suricata IDS on Windows** — Add network IDS as third detection layer
4. **Push to GitHub** — Version control Sysmon config and Splunk correlation searches

## Files

- `README.md` — This file
- `MITRE_Attack_Chain_Playbook_v2.docx` — Detailed attack procedures and detection queries
- `Sysmon_Config.xml` — Sysmon configuration with monitoring rules
- `Splunk_Correlation_Search.spl` — Master multi-stage detection query
- `FortiGate_Syslog_Config.txt` — FortiGate logging configuration

## References

- MITRE ATT&CK Framework: https://attack.mitre.org
- Sysmon Documentation: https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
- Splunk Search Processing Language: https://docs.splunk.com/Documentation/Splunk/latest/SearchReference
- FortiGate Logging: https://docs.fortinet.com/document/fortigate/latest/administration-guide

## Author

SOC Analyst — Home Lab Project  
Date: May 2026  
Lab Platform: VMware Workstation Pro

## License

Educational use only. This project is for cybersecurity training and defensive skill development.
