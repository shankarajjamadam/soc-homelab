# Scenario 07 — C2 Beaconing — Findings & IOC Summary

## Zeek conn.log Analysis

**PCAP file:** scenario07_c2_beacon.pcap (104 packets)  
**Zeek output:** 51 conn.log records  
**Kibana total (id.resp_h: "10.10.10.5"):** 150 documents  

### Connection Pattern

All 150 connections share identical characteristics:

| Field | Value |
|-------|-------|
| Source | 10.10.10.10 (Windows 10 victim) |
| Destination | 10.10.10.5:4444 (Kali C2) |
| Protocol | TCP |
| conn_state | REJ (connection rejected) |
| Duration | ~0.000025 seconds |
| orig_bytes | 0 |
| resp_bytes | 0 |
| history | Sr (SYN sent, RST received) |

### Timing Analysis

Connections fire at approximately 0.5-second intervals — Meterpreter keepalive heartbeat. This is sub-interval of the 60-second beacon script — the implant's internal keepalive is more frequent than the command polling interval.

**Standard deviation:** 0 (confirmed via Splunk stdev analysis)  
**Classification:** Automated C2 beaconing — definitive

---

## IOC Summary

| IOC Type | Value | Confidence |
|----------|-------|------------|
| File name | update.exe | Medium — name can change |
| File path | C:\Users\shank\Downloads\update.exe | High — Downloads not normal for system binaries |
| Destination IP | 10.10.10.5 | High (lab) |
| Destination port | 4444 | High — no legitimate use |
| Parent process | powershell.exe spawning unsigned binary | High — T1059.001 |
| Network pattern | stdev=0, zero bytes, repeated REJ | Very High — definitive beaconing |
| conn_state | REJ with 150+ retries | High — automated persistence |

---

## Splunk Correlation Result

```
_time               Image          ParentImage      DestinationIp  Port  stdev  risk_score
2026-06-05 20:52    update.exe     powershell.exe   10.10.10.5     4444  0      CRITICAL
```

---

## Detection Gap Notes

1. **Jitter evasion:** Real C2 frameworks (Cobalt Strike, Sliver) add random jitter to sleep intervals. Tune stdev threshold to < 2, not < 0.5, for production environments.
2. **HTTPS C2:** If C2 uses port 443 with TLS, port-based detection fails. Requires Zeek ssl.log + JA3 fingerprinting.
3. **DNS C2:** dnscat2/iodine tunnel C2 through DNS. Requires Zeek dns.log — alert on high subdomain query volume or unusually long query names.
4. **Only 2 Sysmon EID 3 events vs 150 Zeek records:** Sysmon captures per-process network events at a higher level — Zeek captures every individual TCP connection attempt, revealing the full beaconing volume.
