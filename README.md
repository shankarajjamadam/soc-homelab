# SOC Home Lab

A lab for practising SOC analyst workflows: building the log pipeline, simulating multi-stage attacks, detecting them across three independent layers, and tuning the detection logic. Used as ongoing portfolio for a transition into security operations.

## What's here

A three-VM environment on VMware Workstation that produces real telemetry from real attacks, with detections written and validated against a structured attack chain.

- **Network detection:** FortiGate firewall logging traffic to Splunk, plus Suricata IDS on Kali watching the wire.
- **Host detection:** Sysmon and Windows Security event logs forwarded to Splunk.
- **SIEM:** Splunk Enterprise on Windows, with three indexes (main, suricata, sysmon) and a cross-layer correlation search that chains process activity via Sysmon ProcessGuid.

Full architecture and topology: [docs/architecture.md](docs/architecture.md).

## What it detects

A five-phase attack chain has been simulated end-to-end and validated through blind-test scoring (46/50 across all phases).

| Phase | Technique | Primary detection |
|-------|-----------|-------------------|
| 1 | nmap SYN scan | FortiGate DROP logs |
| 2 | SMB brute force (hydra/netexec) | Windows EID 4625 / 4624 |
| 3 | SYSTEM shell via smbexec | Sysmon EID 1 (cmd.exe under svchost.exe) |
| 4 | Meterpreter reverse shell | Sysmon EID 3 (callback to 10.10.10.5:4444) |
| 5 | Registry Run-key persistence | Sysmon EID 13 |

A saved Splunk correlation search ties phases 3-5 together by ProcessGuid, reconstructing the post-exploitation chain as one logical sequence.

Full detection matrix with MITRE mappings and cross-layer notes: [docs/attack-detection-matrix.md](docs/attack-detection-matrix.md).

## Repo contents

```
soc-homelab/
├── README.md                       # this file
├── docs/
│   ├── architecture.md             # VM topology, detection stack, limitations
│   └── attack-detection-matrix.md  # attack chain mapped to detection signatures
├── fortigate/
│   └── syslog-config.txt           # FortiGate syslog filter (must be reapplied after reboot)
├── sysmon/                         # Sysmon config (to be added)
├── splunk/                         # Splunk searches and saved reports (to be added)
└── suricata/                       # Custom Suricata rules (to be added)
```

## Status

Working and stable as of April 2026:

- Three-layer log pipeline producing telemetry into Splunk indexes.
- Five-phase attack chain detected end-to-end.
- Cross-layer correlation search saved as both a scheduled report and a critical alert.
- Suricata IDS integrated as a third detection layer alongside Sysmon and FortiGate.
- Custom Suricata rule firing reliably on lab attacker SYN traffic; raw alerts and burst-detection reports both saved.

Honestly described limitations:

- VMnet10 acts as a hub. Same-subnet Kali to Windows traffic does not pass through FortiGate, so FortiGate cannot block lateral attacks. Suricata partially fills this gap but VLAN segmentation is the proper fix.
- Kali has no internet, so Suricata rule updates fail.
- Sysmon EID 3 only logs outbound connections initiated by local Windows processes, not inbound traffic blocked at the firewall.

## What's next

In rough priority order:

1. Externalise Sysmon config, Suricata local rules, and Splunk correlation search to this repo.
2. Fix Kali internet access via FortiGate policy adjustment, enable Suricata rule updates.
3. Implement VLAN-based segmentation to put Kali and Windows on separate subnets, forcing inter-VM traffic through FortiGate.
4. Add a second-phase attack scenario exercising payload delivery and external C2 (requires Kali internet).
5. Retry Suricata-on-Windows for a dual IDS deployment, contingent on VC++ runtime fix.

## About

Built and maintained by Shankar as part of a transition into SOC analyst work. The lab serves as both a learning environment and a portfolio of detection engineering practice.
