# Attack Detection Matrix

## Overview

This matrix maps attack techniques used in the lab to the detection signatures they produce across the three monitoring layers (FortiGate, Suricata, and Sysmon/Windows Security). Each row corresponds to a phase in a multi-stage attack chain that runs from initial recon to persistence.

The chain was simulated end-to-end, and detection was validated against blind-test scoring (46/50 across all phases).

## Attack Chain

The five phases below represent a realistic intrusion sequence: an attacker on the network performs reconnaissance, brute-forces credentials, gains a SYSTEM-level shell, upgrades to a more flexible C2 channel, then establishes persistence for return access.

| Phase | Technique | Tool | MITRE ID |
|-------|-----------|------|----------|
| 1 | Network reconnaissance / SYN scan | nmap (Kali) | T1046 |
| 2 | SMB credential brute force | hydra / netexec (Kali) | T1110.001 |
| 3 | SYSTEM-level shell via service execution | smbexec / impacket (Kali) | T1021.002 |
| 4 | Reverse shell / C2 channel | Meterpreter (Kali, multi/handler) | T1059, T1071 |
| 5 | Registry-based persistence | Run key write (Windows) | T1547.001 |

## Detection Signatures

Each phase produces evidence in one or more layers. The table below shows the primary signal for each phase and where it lands.

| Phase | Detection Layer | Source / Index | Signature |
|-------|----------------|----------------|-----------|
| 1 - Recon | Network | FortiGate / main | DROP logs against unsolicited inbound SYN |
| 2 - Brute force | Host | Windows Security / wineventlog | EID 4625 (failed logon) bursts, followed by EID 4624 (success) |
| 3 - SYSTEM shell | Host | Sysmon / sysmon | EID 1: cmd.exe spawned by svchost.exe (parent-child anomaly) |
| 4 - Reverse shell | Host | Sysmon / sysmon | EID 3: outbound TCP from shell.exe to 10.10.10.5:4444 |
| 5 - Persistence | Host | Sysmon / sysmon | EID 13: registry write to a Run key |

## Cross-Layer Correlation

A saved Splunk correlation search links phases 3, 4, and 5 by chaining on Sysmon's ProcessGuid field. ProcessGuid is unique per process instance and survives across EID 1 (process creation), EID 3 (network), and EID 13 (registry modification), allowing the entire post-exploitation activity from a single intrusion to be reconstructed as one logical chain.

The search uses:
- eval case() to assign a human-readable phase label per event
- eventstats to flag any ProcessGuid that appears in more than one phase as a LINKED_PROCESS
- a filter to exclude noise from the Splunk service account

The search is saved as both a scheduled report and a critical alert.

## Notes

- Phase 1 detection is network-only. Sysmon on Windows does not log inbound connection attempts that are blocked at the firewall, so FortiGate is the sole evidence source for the recon phase.
- Phase 2 produces both a network signal (FortiGate sees the SMB traffic) and a host signal (Windows Security logs the failed/successful logons). The host signal is more reliable for distinguishing brute force from a legitimate login burst because it includes the authentication outcome.
- Phases 3, 4, and 5 are all host-side. By the time the attacker has SYSTEM, network detection becomes secondary - the attacker's actions look like normal local Windows activity to FortiGate. This is the architectural reason that endpoint visibility (Sysmon, EDR) is essential alongside network monitoring.
- Suricata's role in this chain is currently limited to phase 4 (it can alert on the Meterpreter callback if a relevant rule is loaded). Suricata's broader value is in detecting payload delivery, exploit traffic, and known C2 patterns - capabilities that future attack scenarios will exercise.
