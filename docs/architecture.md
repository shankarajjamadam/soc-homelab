# Lab Architecture

## Overview

A three-VM lab on VMware Workstation, designed to practise SOC analyst workflows: log pipeline engineering, attack simulation, multi-layer detection, and host hardening.

## Topology

    Internet
       |
       |
+--------+--------+
|   Host (NAT)    |
+--------+--------+
         |
    VMnet10 (host-only, isolated)
         |
+--------+--------+--------+
|                 |                  |
+----+-----+   +----+-----+   +----+-----+
|  Kali    |   |Windows 10|   |FortiGate |
|  Linux   |   |          |   |   VM     |
|          |   | Splunk + |   |          |
| Attacker |   |  Sysmon  |   | Gateway/ |
|  + IDS   |   |   + UF   |   | Firewall |
|10.10.10.5|   |10.10.10.10|  |10.10.10.1|
+----------+   +-----------+  +----------+

All three VMs sit on a single isolated host-only network (VMnet10). FortiGate is the default gateway. The Windows VM has NAT'd internet access for updates and Splunk operations; Kali does not (this is a known limitation, deferred for a later FortiGate policy fix).

## VMs

### Kali Linux - 10.10.10.5

Role: attacker and network IDS.

- Tools: nmap, hydra, metasploit, impacket, netcat, netexec.
- Suricata 8.0.4 IDS running on eth0 with af-packet.
- Splunk Universal Forwarder 10.2.2 forwarding /var/log/suricata/eve.json to the Splunk indexer on Windows.

### Windows 10 - 10.10.10.10

Role: victim host and SIEM.

- Sysmon installed with a tuned config (sysmon/sysmonconfig.xml).
- Splunk Enterprise indexer.
- Receives logs from itself (Sysmon, Windows Security) plus FortiGate syslog and Suricata events forwarded from Kali.

### FortiGate VM - 10.10.10.1

Role: default gateway and firewall.

- Forwards syslog to Splunk over UDP/514.
- Logs forward-traffic and local-traffic events.
- Configuration snippet for syslog filter is in fortigate/syslog-config.txt. This filter must be reapplied after every FortiGate reboot.

## Detection Stack

Three independent detection layers, each writing to its own Splunk index:

| Layer    | Source                | Index            | What it sees                          |
|----------|-----------------------|------------------|---------------------------------------|
| Network  | FortiGate syslog      | main             | Allowed and dropped traffic, sessions |
| Network  | Suricata IDS (Kali)   | suricata         | IDS alerts, signature matches         |
| Host     | Sysmon (Windows)      | sysmon           | Process creation, network, registry   |
| Host     | Windows Security      | wineventlog      | Logon events, account changes         |

This separation lets correlation searches join host-side and network-side evidence for the same activity, which is the core SOC analyst workflow this lab is designed to practise.

## Known Limitations

- VMnet10 is a hub. Same-subnet traffic does not pass through FortiGate, so FortiGate cannot detect or block lateral attacks Kali to Windows. Suricata on Kali fills part of this gap, but segmentation is the proper fix and is planned.
- Kali has no internet. Suricata rule updates and external tools fail. A FortiGate policy adjustment is needed.
- Splunk UF auto-start cosmetic warning. systemctl is-enabled SplunkForwarder reports bad due to a symlinked unit file. The service does start on boot - the warning is benign and does not need to be "fixed" with disable/enable.
