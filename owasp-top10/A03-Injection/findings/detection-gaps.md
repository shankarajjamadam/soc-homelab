# Detection Gaps and SOC Findings

This document captures the practical detection gaps identified while running the Operation Citrus Squeeze lab. Each finding is paired with recommendations a SOC team could action.

---

## Finding 1: POST Bodies Are Invisible to nginx Logging

### Observation

The nginx `juiceshop_json` log format captures HTTP request headers, URI, status code, and response metadata — but not the request body. A SQL injection payload delivered via JSON POST (e.g. `{"email":"admin@juice-sh.op'--", ...}`) leaves no trace of the payload in nginx access logs.

### Demonstrated Impact

In Phase 2 of this lab, a successful SQL injection authentication bypass against `/rest/user/login` produced a normal-looking log entry with `status=200`. A SIEM detection based on payload pattern matching (`*OR 1=1*`, `*UNION SELECT*`, `*--*`) would produce zero detections against this attack class.

### Remediation Options

| Option | Effort | Trade-off |
|--------|--------|-----------|
| Enable nginx request body logging via `lua` module | Medium | Significant log volume increase; secrets in bodies risk |
| Deploy ModSecurity WAF in front of nginx | High | High detection coverage; tuning effort required |
| Capture application-tier logs (Express/Node access middleware with body capture) | Medium | Requires app change; cleaner data model |
| Deploy Suricata IDS with deep packet inspection rules | High | Catches unencrypted bodies; TLS-decryption complexity |

### Recommended Path

For a small SOC environment, the combination of:
1. **WAF (ModSecurity Core Rule Set)** for payload detection at the perimeter
2. **Behavioural detection in SIEM** (as built in Phase 2) for the cases the WAF misses
3. **Application access logs** for forensic investigation when alerts fire

...provides defence in depth without overwhelming complexity.

---

## Finding 2: Same-Subnet Traffic Bypasses Gateway Firewall Logging

### Observation

The FortiGate VM (10.10.10.1) is the default gateway for the lab subnet, but only sees traffic that requires routing — traffic between hosts on the same subnet (e.g. Kali at .5 attacking Juice Shop at .50) does not transit the gateway.

### Demonstrated Impact

If this lab relied solely on FortiGate syslog for detection, every attack in this scenario would be invisible. Detection is only possible because of the application-tier nginx logs forwarded via Splunk UF.

### Recommendation

For production environments:

- **VLAN segmentation** — placing user/attacker workstations on one VLAN and target services on another forces all inter-tier traffic through the gateway, restoring visibility
- **East-west monitoring** — for unavoidable same-segment workloads, deploy host-based agents (EDR, Sysmon, Auditd, OSquery) or a SPAN/mirror port feeding an IDS

For the lab specifically, this is recorded as a pending improvement (Kali on port1.20 / 10.10.20.0/24, Windows on port1.10 / 10.10.10.0/24).

---

## Finding 3: Application Port Bypass of Reverse Proxy

### Observation

Juice Shop listens on `localhost:3000` and is normally accessed via nginx on port 80. However, port 3000 is also reachable across the network. An attacker who knows or discovers this can bypass nginx — and therefore all logging — by sending traffic directly to port 3000.

### Demonstrated Impact

During lab setup, hitting `http://10.10.10.50:3000` produced zero events in Splunk despite generating live application traffic. This is functionally equivalent to an attacker evading the entire detection stack.

### Remediation

```bash
# Bind Juice Shop to localhost only (where possible in app config)
# OR firewall port 3000 from the network:
sudo ufw deny 3000/tcp
sudo ufw allow from 127.0.0.1 to any port 3000
```

Alternatively, at the FortiGate / network firewall level, block all inbound 3000 traffic to the Ubuntu host.

### Broader Principle

**Any application listener that can be reached without traversing the logging tier is a detection blind spot.** Production deployments should explicitly inventory listening ports and confirm each is either firewalled, monitored, or both.

---

## Finding 4: "No Logs" Does Not Mean "No Traffic"

### Observation

When initial Splunk queries returned zero results, the natural reaction was to assume a pipeline failure (UF down, indexer issue, etc.). In reality, the pipeline was healthy — there was simply no input because attacker traffic was bypassing nginx (see Finding 3).

### Lesson

When investigating "missing logs", confirm input is occurring before troubleshooting the transport. Specifically:

1. Verify the **source file** has fresh writes (`tail -f` the log)
2. Verify the **UF** is running and forwarding to an **active** indexer (not just configured)
3. Verify the **index** exists on the indexer
4. Verify **field extraction** is happening as expected

This four-step diagnostic isolates the failure point quickly.

---

## Finding 5: Configuration Drift in Custom Log Paths

### Observation

The default `/var/log/nginx/access.log` was empty because the Juice Shop server block redirected logs to `/var/log/nginx/juice-shop-access.log`. A new analyst or responder unaware of this custom path would draw the wrong conclusion.

### Recommendation

- Document custom log paths and formats in a runbook accessible to the SOC
- For all monitored hosts, maintain a definitive list of:
  - Source files being monitored
  - Sourcetypes assigned
  - Field structure (especially for JSON formats)
  - Known gaps (e.g. "POST bodies not captured")
- Include a **discovery query** that any analyst can run to confirm what's currently being ingested per host:

  ```spl
  index=* host=<hostname> earliest=-1h
  | stats count, latest(_time) as last_seen by sourcetype, source
  ```

---

## Cumulative Detection Coverage Matrix

How well does the current lab detect each attack phase?

| Phase | Attack | Network Logs Alone | + Behavioural Detection | + Future Suricata | + Future WAF |
|-------|--------|--------------------|-----------------------:|------------------:|-------------:|
| 1 | Recon (404 burst) | ✅ | ✅ | ✅ | ✅ |
| 2 | SQLi auth bypass | ❌ (no body visibility) | ✅ (pattern-of-events) | ✅ (DPI on body) | ✅ (rule match) |
| 3 | NoSQL injection | ❌ | ⚠️ partial (anomalous responses) | ✅ | ✅ |
| 4 | XSS (URL-based) | ✅ (URL pattern) | ✅ | ✅ | ✅ |
| 4 | XSS (body-based) | ❌ | ⚠️ partial | ✅ | ✅ |
| 5 | Command injection | ⚠️ | ✅ (process tree if Sysmon) | ✅ | ✅ |
| 6 | Path traversal | ✅ (URL pattern) | ✅ | ✅ | ✅ |
| 7 | UNION-based exfil | ❌ | ✅ (response size anomaly) | ✅ | ✅ |

**Key insight:** Network logs alone catch only the URL-based attacks. Behavioural and statistical detections close most of the remaining gap, with deep packet inspection and WAF as the gold-standard final layer.
