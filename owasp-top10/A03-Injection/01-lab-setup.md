# Lab Setup — Operation Citrus Squeeze

This document captures the environment configuration used for the OWASP A03 injection detection lab, including configuration gotchas discovered during setup.

---

## Network Topology

All three hosts run on a flat VMware VMnet10 subnet (`10.10.10.0/24`):

| Host | IP | Role | Operating System |
|------|----|------|------------------|
| Kali Linux | 10.10.10.5 | Attacker + Splunk Enterprise | Kali Rolling |
| Ubuntu Server | 10.10.10.50 | Juice Shop target + Splunk UF | Ubuntu 24.04 LTS |
| Windows 10 | 10.10.10.10 | (Reserved for endpoint-tier testing) | Windows 10 |
| FortiGate VM | 10.10.10.1 | Default gateway, syslog source | FortiOS |

**Architectural note:** Same-subnet attacker-to-target traffic is invisible to the FortiGate gateway. Detection for this lab therefore relies on application-tier (nginx) and host-tier (UF) logging. A planned future change is to split attacker and target onto separate VLANs to enable gateway-tier visibility.

---

## Juice Shop Configuration

Juice Shop runs on the Ubuntu host listening on `localhost:3000`. It is fronted by nginx, which provides:

- A single ingress point on port 80
- Structured JSON access logs for SIEM ingestion
- TLS termination point (future enhancement)

### nginx Configuration Excerpt

The relevant nginx server block defines a custom JSON log format and dedicated log file:

```nginx
log_format juiceshop_json escape=json
    '{"timestamp":"$time_iso8601",'
    '"remote_addr":"$remote_addr",'
    '"remote_port":"$remote_port",'
    '"method":"$request_method",'
    '"uri":"$request_uri",'
    '"path":"$uri",'
    '"query":"$args",'
    '"status":$status,'
    '"bytes_sent":$bytes_sent,'
    '"request_time":$request_time,'
    '"upstream_response_time":"$upstream_response_time",'
    '"user_agent":"$http_user_agent",'
    '"referer":"$http_referer",'
    '"authorization":"$http_authorization",'
    '"cookie":"$http_cookie",'
    '"x_forwarded_for":"$http_x_forwarded_for"}';

server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    access_log /var/log/nginx/juice-shop-access.log juiceshop_json;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
    }
}
```

### Critical Configuration Notes

> ⚠️ **Always access Juice Shop via port 80, not 3000.**
> Hitting `http://10.10.10.50:3000` bypasses nginx entirely and produces **zero log events**.
> The detection stack only sees traffic that goes through nginx on port 80.
>
> **Recommended hardening:** Firewall port 3000 from the attacker subnet.

> ⚠️ **The default `/var/log/nginx/access.log` is empty by design.**
> All Juice Shop traffic is logged to the custom path defined in the `server_name _;` block: `/var/log/nginx/juice-shop-access.log`.
> Engineers troubleshooting "missing logs" should always confirm which file is the active log via `sudo nginx -T | grep access_log`.

---

## Splunk Universal Forwarder Configuration

The Universal Forwarder on the Ubuntu host monitors the Juice Shop log file and forwards to the Splunk Enterprise instance on Kali.

### `inputs.conf`

```ini
[monitor:///var/log/nginx/juice-shop-access.log]
disabled = false
index = main
sourcetype = nginx:juice-shop:json
```

### `outputs.conf`

```ini
[tcpout]
defaultGroup = splunk_indexer

[tcpout:splunk_indexer]
server = 10.10.10.5:9997
```

### Verification Commands

After configuration changes, verify the UF is healthy and forwarding:

```bash
# Check service status
sudo systemctl status SplunkForwarder

# Confirm monitored files
sudo /opt/splunkforwarder/bin/splunk list monitor

# Confirm forward-server connection is active (not just configured)
sudo /opt/splunkforwarder/bin/splunk list forward-server
```

The forward-server output must show the indexer under **Active forwards**, not **Configured but inactive**.

---

## Splunk Enterprise Configuration

The Kali host runs Splunk Enterprise with a single `main` index receiving Juice Shop logs.

**Required pre-configuration (learned the hard way):**

- Indexes must exist on the indexer before forwarded data arrives. If the index does not exist, data is silently queued and never indexed.
- For nginx JSON logs, field extraction is automatic when the sourcetype's `KV_MODE = json` is set in `props.conf` (default for `_json` suffix sourcetypes in modern Splunk).

### Verifying Data Ingestion

A simple sanity check that should always return events when the lab is active:

```spl
index=main sourcetype="nginx:juice-shop:json" earliest=-5m
| stats count, max(_time) as last_event
| eval last_event=strftime(last_event,"%Y-%m-%d %H:%M:%S")
```

---

## Burp Suite Setup

Burp Suite Community Edition is used as the attack platform. The simplest configuration is to use Burp's built-in Chromium browser, which is pre-configured to proxy through Burp without certificate or system-proxy adjustments.

### Workflow

1. Launch Burp: `burpsuite &`
2. Choose **Temporary project** → **Use Burp defaults** → **Start Burp**
3. Navigate to **Proxy** → **Intercept** → confirm **"Intercept is off"** (capture passively)
4. Click **Open browser** — a Chromium window opens with Burp as its proxy
5. Browse `http://10.10.10.50` to populate the site map

### Common Gotcha

> ⚠️ **If "Intercept is on", every request pauses awaiting forward action.**
> This is useful for surgical request modification, but unusable for normal browsing.
> Toggle off via Proxy → Intercept → "Intercept is on/off" button before browsing.

---

## Quick Reference — Field Names in `nginx:juice-shop:json`

| Field | Description | Use in Detections |
|-------|-------------|-------------------|
| `remote_addr` | Source IP | Primary correlation key |
| `method` | HTTP method | Filter POST/PATCH for injection endpoints |
| `uri` | Full request URI with query string | Pattern matching for path traversal, XSS |
| `path` | URI without query string | Cleaner endpoint matching |
| `query` | Query string only | Targeted query-string analysis |
| `status` | HTTP response code | Behavioural detection (401 vs 200) |
| `bytes_sent` | Response size | Anomaly detection for data exfil |
| `user_agent` | Client UA string | Bot/scanner identification |
| `referer` | HTTP Referer header | Forced-browsing detection |
| `authorization` | Authorization header | Session/JWT tracking |

> ⚠️ **POST request bodies are not captured by nginx.**
> This is the source of the most important detection gap discussed in this lab.
