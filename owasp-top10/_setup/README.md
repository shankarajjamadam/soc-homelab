# Juice Shop SIEM Pipeline — SOC Visibility Setup

**Purpose.** Make OWASP Juice Shop traffic visible to a SIEM so that subsequent OWASP Top 10 exercises can be paired with detection engineering, not just exploitation. This is the foundation every challenge writeup in this series builds on.

**The portfolio framing.** A pentester writes *"I exploited this."* A SOC analyst writes *"I exploited this, and here's what it looked like in logs, and here's the detection that catches it."* This pipeline turns the lab from the first into the second.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Architecture](#architecture)
- [Components and decisions](#components-and-decisions)
- [Build steps](#build-steps)
- [Validation](#validation)
- [Operational notes](#operational-notes)
- [What I'd do differently](#what-id-do-differently)

---

## Why this exists

After completing the first A01 challenge (Basket IDOR enumeration) I had a working exploit but no log evidence that the attack had happened from a defender's perspective. Burp Suite recorded the attacker's view — every request and response — but that's the attacker's tool. A SOC analyst doesn't get Burp logs from an intruder; they get server-side logs. Without server-side logs the exercise is half-finished.

Juice Shop, run with its default `npm start`, prints application-level info to stdout (startup, configuration, errors) but does not emit per-request access logs. Even if it did, those logs would be ephemeral terminal output, not ingested anywhere.

There are three ways to fix this:

1. **Patch Juice Shop's compiled JavaScript** to enable Morgan request logging. Fast but invasive — modifies the application.
2. **Rebuild Juice Shop from source** with Morgan added to `server.ts`. Clean but slow and pulls in dev dependencies.
3. **Put a reverse proxy in front of Juice Shop** and log at the proxy layer. Production-realistic, untouches the app, gives a clean SIEM ingestion point.

Option 3 was chosen. This is how a real web app is typically deployed — almost always behind nginx, HAProxy, or an equivalent. Logging at the proxy layer is the standard pattern.

## Architecture

```
                  VMnet10 (10.10.10.0/24)
                            │
   ┌────────────────────────┼─────────────────────────┐
   │                        │                         │
Kali (attacker)      Juice Shop VM (10.10.10.50)   Splunk (10.10.10.10)
10.10.10.5                  │                         │
   │                        │                         │
   │   HTTP :80             │                         │
   ├───────────────────────▶│                         │
   │                        ▼                         │
   │              ┌──────────────────┐                │
   │              │  nginx :80       │                │
   │              │  (reverse proxy) │                │
   │              │                  │                │
   │              │  access.log ─────┼─── tailed by ──┼──▶ index=main
   │              │  (JSON format)   │   Splunk UF    │   sourcetype=
   │              └────────┬─────────┘   :9997        │   nginx:juice-shop:json
   │                       │ proxy_pass               │
   │                       ▼                          │
   │              ┌──────────────────┐                │
   │              │  Juice Shop      │                │
   │              │  127.0.0.1:3000  │                │
   │              │  (systemd)       │                │
   │              └──────────────────┘                │
```

**Data flow.**

1. Kali sends an HTTP request to `http://10.10.10.50/` (port 80).
2. nginx receives the request, logs one line of JSON to `/var/log/nginx/juice-shop-access.log`, and proxies the request to `http://127.0.0.1:3000`.
3. Juice Shop (running as a systemd service) handles the request and returns a response.
4. nginx returns the response to Kali.
5. Splunk Universal Forwarder, tailing the access log, ships the new line to the Splunk indexer at `10.10.10.10:9997`.
6. The Splunk indexer parses the JSON (auto-extraction based on the `:json` sourcetype suffix) and stores searchable events in `index=main`.

End-to-end latency from request to searchable event in Splunk is observed at ~10 seconds, dominated by the UF's batch interval and indexer throttling.

## Components and decisions

### Juice Shop as a systemd service (not a bash alias)

The earlier lab setup ran Juice Shop with a `juiceshop` bash alias (`cd ~/juice-shop_20.0.0 && HOST=10.10.10.50 npm start`). That works for interactive development but has three problems for SOC work:

- Logs vanish when the terminal closes.
- The process dies if the SSH session disconnects.
- The application runs as the human user account, with that user's full filesystem access — wrong principle for a service.

Replacing the alias with a systemd unit fixes all three. A dedicated `juiceshop` system user with a locked shell (`/usr/sbin/nologin`) runs the service, the install directory was moved to `/opt/juice-shop` (FHS-correct for third-party application installs), logs go to `/var/log/juice-shop/`, and the service auto-restarts on failure.

Hardening directives in the unit file (`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, `ProtectHome=true`, scoped `ReadWritePaths`) restrict the service's filesystem access to only what it needs. Not exhaustive — a production deployment would add `RestrictAddressFamilies`, `SystemCallFilter`, and seccomp — but a meaningful baseline.

See [`configs/juice-shop.service`](configs/juice-shop.service).

### nginx reverse proxy with JSON access logging

Nginx fronts Juice Shop on port 80. The site config (`configs/nginx-juice-shop.conf`) does three things:

- Logs every request as a single line of JSON to `/var/log/nginx/juice-shop-access.log`.
- Proxies all requests to `http://127.0.0.1:3000`.
- Preserves WebSocket upgrade headers (Juice Shop's chatbot uses WebSockets).

JSON was chosen over the default `combined` log format for one reason: **Splunk auto-extracts JSON fields with zero configuration**. The default nginx format requires a custom field-extraction regex on the SIEM side, which is brittle and a maintenance burden. JSON in, fields out.

The JSON format (`configs/nginx-juice-shop-log-format.conf`) captures fifteen fields. The four that matter most for SOC detection:

| Field | Why it matters |
|---|---|
| `uri` | The resource being requested. For IDOR detection: `/rest/basket/N` — the N is the target object ID. |
| `status` | HTTP response code. 401/403 reveal auth failures; 500 reveals exception-triggering input. |
| `remote_addr` | Source IP. Correlates with FortiGate/Sysmon for the broader attack picture. |
| `authorization` | The JWT token (when present) in the `Authorization` header. The subject claim inside this token, compared against the resource ID in the URI, is what enables true IDOR detection — not just volumetric "someone is enumerating" heuristics. |

`escape=json` is essential. Without it, a request containing a literal `"` character (common in SQL injection payloads) produces invalid JSON and breaks Splunk's parser.

### Splunk Universal Forwarder 10.2.3

The Splunk indexer is already running on the Windows victim (10.10.10.10) for the existing 5-phase Sysmon correlation. Adding the Juice Shop VM as another forwarder source means the IDOR work appears in the same SIEM as the endpoint detection work — one search across both attack types.

Two non-obvious config notes:

- **The forwarder user is `splunkfwd`, not `splunk`**. In UF 10.x, the binary self-corrects ownership of `/opt/splunkforwarder/` to `splunkfwd:splunkfwd` on every command invocation (visible as the "Warning: Attempting to revert SPLUNK_HOME ownership" line). This is least-privilege mode and is correct behaviour; the warning is noise.
- **Log file permissions matter**. The UF runs as `splunkfwd`. If `/var/log/nginx/juice-shop-access.log` is mode `640` owned by `root:adm` (Ubuntu's normal logrotate default), the UF cannot read it. Two fixes: add `splunkfwd` to the `adm` group, or set the access log mode to `644`. The current setup has it mode `644` because the file was first created by systemd as root, not by nginx — this will become an issue after the first logrotate cycle and will need to be addressed then. See [Operational notes](#operational-notes).

### Sourcetype: `nginx:juice-shop:json`

Splunk's `:json` suffix is a convention, not a rule, but it triggers auto-recognition of JSON-formatted events. The full sourcetype is namespaced `nginx:juice-shop:json` so Splunk searches can target this data specifically and not collide with other nginx instances added later.

### Index: `main` (with a planned migration)

Currently sending to `index=main`. The cleaner long-term choice is a dedicated `juiceshop` index, which keeps retention policies, ACLs, and search performance independent. Creating a new index requires changes on the Windows indexer (not on the Linux forwarder side), which was out of scope for this session. **Migration is a follow-up task** — see [What I'd do differently](#what-id-do-differently).

## Build steps

These commands assume Ubuntu 22.04+ on the Juice Shop VM, with Juice Shop 20.0.0 already installed at `~/juice-shop_20.0.0` from prior lab work.

### 1. Create the service user

```bash
sudo useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/juiceshop --create-home juiceshop
```

### 2. Move Juice Shop to /opt and chown

```bash
sudo mv ~/juice-shop_20.0.0 /opt/juice-shop
sudo chown -R juiceshop:juiceshop /opt/juice-shop
```

### 3. Create the log directory

```bash
sudo mkdir -p /var/log/juice-shop
sudo chown juiceshop:juiceshop /var/log/juice-shop
sudo chmod 755 /var/log/juice-shop
```

### 4. Install the systemd unit

Copy [`configs/juice-shop.service`](configs/juice-shop.service) to `/etc/systemd/system/juice-shop.service`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now juice-shop.service
sudo systemctl status juice-shop.service
```

Verify `Active: active (running)`.

### 5. Install nginx and disable the default site

```bash
sudo apt update && sudo apt install -y nginx
sudo rm /etc/nginx/sites-enabled/default
```

**Note:** `rm` the symlink, not `mv`. nginx loads every file in `sites-enabled/` regardless of extension — renaming to `default.disabled` does not actually disable it and produces a `duplicate default server` error when our config is added.

### 6. Install the nginx configs

Copy:
- [`configs/nginx-juice-shop-log-format.conf`](configs/nginx-juice-shop-log-format.conf) → `/etc/nginx/conf.d/juice-shop-log-format.conf`
- [`configs/nginx-juice-shop.conf`](configs/nginx-juice-shop.conf) → `/etc/nginx/sites-available/juice-shop`

Enable the site:
```bash
sudo ln -sf /etc/nginx/sites-available/juice-shop /etc/nginx/sites-enabled/juice-shop
sudo nginx -t
sudo systemctl reload nginx
```

### 7. Install Splunk Universal Forwarder

```bash
cd /tmp
wget -O splunkforwarder.deb "https://download.splunk.com/products/universalforwarder/releases/10.2.3/linux/splunkforwarder-10.2.3-4d61cf8a5c0c-linux-amd64.deb"
sudo dpkg -i splunkforwarder.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license --answer-yes
# Create admin account when prompted
```

### 8. Configure the UF

```bash
sudo /opt/splunkforwarder/bin/splunk add forward-server 10.10.10.10:9997 -auth admin:PASSWORD
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/nginx/juice-shop-access.log \
  -sourcetype nginx:juice-shop:json \
  -index main \
  -auth admin:PASSWORD
sudo /opt/splunkforwarder/bin/splunk restart
```

### 9. Add `splunkfwd` to the `adm` group (logrotate compatibility)

Required so the UF can still read the nginx access log after the first daily logrotate. See [Operational notes](#logrotate-compatibility-applied-proactively) for context.

```bash
sudo usermod -a -G adm splunkfwd
sudo /opt/splunkforwarder/bin/splunk restart
```

### 10. Enable UF auto-start on boot

```bash
sudo /opt/splunkforwarder/bin/splunk enable boot-start -systemd-managed 1
```

## Validation

After the build, three checks confirm the pipeline is working end-to-end.

### Check 1 — nginx receives requests and writes JSON

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://10.10.10.50/
sudo tail -1 /var/log/nginx/juice-shop-access.log
```

Expected: HTTP `200`, and a JSON line in the log with all fifteen fields populated.

### Check 2 — UF has an active forward connection

```bash
sudo /opt/splunkforwarder/bin/splunk list forward-server -auth admin:PASSWORD
```

Expected:
```
Active forwards:
        10.10.10.10:9997
Configured but inactive forwards:
        None
```

If `10.10.10.10:9997` appears under "Configured but inactive", the indexer is not reachable — check network connectivity and that Splunk receiving is enabled on port 9997.

### Check 3 — Events appear in Splunk with parsed fields

In Splunk Search:
```spl
index=main sourcetype="nginx:juice-shop:json" earliest=-5m
```

Expected: events appear within ~10 seconds of the curl request, with auto-extracted fields visible in the "Interesting Fields" sidebar (`method`, `uri`, `status`, `remote_addr`, `user_agent`, `authorization`, `bytes_sent`, `request_time`, etc.).

## Operational notes

### Logrotate compatibility (applied proactively)

Ubuntu's default `/etc/logrotate.d/nginx` rotates `/var/log/nginx/*.log` daily, gzips the rotated file, and creates the new log with mode `640` owned by `www-data:adm`. The Splunk UF runs as `splunkfwd`, which by default is not in `adm`. Without intervention, the UF would silently lose read access to the new log file after the first rotation.

**Applied fix:** add `splunkfwd` to the `adm` group during initial build:
```bash
sudo usermod -a -G adm splunkfwd
sudo /opt/splunkforwarder/bin/splunk restart
```

Verify with:
```bash
groups splunkfwd
# Expected: splunkfwd : splunkfwd adm
```

Applied proactively to avoid a silent indexing-gap incident at the first daily rotation.

### Port 3000 is still externally accessible

The systemd unit sets `HOST=127.0.0.1`, intending to bind Juice Shop to loopback only. **Juice Shop ignores this** — `HOST` is used internally for self-referencing URLs, not for the listen address. The actual listen is hardcoded to `0.0.0.0:3000`.

Consequence: an attacker on the same network segment can bypass nginx by hitting `http://10.10.10.50:3000/` directly, and those requests will not be logged.

For the current lab work this is acceptable — all attacks are run intentionally through nginx on port 80. For a hardened setup, either:

- Add a `ufw deny 3000/tcp` rule, leaving loopback unaffected.
- Patch Juice Shop's `app.listen()` call to bind to `127.0.0.1` explicitly.

Deferred to a future hardening session.

### FortiGate syslog filter resets on reboot

Documented separately in the main lab handover. Not specific to this pipeline but worth flagging: same-subnet traffic between Kali (10.10.10.5) and Juice Shop (10.10.10.50) does not pass through FortiGate, so attacks are visible only via this nginx pipeline, not via firewall logs.

### Splunk UF version vs indexer version

UF is 10.2.3. The indexer on Windows is older (installed earlier in lab build, version not re-verified). Splunk supports forward-compatibility within reason, but if events stop arriving cleanly after a UF upgrade, indexer version is the first thing to check.

## What I'd do differently

A few choices that worked but are worth revisiting:

**1. Dedicated Splunk index instead of `main`.** Sending to `index=main` works but means the Juice Shop data sits alongside everything else (Sysmon, FortiGate). A dedicated `juiceshop` index would give independent retention, cleaner search scoping, and easier RBAC if this were a multi-team environment. Requires `indexes.conf` changes on the Windows indexer side.

**2. The `default_server` rename trap.** I renamed `/etc/nginx/sites-enabled/default` to `default.disabled` thinking nginx would ignore the new extension. It doesn't — nginx loads every file in `sites-enabled/` regardless of name. The fix is `rm` (or unlinking the symlink), not rename. Cost about 5 minutes to diagnose.

**3. The `HOST` environment variable assumption.** I assumed Juice Shop's `HOST` env var controlled its bind address. It doesn't. A quick `ss -tlnp | grep 3000` after the change immediately revealed the wildcard bind. Lesson: verify the bind address with `ss`, never assume an environment variable means what you think it means.

**4. No ELK-side equivalent yet.** This pipeline only feeds Splunk. The lab also has ELK (10.10.10.30) which already receives Winlogbeat from Windows. Adding a Filebeat input on the Juice Shop VM (pointed at the same access log) would give parity across both SIEMs and enable side-by-side detection comparison. Filed under "next session."

**5. No TLS on UF → indexer link.** Splunk UF supports TLS-encrypted forwarding, configured via `outputs.conf` and certificates on both sides. The current setup is plaintext TCP/9997. Acceptable for a lab; would be unacceptable in production. Re-keying for TLS is a 15-minute job whenever it becomes priority.

---

## Related work in this repo

- [`../A01-broken-access-control/`](../A01-broken-access-control/) — first OWASP challenge writeup (basket IDOR). Pre-dates this pipeline; the detection-engineering section will be added once this pipeline is exercised against the exploit.
- Forthcoming: A02 Cryptographic Failures, A03 Injection, etc. — each will reference this pipeline as the SOC visibility substrate.
