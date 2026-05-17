# A02:2021 — Cryptographic Failures: Sensitive File Exposure

**Target:** OWASP Juice Shop 20.0.0 (lab deployment at `http://10.10.10.50/`)
**Date:** 18 May 2026
**Tooling:** Burp Suite Community, Splunk (via the nginx pipeline at [`../_setup/`](../_setup/))

---

## TL;DR

The `/ftp/` directory of Juice Shop exposes a mix of intentional and unintentional sensitive files via HTTP, with no authentication. Three findings:

| # | Finding | Severity | Status |
|---|---|---|---|
| 1 | Directory listing enabled on `/ftp/` | Medium | Exploited |
| 2 | Confidential acquisitions document accessible | Medium | Exploited |
| 3 | Backup file (`.bak`) filter bypassed via null byte injection | **High** | Exploited |

All three were found in a single session through Burp Suite, starting from a legitimate UI link. The third finding is the strongest portfolio piece because it demonstrates a **parser differential** vulnerability — a class of bug that appears across HTTP request smuggling, WAF bypass, JWT confusion, and many other attack surfaces.

A Splunk detection rule was built and saved that catches the null byte injection pattern in nginx logs. False positive rate is essentially zero — legitimate users never send URLs containing `%00` or `%2500`.

---

## Table of contents

- [About this challenge category](#about-this-challenge-category)
- [The discovery — finding `/ftp/`](#the-discovery--finding-ftp)
- [Finding 1: directory listing enabled](#finding-1-directory-listing-enabled)
- [Finding 2: confidential document accessible](#finding-2-confidential-document-accessible)
- [Finding 3: backup file filter bypass (parser differential)](#finding-3-backup-file-filter-bypass-parser-differential)
- [SOC detection engineering](#soc-detection-engineering)
- [What this teaches](#what-this-teaches)
- [Recommended remediation](#recommended-remediation)

---

## About this challenge category

OWASP A02:2021 — Cryptographic Failures — covers any failure to protect data in transit or at rest. The category is broader than its name suggests: it includes weak ciphers, missing TLS, unhashed passwords, and (the angle relevant here) sensitive data left in places it shouldn't be.

The Juice Shop challenge solved here — **"Forgotten Sales Channel"** — is technically about a leaked coupon backup file, but the *method* of exploitation involves a filter bypass that's not really cryptographic at all. OWASP's categorization is loose; in a strict reading, this finding sits closer to **A05 Security Misconfiguration**. The lesson the challenge teaches — *that legacy files left on production servers are dangerous* — is the A02 angle.

---

## The discovery — finding `/ftp/`

A pentester's first question on any target is "what does the application reveal about itself without me asking?"

Browsing Juice Shop as a normal user with Burp Suite intercepting:

1. Navigated to **About Us** from the main menu
2. Read the page — noticed a link to the "Terms of Use" document
3. Clicked the link

Burp's HTTP history captured the underlying request:

```
GET /ftp/legal.md HTTP/1.1
Host: 10.10.10.50
```

**This is the leak.** A normal user, clicking a normal-looking link, has just learned that the server hosts an `/ftp/` directory accessible without authentication. The application's own UI advertised the existence of an endpoint that should have been internal.

This is the pattern a SOC analyst should remember: **applications often reveal their attack surface through legitimate-looking links.** Pentesting starts with reading what the application volunteers about itself.

---

## Finding 1: directory listing enabled

### What was tested

Sent a request to the `/ftp/` endpoint without specifying a filename, to see what the server would return.

```
GET /ftp/ HTTP/1.1
Host: 10.10.10.50
```

### What was found

The server returned `HTTP/1.1 200 OK` with an HTML page titled `listing directory /ftp/`. The body contained a full enumeration of files in the directory:

```
acquisitions.md
announcement_encrypted.md
coupons_2013.md.bak
eastere.gg
encrypt.pyc
incident-support.kdbx
legal.md
package-lock.json.bak
package.json.bak
suspicious_errors.yml
quarantine/
```

### Why this matters

A production web server should never enumerate directory contents in response to an HTTP GET on a directory path. The legitimate user-facing files (`legal.md`) could have been served via specific links; there is no business reason to expose the directory index.

Once an attacker has the file list, the difficulty of finding sensitive content drops from "guess names" to "try the named files in order." Several of the files listed are explicitly suspicious:

| File | Why it's suspicious |
|---|---|
| `coupons_2013.md.bak` | `.bak` extension — implies a forgotten backup |
| `incident-support.kdbx` | KeePass password database extension — exposed credentials |
| `package-lock.json.bak` | npm dependency snapshot — leaks library versions for CVE matching |
| `suspicious_errors.yml` | Filename literally announces it's interesting |

This finding alone is reportable in any real engagement. **Severity: Medium** (information disclosure with high follow-on risk).

---

## Finding 2: confidential document accessible

### What was tested

After the directory listing revealed `acquisitions.md`, sent a direct GET request:

```
GET /ftp/acquisitions.md HTTP/1.1
Host: 10.10.10.50
```

### What was found

`HTTP/1.1 200 OK` with markdown content. The document begins:

```markdown
# Planned Acquisitions

> This document is confidential! Do not distribute!

Our company plans to acquire several competitors within the next year.
This will have a significant stock market impact as we will elaborate in
detail in the following paragraph:
```

The file's own opening sentence declares it confidential. The server served it anyway. (This solves the Juice Shop **"Confidential Document"** challenge.)

### Why this matters

The file's content has real-world parallels: M&A target lists, pending litigation memos, unannounced product roadmaps. Any of these in a production environment would be a material disclosure event.

The root cause is the same as Finding 1: the `/ftp/` directory has no access control. **Severity: Medium** (confidential information disclosure).

---

## Finding 3: backup file filter bypass (parser differential)

This is the most technically interesting finding and the one that produced the strongest SOC detection.

### Step 1 — Discover the filter exists

The directory listing showed `coupons_2013.md.bak`. The `.bak` extension is a classic indicator of forgotten backups. Sent a direct GET:

```
GET /ftp/coupons_2013.md.bak HTTP/1.1
Host: 10.10.10.50
```

Response: `HTTP/1.1 403 Forbidden`, with body:

```html
<title>Error: Only .md and .pdf files are allowed!</title>
```

**This error message is the entire vulnerability.** The server has politely told the attacker exactly how its filter works. A correctly designed filter would return a generic `403 Forbidden` with no detail. Juice Shop reveals:

- The filter exists
- It's an extension-based check
- It allows `.md` and `.pdf`

### Step 2 — Understand the filter's structure

A pentester's next thought: *"the filter is checking the URL string for an extension. It's not parsing the filename structure. There must be a way to make a URL `endsWith(".md")` while still pointing to a `.bak` file."*

This is the moment of insight that turns a 403 into a 200.

### Step 3 — Craft the bypass

The bypass uses a **null byte** (`\x00`). In low-level languages and many file system calls, a null byte terminates a string — meaning code that reads a file path will stop at the null and ignore everything after it.

The plan:

| Layer | Sees the path as | Action |
|---|---|---|
| Juice Shop's filter (string check) | `/ftp/coupons_2013.md.bak\0.md` | Last 3 chars are `.md`, allow ✓ |
| Juice Shop's file reader | `/ftp/coupons_2013.md.bak\0.md` | Passes to OS |
| OS file open call | `/ftp/coupons_2013.md.bak` | Terminates at null, opens the `.bak` |

The null byte can't be typed directly in a URL. It's URL-encoded as `%00`.

But there's a complication: the request passes through **nginx** before reaching Juice Shop. nginx URL-decodes the request once. So `%00` arriving from the client becomes a literal null byte in the path that nginx sees — and nginx rejects URLs containing null bytes as malformed.

The workaround: **double encoding**. Send `%2500`, which represents the literal characters `%`, `2`, `5`, `0`, `0`. nginx decodes once → `%00`. Juice Shop's filter and file reader interpret this differently from each other, and the parser differential is born.

Final URL crafted in Burp Repeater:

```
GET /ftp/coupons_2013.md.bak%2500.md HTTP/1.1
Host: 10.10.10.50
```

### Step 4 — Confirm the exploit

Response:

```
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 131

n<MibgC7sn
mNYS#gC7sn
o*IVigC7sn
k#pDlgC7sn
o*I]pgC7sn
n(XRvgC7sn
n(XLtgC7sn
k#*AfgC7sn
q:<IqgC7sn
pEw8ogC7sn
pesl[BgC7sn
l}6D$gC7ss
```

The body is the leaked coupon list. The filter has been bypassed. The Juice Shop "Forgotten Sales Channel" challenge is solved.

### Why this finding matters most

The vulnerability is a **parser differential** — two pieces of code interpreting the same input differently. This is one of the most important bug classes in security:

- **HTTP request smuggling** — front-end and back-end proxies disagree on where a request ends
- **JWT confusion** — verifier and parser disagree on algorithm
- **SQL injection bypass** — sanitizer and database disagree on escape syntax
- **WAF evasion** — WAF and application disagree on URL encoding semantics

When a system has multiple layers and each layer parses input independently, the gaps between their interpretations are exploitable. The `coupons_2013.md.bak%2500.md` URL is a textbook example: four layers (nginx, Juice Shop filter, Juice Shop file reader, OS) all see the path differently. The attack lives in the gap.

**Severity: High** (sensitive data exposure with an explicit security control bypass).

---

## SOC detection engineering

### What's visible in nginx logs

The full attack chain captured in the [SIEM pipeline](../_setup/) appears in Splunk:

```spl
index=main sourcetype="nginx:juice-shop:json" uri="/ftp*"
| sort _time
| table _time, remote_addr, method, uri, status, bytes_sent
```

Result:

| Time | URI | Status | Comment |
|---|---|---|---|
| T+0:00 | `/ftp/` | 200 | Directory listing accessed |
| T+0:25 | `/ftp/` | 200 | Re-loaded — building target list |
| T+5:00 | `/ftp/legal.md` | 200 | Legitimate-looking file accessed |
| T+6:00 | `/ftp/acquisitions.md` | 200 | Confidential document accessed |
| T+8:00 | `/ftp/eastere.gg` | 403 | Filter encountered |
| T+15:00 | `/ftp/coupons_2013.md.bak` | 403 | Probing for backups |
| T+22:00 | `/ftp/coupons_2013.md.bak%2500.md` | 200 | **Bypass successful** |

Unlike the A01 Mass Assignment finding (where the malicious payload was hidden in the request body), **every step of this attack chain is visible in the URI itself** — exactly the kind of data nginx logs by default.

### The detection rule

```spl
index=main sourcetype="nginx:juice-shop:json"
(uri="*%00*" OR uri="*%2500*")
| eval detection_name="A02 Null Byte Injection / Filter Bypass"
| eval severity="critical"
| table _time, remote_addr, method, uri, status, detection_name, severity
```

### Why this detection is high quality

| Property | Assessment |
|---|---|
| **False positive rate** | Essentially zero. No legitimate application uses `%00` or `%2500` in URLs. |
| **False negative rate** | Catches the most common null-byte encoding variants. A determined attacker could try `%c0%80` (overlong UTF-8 null) or other encodings; rule could be extended. |
| **Detection latency** | Fires within seconds of the attack URI being indexed. |
| **Data dependency** | Uses only the `uri` field from default nginx logs. No request body parsing required. |
| **Tuning required** | None. |

Compare this to the [A01 Mass Assignment detection](../A01-broken-access-control/) which only catches *iteration patterns*, not the attack itself. **This detection catches the actual exploit, every time, with zero noise.** That's the standard a SOC detection should aspire to.

### Saved as an alert

The detection is saved in Splunk as a scheduled alert:

- **Name:** `A02 - Null Byte Injection / Filter Bypass (Juice Shop)`
- **Schedule:** Every 10 minutes
- **Time range:** Last 15 minutes
- **Trigger:** Results > 0
- **Severity:** Critical

A second related detection — for backup file probing — can be added as a lower-severity sibling rule:

```spl
index=main sourcetype="nginx:juice-shop:json"
(uri="*.bak*" OR uri="*.old*" OR uri="*.orig*" OR uri="*.tmp*" OR uri="*.swp*")
| eval detection_name="A02 Backup File Probing"
| eval severity="high"
```

Together they catch both the *attempt* (probing for backup files) and the *success* (filter bypass via null byte).

---

## What this teaches

A few transferable lessons worth carrying into other targets:

**1. Read the application's own communication.** The filter's error message announced exactly which extensions were allowed. Verbose error messages are an information disclosure vulnerability in themselves; they're also a gift to defenders who need to understand the attack surface.

**2. Filters that check string suffixes are fragile.** Any time security depends on `endsWith()` or a regex match against a string, ask: "what if the string is constructed to defeat the check while preserving the dangerous content?" The answer is usually that there's a way.

**3. Parser differentials are everywhere.** Two layers interpreting the same input differently is a recurring pattern. When designing systems, ensure layers either agree on canonical form (normalize early) or that the layer making the security decision is the same one that consumes the value.

**4. Verbose nginx logging covers application-layer attacks too — when the attack is in the URI.** A02 file exposure attacks are URI-shaped, so default nginx logging captures them perfectly. This is the inverse of the A01 Mass Assignment scenario, where the attack was body-shaped and invisible to nginx.

**5. Burp Suite is for thinking, not just testing.** The discovery — that `.md` and `.pdf` were the allowed extensions — came from reading a 403 error message in Burp's response pane. Sitting on a single endpoint and iterating in Repeater is where pentesting actually happens; `curl` is for after you know what you want.

---

## Recommended remediation

For the application owner, in order of priority:

1. **Disable directory listing on `/ftp/`** — there is no legitimate reason for it. In nginx terms: `autoindex off;` (or equivalent in the application server).

2. **Move sensitive files off the web-accessible filesystem.** `coupons_2013.md.bak`, `incident-support.kdbx`, and similar should not be reachable via HTTP regardless of filter rules.

3. **Replace the extension-based filter with an explicit allowlist of file paths.** Instead of "allow any URL ending in `.md`", maintain a list of specific files that may be served. Defense by structure beats defense by string matching.

4. **Generic 403 responses** — the filter's response should not leak its logic. `403 Forbidden` with no body, or a generic error page.

5. **At the WAF / reverse proxy layer (nginx):** reject any URL containing encoded null bytes (`%00`, `%2500`). This is the same rule we wrote as a Splunk detection — applied as a blocking rule, it stops the attack entirely.

   Example nginx config:
   ```nginx
   if ($request_uri ~* "%00|%2500") {
       return 400;
   }
   ```

---

## Related work in this repo

- [`../_setup/juice-shop-siem-pipeline/`](../_setup/) — the nginx + Splunk pipeline that made detection of this attack possible
- [`../A01-broken-access-control/`](../A01-broken-access-control/) — first OWASP challenge writeup (Basket IDOR + Mass Assignment)
- Forthcoming: A03 Injection, A04, etc.
