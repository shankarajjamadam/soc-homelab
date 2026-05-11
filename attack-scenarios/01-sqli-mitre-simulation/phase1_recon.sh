#!/bin/bash
#==============================================================================
# SOC Lab — SQL Injection Simulation
# Phase 1: Reconnaissance (MITRE ATT&CK T1595.002)
#
# Author : Shankar
# Target : 10.10.10.10 (Windows 10 victim, Apache + DVWA)
# Source : 10.10.10.5  (Kali attacker)
#
# Logs generated:
#   ~/sqli_sim/recon_nmap.txt
#   ~/sqli_sim/recon_gobuster.txt
#   ~/sqli_sim/phase1.log         (full session transcript)
#==============================================================================

set -u

# --- Config ---
TARGET_IP="10.10.10.10"
TARGET_URL="http://${TARGET_IP}/DVWA/"
WORDLIST="/usr/share/wordlists/dirb/common.txt"
OUTDIR="${HOME}/sqli_sim"
LOGFILE="${OUTDIR}/phase1.log"

# --- Setup ---
mkdir -p "${OUTDIR}"

# Print to both screen and log file
log() {
    echo "$@" | tee -a "${LOGFILE}"
}

banner() {
    log ""
    log "=============================================================="
    log " $1"
    log "=============================================================="
}

# --- Pre-flight ---
banner "PHASE 1 - RECONNAISSANCE  |  MITRE T1595.002"
log "Start time : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "Attacker   : $(hostname) ($(hostname -I | awk '{print $1}'))"
log "Target     : ${TARGET_IP}"
log "Output dir : ${OUTDIR}"

# Verify wordlist exists before we get 2 minutes in
if [[ ! -f "${WORDLIST}" ]]; then
    log "ERROR: wordlist not found: ${WORDLIST}"
    log "Install with: sudo apt install -y dirb"
    exit 1
fi

# Verify tools are installed
for tool in nmap whatweb gobuster; do
    if ! command -v "${tool}" >/dev/null 2>&1; then
        log "ERROR: ${tool} not installed. Run: sudo apt install -y ${tool}"
        exit 1
    fi
done

# Verify target is reachable before launching scans
log ""
log "[*] Pre-flight: testing target reachability..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${TARGET_URL}")
if [[ "${HTTP_CODE}" != "200" && "${HTTP_CODE}" != "302" ]]; then
    log "ERROR: target returned HTTP ${HTTP_CODE} — aborting"
    exit 1
fi
log "[+] Target reachable (HTTP ${HTTP_CODE})"

# --- Step 1: Nmap service scan ---
banner "Step 1/3 — Nmap service/version scan"
log "Command: nmap -sV -p 80,443,3306,8080 ${TARGET_IP}"
log ""
nmap -sV -p 80,443,3306,8080 "${TARGET_IP}" \
    -oN "${OUTDIR}/recon_nmap.txt" | tee -a "${LOGFILE}"

# --- Step 2: WhatWeb tech fingerprinting ---
banner "Step 2/3 — WhatWeb fingerprint"
log "Command: whatweb ${TARGET_URL}"
log ""
whatweb "${TARGET_URL}" | tee -a "${LOGFILE}"

# --- Step 3: Gobuster directory bruteforce ---
banner "Step 3/3 — Gobuster directory enumeration"
log "Command: gobuster dir -u ${TARGET_URL} -w ${WORDLIST} -t 20"
log "Expected runtime: 1-2 minutes"
log ""
gobuster dir \
    -u "${TARGET_URL}" \
    -w "${WORDLIST}" \
    -t 20 \
    -o "${OUTDIR}/recon_gobuster.txt" 2>&1 | tee -a "${LOGFILE}"

# --- Summary ---
banner "PHASE 1 COMPLETE"
log "End time : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
log ""
log "Artifacts:"
log "  ${OUTDIR}/recon_nmap.txt"
log "  ${OUTDIR}/recon_gobuster.txt"
log "  ${OUTDIR}/phase1.log"
log ""
log "Next step: validate detection in Splunk, then run Phase 2 (manual SQLi)."
log ""
log "Splunk validation queries:"
log '  index=main sourcetype=access_combined clientip=10.10.10.5 status=404'
log '  | stats count, dc(uri) as unique_404s by clientip'
log ''
log '  index=main sourcetype=access_combined clientip=10.10.10.5'
log '  | stats count by useragent | sort -count'
