#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:04_NAV_TOC — Section index | nav,toc,index | L5-48
# MRK:04_ROOT — ROOT CHECK | root,check,db,nmap,requires | L50-58 | ⚠ no-insert-before
# MRK:04_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration,edit,pt | L60-87 | ⚠ no-insert-before; propose-before-edit
# MRK:04_LOG — COLOURS AND LOGGING | log,colours,logging | L89-134 | ⚠ no-insert-before
# MRK:04_DB — MSF DB CREDENTIALS | db,msf,credentials,tcp,peer | L136-156 | ⚠ no-insert-before; propose-before-edit
# MRK:04_ARGS — ARGUMENT PARSING | args,argument,parsing | L158-175 | ⚠ no-insert-before
# MRK:04_SCAN — SCAN EXECUTION MODEL | scan,execution,model,rc,spool | L177-244 | ⚠ no-insert-before; read-toc-first
# MRK:04_CONFIRM — SCOPE CONFIRMATION | confirm,scope,confirmation | L246-270 | ⚠ no-insert-before; propose-before-edit
# MRK:04_TARGETS — TARGET LIST ASSEMBLY | targets,target,list,assembly,host | L272-328 | ⚠ no-insert-before; read-toc-first
# MRK:04_ASSESS — PER-HOST TLS ASSESSMENT | assess,host,tls,assessment,cert | L330-788 | ⚠ no-insert-before; read-toc-first
# MRK:04_SCREENS — SCREENSHOT CAPTURE | screens,screenshot,capture,external,grabscores | L790-808 | ⚠ no-insert-before
# MRK:04_MAIN — MAIN entry point | main,entry,point | L810-884 | ⚠ no-insert-before; read-toc-first
# NAV-LEN: 12 entries | Integrity-hash: 04bf07ede641cb6e | Last-indexed: 2026-06-16T08:16:14Z

# =============================================================================
# 04_tls_scan.sh — TechGuard. [VAPT-enhanced]
# TLS/Certificate assessment — separate from main scan
# VAPT additions: CT log lookup (crt.sh), certificate key size & SAN check,
#   ALPACA attack hint, ROBOT attack check (RSA key exchange), HSTS preload
#   validation, expanded security header list, Lucky13/BEAST/POODLE explicit
#   identification, post-quantum TLS awareness note.
# Consumes: working/tls_targets.txt (produced by 03_comp_scan.sh)
# Or:       --targets <file>  or  --host <IP:PORT>
# =============================================================================
# USAGE:
#   ./04_tls_scan.sh [OPTIONS]
#
# OPTIONS:
#   --targets <file>    File with host:port entries (default: working/tls_targets.txt)
#   --host <IP:PORT>    Single target (can repeat)
#   --fast              Skip testssl; openssl + nmap ssl-enum-ciphers only
#   --output-dir <dir>  Screenshots output dir (default: screens/)
#   --grab-screens      Run GrabScores-v2.5.py after testssl (external helper; requires Playwright)
#   --dry-run           Print what would run without executing db_nmap
#
# ENVIRONMENT VARS:
#   PROJECT_NAME        MSF workspace name
#   EVIDENCE_BASE       Base evidence directory (default: evidence)
#   TESTSSL_TIMEOUT     Seconds per host for testssl (default: 300)
set -uo pipefail

# Location of this script — keep evidence inside this PT-Orc directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# MRK:04_ROOT — ROOT CHECK | root,check,db,nmap,requires | L50-58
# NAV-RULE: no-insert-before
# =============================================================================
if [[ "$EUID" -ne 0 ]] && [[ "${PTORC_ALLOW_NON_ROOT:-0}" != "1" ]]; then
    echo "[ERROR] This script must be run as root (required for db_nmap)."
    echo "        Run: sudo $0 $*"
    exit 1
fi

# =============================================================================
# MRK:04_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration,edit,pt | L60-87
# NAV-RULE: no-insert-before; propose-before-edit
# =============================================================================

# Load shared engagement config (PROJECT_NAME, MODE, …)
# shellcheck source=pt-orc.conf
[[ -f "${SCRIPT_DIR}/pt-orc.conf" ]] && source "${SCRIPT_DIR}/pt-orc.conf" \
    || echo "[WARN] pt-orc.conf not found in ${SCRIPT_DIR} — set variables in pt-orc.conf"

# Shared helpers (logging, DB access, trail/notes writer). Source AFTER pt-orc.conf
# so PROJECT_NAME / MSF_DB_* are already in env when parse_db_conf runs.
# shellcheck source=orc-common-lib.sh
[[ -f "${SCRIPT_DIR}/orc-common-lib.sh" ]] && source "${SCRIPT_DIR}/orc-common-lib.sh" \
    || echo "[WARN] orc-common-lib.sh not found — trail/notes writes will be disabled"

# Keep evidence inside the PT-Orc directory
PROJ_SLUG="${PROJECT_NAME//[^A-Za-z0-9._-]/_}"
EVIDENCE_BASE="${SCRIPT_DIR}/evidence/${PROJ_SLUG}"
TESTSSL_TIMEOUT="${TESTSSL_TIMEOUT:-300}"
SCREENS_DIR="${SCREENS_DIR:-screens}"
FAST_MODE=0
GRAB_SCREENS=0
DRY_RUN=0

TARGETS_FILE="working/${PROJ_SLUG}_tls_targets.txt"
EXTRA_HOSTS=()
AUTO_YES=0

# =============================================================================
# MRK:04_LOG — COLOURS AND LOGGING | log,colours,logging | L89-134
# NAV-RULE: no-insert-before
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

_ts()  { date +'%Y%m%d_%H%M%S'; }
_now() { date +'%Y-%m-%d %H:%M:%S'; }

SESSION_TS="$(_ts)"
EV_TS="$(_ev_ts)"
[[ "$EVIDENCE_BASE" != /* ]] && EVIDENCE_BASE="$(pwd)/${EVIDENCE_BASE}"
# Ensure evidence dirs exist under repo
mkdir -p "${EVIDENCE_BASE}/_sweep" "${SCRIPT_DIR}/working"
LOG_FILE="${EVIDENCE_BASE}/_sweep/tls_scan_${SESSION_TS}.log"
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "tls-findings" "jsonl")"
TLS_SUMMARY_FILE="${SCRIPT_DIR}/working/$(ev_fname "tls-summary" "md")"

# Colored output to stderr, plain log to file
log()      { local m="[$(_now)] $1";       echo -e "${BLUE}${m}${NC}"        >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()   { local m="[$(_now)] ✓ $1";    echo -e "${GREEN}${m}${NC}"        >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn() { local m="[$(_now)] ⚠ $1";    echo -e "${YELLOW}${m}${NC}"       >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err()  { local m="[$(_now)] ✗ $1";    echo -e "${RED}${m}${NC}"          >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_info() { local m="[$(_now)]   $1";    echo -e "${CYAN}${m}${NC}"         >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_find() { local m="[$(_now)] ★ FINDING: $1"; echo -e "${BOLD}${RED}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }

_FIND_CTR=0

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4"
    (( _FIND_CTR++ )) || true
    local fid="f-04-$(printf '%03d' "${_FIND_CTR}")"
    local ev_id="ev-04-$(printf '%03d' "${_FIND_CTR}")"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"04_tls_scan","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
        "$fid" \
        "$(echo "$title" | sed 's/"/\\"/g')" \
        "$sev" \
        "$ev_id" \
        "$(echo "$desc" | sed 's/"/\\"/g')" \
        "$(echo "$rec"  | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_find "${sev^^}: ${title}"
}

# Ownership helper removed per operator preference; leave ownership as-is

# =============================================================================
# MRK:04_DB — MSF DB CREDENTIALS | db,msf,credentials,tcp,peer | L136-156
# NAV-RULE: no-insert-before; propose-before-edit
# =============================================================================

MSF_DB_CONF="/usr/share/metasploit-framework/config/database.yml"
# Always 127.0.0.1 — Unix socket requires peer auth (fails as root). TCP uses password auth.
MSF_DB_USER="msf"; MSF_DB_NAME="msf"; MSF_DB_HOST="127.0.0.1"; MSF_DB_PORT="5432"
MSF_DB_PASS="${MSF_DB_PASS:-}"

parse_db_conf() {
    [[ -f "$MSF_DB_CONF" ]] || return
    MSF_DB_USER=$(grep -m1 'username:' "$MSF_DB_CONF" | awk '{print $2}' | tr -d "'\"" || echo "msf")
    MSF_DB_NAME=$(grep -m1 'database:'  "$MSF_DB_CONF" | awk '{print $2}' | tr -d "'\"" || echo "msf")
    MSF_DB_PORT=$(grep -m1 'port:'      "$MSF_DB_CONF" | awk '{print $2}' | tr -d "'\"" || echo "5432")
    MSF_DB_HOST="127.0.0.1"   # intentionally ignore yaml 'host:' — always TCP
    if [[ -z "${MSF_DB_PASS}" ]]; then
        MSF_DB_PASS=$(grep -m1 'password:' "$MSF_DB_CONF" | awk '{print $2}' | tr -d "'\"" 2>/dev/null || true)
    fi
    export MSF_DB_PASS
}

# =============================================================================
# MRK:04_ARGS — ARGUMENT PARSING | args,argument,parsing | L158-175
# NAV-RULE: no-insert-before
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)      TARGETS_FILE="$2"; shift 2 ;;
        --host)         EXTRA_HOSTS+=("$2"); shift 2 ;;
        --fast)         FAST_MODE=1; shift ;;
        --output-dir)   SCREENS_DIR="$2"; shift 2 ;;
        --grab-screens) GRAB_SCREENS=1; shift ;;
        --yes)          AUTO_YES=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        *) log_err "Unknown argument: $1"; exit 1 ;;
    esac
done


# =============================================================================
# MRK:04_SCAN — SCAN EXECUTION MODEL | scan,execution,model,rc,spool | L177-244
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

RC_DIR="${EVIDENCE_BASE}/_msf"

# Run db_nmap via msfconsole resource script. Spool captures full session.
# NSE output → notes table. rc file kept as evidence.
# Usage: run_rc_scan <label> <nmap_args...>
run_rc_scan() {
    local label="${1//\//_}"; shift   # sanitize: slashes in IPs must not become path separators
    if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
        log "  [DRY RUN] would run: db_nmap $*"
        return 0
    fi
    local ts; ts="$(_ts)"
    local rc_file="${RC_DIR}/${label}_${ts}.rc"
    local spool_file="${RC_DIR}/${label}_${ts}.log"

    mkdir -p "$RC_DIR"

    {
        printf 'spool %s\n'        "$spool_file"
        printf 'workspace -a %s\n'    "$PROJECT_NAME"
        printf 'db_nmap %s\n'      "$*"
        printf 'spool off\n'
        printf 'exit\n'
    } > "$rc_file"

    log "  rc_scan [${label}] → ${rc_file}"
    log "  spool  [${label}] → ${spool_file}  (tail -f to follow)"

    # </dev/null: prevents msfconsole from reading stdout as commands if rc file is missing
    PGPASSWORD="${MSF_DB_PASS:-}" msfconsole -q -r "$rc_file" </dev/null
    local rc=$?
    [[ $rc -ne 0 ]] \
        && log_warn "  msfconsole rc=${rc} [${label}] — check: ${spool_file}" \
        || log_ok   "  rc_scan done [${label}]"
    return $rc
}

# Export MSF DB via rc file.
# Usage: export_db <phase_label>
export_db() {
    local phase="${1:-tls}"
    local ts; ts="$(_ts)"
    local label="${phase}_${ts}"
    local rc_file="${RC_DIR}/export_${label}.rc"
    local spool_file="${RC_DIR}/export_${label}.log"

    mkdir -p "$RC_DIR" "${EVIDENCE_BASE}/_exports"

    {
        printf 'spool %s\n'     "$spool_file"
        printf 'workspace -a %s\n' "$PROJECT_NAME"
        printf 'hosts    -o %s/_exports/hosts_%s.csv\n'    "$EVIDENCE_BASE" "$label"
        printf 'services -o %s/_exports/services_%s.csv\n' "$EVIDENCE_BASE" "$label"
        printf 'notes    -o %s/_exports/notes_%s.csv\n'    "$EVIDENCE_BASE" "$label"
        printf 'spool off\n'
        printf 'exit\n'
    } > "$rc_file"

    log "Exporting MSF DB (${phase})..."
    PGPASSWORD="${MSF_DB_PASS:-}" msfconsole -q -r "$rc_file" </dev/null >/dev/null 2>&1 \
        && log_ok "Exported: hosts_${label}.csv | services_${label}.csv | notes_${label}.csv" \
        || log_warn "MSF export may have partial results (${phase}) — check ${spool_file}"
}

# =============================================================================
# MRK:04_CONFIRM — SCOPE CONFIRMATION | confirm,scope,confirmation | L246-270
# NAV-RULE: no-insert-before; propose-before-edit
# =============================================================================

scope_confirm() {
    local target_count="${1:-0}"
    [[ "${AUTO_YES:-0}" -eq 1 ]] && return 0
    echo ""
    echo -e "\033[1m\033[1;33m════════════════════════════════════════════════\033[0m"
    echo -e "\033[1m  SCOPE CONFIRMATION — 04_tls_scan.sh\033[0m"
    echo -e "\033[1m\033[1;33m════════════════════════════════════════════════\033[0m"
    printf "  %-22s %s\n" "Project:"    "${PROJECT_NAME}"
    printf "  %-22s %s\n" "Targets:"    "${target_count}"
    printf "  %-22s %s\n" "Mode:"       "$([ "$FAST_MODE" -eq 1 ] && echo "fast (nmap ssl-ciphers)" || echo "full (testssl)")"
    printf "  %-22s %s\n" "Targets file:" "${TARGETS_FILE}"
    printf "  %-22s %s\n" "Dry run:"    "$([ "${DRY_RUN:-0}" -eq 1 ] && echo "YES" || echo "no")"
    echo -e "\033[1m\033[1;33m════════════════════════════════════════════════\033[0m"
    echo ""
    echo -e "\033[1mConfirm authorisation is in place and scope is correct.\033[0m"
    echo -n "  Type YES to continue: "
    read -r answer
    [[ "$answer" != "YES" ]] && { echo "Aborted."; exit 0; }
    echo ""
}

# =============================================================================
# MRK:04_TARGETS — TARGET LIST ASSEMBLY | targets,target,list,assembly,host | L272-328
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

assemble_targets() {
    local targets=()

    # From file
    if [[ -f "$TARGETS_FILE" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" || "$line" == \#* ]] && continue
            targets+=("$line")
        done < "$TARGETS_FILE"
    else
        log_warn "Targets file not found: ${TARGETS_FILE}"
    fi

    # From --host args
    set +u
    for h in "${EXTRA_HOSTS[@]}"; do
        targets+=("$h")
    done
    set -u

    # Fallback: if still no targets, read the generic targets file (produced by 01_dns_recon.sh)
    # and add standard HTTPS ports. This handles the case where 03_comp_scan.sh found no open
    # ports so never wrote the TLS-specific targets file.
    set +u
    if [[ ${#targets[@]} -eq 0 ]]; then
        local fallback_file="${SCRIPT_DIR}/${PTE_TARGETS_FILE:-targets.txt}"
        if [[ -f "$fallback_file" ]]; then
            local fallback_ips=()
            while IFS= read -r line; do
                [[ -z "$line" || "$line" == \#* ]] && continue
                local ip="${line%%/*}"  # strip CIDR suffix
                fallback_ips+=("$ip")
            done < "$fallback_file"
            if [[ ${#fallback_ips[@]} -gt 0 ]]; then
                log_warn "No TLS-specific targets file — falling back to ${fallback_file} (${#fallback_ips[@]} IP(s)) with ports 443 8443 4443"
                for ip in "${fallback_ips[@]}"; do
                    for port in 443 8443 4443; do
                        targets+=("${ip}:${port}")
                    done
                done
            fi
        fi
    fi
    set -u

    # Deduplicate
    set +u
    if [[ ${#targets[@]} -gt 0 ]]; then
        printf '%s\n' "${targets[@]}" | sort -u
    fi
    set -u
}

# =============================================================================
# MRK:04_ASSESS — PER-HOST TLS ASSESSMENT | assess,host,tls,assessment,cert | L330-788
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

assess_host() {
    local target="$1"   # IP:PORT
    local ip="${target%%:*}"
    ip="${ip%%/*}"      # strip CIDR suffix if present (e.g. 10.0.0.1/32 → 10.0.0.1)
    local port="${target##*:}"
    local dir="${EVIDENCE_BASE}/${ip}"

    mkdir -p "$dir"
    log "Assessing TLS: ${target}"

    # ── 1. Certificate info (openssl) ──────────────────────────────────────
    local cert_out="${dir}/$(ev_fname "tls-cert" "txt" "${ip}:${port}")"
    {
        echo "# TLS Certificate — ${target}"
        echo "# Engagement: ${PROJECT_NAME}"
        echo "# Date/Time:  $(_now)"
        echo "---"
        timeout 15 bash -c \
            "echo | openssl s_client -connect '${ip}:${port}' \
             -servername '${ip}' -showcerts 2>/dev/null \
             | openssl x509 -noout -text 2>/dev/null" || \
            echo "[WARN] openssl handshake failed or timed out"
    } | tee "$cert_out"
    log_ok "  Certificate: ${cert_out}"

    # Quick cert facts for follow-up
    local expiry; expiry=$(grep -m1 "Not After" "$cert_out" 2>/dev/null || echo "unknown")
    local subject; subject=$(grep -m1 "Subject:" "$cert_out" 2>/dev/null || echo "unknown")
    log_info "  Subject: ${subject}"
    log_info "  Expiry:  ${expiry}"

    # ── 1b. Certificate expiry check ──────────────────────────────────────────
    local cert_pem_file="${dir}/$(ev_fname "tls-cert-pem" "pem" "${ip}:${port}")"
    if timeout 12 bash -c "echo | openssl s_client -connect '${ip}:${port}' \
        -servername '${ip}' 2>/dev/null | openssl x509" > "$cert_pem_file" 2>/dev/null \
        && [[ -s "$cert_pem_file" ]]; then
        if ! openssl x509 -noout -checkend 0 -in "$cert_pem_file" 2>/dev/null; then
            emit_finding "critical" "TLS Certificate Expired: ${target}" \
                "The TLS certificate on ${target} has passed its expiry date. Browsers and clients display a hard certificate error, causing service disruption. An expired certificate on an active service indicates a certificate management failure." \
                "Replace the certificate immediately. Automate renewal using certbot or CA-provided tooling. Implement monitoring alerts at 30-day and 7-day expiry thresholds."
        elif ! openssl x509 -noout -checkend 2592000 -in "$cert_pem_file" 2>/dev/null; then
            emit_finding "medium" "TLS Certificate Expiring Within 30 Days: ${target}" \
                "The TLS certificate on ${target} expires within 30 days. Certificate expiry will cause client-visible errors and service disruption." \
                "Renew the certificate before expiry. Implement automated renewal with certbot or equivalent, and monitoring alerts at 30-day and 7-day thresholds."
        elif ! openssl x509 -noout -checkend 7776000 -in "$cert_pem_file" 2>/dev/null; then
            emit_finding "low" "TLS Certificate Expiring Within 90 Days: ${target}" \
                "The TLS certificate on ${target} expires within 90 days. Schedule renewal to avoid service disruption." \
                "Renew the certificate before expiry. Implement automated certificate renewal and expiry monitoring."
        fi
    fi

    # ── 2. Legacy protocol checks (openssl) ────────────────────────────────
    # OpenSSL 3.x dropped SSLv2/SSLv3 entirely — test only what the local binary
    # supports. TLS 1.0/1.1 "unexpected eof" means the server refused that version,
    # which is the expected (correct) result for a hardened server.
    local legacy_out="${dir}/$(ev_fname "tls-legacy" "txt" "${ip}:${port}")"
    {
        echo "# Legacy Protocol Check — ${target}"
        echo "# Engagement: ${PROJECT_NAME}"
        echo "# Date/Time:  $(_now)"
        echo "---"
        local openssl_help; openssl_help=$(openssl s_client -help 2>&1 || true)
        for proto in ssl2 ssl3 tls1 tls1_1; do
            if ! echo "$openssl_help" | grep -q -- "-${proto}"; then
                echo "[${proto}] NOT TESTED — local OpenSSL does not support -${proto} (removed in OpenSSL 3.x)"
                continue
            fi
            local result
            result=$(timeout 8 bash -c \
                "echo | openssl s_client -connect '${ip}:${port}' \
                 -${proto} 2>&1 | grep -E 'CONNECTED|Protocol|refused|eof|alert|handshake|error' | head -3" \
                2>/dev/null || echo "timeout/connection error")
            # "unexpected eof" = server actively rejected the protocol (good)
            if echo "$result" | grep -q "unexpected eof\|alert\|refused"; then
                echo "[${proto}] REJECTED by server (expected for hardened config)"
            elif echo "$result" | grep -q "CONNECTED"; then
                echo "[${proto}] ACCEPTED — server supports this legacy protocol (FINDING)"
            else
                echo "[${proto}] ${result:-no response}"
            fi
        done
    } | tee "$legacy_out"
    log_ok "  Legacy check: ${legacy_out}"

    # Emit findings for accepted legacy protocols (< process-sub keeps _FIND_CTR in current shell)
    while IFS= read -r leg_line; do
        if [[ "$leg_line" =~ \[ssl2\].*ACCEPTED ]]; then
            emit_finding "critical" "SSLv2 Accepted: ${target}" \
                "The server at ${target} accepted an SSLv2 connection. SSLv2 has been broken since 1996 and is exploitable via the DROWN attack (CVE-2016-0800), allowing decryption of captured HTTPS sessions. Its presence indicates a severely misconfigured TLS stack." \
                "Disable SSLv2 immediately. In Apache: 'SSLProtocol all -SSLv2 -SSLv3'. In Nginx: 'ssl_protocols TLSv1.2 TLSv1.3;'. Restart the service and verify with testssl or sslyze."
        elif [[ "$leg_line" =~ \[ssl3\].*ACCEPTED ]]; then
            emit_finding "critical" "SSLv3 Accepted: ${target}" \
                "The server at ${target} accepted an SSLv3 connection. SSLv3 is vulnerable to the POODLE attack (CVE-2014-3566), allowing decryption of HTTPS traffic. RFC 7568 has prohibited SSLv3 since 2015." \
                "Disable SSLv3. Minimum supported protocol version must be TLS 1.2. In Nginx: 'ssl_protocols TLSv1.2 TLSv1.3;'. In Apache: 'SSLProtocol all -SSLv2 -SSLv3'."
        elif [[ "$leg_line" =~ \[tls1\].*ACCEPTED ]]; then
            emit_finding "medium" "TLS 1.0 Accepted: ${target}" \
                "The server at ${target} accepted a TLS 1.0 connection. TLS 1.0 is deprecated per RFC 8996 and vulnerable to BEAST (CVE-2011-3389) and Lucky13 attacks. PCI-DSS 3.2+ prohibits TLS 1.0 for cardholder data environments." \
                "Disable TLS 1.0. Set minimum protocol to TLS 1.2. In Nginx: 'ssl_protocols TLSv1.2 TLSv1.3;'. In Apache: 'SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1'."
        elif [[ "$leg_line" =~ \[tls1_1\].*ACCEPTED ]]; then
            emit_finding "medium" "TLS 1.1 Accepted: ${target}" \
                "The server at ${target} accepted a TLS 1.1 connection. TLS 1.1 is deprecated per RFC 8996 and must be disabled on all production services." \
                "Disable TLS 1.1. Set minimum protocol to TLS 1.2. In Nginx: 'ssl_protocols TLSv1.2 TLSv1.3;'. In Apache: 'SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1'."
        fi
    done < <(grep "ACCEPTED" "$legacy_out" 2>/dev/null)

    if [[ "$FAST_MODE" -eq 1 ]]; then
        # ── FAST: nmap ssl-enum-ciphers only ───────────────────────────────
        local cipher_out="${dir}/$(ev_fname "tls-nmap-ciphers" "nmap" "${ip}:${port}")"
        cipher_out="${cipher_out%.nmap}"
        run_rc_scan "ssl-ciphers_${ip}_${port}" \
             -Pn -p "$port" \
             --script "ssl-enum-ciphers,ssl-cert" \
             --script-timeout 2m \
             -T3 \
             "$ip" \
             -oA "$cipher_out"
        log_ok "  Cipher enum: ${cipher_out}.nmap"
    else
        # ── FULL: testssl (non-interactive, batch mode) ─────────────────────
        if command -v testssl &>/dev/null; then
            local testssl_html; testssl_html="${dir}/$(ev_fname "tls-testssl" "html" "${ip}:${port}")"
            local testssl_base="${testssl_html%.html}"
            log "  Running testssl on ${target} (timeout: ${TESTSSL_TIMEOUT}s)..."
            timeout "$TESTSSL_TIMEOUT" testssl \
                --htmlfile "${testssl_base}.html" \
                --jsonfile  "${testssl_base}.json" \
                --logfile   "${testssl_base}.log" \
                --severity  LOW \
                --color 0 \
                --warnings  batch \
                "${ip}:${port}" 2>&1 | tee "${testssl_base}.console.txt"
            local _tssl_rc=${PIPESTATUS[0]}
            if [[ $_tssl_rc -eq 124 ]]; then
                log_warn "  testssl timed out on ${target} (>${TESTSSL_TIMEOUT}s)"
            elif [[ $_tssl_rc -ne 0 ]] && [[ ! -s "${testssl_base}.json" ]]; then
                log_warn "  testssl failed on ${target} (rc=${_tssl_rc}) — no output produced"
            else
                log_ok "  testssl: ${testssl_base}.{html,json,log}"
            fi

            # Parse quick severity summary from JSON
            if [[ -f "${testssl_base}.json" ]] && command -v jq &>/dev/null; then
                log_info "  Severity summary:"
                jq -r '.[] | select(.severity != null) | "\(.severity): \(.id) — \(.finding)"' \
                    "${testssl_base}.json" 2>/dev/null | \
                    grep -E "CRITICAL|HIGH|MEDIUM" | head -15 | \
                    while IFS= read -r line; do log_info "    ${line}"; done
            fi

            # Emit CRITICAL/HIGH testssl findings to JSONL (capped at 10 to avoid report inflation)
            if [[ -f "${testssl_base}.json" ]]; then
                local _ts_find_ct=0 _ts_find_sup=0
                while IFS='|' read -r tsev tid tfinding; do
                    [[ -z "$tsev" ]] && continue
                    if [[ $_ts_find_ct -ge 10 ]]; then
                        (( _ts_find_sup++ )) || true
                        continue
                    fi
                    local ts_sev; [[ "$tsev" == "CRITICAL" ]] && ts_sev="critical" || ts_sev="high"
                    emit_finding "$ts_sev" "testssl [${tid}]: ${target}" \
                        "${tfinding}" \
                        "Review the full testssl report for remediation details: ${testssl_base}.{json,html,log}"
                    (( _ts_find_ct++ )) || true
                done < <(python3 -c "
import json,sys
try:
    with open(sys.argv[1]) as f:
        data=json.load(f)
    for e in data:
        sev=str(e.get('severity','')).upper()
        if sev in ('CRITICAL','HIGH'):
            print(sev+'|'+str(e.get('id',''))+'|'+str(e.get('finding','')).replace('|','/'))
except:pass
" "${testssl_base}.json" 2>/dev/null)
                [[ $_ts_find_sup -gt 0 ]] && log_info "  testssl: ${_ts_find_sup} additional HIGH/CRITICAL finding(s) suppressed (>10 cap) — see ${testssl_base}.json"
            fi
        else
            log_warn "  testssl not found — falling back to nmap ssl-enum-ciphers"
            local cipher_out="${dir}/$(ev_fname "tls-nmap-ciphers" "nmap" "${ip}:${port}")"
            cipher_out="${cipher_out%.nmap}"
            run_rc_scan "ssl-ciphers_${ip}_${port}" \
                 -Pn -p "$port" \
                 --script "ssl-enum-ciphers,ssl-cert" \
                 --script-timeout 2m \
                 -T3 \
                 "$ip" \
                 -oA "$cipher_out"
            log_ok "  Cipher enum: ${cipher_out}.nmap"
        fi
    fi

    # ── 2b. VAPT: Extended certificate analysis ────────────────────────────
    if [[ "$DRY_RUN" -eq 0 ]]; then
        local cert_ext_out="${dir}/$(ev_fname "tls-cert-ext" "txt" "${ip}:${port}")"
        {
            echo "# Extended Certificate Analysis — ${target}"
            echo "# Engagement: ${PROJECT_NAME}"
            echo "# Date/Time:  $(_now)"
            echo "---"

            # Key size and algorithm
            local key_info
            key_info=$(timeout 15 bash -c \
                "echo | openssl s_client -connect '${ip}:${port}' -servername '${ip}' 2>/dev/null \
                 | openssl x509 -noout -text 2>/dev/null \
                 | grep -E 'Public Key Algorithm|RSA Public-Key|Public-Key|Signature Algorithm'" 2>/dev/null || true)
            echo "=== Key / Algorithm ==="
            echo "${key_info:-[could not parse]}"
            # Flag weak key sizes
            if echo "$key_info" | grep -qiE "RSA Public-Key: \(102[0-4]|512|768\) bit|Public-Key: \(102[0-4]|512|768\)"; then
                echo "[FINDING] Weak RSA key size detected — below 2048 bits"
            fi

            # Subject Alternative Names
            echo ""
            echo "=== Subject Alternative Names ==="
            local sans
            sans=$(timeout 15 bash -c \
                "echo | openssl s_client -connect '${ip}:${port}' -servername '${ip}' 2>/dev/null \
                 | openssl x509 -noout -text 2>/dev/null \
                 | grep -A1 'Subject Alternative Name'" 2>/dev/null || true)
            echo "${sans:-[none found]}"

            # CT SCT presence (Certificate Transparency)
            echo ""
            echo "=== Certificate Transparency (SCT) ==="
            local sct_info
            sct_info=$(timeout 15 bash -c \
                "echo | openssl s_client -connect '${ip}:${port}' -servername '${ip}' 2>/dev/null \
                 | openssl x509 -noout -text 2>/dev/null \
                 | grep -A5 'CT Precertificate SCTs\|Signed Certificate Timestamp'" 2>/dev/null || true)
            if [[ -n "$sct_info" ]]; then
                echo "[CT] SCTs present — certificate logged in public CT logs"
                echo "$sct_info"
            else
                echo "[CT] No SCTs found in certificate — may not be in CT logs"
                echo "     Note: check crt.sh for this domain's certificates"
            fi

            # ALPACA attack hint (cross-protocol redirect check)
            echo ""
            echo "=== ALPACA Attack Assessment ==="
            echo "ALPACA (Application Layer Protocol Confusion):"
            echo "  Vulnerable if TLS cert covers multiple services (e.g. SMTP+HTTPS on same cert)"
            local cert_domain
            cert_domain=$(grep -oE "CN = [^,]+" "$cert_out" 2>/dev/null | head -1 | sed 's/CN = //' || true)
            echo "  Certificate CN: ${cert_domain:-[unknown]}"
            echo "  Manual check: confirm port ${port} does not share cert with SMTP(25/587/465) or FTP(21) services"

            # ROBOT attack hint (RSA key exchange)
            echo ""
            echo "=== ROBOT Attack Awareness ==="
            local kex_algo
            kex_algo=$(timeout 8 bash -c \
                "echo | openssl s_client -connect '${ip}:${port}' -servername '${ip}' 2>/dev/null \
                 | grep 'New, '" 2>/dev/null || true)
            if echo "$kex_algo" | grep -qiE "RSA\b"; then
                echo "[ROBOT RISK] RSA key exchange in use — server may be vulnerable to Bleichenbacher/ROBOT"
                echo "  CVE-2017-13099 / ROBOT: test with robot-detect tool for confirmation"
            else
                echo "[RSA KEX] Not detected in cipher suite — lower ROBOT risk (ECDHE/DHE preferred)"
            fi

            # Post-quantum TLS note
            echo ""
            echo "=== Post-Quantum TLS ==="
            local pq_ciphers
            pq_ciphers=$(timeout 8 bash -c \
                "echo | openssl s_client -connect '${ip}:${port}' -servername '${ip}' 2>/dev/null \
                 | grep 'Cipher    :'" 2>/dev/null || true)
            echo "Active cipher: ${pq_ciphers:-[could not determine]}"
            echo "PQ-awareness: TLS 1.3 with X25519/P-256 key exchange is quantum-safe *for confidentiality*"
            echo "  but authentication (RSA/ECDSA signatures) is still quantum-vulnerable."
            echo "  NIST PQC winners (ML-KEM/ML-DSA) not yet widely deployed. Monitor RFC 9180+ adoption."
        } | tee "$cert_ext_out"
        log_ok "  Extended cert analysis: ${cert_ext_out}"

        # Emit findings detected in extended cert analysis (grep output file — avoids subshell issue)
        if grep -q "\[FINDING\] Weak RSA key" "$cert_ext_out" 2>/dev/null; then
            local weak_key_detail; weak_key_detail=$(grep -oiE "(RSA Public-Key|Public-Key): \([0-9]+ bit\)" "$cert_ext_out" | head -1 || echo "< 2048-bit key")
            emit_finding "high" "Weak TLS Certificate Key Size: ${target}" \
                "The TLS certificate on ${target} uses a weak RSA key (${weak_key_detail}). Keys below 2048 bits are factorable with modern hardware/cloud resources, compromising the confidentiality of all sessions. NIST SP 800-131A requires a minimum of 2048-bit RSA keys." \
                "Reissue the certificate with a minimum 2048-bit RSA key (4096 recommended). Consider ECDSA P-256/P-384 for equivalent security with smaller key sizes."
        fi
        if grep -q "\[ROBOT RISK\]" "$cert_ext_out" 2>/dev/null; then
            emit_finding "medium" "RSA Key Exchange In Use — ROBOT Risk: ${target}" \
                "The TLS connection to ${target} uses RSA key exchange. Servers supporting RSA-based cipher suites may be vulnerable to the ROBOT attack (CVE-2017-13099, Bleichenbacher padding oracle), enabling passive decryption of recorded TLS sessions. RSA key exchange also provides no forward secrecy." \
                "Disable RSA key exchange cipher suites. Prefer ECDHE/DHE suites for forward secrecy. In Nginx: 'ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:!kRSA'. Confirm with the robot-detect tool (https://robotattack.org)."
        fi
        if grep -q "\[CT\] No SCTs found" "$cert_ext_out" 2>/dev/null; then
            emit_finding "info" "No Certificate Transparency SCTs Found: ${target}" \
                "No Signed Certificate Timestamps (SCTs) were embedded in the certificate served by ${target}. SCTs are required for certificates issued after April 2018 per Chrome CT policy. Absence may indicate a privately issued certificate not subject to public audit, or a TLS stack misconfiguration." \
                "Ensure the certificate includes embedded SCTs (issued by a public CA with CT support). Verify certificate inclusion at crt.sh. For internal CAs, consider OCSP stapling with CT-aware tooling."
        fi

        # CT log lookup via crt.sh (passive — no active connection to target)
        local cn_for_ct; cn_for_ct=$(grep -oE "CN = [^,]+" "$cert_out" 2>/dev/null | head -1 | sed 's/CN = //' || true)
        if [[ -n "$cn_for_ct" && "$cn_for_ct" != "[unknown]" ]]; then
            local ct_out="${dir}/$(ev_fname "tls-ct-log" "json" "${ip}:${port}")"
            log "  CT log lookup (crt.sh): ${cn_for_ct}"
            local ct_resp
            ct_resp=$(curl -s --max-time 20 \
                "https://crt.sh/?q=${cn_for_ct}&output=json" 2>/dev/null || true)
            if [[ -n "$ct_resp" ]]; then
                echo "$ct_resp" > "$ct_out" || true
                local ct_count
                ct_count=$(echo "$ct_resp" | python3 -c \
                    "import json,sys; d=json.load(sys.stdin); print(len(d))" 2>/dev/null || echo "0")
                log_info "  CT log: ${ct_count} certificate(s) found for ${cn_for_ct}"
                # Extract unique sans from CT for subdomain discovery
                local ct_sans
                ct_sans=$(echo "$ct_resp" | python3 -c \
                    "import json,sys
d=json.load(sys.stdin)
names=set()
for e in d:
    for n in e.get('name_value','').split('\n'):
        n=n.strip().lstrip('*.')
        if n: names.add(n)
print('\n'.join(sorted(names)))" 2>/dev/null || true)
                if [[ -n "$ct_sans" ]]; then
                    local ct_sans_file="${dir}/$(ev_fname "tls-ct-sans" "txt" "${ip}:${port}")"
                    echo "$ct_sans" > "$ct_sans_file"
                    log_info "  CT SANs discovered ($(echo "$ct_sans" | wc -l)): see ${ct_sans_file}"
                fi
            fi
        fi
    fi

    # ── 3. Security headers (curl) ─────────────────────────────────────────
    # Skip for known non-HTTP TLS services (mail, DB, LDAP, etc.)
    local _is_http=1
    case "$port" in
        25|110|143|465|587|993|995|636|389|3268|3269|5432|3306|27017|6379|1433)
            _is_http=0 ;;
    esac

    local headers_out="${dir}/$(ev_fname "tls-headers" "txt" "${ip}:${port}")"
    if [[ $_is_http -eq 0 ]]; then
        { echo "# HTTP Security Headers — ${target}"
          echo "# Engagement: ${PROJECT_NAME}"
          echo "# Date/Time:  $(_now)"
          echo "---"
          echo "[SKIP] Port ${port} is not an HTTP service — header check not applicable"
        } > "$headers_out"
        log_info "  Skipping HTTP header check — port ${port} is not an HTTP service"
    else
        {
            echo "# HTTP Security Headers — ${target}"
            echo "# Engagement: ${PROJECT_NAME}"
            echo "# Date/Time:  $(_now)"
            echo "---"
            curl --max-time 15 --connect-timeout 5 \
                 -sk -I "https://${ip}:${port}" 2>/dev/null || \
                curl --max-time 15 --connect-timeout 5 \
                     -I "http://${ip}:${port}" 2>/dev/null || \
                echo "[WARN] curl failed"
        } | tee "$headers_out"
    fi

    # Analyse security headers — only meaningful for HTTP services
    local sec_headers_out="${dir}/$(ev_fname "tls-sec-headers" "txt" "${ip}:${port}")"
    if [[ $_is_http -eq 0 ]]; then
        echo "[SKIP] Port ${port} is not an HTTP service — header analysis not applicable" > "$sec_headers_out"
    else
        {
            echo "# Security Headers Analysis — ${target}"
            echo "# Engagement: ${PROJECT_NAME}"
            echo "# Date/Time:  $(_now)"
            echo "---"
            local raw; raw=$(cat "$headers_out")
            local headers_to_check=(
                "Strict-Transport-Security"
                "Content-Security-Policy"
                "X-Frame-Options"
                "X-Content-Type-Options"
                "X-XSS-Protection"
                "Referrer-Policy"
                "Permissions-Policy"
                "Cross-Origin-Opener-Policy"
                "Cross-Origin-Resource-Policy"
                "Cross-Origin-Embedder-Policy"
                "Cache-Control"
                "Clear-Site-Data"
                "NEL"
            )
            local missing=()
            for h in "${headers_to_check[@]}"; do
                local val; val=$(echo "$raw" | grep -i "^${h}:" | head -1 || true)
                if [[ -n "$val" ]]; then
                    echo "  PRESENT: ${val}"
                else
                    echo "  MISSING: ${h}"
                    missing+=("$h")
                fi
            done
            echo ""
            echo "Missing headers (${#missing[@]}): ${missing[*]:-none}"

            # HSTS preload check
            local hsts_val; hsts_val=$(echo "$raw" | grep -i "^Strict-Transport-Security:" | head -1 || true)
            if [[ -n "$hsts_val" ]]; then
                echo ""
                echo "=== HSTS Analysis ==="
                echo "  Value: ${hsts_val}"
                echo "$hsts_val" | grep -qi "includeSubDomains" \
                    && echo "  [OK] includeSubDomains present" \
                    || echo "  [WARN] includeSubDomains MISSING — subdomains not covered by HSTS"
                echo "$hsts_val" | grep -qi "preload" \
                    && echo "  [OK] preload directive present" \
                    || echo "  [INFO] preload not set — not eligible for browser HSTS preload list"
                local max_age
                max_age=$(echo "$hsts_val" | grep -oE "max-age=[0-9]+" | grep -oE "[0-9]+" || echo "0")
                [[ "$max_age" -lt 31536000 ]] && \
                    echo "  [WARN] max-age=${max_age}s < 1 year (31536000s) — HSTS preload requires ≥1 year" || \
                    echo "  [OK] max-age=${max_age}s (≥1 year)"
            fi

            # Lucky13 / BEAST / POODLE indicator from legacy check output
            echo ""
            echo "=== Known TLS Attack Indicators ==="
            if [[ -f "$legacy_out" ]]; then
                echo "From legacy protocol check:"
                grep -E "ACCEPTED|REJECTED|NOT TESTED|FINDING" "$legacy_out" 2>/dev/null | sed 's/^/  /' || true
                grep -qi "tls1.*ACCEPTED\|tls1_1.*ACCEPTED" "$legacy_out" 2>/dev/null \
                    && echo "  [BEAST/LUCKY13 RISK] TLS 1.0/1.1 accepted — CBC cipher modes vulnerable to BEAST and Lucky13 timing attacks" || true
            fi
        } | tee "$sec_headers_out"

        # Emit findings for critical missing headers (outside tee to keep _FIND_CTR in current shell)
        if [[ $_is_http -eq 1 ]]; then
            if grep -q "MISSING: Strict-Transport-Security" "$sec_headers_out" 2>/dev/null; then
                emit_finding "medium" "Missing HSTS Header: ${target}" \
                    "The HTTP Strict-Transport-Security (HSTS) header is absent on ${target}. Without HSTS, clients connecting via HTTP are not automatically upgraded to HTTPS, enabling SSL stripping attacks. OWASP and NIST SP 800-52 require HSTS for all externally accessible HTTPS endpoints." \
                    "Add to server configuration: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'. Verify full HTTPS coverage before enabling preload to prevent access lockout."
            fi
            if grep -q "MISSING: X-Frame-Options" "$sec_headers_out" 2>/dev/null && \
               grep -q "MISSING: Content-Security-Policy" "$sec_headers_out" 2>/dev/null; then
                emit_finding "medium" "Missing Clickjacking Protection (X-Frame-Options + CSP): ${target}" \
                    "Neither X-Frame-Options nor Content-Security-Policy frame-ancestors is present on ${target}. This leaves the application vulnerable to clickjacking attacks, where a malicious page embeds the target in an invisible iframe and tricks users into unintentional interactions with sensitive UI elements." \
                    "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'. Also add 'Content-Security-Policy: frame-ancestors \\'none\\'' or 'frame-ancestors \\'self\\'' for defence in depth."
            fi
            if grep -q "\[WARN\] max-age=" "$sec_headers_out" 2>/dev/null; then
                emit_finding "low" "HSTS max-age Below Recommended Threshold: ${target}" \
                    "The HSTS max-age directive on ${target} is below 31536000 seconds (1 year). A short max-age means browsers periodically fall back to HTTP during the gap window, reducing SSL stripping protection." \
                    "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'. The HSTS preload list requires a minimum of 31536000 seconds."
            fi
        fi
    fi

    log_ok "  Headers: ${sec_headers_out}"

    # ── 4. Append to TLS summary ───────────────────────────────────────────
    echo "| ${ip} | ${port} | ${expiry} | ${subject} | ${dir} |" \
        >> "$TLS_SUMMARY_FILE"
}

# =============================================================================
# MRK:04_SCREENS — SCREENSHOT CAPTURE | screens,screenshot,capture,external,grabscores | L790-808
# NAV-RULE: no-insert-before
# =============================================================================

run_grab_scores() {
    if [[ "$GRAB_SCREENS" -eq 0 ]]; then return; fi
    local script_path="${SCRIPT_DIR}/GrabScores-v2.5.py"
    if [[ ! -f "$script_path" ]]; then
        log_warn "GrabScores-v2.5.py not found at ${script_path} — skipping screenshots"
        return
    fi
    mkdir -p "$SCREENS_DIR"
    log "Running GrabScores-v2.5.py..."
    python3 "$script_path" \
        --targets "$TARGETS_FILE" \
        --output-dir "$SCREENS_DIR" 2>&1 | tee "${SCRIPT_DIR}/working/$(ev_fname "tls-grab-scores" "log")"
    log_ok "Screenshots: ${SCREENS_DIR}"
}

# =============================================================================
# MRK:04_MAIN — MAIN entry point | main,entry,point | L810-884
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

main() {
    echo -e "${GREEN}"
    echo "════════════════════════════════════════════════"
    echo "  04_tls_scan.sh"
    echo "  TechGuard."
    echo "  Project: ${PROJECT_NAME}"
    echo "  Mode:    $([ "$FAST_MODE" -eq 1 ] && echo "fast" || echo "full (testssl)")"
    echo "  Findings: ${FINDINGS_FILE}"
    echo "════════════════════════════════════════════════"
    echo -e "${NC}"

    parse_db_conf

    # Trail: phase start
    local _04_t_start; _04_t_start=$(date +%s)
    trail_phase_start phase "tls" project "${PROJECT_NAME:-}" mode "${MODE:-}" session "${SESSION_TS:-$(_ts)}" ts "$(date -u +%FT%TZ)" fast_mode "${FAST_MODE:-0}" 2>/dev/null || true

    # TLS summary header
    mkdir -p "${EVIDENCE_BASE}/_sweep" "${EVIDENCE_BASE}/_exports" "${SCRIPT_DIR}/working"
    cat > "$TLS_SUMMARY_FILE" << EOF
# TLS Assessment Summary — ${PROJECT_NAME}
*Generated: $(_now) | Session: ${SESSION_TS}*

| IP | Port | Cert Expiry | Subject | Evidence Dir |
|----|------|-------------|---------|--------------|
EOF

    # Assemble and process targets
    local targets; targets="$(assemble_targets)"
    if [[ -z "$targets" ]]; then
        log_err "No targets found. Provide --targets <file> or --host <IP:PORT>"
        exit 1
    fi

    local count; count=$(echo "$targets" | wc -l | tr -d ' ')
    log "TLS targets: ${count}"
    scope_confirm "$count"

    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        assess_host "$target"
    done <<< "$targets"

    # Screenshots
    run_grab_scores

    # Finalise summary
    echo "" >> "$TLS_SUMMARY_FILE"
    echo "---" >> "$TLS_SUMMARY_FILE"
    echo "## JSONL Findings (auto-ingested by 12_report_pack.sh)" >> "$TLS_SUMMARY_FILE"
    echo "- **Count:** ${_FIND_CTR}" >> "$TLS_SUMMARY_FILE"
    echo "- **File:** \`${FINDINGS_FILE}\`" >> "$TLS_SUMMARY_FILE"
    echo "" >> "$TLS_SUMMARY_FILE"
    echo "*04_tls_scan.sh | TechGuard. | Findings: ${_FIND_CTR}*" \
        >> "$TLS_SUMMARY_FILE"

    export_db "tls"

    # Trail: phase end
    local _04_t_end; _04_t_end=$(date +%s)
    trail_phase_end phase "tls" project "${PROJECT_NAME:-}" session "${SESSION_TS:-}" duration_sec "$((_04_t_end - _04_t_start))" targets "$count" ts "$(date -u +%FT%TZ)" 2>/dev/null || true

    log_ok "Findings: ${_FIND_CTR} written to ${FINDINGS_FILE}"
    log_ok "TLS scan complete. Summary: ${TLS_SUMMARY_FILE}"
    log_ok "Evidence per host: ${EVIDENCE_BASE}/<IP>/testssl_<port>_<TS>.{html,json,log}"
}

main

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
