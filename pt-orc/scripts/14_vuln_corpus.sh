#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:14_NAV_TOC — Section index | nav,toc,index | L5-44
# - MRK:14_CONF   — CONF + LOG + AI-LIB SOURCE         | conf,log,colors,session,lib  | L45-135
# - MRK:14_ARGS   — ARGUMENT PARSING                   | args,cli,flags,depth         | L136-205
# - MRK:14_DB     — SERVICE EXTRACTION + TARGETS        | db,msf,services,targets      | L206-310
# - MRK:14_FIND   — EMIT CORPUS FINDING                 | finding,jsonl,emit,cve_ids   | L311-355
# - MRK:14_UTILS  — SHARED UTILITIES                    | utils,banner,keyword,tools   | L356-420
# - MRK:14_PROF   — PROFILE / TEST ENABLE               | profile,enable,skip,depth    | L421-465
# - MRK:14_T01    — T01 NVD CVE SWEEP                   | nvd,cve,sweep,correlate      | L466-600
# - MRK:14_T02    — T02 EXPLOITDB PoC CROSS-REFERENCE   | exploitdb,poc,searchsploit   | L601-680
# - MRK:14_T03    — T03 OSV PACKAGE LOOKUP              | osv,package,ecosystem,vuln   | L681-750
# - MRK:14_T04    — T04 NUCLEI FULL TEMPLATE SUITE      | nuclei,template,full,cve     | L751-870
# - MRK:14_MAIN   — MAIN                                | main,entry,loop,summary      | L871-980
# NAV-LEN: 11 entries | Integrity-hash: 0000000000000000 | Last-indexed: 2026-06-22T00:00:00Z

# =============================================================================
# 14_vuln_corpus.sh — Vulnerability Corpus Correlation — Step 14 of PT-Orc Suite
# TechGuard. | Mythos AI layer v1.0
# =============================================================================
# Correlates discovered services against threat-intelligence sources and runs
# the full Nuclei template suite. Produces JSONL findings consumed by step 15
# (attack chain synthesis) and step 12 (report pack).
#
#   T01  NVD API v2 CVE sweep  — correlate services to known CVEs
#   T02  ExploitDB cross-ref   — match CVE IDs to public PoC exploits
#   T03  OSV package lookup    — package-level vulns from step 8 findings
#   T04  Nuclei full suite     — 9,500+ template scan at NUCLEI_FULL_SEVERITY
#
# USAGE:
#   sudo ./14_vuln_corpus.sh [OPTIONS]
#
# OPTIONS:
#   --yes              Bypass scope prompt
#   --dry-run          Print actions; send no traffic
#   --profile <d>      standard | deep  (default: TESTING_DEPTH from conf)
#   --tier <t>         ghost | normal | loud | evasion
#   --url <u>          Inject extra target URL (repeatable; for T04 nuclei)
#   -h|--help          Show this help and exit
# =============================================================================

set -uo pipefail

# =============================================================================
# MRK:14_CONF — CONF + LOG + AI-LIB SOURCE | conf,log,colors,session,lib | L45-135
# NAV-RULE: no-insert-before
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=pt-orc.conf
[[ -f "${SCRIPT_DIR}/pt-orc.conf" ]] && source "${SCRIPT_DIR}/pt-orc.conf" \
    || echo "[WARN] pt-orc.conf not found in ${SCRIPT_DIR}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

_now() { date +'%Y-%m-%d %H:%M:%S'; }
_ts()  { date +'%Y%m%d_%H%M%S'; }
_ev_ts() { date +'%Y-%m-%d-%H-%M-%S'; }
ev_fname() {
    local name="${1:?ev_fname: name required}" ext="${2:?ev_fname: ext required}" extra="${3:-}"
    local ts; ts="${EV_TS:-$(_ev_ts)}"
    local pfx="${PROJ_SLUG:-project}-${ENGAGEMENT_PROFILE:-web}"
    if [[ -n "$extra" ]]; then
        printf '%s-%s-%s-%s.%s' "$pfx" "$name" "$extra" "$ts" "$ext"
    else
        printf '%s-%s-%s.%s' "$pfx" "$name" "$ts" "$ext"
    fi
}
find_latest_ev() {
    local pattern="${1:?find_latest_ev: pattern required}"
    local wdir="${WORKING_DIR:-${SCRIPT_DIR:-$(pwd)}/working}"
    find "$wdir" -maxdepth 1 -name "$pattern" -type f 2>/dev/null | sort -r | head -1
}
SESSION_TS="$(_ts)"
EV_TS="$(_ev_ts)"

mkdir -p working evidence

LOG_FILE="working/14_corpus_${SESSION_TS}.log"
log()      { local m="[$(_now)] $1";     echo -e "${BLUE}${m}${NC}";    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()   { local m="[$(_now)] ✓ $1";  echo -e "${GREEN}${m}${NC}";   echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn() { local m="[$(_now)] ⚠ $1";  echo -e "${YELLOW}${m}${NC}";  echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err()  { local m="[$(_now)] ✗ $1";  echo -e "${RED}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_info() { local m="[$(_now)]   $1";  echo -e "${CYAN}${m}${NC}";    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_step() {
    local n="$1" name="$2" script="$3"
    local line; line="$(printf '━%.0s' {1..52})"
    echo ""
    echo -e "${BOLD}${BLUE}${line}${NC}"
    echo -e "${BOLD}${BLUE}  STEP ${n} — ${name}${NC}"
    echo -e "${BOLD}${BLUE}  $(basename "${script:-?}")${NC}"
    echo -e "${BOLD}${BLUE}${line}${NC}"
    echo ""
    echo "[$(_now)] START step ${n} — ${name} — $(basename "${script:-?}")" >> "$LOG_FILE" 2>/dev/null || true
}

PROJ_SLUG="${PROJECT_NAME:-PT-Orc}"
PROJ_SLUG="${PROJ_SLUG//[^a-zA-Z0-9_-]/_}"

FINDINGS_FILE="${SCRIPT_DIR:-$(pwd)}/working/$(ev_fname "14-corpus-findings" "jsonl")"
EVIDENCE_BASE="evidence/${SESSION_TS}/14_corpus"
mkdir -p "$EVIDENCE_BASE"
FINDING_COUNT=0

# Source orc-ai-lib.sh — AI inference + threat-intel API helpers.
# Must be sourced after pt-orc.conf so conf vars (OLLAMA_HOST etc.) are visible.
_AI_LIB="${SCRIPT_DIR}/orc-ai-lib.sh"
if [[ -f "$_AI_LIB" ]]; then
    # shellcheck source=orc-ai-lib.sh
    source "$_AI_LIB"
    log_ok "orc-ai-lib.sh sourced"
else
    log_warn "orc-ai-lib.sh not found at ${_AI_LIB} — T01/T02/T03 will be skipped"
    # Define stubs so the rest of the script doesn't crash
    nvd_cve_lookup_keyword() { return 0; }
    exploitdb_search()       { return 0; }
    osv_lookup()             { return 0; }
fi

# =============================================================================
# MRK:14_ARGS — ARGUMENT PARSING | args,cli,flags,depth | L136-205
# NAV-RULE: no-insert-before
# =============================================================================
usage() {
    sed -n '/^# USAGE:/,/^# ====/{s/^# \?//; /^===/ q; p}' "$0"
}

AUTO_YES=0
DRY_RUN=0
DEPTH="${TESTING_DEPTH:-standard}"
TIER="${GLOBAL_TIER:-normal}"
TARGET_URLS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes)      AUTO_YES=1; shift ;;
        --dry-run)  DRY_RUN=1; shift ;;
        --profile)  DEPTH="$2"; shift 2 ;;
        --tier)     TIER="$2"; shift 2 ;;
        --url)      TARGET_URLS+=("$2"); shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *)          log_err "Unknown argument: $1"; usage; exit 1 ;;
    esac
done

# =============================================================================
# MRK:14_DB — SERVICE EXTRACTION + TARGETS | db,msf,services,targets | L206-310
# NAV-RULE: no-insert-before
# =============================================================================

# _msf_query <sql> — run a query against MSF DB. Returns empty string on failure.
_msf_query() {
    local query="$1"
    PGPASSWORD="${MSF_DB_PASS:-}" psql \
        -h 127.0.0.1 \
        -U "${MSF_DB_USER:-msf}" \
        -d "${MSF_DB_NAME:-msf}" \
        -p "${MSF_DB_PORT:-5432}" \
        -t -A -F $'\t' \
        -c "$query" 2>/dev/null
}

# _get_services — emit tab-separated rows: port TAB name TAB info TAB address
# Primary: MSF DB services table (with workspace filter)
# Fallback: parse step 7 JSONL findings for service info
_get_services() {
    local rows
    rows="$(_msf_query "
        SELECT s.port, s.name, s.info, h.address
        FROM services s
        JOIN hosts h ON s.host_id = h.id
        JOIN workspaces w ON h.workspace_id = w.id
        WHERE w.name = '${PROJECT_NAME:-}'
          AND s.info IS NOT NULL
          AND s.info != ''
        ORDER BY h.address, s.port
        LIMIT ${CORPUS_MAX_SERVICES:-50};" 2>/dev/null)" || true

    if [[ -n "$rows" ]]; then
        log_ok "MSF DB: service rows returned"
        echo "$rows"
        return 0
    fi

    log_warn "MSF DB unavailable or empty — falling back to step 7 JSONL findings"
    local f
    for f in "${SCRIPT_DIR}/working"/*_07_service_findings*.jsonl; do
        [[ -f "$f" ]] || continue
        _real_jq -r '
            select(.title != null and .description != null) |
            "0\tunknown\t" + .title + " " + (.description | split("\n")[0]) + "\t0.0.0.0"
        ' "$f" 2>/dev/null | head -"${CORPUS_MAX_SERVICES:-50}"
        return 0
    done

    log_warn "No service data found (MSF DB empty and no step 7 JSONL) — NVD/EDB sweep will be empty"
}

# _web_urls_from_db — read web URLs from MSF DB (for T04 nuclei targeting)
_web_urls_from_db() {
    local rows
    rows="$(_msf_query "
        SELECT DISTINCT
            CASE WHEN s.name IN ('https','ssl','https?') THEN 'https' ELSE 'http' END
            || '://' || COALESCE(NULLIF(ws.vhost,''), h.address) || ':' || s.port
        FROM web_sites ws
        JOIN services  s ON ws.service_id = s.id
        JOIN hosts     h ON s.host_id     = h.id
        JOIN workspaces w ON h.workspace_id = w.id
        WHERE w.name = '${PROJECT_NAME:-}'
        ORDER BY 1;" 2>/dev/null)" || true
    grep -E '^https?://' <<< "$rows" 2>/dev/null || true
}

# assemble_web_targets — populate TARGET_URLS for T04 (nuclei)
assemble_web_targets() {
    log "Assembling web targets (for nuclei, workspace: ${PROJECT_NAME:-?})"
    local db_urls
    db_urls="$(_web_urls_from_db)"
    if [[ -n "$db_urls" ]]; then
        while IFS= read -r u; do
            [[ -z "$u" ]] && continue
            TARGET_URLS+=("$u")
        done <<< "$db_urls"
        log_ok "DB: ${#TARGET_URLS[@]} web URL(s)"
    else
        log_warn "No web targets in DB — using TARGET_IPS from conf"
        local ip port proto
        for ip in ${TARGET_IPS:-}; do
            for port in 80 443 8080 8443; do
                [[ "$port" =~ ^(443|8443)$ ]] && proto="https" || proto="http"
                TARGET_URLS+=("${proto}://${ip}:${port}")
            done
        done
    fi
    local seen=() uniq=() u
    for u in "${TARGET_URLS[@]:-}"; do
        local already=0 s
        for s in "${seen[@]:-}"; do [[ "$s" == "$u" ]] && already=1 && break; done
        if [[ "$already" -eq 0 ]]; then seen+=("$u"); uniq+=("$u"); fi
    done
    TARGET_URLS=("${uniq[@]:-}")
}

scope_confirm() {
    [[ "$AUTO_YES" -eq 1 ]] && return 0
    echo ""
    echo -e "${YELLOW}${BOLD}  ╔══ VULN CORPUS — SCOPE CONFIRMATION ══╗${NC}"
    echo -e "${YELLOW}  Project  : ${PROJECT_NAME:-[unset]}${NC}"
    echo -e "${YELLOW}  Profile  : ${DEPTH}${NC}"
    echo -e "${YELLOW}  Tier     : ${TIER}${NC}"
    echo -e "${YELLOW}  Dry-run  : ${DRY_RUN}${NC}"
    echo -e "${YELLOW}${BOLD}  This step queries NVD/ExploitDB and runs nuclei against targets.${NC}"
    echo -e "${YELLOW}${BOLD}  Only proceed on systems you are authorised to test.${NC}"
    echo -e "${YELLOW}${BOLD}  ╚════════════════════════════════════════╝${NC}"
    echo ""
    read -r -p "  Confirm corpus sweep? [y/N] " _ans
    [[ "$_ans" =~ ^[Yy]$ ]] || { log "Scope not confirmed — exiting"; exit 0; }
}

# =============================================================================
# MRK:14_FIND — EMIT CORPUS FINDING | finding,jsonl,emit,cve_ids | L311-355
# NAV-RULE: no-insert-before
# =============================================================================
# emit_corpus_finding — write one JSONL record to FINDINGS_FILE.
# Args: sev title desc rec cve_ids_json [ev_tag]
# cve_ids_json must be a valid JSON array, e.g. '["CVE-2024-1234"]' or '[]'.
# The extra cve_ids field is ignored by report_pack but consumed by step 15.
emit_corpus_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4"
    local cve_ids_json="${5:-[]}" ev_tag="${6:-}"
    FINDING_COUNT=$(( FINDING_COUNT + 1 ))
    local id; id="$(printf 'f-14-corpus-%04d' "$FINDING_COUNT")"
    local ev_arr="[]"
    [[ -n "$ev_tag" ]] && ev_arr="[\"${ev_tag}\"]"
    local ts; ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    _esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r'; }
    printf '{"id":"%s","title":"%s","severity":"%s","phase":"14_vuln_corpus","evidence_ids":%s,"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":"","discovered_at":"%s","cve_ids":%s}\n' \
        "$id" "$(_esc "$title")" "$sev" "$ev_arr" \
        "$(_esc "$desc")" "$(_esc "$rec")" "$ts" "$cve_ids_json" \
        >> "$FINDINGS_FILE"
    log_ok "  [${id}] ${sev^^} — ${title}"
}

# =============================================================================
# MRK:14_UTILS — SHARED UTILITIES | utils,banner,keyword,tools | L356-420
# NAV-RULE: no-insert-before
# =============================================================================
_have() { command -v "$1" >/dev/null 2>&1; }

# _banner_to_keyword — normalise MSF DB service banner to a NVD-safe keyword.
# Input:  "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 protocol 2.0"
# Output: "OpenSSH 8.9p1"
# Handles: slash-versions (Apache/2.4.58), leading punctuation, paren groups.
_banner_to_keyword() {
    local banner="$1"
    local kw
    kw=$(echo "$banner" \
        | sed 's|/| |g'              \
        | sed 's/([^)]*)//g'         \
        | sed 's/^[^a-zA-Z0-9]*//'  \
        | sed 's/[[:space:]]\+/ /g'  \
        | awk '{print $1, $2}'       \
        | xargs)  # trim leading/trailing whitespace
    # Require at least one letter and minimum length
    if [[ "${#kw}" -lt 3 || ! "$kw" =~ [a-zA-Z] ]]; then
        return 1
    fi
    echo "$kw"
}

# _cvss_passes — returns 0 (pass) when cvss_score >= CORPUS_MIN_CVSS.
# Uses awk for portable float comparison.
_cvss_passes() {
    local score="$1"
    local min="${CORPUS_MIN_CVSS:-7.0}"
    awk -v s="$score" -v m="$min" 'BEGIN { exit (s+0 >= m+0) ? 0 : 1 }'
}

# =============================================================================
# MRK:14_PROF — PROFILE / TEST ENABLE | profile,enable,skip,depth | L421-465
# NAV-RULE: no-insert-before
# =============================================================================
declare -A _T_ENABLED

_setup_profile() {
    case "${DEPTH}" in
        baseline)
            _T_ENABLED=([T01]=0 [T02]=0 [T03]=0 [T04]=0)
            ;;
        standard)
            _T_ENABLED=([T01]=1 [T02]=1 [T03]=1 [T04]=1)
            ;;
        deep|retest|*)
            _T_ENABLED=([T01]=1 [T02]=1 [T03]=1 [T04]=1)
            ;;
    esac
    log "Profile: ${DEPTH} | Enabled: $(
        local en=(); local k
        for k in T01 T02 T03 T04; do
            [[ "${_T_ENABLED[$k]:-0}" -eq 1 ]] && en+=("$k")
        done
        echo "${en[*]:-none}"
    )"
}

_test_skip() { [[ "${_T_ENABLED[$1]:-0}" -eq 0 ]]; }

# =============================================================================
# MRK:14_T01 — T01 NVD CVE SWEEP | nvd,cve,sweep,correlate | L466-600
# NAV-RULE: no-insert-before
# =============================================================================
# Reads service banners from MSF DB (or step 7 JSONL fallback),
# normalises them to NVD-safe keywords, queries NVD API v2, and emits
# JSONL findings for CVEs scoring >= CORPUS_MIN_CVSS.
# CVE deduplication prevents the same CVE being emitted multiple times
# when it appears across different services (e.g. OpenSSL on 443 and 993).
T01_nvd_sweep() {
    log_step "14/T01" "NVD CVE Sweep" "$0"
    _test_skip T01 && { log_warn "T01 disabled for profile '${DEPTH}' — skipping"; return 0; }

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] T01: would run NVD keyword sweep against discovered services"
        return 0
    fi

    declare -A _emitted_cves=()
    local svc_count=0 cve_count=0 emit_count=0

    log "Reading services (max: ${CORPUS_MAX_SERVICES:-50})..."
    local svc_data
    svc_data="$(_get_services)" || true

    if [[ -z "$svc_data" ]]; then
        log_warn "T01: no service data available — NVD sweep skipped"
        return 0
    fi

    while IFS=$'\t' read -r port svc_name info addr; do
        [[ -z "$info" ]] && continue
        svc_count=$(( svc_count + 1 ))

        local keyword
        keyword=$(_banner_to_keyword "$info") || {
            log_info "  T01: skipping unclassifiable banner: ${info:0:60}"
            continue
        }

        log_info "  T01: ${addr}:${port} [${svc_name}] → keyword: '${keyword}'"

        local nvd_jsonl
        nvd_jsonl=$(nvd_cve_lookup_keyword "$keyword" "${CORPUS_NVD_RESULTS_PER_SERVICE:-100}") || true
        [[ -z "$nvd_jsonl" ]] && continue

        local cve_json cve_id score severity desc title
        while IFS= read -r cve_json; do
            [[ -z "$cve_json" ]] && continue
            cve_count=$(( cve_count + 1 ))

            cve_id=$(echo "$cve_json" | _real_jq -r '.cve_id // ""' 2>/dev/null)
            [[ -z "$cve_id" ]] && continue

            # Deduplicate: skip if already emitted this CVE ID
            [[ -n "${_emitted_cves[$cve_id]:-}" ]] && continue

            # CVSS filter — applied at emit time so cache stays useful
            score=$(echo "$cve_json" | _real_jq -r '.cvss_score // "0"' 2>/dev/null || echo "0")
            _cvss_passes "$score" || continue

            severity=$(echo "$cve_json" | _real_jq -r '.severity // "UNKNOWN"' 2>/dev/null)
            desc=$(echo "$cve_json" | _real_jq -r '.description // ""' 2>/dev/null)

            # Map NVD severity to suite severity
            local mapped_sev
            case "${severity^^}" in
                CRITICAL)           mapped_sev="critical" ;;
                HIGH)               mapped_sev="high" ;;
                MEDIUM)             mapped_sev="medium" ;;
                LOW)                mapped_sev="low" ;;
                *)                  mapped_sev="medium" ;;
            esac

            title="${cve_id}: ${keyword} (CVSS ${score})"
            local rec="Apply vendor patch for ${cve_id}. Verify affected version at https://nvd.nist.gov/vuln/detail/${cve_id}. Isolate service ${addr}:${port} until patched."

            emit_corpus_finding "$mapped_sev" \
                "$title" \
                "${desc:0:500} [Service: ${addr}:${port} / ${svc_name} / banner: ${info:0:80}]" \
                "$rec" \
                "[\"${cve_id}\"]"

            _emitted_cves[$cve_id]=1
            emit_count=$(( emit_count + 1 ))
        done <<< "$nvd_jsonl"

    done <<< "$svc_data"

    log_ok "T01 complete — services: ${svc_count} | CVEs seen: ${cve_count} | findings emitted: ${emit_count}"
}

# =============================================================================
# MRK:14_T02 — T02 EXPLOITDB PoC CROSS-REFERENCE | exploitdb,poc,searchsploit | L601-680
# NAV-RULE: no-insert-before
# =============================================================================
# Reads CVE IDs emitted by T01 from FINDINGS_FILE and cross-references each
# against the local ExploitDB database using searchsploit. A PoC match
# upgrades the exploitability signal for step 15 chain scoring.
T02_exploitdb_xref() {
    log_step "14/T02" "ExploitDB PoC Cross-Reference" "$0"
    _test_skip T02 && { log_warn "T02 disabled for profile '${DEPTH}' — skipping"; return 0; }

    if ! _have searchsploit; then
        log_warn "T02: searchsploit not installed (apt install exploitdb) — skipping"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] T02: would cross-reference CVE IDs with ExploitDB"
        return 0
    fi

    if [[ ! -f "$FINDINGS_FILE" ]]; then
        log_warn "T02: no corpus findings yet (T01 may have been skipped) — skipping"
        return 0
    fi

    # Collect unique CVE IDs emitted in T01
    local cve_ids=()
    while IFS= read -r cve_id; do
        [[ -z "$cve_id" ]] && continue
        cve_ids+=("$cve_id")
    done < <(_real_jq -r '.cve_ids[]?' "$FINDINGS_FILE" 2>/dev/null | sort -u)

    local total="${#cve_ids[@]}"
    if [[ "$total" -eq 0 ]]; then
        log_warn "T02: no CVE IDs in T01 findings — ExploitDB xref skipped"
        return 0
    fi
    log "T02: cross-referencing ${total} CVE ID(s) against ExploitDB..."

    declare -A _seen_edb=()
    local xref_count=0

    local cve_id
    for cve_id in "${cve_ids[@]}"; do
        local edb_out
        edb_out=$(exploitdb_search "$cve_id" 2>/dev/null) || true
        [[ -z "$edb_out" ]] && continue

        local edb_json edb_id title path
        while IFS= read -r edb_json; do
            [[ -z "$edb_json" ]] && continue
            edb_id=$(_real_jq -r '.edb_id // ""' <<< "$edb_json" 2>/dev/null)
            [[ -z "$edb_id" || -n "${_seen_edb[$edb_id]:-}" ]] && continue

            title=$(_real_jq -r '.title // ""' <<< "$edb_json" 2>/dev/null)
            path=$(_real_jq -r '.path // ""' <<< "$edb_json" 2>/dev/null)

            local ev_file="${EVIDENCE_BASE}/$(ev_fname "corpus-edb" "txt" "$edb_id")"
            {
                echo "EDB-ID:  ${edb_id}"
                echo "CVE:     ${cve_id}"
                echo "Title:   ${title}"
                echo "Path:    ${path}"
                [[ -f "$path" ]] && echo "---" && head -30 "$path" 2>/dev/null
            } > "$ev_file"

            emit_corpus_finding "high" \
                "Public PoC available: ${cve_id} (EDB-${edb_id})" \
                "ExploitDB contains a proof-of-concept exploit for ${cve_id}: \"${title}\". Public PoC availability significantly elevates exploitability and attack priority." \
                "Treat ${cve_id} as actively exploitable. Prioritise patching immediately. Review PoC at ${path} for remediation guidance." \
                "[\"${cve_id}\"]" \
                "edb_${edb_id}"

            _seen_edb[$edb_id]=1
            xref_count=$(( xref_count + 1 ))
        done <<< "$edb_out"
    done

    log_ok "T02 complete — ${total} CVE(s) searched | ${xref_count} PoC finding(s) emitted"
}

# =============================================================================
# MRK:14_T03 — T03 OSV PACKAGE LOOKUP | osv,package,ecosystem,vuln | L681-750
# NAV-RULE: no-insert-before
# =============================================================================
# Reads package/ecosystem pairs from step 8 (App/API Review) JSONL findings.
# Step 8 may emit findings with extra fields: package_name and ecosystem.
# If no such data exists, T03 logs a notice and exits cleanly — it does not
# fabricate package names from HTTP headers or service banners.
T03_osv_sweep() {
    log_step "14/T03" "OSV Package Vulnerability Lookup" "$0"
    _test_skip T03 && { log_warn "T03 disabled for profile '${DEPTH}' — skipping"; return 0; }

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] T03: would query OSV.dev for package-level vulns"
        return 0
    fi

    # Collect package/ecosystem pairs from step 8 JSONL
    local pkg_data=()
    local f
    for f in "${SCRIPT_DIR}/working"/*_08_*findings*.jsonl; do
        [[ -f "$f" ]] || continue
        while IFS='|' read -r pkg eco; do
            [[ -z "$pkg" || -z "$eco" ]] && continue
            pkg_data+=("${pkg}|${eco}")
        done < <(_real_jq -r '
            select(.package_name != null and .ecosystem != null) |
            .package_name + "|" + .ecosystem
        ' "$f" 2>/dev/null)
    done

    if [[ "${#pkg_data[@]}" -eq 0 ]]; then
        log_warn "T03: no package_name/ecosystem data in step 8 findings — OSV sweep skipped"
        log_warn "     (Step 8 must emit findings with package_name and ecosystem fields to enable T03)"
        return 0
    fi

    log "T03: querying OSV.dev for ${#pkg_data[@]} package(s)..."
    local osv_count=0

    local entry pkg eco
    for entry in "${pkg_data[@]}"; do
        pkg="${entry%%|*}"
        eco="${entry##*|}"

        local osv_jsonl
        osv_jsonl=$(osv_lookup "$pkg" "$eco" 2>/dev/null) || true
        [[ -z "$osv_jsonl" ]] && continue

        local vuln osv_id aliases summary
        while IFS= read -r vuln; do
            [[ -z "$vuln" ]] && continue
            osv_id=$(_real_jq -r '.osv_id // ""' <<< "$vuln" 2>/dev/null)
            [[ -z "$osv_id" ]] && continue
            aliases=$(_real_jq -r '(.aliases // []) | join(", ")' <<< "$vuln" 2>/dev/null)
            summary=$(_real_jq -r '.summary // ""' <<< "$vuln" 2>/dev/null)

            local cve_arr
            cve_arr=$(_real_jq -r '[ .aliases[]? | select(startswith("CVE-")) ]' <<< "$vuln" 2>/dev/null || echo "[]")

            emit_corpus_finding "high" \
                "OSV: ${osv_id} in ${pkg} (${eco})" \
                "Package ${pkg} (ecosystem: ${eco}) has a known vulnerability: ${osv_id} [${aliases}]. ${summary}" \
                "Update ${pkg} to a patched version. Check OSV advisory at https://osv.dev/vulnerability/${osv_id} for exact fixed version." \
                "$cve_arr"

            osv_count=$(( osv_count + 1 ))
        done <<< "$osv_jsonl"
    done

    log_ok "T03 complete — ${#pkg_data[@]} package(s) checked | ${osv_count} finding(s) emitted"
}

# =============================================================================
# MRK:14_T04 — T04 NUCLEI FULL TEMPLATE SUITE | nuclei,template,full,cve | L751-870
# NAV-RULE: no-insert-before
# =============================================================================
# Runs the full Nuclei template library against web targets.
# Step 13 T04 ran nuclei with a targeted severity subset; this run uses
# NUCLEI_FULL_SEVERITY (default: critical,high) with the complete template set.
# Both JSONL outputs are visible to report_pack (step 12) via *_findings*.jsonl glob.
T04_nuclei_full() {
    log_step "14/T04" "Nuclei Full Template Suite" "$0"
    _test_skip T04 && { log_warn "T04 disabled for profile '${DEPTH}' — skipping"; return 0; }

    if ! _have nuclei; then
        log_warn "T04: nuclei not installed — skipping"
        return 0
    fi

    if [[ "${#TARGET_URLS[@]}" -eq 0 ]]; then
        log_warn "T04: no web targets — nuclei full suite skipped"
        return 0
    fi

    local sev="${NUCLEI_FULL_SEVERITY:-critical,high}"
    local rate="${NUCLEI_RATE_LIMIT:-100}"
    local conc="${NUCLEI_CONCURRENCY:-10}"
    local templates_flag=""
    [[ -n "${NUCLEI_TEMPLATES_DIR:-}" ]] && templates_flag="-t ${NUCLEI_TEMPLATES_DIR}"

    # Add -stats only for deep scans (shows live progress)
    local stats_flag=""
    [[ "$DEPTH" == "deep" ]] && stats_flag="-stats"

    local nuclei_out="${EVIDENCE_BASE}/$(ev_fname "corpus-nuclei" "jsonl")"
    local target_file="${EVIDENCE_BASE}/$(ev_fname "corpus-nuclei-targets" "txt")"
    printf '%s\n' "${TARGET_URLS[@]}" > "$target_file"

    log "T04: nuclei full suite — severity: ${sev} | targets: ${#TARGET_URLS[@]} | rate: ${rate}/s"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] nuclei -l ${target_file} -severity ${sev} -rl ${rate} -c ${conc} -jsonl -o ${nuclei_out} ${templates_flag} ${stats_flag}"
        return 0
    fi

    nuclei \
        -l "$target_file" \
        -severity "$sev" \
        -rl "$rate" \
        -c "$conc" \
        -jsonl \
        -o "$nuclei_out" \
        -no-color \
        ${templates_flag:+$templates_flag} \
        ${stats_flag:+$stats_flag} \
        2>>"$LOG_FILE" || true

    if [[ ! -f "$nuclei_out" ]]; then
        log_warn "T04: nuclei produced no output file"
        return 0
    fi

    local hit_count=0
    local hit_json mapped_sev info cve_ref cve_arr template_id
    while IFS= read -r hit_json; do
        [[ -z "$hit_json" ]] && continue
        hit_count=$(( hit_count + 1 ))

        template_id=$(_real_jq -r '.template-id // .templateID // "unknown"' <<< "$hit_json" 2>/dev/null)
        local raw_sev; raw_sev=$(_real_jq -r '.info.severity // "medium"' <<< "$hit_json" 2>/dev/null)
        case "${raw_sev,,}" in
            critical) mapped_sev="critical" ;;
            high)     mapped_sev="high" ;;
            medium)   mapped_sev="medium" ;;
            low)      mapped_sev="low" ;;
            *)        mapped_sev="info" ;;
        esac

        info=$(_real_jq -r '.info.name // .template-id // "nuclei finding"' <<< "$hit_json" 2>/dev/null)
        local matched_at; matched_at=$(_real_jq -r '."matched-at" // .host // ""' <<< "$hit_json" 2>/dev/null)
        local vuln_desc; vuln_desc=$(_real_jq -r '.info.description // ""' <<< "$hit_json" 2>/dev/null)

        # Extract CVE references if present in nuclei output
        cve_ref=$(_real_jq -r '
            [ .info.classification.cve_id[]? // empty ] |
            if length > 0 then . else
              [ (.info.tags // [] | .[]? | select(startswith("cve-"))) ] |
              map(ascii_upcase)
            end
        ' <<< "$hit_json" 2>/dev/null || echo "[]")

        emit_corpus_finding "$mapped_sev" \
            "Nuclei: ${info} @ ${matched_at}" \
            "${vuln_desc:+${vuln_desc} }Template: ${template_id}. Matched at: ${matched_at}." \
            "Review nuclei finding ${template_id} at ${matched_at}. Apply vendor patches or configuration hardening as described in the template." \
            "${cve_ref:-[]}" \
            "nuclei_${template_id}"

    done < "$nuclei_out"

    log_ok "T04 complete — ${hit_count} nuclei finding(s) emitted"
}

# =============================================================================
# MRK:14_MAIN — MAIN | main,entry,loop,summary | L871-980
# NAV-RULE: no-insert-before
# =============================================================================
main() {
    log_step 14 "Vulnerability Corpus Correlation" "$0"
    log "Project    : ${PROJECT_NAME:-[unset]}"
    log "Depth      : ${DEPTH}"
    log "Tier       : ${TIER}"
    log "Dry-run    : ${DRY_RUN}"
    log "Findings   : ${FINDINGS_FILE}"

    _setup_profile

    # Assemble web targets for T04 nuclei
    assemble_web_targets

    scope_confirm

    log ""
    log "═══════════════════════════════════════════════════════"
    log "  Starting Vulnerability Corpus sweep"
    log "═══════════════════════════════════════════════════════"

    T01_nvd_sweep
    T02_exploitdb_xref
    T03_osv_sweep
    T04_nuclei_full

    # Summary
    local total_findings=0
    if [[ -f "$FINDINGS_FILE" ]]; then
        total_findings=$(wc -l < "$FINDINGS_FILE")
    fi

    local line; line="$(printf '═%.0s' {1..52})"
    echo ""
    echo -e "${BOLD}${BLUE}${line}${NC}"
    echo -e "${BOLD}${BLUE}  STEP 14 — Vulnerability Corpus — COMPLETE${NC}"
    echo -e "${BOLD}${BLUE}${line}${NC}"
    echo -e "  ${GREEN}Findings written : ${total_findings}${NC}"
    echo -e "  ${GREEN}Findings file    : ${FINDINGS_FILE}${NC}"
    echo -e "  ${GREEN}Evidence dir     : ${EVIDENCE_BASE}${NC}"
    echo -e "  ${CYAN}Next step        : 15_attack_chain.sh (AI attack path synthesis)${NC}"
    echo ""

    log "Step 14 complete — ${total_findings} corpus finding(s) in ${FINDINGS_FILE}"
}

main "$@"
