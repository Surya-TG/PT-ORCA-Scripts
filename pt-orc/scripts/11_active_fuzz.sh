#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:11_NAV_TOC — Section index | nav,toc,index | L5-43
# - MRK:11_CONF   — CONF + LOG                   | conf,log,colors,session  | L44-130
# - MRK:11_ARGS   — ARGUMENT PARSING              | args,cli,flags,depth     | L131-215
# - MRK:11_DB     — MSF DB HELPERS                | db,msf,web,targets       | L216-265
# - MRK:11_SCOPE  — SCOPE CONFIRM + TARGETS       | scope,targets,assembly   | L266-335
# - MRK:11_FIND   — EMIT FINDING                  | finding,jsonl,emit       | L336-375
# - MRK:11_UTILS  — SHARED UTILITIES              | utils,curl,proxy,tools   | L376-445
# - MRK:11_PROF   — PROFILE / TEST ENABLE         | profile,enable,skip,tier | L446-490
# - MRK:11_T01    — T01 BURP SUITE REST API       | burp,active,scan,rest    | L491-730
# - MRK:11_T02    — T02 SQLMAP SQL INJECTION       | sqlmap,sqli,injection    | L731-920
# - MRK:11_T03    — T03 DALFOX XSS FUZZER         | dalfox,xss,blind,dom     | L921-1060
# - MRK:11_T04    — T04 NUCLEI TEMPLATE SCAN      | nuclei,template,cve      | L1061-1220
# - MRK:11_T05    — T05 COMMIX COMMAND INJECTION   | commix,cmdi,os           | L1221-1330
# - MRK:11_T06    — T06 ARJUN HIDDEN PARAMS       | arjun,hidden,params      | L1331-1440
# - MRK:11_T07    — T07 TPLMAP SSTI               | tplmap,ssti,template     | L1441-1530
# - MRK:11_T08    — T08 GHAURI ADVANCED SQLI      | ghauri,sqli,second-order | L1531-1640
# - MRK:11_T09    — T09 FFUF PAYLOAD FUZZING      | ffuf,lfi,rfi,traversal   | L1641-1770
# - MRK:11_T10    — T10 CRLFUZZ CRLF INJECTION    | crlf,header,injection    | L1771-1860
# - MRK:11_TRUN   — PER-TARGET DISPATCHER         | dispatch,run,test        | L1861-1930
# - MRK:11_MAIN   — MAIN                          | main,entry,loop          | L1931-2060
# NAV-LEN: 20 entries | Integrity-hash: d4e9f2a8c1b7 | Last-indexed: 2026-06-18T00:00:00Z

# =============================================================================
# 13_active_fuzz.sh — Active Fuzzing & Scanning — Step 11 of PT-Orc Suite
# TechGuard.
# =============================================================================
# Runs advanced active fuzzing across all discovered web targets:
#   T01  Burp Suite Professional REST API — automated crawl-and-audit
#   T02  sqlmap  — multi-vector SQL injection (GET/POST/cookie/header)
#   T03  dalfox  — reflected, DOM, and blind XSS fuzzing
#   T04  nuclei  — community template CVE/misconfig scan
#   T05  commix  — OS command injection testing
#   T06  arjun   — hidden HTTP parameter discovery + fuzz
#   T07  tplmap  — server-side template injection (SSTI)
#   T08  ghauri  — second-order and advanced SQL injection
#   T09  ffuf    — payload fuzzing (LFI / path traversal / RFI)
#   T10  crlfuzz — CRLF / header injection
#
# USAGE:
#   sudo ./13_active_fuzz.sh [OPTIONS]
#
# OPTIONS:
#   --yes               Bypass scope prompt
#   --dry-run           Print actions; send no traffic
#   --profile <d>       quick | standard | deep  (default: TESTING_DEPTH from conf)
#   --tier <t>          ghost | normal | loud | evasion
#   --url <u>           Inject extra target URL (repeatable; stacks with DB targets)
#   --burp-key <k>      Override BURP_API_KEY from conf
#   --cookie <c>        Session cookie string forwarded to all tools
#   --proxy <p>         HTTP proxy (e.g. http://127.0.0.1:8080)
#   -h|--help           Show this help and exit
# =============================================================================

set -uo pipefail

# =============================================================================
# MRK:11_CONF — CONF + LOG | conf,log,colors,session | L44-130
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

LOG_FILE="working/11_fuzz_${SESSION_TS}.log"
log()      { local m="[$(_now)] $1";     echo -e "${BLUE}${m}${NC}";    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()   { local m="[$(_now)] ✓ $1";  echo -e "${GREEN}${m}${NC}";   echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn() { local m="[$(_now)] ⚠ $1";  echo -e "${YELLOW}${m}${NC}";  echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err()  { local m="[$(_now)] ✗ $1";  echo -e "${RED}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
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

# Sanitise PROJECT_NAME → filesystem-safe slug
PROJ_SLUG="${PROJECT_NAME:-PT-Orc}"
PROJ_SLUG="${PROJ_SLUG//[^a-zA-Z0-9_-]/_}"

FINDINGS_FILE="${SCRIPT_DIR:-$(pwd)}/working/$(ev_fname "13-fuzz-findings" "jsonl")"
EVIDENCE_BASE="evidence/${SESSION_TS}/11_fuzz"
mkdir -p "$EVIDENCE_BASE"
FINDING_COUNT=0

# =============================================================================
# MRK:11_ARGS — ARGUMENT PARSING | args,cli,flags,depth | L131-215
# NAV-RULE: no-insert-before
# =============================================================================
usage() {
    grep '^# USAGE:' -A 20 "$0" | sed 's/^# \?//'
}

AUTO_YES=0
DRY_RUN=0
DEPTH="${TESTING_DEPTH:-standard}"
TIER="${GLOBAL_TIER:-normal}"
TARGET_URLS=()
OPT_BURP_KEY="${BURP_API_KEY:-}"
OPT_FUZZ_COOKIE="${FUZZ_COOKIE:-}"
OPT_FUZZ_PROXY="${FUZZ_PROXY:-}"
OPT_DALFOX_BLIND="${DALFOX_BLIND_URL:-}"
OPT_DALFOX_TIMEOUT="${DALFOX_TIMEOUT:-10}"
OPT_SQLMAP_LEVEL="${SQLMAP_LEVEL:-3}"
OPT_SQLMAP_RISK="${SQLMAP_RISK:-2}"
OPT_SQLMAP_TAMPER="${SQLMAP_TAMPER:-}"
OPT_NUCLEI_SEV="${NUCLEI_SEVERITY:-critical,high,medium}"
OPT_NUCLEI_TEMPLATES="${NUCLEI_TEMPLATES_DIR:-}"
OPT_BURP_URL="${BURP_API_URL:-http://127.0.0.1:1337}"
OPT_BURP_SCAN_CONFIG="${BURP_SCAN_CONFIG:-Crawl and Audit - Balanced}"
FUZZ_TIMEOUT_VAL="${FUZZ_TIMEOUT:-3600}"
FUZZ_THREADS_VAL="${FUZZ_THREADS:-5}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes)          AUTO_YES=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        --profile)      DEPTH="$2"; shift 2 ;;
        --tier)         TIER="$2"; shift 2 ;;
        --url)          TARGET_URLS+=("$2"); shift 2 ;;
        --burp-key)     OPT_BURP_KEY="$2"; shift 2 ;;
        --cookie)       OPT_FUZZ_COOKIE="$2"; shift 2 ;;
        --proxy)        OPT_FUZZ_PROXY="$2"; shift 2 ;;
        -h|--help)      usage; exit 0 ;;
        *)              log_err "Unknown argument: $1"; usage; exit 1 ;;
    esac
done

# =============================================================================
# MRK:11_DB — MSF DB HELPERS | db,msf,web,targets | L216-265
# NAV-RULE: no-insert-before
# =============================================================================
_msf_query() {
    local query="$1"
    PGPASSWORD="${MSF_DB_PASS:-}" psql \
        -h 127.0.0.1 \
        -U "${MSF_DB_USER:-msf}" \
        -d "${MSF_DB_NAME:-msf}" \
        -p "${MSF_DB_PORT:-5432}" \
        -t -A \
        -c "$query" 2>/dev/null
}

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

# =============================================================================
# MRK:11_SCOPE — SCOPE CONFIRM + TARGETS | scope,targets,assembly | L266-335
# NAV-RULE: no-insert-before
# =============================================================================
assemble_targets() {
    local db_urls fallback_urls
    log "Assembling web targets from MSF DB (workspace: ${PROJECT_NAME:-?})"
    db_urls="$(_web_urls_from_db)"
    if [[ -n "$db_urls" ]]; then
        while IFS= read -r u; do
            [[ -z "$u" ]] && continue
            TARGET_URLS+=("$u")
        done <<< "$db_urls"
        log_ok "DB: ${#TARGET_URLS[@]} URL(s) found"
    else
        log_warn "No web targets in MSF DB — falling back to TARGET_IPS + common ports"
        local ip port proto
        for ip in ${TARGET_IPS:-}; do
            for port in 80 443 8080 8443 8888; do
                [[ "$port" =~ ^(443|8443)$ ]] && proto="https" || proto="http"
                TARGET_URLS+=("${proto}://${ip}:${port}")
            done
        done
    fi

    # Deduplicate
    local seen=()
    local uniq=()
    local u
    for u in "${TARGET_URLS[@]}"; do
        local already=0
        local s
        for s in "${seen[@]:-}"; do [[ "$s" == "$u" ]] && already=1 && break; done
        if [[ "$already" -eq 0 ]]; then
            seen+=("$u")
            uniq+=("$u")
        fi
    done
    TARGET_URLS=("${uniq[@]}")
}

scope_confirm() {
    [[ "$AUTO_YES" -eq 1 ]] && return 0
    echo ""
    echo -e "${YELLOW}${BOLD}  ╔══ ACTIVE FUZZ — SCOPE CONFIRMATION ══╗${NC}"
    echo -e "${YELLOW}  Project : ${PROJECT_NAME:-[unset]}${NC}"
    echo -e "${YELLOW}  Targets : ${#TARGET_URLS[@]} URL(s)${NC}"
    local u
    for u in "${TARGET_URLS[@]}"; do echo -e "${YELLOW}    • ${u}${NC}"; done
    echo -e "${YELLOW}  Profile : ${DEPTH}${NC}"
    echo -e "${YELLOW}  Tier    : ${TIER}${NC}"
    echo -e "${YELLOW}${BOLD}  WARNING: This step sends active attack payloads.${NC}"
    echo -e "${YELLOW}${BOLD}  Only proceed on systems you are authorised to test.${NC}"
    echo -e "${YELLOW}${BOLD}  ╚═══════════════════════════════════════╝${NC}"
    echo ""
    read -r -p "  Confirm active fuzz against these targets? [y/N] " _ans
    [[ "$_ans" =~ ^[Yy]$ ]] || { log "Scope not confirmed — exiting"; exit 0; }
}

# =============================================================================
# MRK:11_FIND — EMIT FINDING | finding,jsonl,emit | L336-375
# NAV-RULE: no-insert-before
# =============================================================================
emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="${5:-}"
    FINDING_COUNT=$(( FINDING_COUNT + 1 ))
    local id; id="$(printf 'f-13-fuzz-%04d' "$FINDING_COUNT")"
    local ev_arr="[]"
    [[ -n "$ev_tag" ]] && ev_arr="[\"${ev_tag}\"]"
    local ts; ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    # Escape JSON-unsafe characters in text fields
    local _esc
    _esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r'; }
    printf '{"id":"%s","title":"%s","severity":"%s","phase":"11_active_fuzz","evidence_ids":%s,"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":"","discovered_at":"%s"}\n' \
        "$id" "$(_esc "$title")" "$sev" "$ev_arr" \
        "$(_esc "$desc")" "$(_esc "$rec")" "$ts" \
        >> "$FINDINGS_FILE"
    log_ok "  [${id}] ${sev^^} — ${title}"
}

# =============================================================================
# MRK:11_UTILS — SHARED UTILITIES | utils,curl,proxy,tools | L376-445
# NAV-RULE: no-insert-before
# =============================================================================
_have() { command -v "$1" > /dev/null 2>&1; }

_slug() { printf '%s' "$1" | tr -cs 'a-zA-Z0-9' '_' | sed 's/__*/_/g; s/^_*//; s/_*$//'; }

_strip_html() {
    sed 's/<[^>]*>//g; s/&lt;/</g; s/&gt;/>/g; s/&amp;/\&/g; s/&#[0-9]*;//g' <<< "$1"
}

_tier_delay() {
    case "$TIER" in
        ghost)   echo 2 ;;
        evasion) echo 3 ;;
        loud)    echo 0 ;;
        *)       echo 1 ;;
    esac
}

# Build common HTTP flag fragments for curl
_curl_args() {
    local args=()
    [[ -n "$OPT_FUZZ_COOKIE" ]] && args+=(-H "Cookie: ${OPT_FUZZ_COOKIE}")
    [[ -n "$OPT_FUZZ_PROXY"  ]] && args+=(-x "$OPT_FUZZ_PROXY")
    args+=(-k --max-time 30 -s)
    printf '%s\n' "${args[@]}"
}

# Normalise Burp/tool severity → suite severity
_norm_sev() {
    case "${1,,}" in
        critical|info_high) echo "critical" ;;
        high)               echo "high" ;;
        medium)             echo "medium" ;;
        low)                echo "low" ;;
        *)                  echo "info" ;;
    esac
}

# Write raw tool output to evidence dir and echo the path
_save_evidence() {
    local tag="$1" ext="${2:-txt}"
    local f="${EVIDENCE_BASE}/$(ev_fname "fuzz-${tag}" "${ext}")"
    cat > "$f"
    echo "$f"
}

# =============================================================================
# MRK:11_PROF — PROFILE / TEST ENABLE | profile,enable,skip,tier | L446-490
# NAV-RULE: no-insert-before
# =============================================================================
declare -A _T_ENABLED

_setup_profile() {
    case "$DEPTH" in
        quick)
            # Fast automated tools only — Burp headless + nuclei templates
            _T_ENABLED=([T01]=1 [T02]=0 [T03]=0 [T04]=1 [T05]=0 [T06]=0 [T07]=0 [T08]=0 [T09]=0 [T10]=0)
            ;;
        standard)
            # Core web attack classes — skip slow/niche (arjun,tplmap,ghauri)
            _T_ENABLED=([T01]=1 [T02]=1 [T03]=1 [T04]=1 [T05]=1 [T06]=0 [T07]=0 [T08]=0 [T09]=1 [T10]=1)
            ;;
        deep|*)
            _T_ENABLED=([T01]=1 [T02]=1 [T03]=1 [T04]=1 [T05]=1 [T06]=1 [T07]=1 [T08]=1 [T09]=1 [T10]=1)
            ;;
    esac
    log "Profile: ${DEPTH} | Enabled tests: $(
        local en=()
        local k
        for k in T01 T02 T03 T04 T05 T06 T07 T08 T09 T10; do
            [[ "${_T_ENABLED[$k]:-0}" -eq 1 ]] && en+=("$k")
        done
        echo "${en[*]}"
    )"
}

# Returns 0 (skip) when test is disabled; non-zero (run) when enabled
_test_skip() { [[ "${_T_ENABLED[$1]:-0}" -eq 0 ]]; }

# =============================================================================
# MRK:11_T01 — T01 BURP SUITE REST API | burp,active,scan,rest | L491-730
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================
# Burp Suite Professional REST API active crawl-and-audit.
# Supports both v0.1 (Burp ≤2023.3) and v1 (Burp ≥2023.4).
# Polls until scan completes or FUZZ_TIMEOUT expires, then maps issue_events
# to JSONL findings.
# =============================================================================
test_T01_burp_scan() {
    local base_url="$1"
    log_step "11.T01" "Burp Suite REST API Scan" "11_active_fuzz.sh"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] Burp REST API scan: ${base_url}"
        return 0
    fi

    local burp_base="${OPT_BURP_URL%/}"
    local burp_auth_hdr=""
    [[ -n "$OPT_BURP_KEY" ]] && burp_auth_hdr="-H Authorization: Bearer ${OPT_BURP_KEY}"

    # ── 1. Detect running Burp and API version ────────────────────────────────
    local api_ver=""
    local _curl_base=()
    _curl_base=(-sk --max-time 10)
    [[ -n "$OPT_BURP_KEY" ]] && _curl_base+=(-H "Authorization: Bearer ${OPT_BURP_KEY}")

    # Probe v0.1 first (most deployed)
    if curl "${_curl_base[@]}" -o /dev/null -w "%{http_code}" \
            "${burp_base}/v0.1/scan" -X GET 2>/dev/null | grep -qE '^(200|405|400)'; then
        api_ver="v0.1"
    elif curl "${_curl_base[@]}" -o /dev/null -w "%{http_code}" \
            "${burp_base}/v1/scan" -X GET 2>/dev/null | grep -qE '^(200|405|400)'; then
        api_ver="v1"
    else
        log_warn "T01: Burp REST API not reachable at ${burp_base} — is Burp Pro running? Skipping."
        return 0
    fi
    log_ok "T01: Burp REST API detected (${api_ver}) at ${burp_base}"

    # ── 2. Select scan config based on depth ─────────────────────────────────
    local scan_config
    case "$DEPTH" in
        quick)    scan_config="Crawl and Audit - Fast" ;;
        standard) scan_config="${OPT_BURP_SCAN_CONFIG}" ;;
        deep)     scan_config="Crawl and Audit - Deep" ;;
        *)        scan_config="${OPT_BURP_SCAN_CONFIG}" ;;
    esac

    # ── 3. POST scan request ──────────────────────────────────────────────────
    local scan_body task_id
    if [[ "$api_ver" == "v0.1" ]]; then
        scan_body="$(printf '{"urls":["%s"],"scan_configurations":[{"name":"%s"}],"application_logins":[]}' \
            "$base_url" "$scan_config")"
        task_id="$(curl "${_curl_base[@]}" -s -X POST \
            -H "Content-Type: application/json" \
            -d "$scan_body" \
            "${burp_base}/v0.1/scan" 2>/dev/null \
            | grep -o '"task_id":"[^"]*"' | cut -d'"' -f4)"
    else
        # v1 API schema
        scan_body="$(printf '{"urls":["%s"],"scope":{"include":[{"rule":"%s","type":"SimpleScopeRule"}],"exclude":[]},"scan_config":{"scan_callback_url":""}}' \
            "$base_url" "$base_url")"
        task_id="$(curl "${_curl_base[@]}" -s -X POST \
            -H "Content-Type: application/json" \
            -d "$scan_body" \
            "${burp_base}/v1/scan" 2>/dev/null \
            | grep -o '"task_id":"[^"]*"' | cut -d'"' -f4)"
    fi

    if [[ -z "$task_id" ]]; then
        log_warn "T01: Burp scan creation failed for ${base_url} — check Burp Pro license and API config"
        return 0
    fi
    log "T01: Burp scan started | task_id=${task_id} | config='${scan_config}'"

    # ── 4. Poll until complete ────────────────────────────────────────────────
    local poll_interval=30
    local max_wait="$FUZZ_TIMEOUT_VAL"
    local waited=0
    local status=""
    local poll_url="${burp_base}/${api_ver}/scan/${task_id}"

    while [[ "$waited" -lt "$max_wait" ]]; do
        sleep "$poll_interval"
        waited=$(( waited + poll_interval ))

        status="$(curl "${_curl_base[@]}" -s "${poll_url}" 2>/dev/null \
            | grep -o '"scan_status":"[^"]*"' | cut -d'"' -f4)"

        log "T01: [${waited}s/${max_wait}s] Burp scan ${task_id} — status: ${status:-unknown}"

        case "$status" in
            succeeded|complete|finished) break ;;
            failed|aborted)
                log_warn "T01: Burp scan ${task_id} ended with status: ${status}"
                return 0
                ;;
        esac
        # Increase polling interval gradually
        [[ "$waited" -gt 300 ]] && poll_interval=60
    done

    if [[ "$status" != "succeeded" && "$status" != "complete" && "$status" != "finished" ]]; then
        log_warn "T01: Burp scan ${task_id} did not complete within ${max_wait}s (status: ${status:-timeout})"
        return 0
    fi

    # ── 5. Retrieve issue_events ──────────────────────────────────────────────
    local issues_url="${burp_base}/${api_ver}/scan/${task_id}/issue_events"
    local raw_issues
    raw_issues="$(curl "${_curl_base[@]}" -s "${issues_url}" 2>/dev/null)"

    local ev_file
    ev_file="$(printf '%s' "$raw_issues" | _save_evidence "burp_issues_$(_slug "$base_url")" "json")"
    log "T01: Issue events saved → ${ev_file}"

    # ── 6. Parse and emit findings ────────────────────────────────────────────
    # Extract each issue block using Python if available, else awk
    local issue_count=0
    if _have python3; then
        while IFS='|' read -r iname isev iconf ipath idesc irec; do
            [[ -z "$iname" ]] && continue
            # Filter low-confidence unless deep
            if [[ "$DEPTH" != "deep" ]]; then
                [[ "$iconf" == "tentative" ]] && continue
            fi
            local mapped_sev; mapped_sev="$(_norm_sev "$isev")"
            local clean_desc; clean_desc="$(_strip_html "${idesc:-No detail provided.}")"
            local clean_rec;  clean_rec="$(_strip_html  "${irec:-Refer to Burp finding for remediation guidance.}")"
            emit_finding "$mapped_sev" \
                "Burp: ${iname} at ${ipath:-/}" \
                "Burp Suite active scan identified: ${iname} on ${base_url}${ipath:-}. ${clean_desc}" \
                "$clean_rec" \
                "burp_issues_$(_slug "$base_url")_${SESSION_TS}.json"
            issue_count=$(( issue_count + 1 ))
        done < <(python3 - "$ev_file" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    events = data.get("issue_events", [])
    for ev in events:
        if ev.get("type") != "issue_found":
            continue
        iss = ev.get("issue", {})
        name = iss.get("name","").replace("|","").replace("\n"," ")
        sev  = iss.get("severity","info")
        conf = iss.get("confidence","tentative")
        path = iss.get("path","")
        desc = iss.get("description","").replace("|","").replace("\n"," ")[:500]
        rem  = iss.get("remediation","").replace("|","").replace("\n"," ")[:300]
        print(f"{name}|{sev}|{conf}|{path}|{desc}|{rem}")
except Exception as e:
    sys.exit(0)
PYEOF
)
    else
        # Fallback: rough grep-based extraction
        local issue_names
        issue_names="$(grep -o '"name":"[^"]*"' "$ev_file" 2>/dev/null | cut -d'"' -f4 | sort -u)"
        while IFS= read -r iname; do
            [[ -z "$iname" ]] && continue
            emit_finding "medium" \
                "Burp: ${iname} at ${base_url}" \
                "Burp Suite active scan identified: ${iname} on ${base_url}. See evidence for details." \
                "Review the Burp scan evidence and apply the remediation guidance provided by Burp Suite." \
                "burp_issues_$(_slug "$base_url")_${SESSION_TS}.json"
            issue_count=$(( issue_count + 1 ))
        done <<< "$issue_names"
    fi

    log_ok "T01: Burp scan complete — ${issue_count} finding(s) emitted"
}

# =============================================================================
# MRK:11_T02 — T02 SQLMAP SQL INJECTION | sqlmap,sqli,injection | L731-920
# NAV-RULE: no-insert-before
# =============================================================================
# Multi-vector SQLi: GET params, POST forms, Cookie values, HTTP headers.
# Level/risk come from conf (SQLMAP_LEVEL/SQLMAP_RISK); tamper scripts applied
# automatically in standard/deep to bypass common WAFs.
# =============================================================================
test_T02_sqlmap() {
    local base_url="$1"
    log_step "11.T02" "sqlmap SQL Injection" "11_active_fuzz.sh"

    if ! _have sqlmap; then
        log_warn "T02: sqlmap not installed — skipping (install: pip3 install sqlmap)"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] sqlmap: ${base_url}"
        return 0
    fi

    local level="$OPT_SQLMAP_LEVEL"
    local risk="$OPT_SQLMAP_RISK"
    local crawl_depth=2
    local tamper_flag=()
    local extra_headers=()

    # Depth-tuned settings
    case "$DEPTH" in
        quick)
            level=1; risk=1; crawl_depth=1
            ;;
        deep)
            level=5; risk=3; crawl_depth=3
            tamper_flag=(--tamper "randomcase,space2comment,between,charencode")
            extra_headers=(
                --headers "X-Forwarded-For: 127.0.0.1"
                --headers "X-Real-IP: 127.0.0.1"
                --headers "User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1)"
            )
            ;;
        *)
            tamper_flag=(--tamper "randomcase,space2comment")
            ;;
    esac

    [[ -n "$OPT_SQLMAP_TAMPER" ]] && tamper_flag=(--tamper "$OPT_SQLMAP_TAMPER")

    local slug; slug="$(_slug "$base_url")"
    local out_dir="${EVIDENCE_BASE}/sqlmap_${slug}"
    mkdir -p "$out_dir"

    local common_flags=(
        --batch
        --level="$level"
        --risk="$risk"
        --random-agent
        --timeout=30
        --retries=2
        --threads="$FUZZ_THREADS_VAL"
        --output-dir="$out_dir"
        "${tamper_flag[@]+"${tamper_flag[@]}"}"
        "${extra_headers[@]+"${extra_headers[@]}"}"
    )
    [[ -n "$OPT_FUZZ_COOKIE" ]] && common_flags+=(--cookie "$OPT_FUZZ_COOKIE")
    [[ -n "$OPT_FUZZ_PROXY"  ]] && common_flags+=(--proxy "$OPT_FUZZ_PROXY")
    [[ "$TIER" == "ghost" || "$TIER" == "evasion" ]] && common_flags+=(--delay="$(_tier_delay)")

    local found_sqli=()

    # ── Run A: URL + GET params ──────────────────────────────────────────────
    log "T02: sqlmap GET scan → ${base_url}"
    local run_a_out="${out_dir}/get_scan.txt"
    sqlmap -u "$base_url" \
        "${common_flags[@]}" \
        --crawl="$crawl_depth" \
        --forms 2>&1 | tee "$run_a_out" | grep -E "^\[" | tail -30 &>> "$LOG_FILE" || true

    # ── Run B: POST forms (explicit crawl) ───────────────────────────────────
    log "T02: sqlmap forms crawl → ${base_url}"
    local run_b_out="${out_dir}/forms_scan.txt"
    sqlmap -u "$base_url" \
        "${common_flags[@]}" \
        --forms \
        --crawl="$crawl_depth" 2>&1 | tee "$run_b_out" | grep -E "^\[" | tail -30 &>> "$LOG_FILE" || true

    # ── Run C (deep only): Cookie injection ──────────────────────────────────
    if [[ "$DEPTH" == "deep" && -n "$OPT_FUZZ_COOKIE" ]]; then
        log "T02: sqlmap cookie injection"
        local run_c_out="${out_dir}/cookie_scan.txt"
        sqlmap -u "$base_url" \
            "${common_flags[@]}" \
            --cookie="$OPT_FUZZ_COOKIE" \
            --level=2 2>&1 | tee "$run_c_out" | grep -E "^\[" | tail -20 &>> "$LOG_FILE" || true
    fi

    # ── Parse results ─────────────────────────────────────────────────────────
    local report_files
    report_files="$(find "$out_dir" -name "*.txt" -type f 2>/dev/null)"
    local param_line url_line
    while IFS= read -r report_f; do
        [[ -z "$report_f" ]] && continue
        while IFS= read -r line; do
            if echo "$line" | grep -qiE "parameter '.*' is (injectable|vulnerable)|sqlmap identified.*injection"; then
                local param; param="$(echo "$line" | grep -oP "parameter '\K[^']+")"
                local tgt_url; tgt_url="$(grep -m1 'Target URL:' "$report_f" | awk '{print $NF}')"
                local key="${tgt_url:-$base_url}:${param:-unknown}"
                # Avoid duplicate findings for same target+param
                local dup=0
                local k
                for k in "${found_sqli[@]:-}"; do [[ "$k" == "$key" ]] && dup=1 && break; done
                if [[ "$dup" -eq 0 ]]; then
                    found_sqli+=("$key")
                    local inj_type; inj_type="$(echo "$line" | grep -oiP "(Boolean|Error|Union|Stacked|Time-based|Inline)[- ]?based[^;]*" | head -1)"
                    emit_finding "critical" \
                        "SQL Injection — parameter '${param:-unknown}'" \
                        "sqlmap confirmed SQL injection in parameter '${param:-unknown}' on ${tgt_url:-$base_url}. Technique: ${inj_type:-detected}. Evidence: ${report_f}" \
                        "Use parameterised queries / prepared statements. Never concatenate user-supplied input into SQL statements. Apply least-privilege DB accounts. Evidence path: ${report_f}" \
                        "sqlmap_${slug}_${SESSION_TS}"
                fi
            fi
        done < "$report_f"
    done <<< "$report_files"

    log_ok "T02: sqlmap complete — ${#found_sqli[@]} confirmed injection(s) | evidence: ${out_dir}"
}

# =============================================================================
# MRK:11_T03 — T03 DALFOX XSS FUZZER | dalfox,xss,blind,dom | L921-1060
# NAV-RULE: no-insert-before
# =============================================================================
# Reflected, DOM, stored, and blind XSS via dalfox.
# Blind XSS uses DALFOX_BLIND_URL from conf for OOB callback.
# =============================================================================
test_T03_dalfox() {
    local base_url="$1"
    log_step "11.T03" "dalfox XSS Fuzzer" "11_active_fuzz.sh"

    if ! _have dalfox; then
        log_warn "T03: dalfox not installed — skipping (install: go install github.com/hahwul/dalfox/v2@latest)"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] dalfox: ${base_url}"
        return 0
    fi

    local slug; slug="$(_slug "$base_url")"
    local out_json="${EVIDENCE_BASE}/$(ev_fname "fuzz-dalfox" "json" "$slug")"

    local df_flags=(
        --timeout "$OPT_DALFOX_TIMEOUT"
        --output "$out_json"
        --format json
        --no-color
    )
    [[ -n "$OPT_FUZZ_COOKIE"  ]] && df_flags+=(--cookie "$OPT_FUZZ_COOKIE")
    [[ -n "$OPT_FUZZ_PROXY"   ]] && df_flags+=(--proxy "$OPT_FUZZ_PROXY")
    [[ -n "$OPT_DALFOX_BLIND" ]] && df_flags+=(--blind "$OPT_DALFOX_BLIND")

    case "$TIER" in
        ghost|evasion) df_flags+=(--delay "$(_tier_delay)" --timeout 30) ;;
        loud)          df_flags+=(--worker 10) ;;
    esac

    case "$DEPTH" in
        quick)
            df_flags+=(--only-discovery)
            ;;
        deep)
            df_flags+=(--deep-domxss --mining-dict --waf-bypass)
            ;;
    esac

    log "T03: dalfox scanning ${base_url}"
    dalfox url "$base_url" "${df_flags[@]}" &>> "$LOG_FILE" || true

    # Parse JSON output
    local xss_count=0
    if [[ -f "$out_json" ]] && _have python3; then
        while IFS='|' read -r xtype xurl xparam xpoc; do
            [[ -z "$xtype" ]] && continue
            emit_finding "high" \
                "XSS — ${xtype} in ${xparam:-parameter}" \
                "${xtype} XSS confirmed by dalfox on ${xurl:-$base_url}. Parameter: ${xparam:-unknown}. PoC payload: ${xpoc:-see evidence}." \
                "Encode all user-supplied output using context-appropriate encoding (HTML, JS, URL). Implement a Content-Security-Policy header. Use a modern framework with automatic XSS protection." \
                "dalfox_${slug}_${SESSION_TS}.json"
            xss_count=$(( xss_count + 1 ))
        done < <(python3 - "$out_json" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    results = data if isinstance(data, list) else data.get("results", [])
    for r in results:
        xtype = r.get("type","Reflected").replace("|","")
        xurl  = r.get("url","").replace("|","")
        param = r.get("param","").replace("|","")
        poc   = r.get("evidence","").replace("|","").replace("\n"," ")[:200]
        print(f"{xtype}|{xurl}|{param}|{poc}")
except Exception:
    sys.exit(0)
PYEOF
)
    elif [[ -f "$out_json" ]]; then
        # Fallback: grep for XSS confirmed lines
        if grep -qi '"type"' "$out_json" 2>/dev/null; then
            emit_finding "high" \
                "XSS confirmed at ${base_url}" \
                "dalfox confirmed one or more XSS vulnerabilities on ${base_url}. See evidence for details." \
                "Encode all user-supplied output. Implement Content-Security-Policy." \
                "dalfox_${slug}_${SESSION_TS}.json"
            xss_count=1
        fi
    fi

    log_ok "T03: dalfox complete — ${xss_count} XSS finding(s) | evidence: ${out_json}"
}

# =============================================================================
# MRK:11_T04 — T04 NUCLEI TEMPLATE SCAN | nuclei,template,cve | L1061-1220
# NAV-RULE: no-insert-before
# =============================================================================
# Community-template scanning for CVEs, misconfigs, exposures, and tech-specific
# vulnerabilities. JSON output mapped directly to JSONL findings.
# =============================================================================
test_T04_nuclei() {
    local base_url="$1"
    log_step "11.T04" "nuclei Template Scan" "11_active_fuzz.sh"

    if ! _have nuclei; then
        log_warn "T04: nuclei not installed — skipping (install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] nuclei: ${base_url}"
        return 0
    fi

    local slug; slug="$(_slug "$base_url")"
    local out_json="${EVIDENCE_BASE}/$(ev_fname "fuzz-nuclei" "jsonl" "$slug")"

    local n_flags=(
        -u "$base_url"
        -severity "$OPT_NUCLEI_SEV"
        -json-export "$out_json"
        -silent
        -no-color
        -rl "${NUCLEI_RATE_LIMIT:-100}"
        -c  "${NUCLEI_CONCURRENCY:-10}"
        -timeout 10
    )
    [[ -n "$OPT_NUCLEI_TEMPLATES" ]] && n_flags+=(-t "$OPT_NUCLEI_TEMPLATES")
    [[ -n "$OPT_FUZZ_PROXY"       ]] && n_flags+=(-proxy "$OPT_FUZZ_PROXY")
    [[ -n "$OPT_FUZZ_COOKIE"      ]] && n_flags+=(-H "Cookie: ${OPT_FUZZ_COOKIE}")

    # Select template categories by depth
    case "$DEPTH" in
        quick)
            n_flags+=(-tags "cve,exposure" -etags "fuzzing,network")
            ;;
        deep)
            n_flags+=(-tags "cve,exposure,misconfigurations,vulnerabilities,fuzzing,technologies,default-logins")
            ;;
        *)
            n_flags+=(-tags "cve,exposure,misconfigurations,vulnerabilities")
            ;;
    esac

    case "$TIER" in
        ghost|evasion) n_flags+=(-rl 10 -c 3 -timeout 20) ;;
        loud)          n_flags+=(-rl 300 -c 25) ;;
    esac

    log "T04: nuclei scanning ${base_url} | severity=${OPT_NUCLEI_SEV}"
    nuclei "${n_flags[@]}" &>> "$LOG_FILE" || true

    # Parse JSONL findings
    local nc=0
    if [[ -f "$out_json" ]] && _have python3; then
        while IFS='|' read -r tmpl_id name sev host matched desc; do
            [[ -z "$tmpl_id" ]] && continue
            local mapped_sev; mapped_sev="$(_norm_sev "$sev")"
            emit_finding "$mapped_sev" \
                "nuclei: ${name} [${tmpl_id}]" \
                "nuclei detected ${name} (template: ${tmpl_id}) on ${host}. Match: ${matched:-see evidence}. ${desc}" \
                "Review the nuclei template (${tmpl_id}) remediation guidance. Update affected software, remove unnecessary exposures, and verify the finding is not a false positive before patching." \
                "nuclei_${slug}_${SESSION_TS}.jsonl"
            nc=$(( nc + 1 ))
        done < <(python3 - "$out_json" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            tmpl   = r.get("template-id","").replace("|","")
            name   = r.get("info",{}).get("name","").replace("|","")
            sev    = r.get("info",{}).get("severity","info")
            host   = r.get("host","").replace("|","")
            match  = r.get("matched-at","").replace("|","")
            desc   = r.get("info",{}).get("description","").replace("|","").replace("\n"," ")[:300]
            print(f"{tmpl}|{name}|{sev}|{host}|{match}|{desc}")
except Exception:
    sys.exit(0)
PYEOF
)
    elif [[ -f "$out_json" ]]; then
        local raw_count; raw_count="$(wc -l < "$out_json")"
        if [[ "$raw_count" -gt 0 ]]; then
            emit_finding "medium" \
                "nuclei: ${raw_count} template match(es) on ${base_url}" \
                "nuclei found ${raw_count} match(es) on ${base_url}. Review the evidence file for details." \
                "Review each matched template and apply remediation per the nuclei template guidance." \
                "nuclei_${slug}_${SESSION_TS}.jsonl"
            nc="$raw_count"
        fi
    fi

    log_ok "T04: nuclei complete — ${nc} finding(s) | evidence: ${out_json}"
}

# =============================================================================
# MRK:11_T05 — T05 COMMIX COMMAND INJECTION | commix,cmdi,os | L1221-1330
# NAV-RULE: no-insert-before
# =============================================================================
test_T05_commix() {
    local base_url="$1"
    log_step "11.T05" "commix Command Injection" "11_active_fuzz.sh"

    if ! _have commix; then
        log_warn "T05: commix not installed — skipping (install: pip3 install commix)"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] commix: ${base_url}"
        return 0
    fi

    local slug; slug="$(_slug "$base_url")"
    local out_file="${EVIDENCE_BASE}/$(ev_fname "fuzz-commix" "txt" "$slug")"

    local cx_flags=(
        --url="$base_url"
        --batch
        --crawl=2
        --output-dir="${EVIDENCE_BASE}/commix_${slug}"
        --timeout="${COMMIX_TIMEOUT:-30}"
    )
    [[ -n "$OPT_FUZZ_COOKIE" ]] && cx_flags+=(--cookie="$OPT_FUZZ_COOKIE")
    [[ -n "$OPT_FUZZ_PROXY"  ]] && cx_flags+=(--proxy="$OPT_FUZZ_PROXY")
    [[ "$DEPTH" == "deep"    ]] && cx_flags+=(--level="${COMMIX_LEVEL:-3}" --all)
    [[ "$TIER"  == "ghost"   ]] && cx_flags+=(--delay=2)

    log "T05: commix scanning ${base_url}"
    commix "${cx_flags[@]}" 2>&1 | tee "$out_file" | grep -iE "vuln|inject|found" &>> "$LOG_FILE" || true

    # Parse output for confirmed injections
    local cmdi_found=0
    if grep -qiE "you can use '--os-shell' option|Parameter.*is (vulnerable|injectable)|command injection" "$out_file" 2>/dev/null; then
        local param; param="$(grep -ioP "parameter '\K[^']+" "$out_file" | head -1)"
        emit_finding "critical" \
            "OS Command Injection — ${param:-parameter}" \
            "commix confirmed OS command injection in ${param:-a parameter} on ${base_url}. Remote code execution is possible. Evidence: ${out_file}" \
            "Never pass user-supplied data to shell commands. Use application-layer APIs instead of shell invocations. Apply strict input validation with allowlists. Isolate the application in a minimal container with no shell access." \
            "commix_${slug}_${SESSION_TS}.txt"
        cmdi_found=1
    fi

    log_ok "T05: commix complete — ${cmdi_found} injection(s) confirmed | evidence: ${out_file}"
}

# =============================================================================
# MRK:11_T06 — T06 ARJUN HIDDEN PARAMS | arjun,hidden,params | L1331-1440
# NAV-RULE: no-insert-before
# =============================================================================
test_T06_arjun() {
    local base_url="$1"
    log_step "11.T06" "arjun Hidden Parameter Discovery" "11_active_fuzz.sh"

    if ! _have arjun; then
        log_warn "T06: arjun not installed — skipping (install: pip3 install arjun)"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] arjun: ${base_url}"
        return 0
    fi

    local slug; slug="$(_slug "$base_url")"
    local out_json="${EVIDENCE_BASE}/$(ev_fname "fuzz-arjun" "json" "$slug")"

    local arj_flags=(
        -u "$base_url"
        -o "$out_json"
        --passive
        -t "${ARJUN_THREADS:-10}"
        -q
    )
    [[ -n "$OPT_FUZZ_COOKIE" ]] && arj_flags+=(-c "$OPT_FUZZ_COOKIE")
    [[ -n "$OPT_FUZZ_PROXY"  ]] && arj_flags+=(--proxy "$OPT_FUZZ_PROXY")
    [[ "$DEPTH" == "deep"    ]] && arj_flags+=(--stable)

    log "T06: arjun param discovery → ${base_url}"
    arjun "${arj_flags[@]}" &>> "$LOG_FILE" || true

    # Report discovered params
    if [[ -f "$out_json" ]]; then
        local params
        params="$(python3 -c "import json,sys; d=json.load(open('$out_json')); print(', '.join(d))" 2>/dev/null || \
                  grep -o '"[^"]*"' "$out_json" | tr -d '"' | tr '\n' ',' 2>/dev/null)"
        if [[ -n "$params" ]]; then
            emit_finding "medium" \
                "Hidden Parameters Discovered at ${base_url}" \
                "arjun discovered undocumented HTTP parameters on ${base_url}: ${params}. Hidden parameters may expose administrative functions, debug endpoints, or bypass access controls." \
                "Audit all accepted parameters server-side. Remove or disable undocumented parameters. Apply strict allowlist validation. Review hidden parameters for IDOR, privilege escalation, or injection risks." \
                "arjun_${slug}_${SESSION_TS}.json"
        fi
    fi

    log_ok "T06: arjun complete | evidence: ${out_json}"
}

# =============================================================================
# MRK:11_T07 — T07 TPLMAP SSTI | tplmap,ssti,template | L1441-1530
# NAV-RULE: no-insert-before
# =============================================================================
test_T07_tplmap() {
    local base_url="$1"
    log_step "11.T07" "tplmap SSTI" "11_active_fuzz.sh"

    if ! _have tplmap; then
        log_warn "T07: tplmap not installed — skipping (install: pip3 install tplmap or clone from GitHub)"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] tplmap: ${base_url}"
        return 0
    fi

    local slug; slug="$(_slug "$base_url")"
    local out_file="${EVIDENCE_BASE}/$(ev_fname "fuzz-tplmap" "txt" "$slug")"

    # tplmap marks injection point with * in URL; probe query params first
    local probe_url="${base_url}?q=*"
    [[ "$base_url" == *\?* ]] && probe_url="${base_url}&q=*"

    local tp_flags=(
        -u "$probe_url"
        --level="${TPLMAP_LEVEL:-5}"
    )
    [[ -n "$OPT_FUZZ_COOKIE" ]] && tp_flags+=(--cookie "$OPT_FUZZ_COOKIE")
    [[ -n "$OPT_FUZZ_PROXY"  ]] && tp_flags+=(--proxy "$OPT_FUZZ_PROXY")

    log "T07: tplmap SSTI probing → ${probe_url}"
    tplmap "${tp_flags[@]}" 2>&1 | tee "$out_file" | grep -iE "engine|inject|found|vulnerable" &>> "$LOG_FILE" || true

    if grep -qiE "Server Side Template Injection|engine '.*'|tplmap identified" "$out_file" 2>/dev/null; then
        local engine; engine="$(grep -ioP "engine '\K[^']+" "$out_file" | head -1)"
        emit_finding "critical" \
            "Server-Side Template Injection (SSTI) — ${engine:-detected}" \
            "tplmap confirmed SSTI via template engine '${engine:-unknown}' on ${base_url}. SSTI allows remote code execution on the server. Evidence: ${out_file}" \
            "Never render user-supplied input through a template engine. Use sandboxed templates if rendering is required. Disable dangerous template functions (eval, exec, etc.). Upgrade the template engine and apply vendor patches." \
            "tplmap_${slug}_${SESSION_TS}.txt"
    fi

    log_ok "T07: tplmap complete | evidence: ${out_file}"
}

# =============================================================================
# MRK:11_T08 — T08 GHAURI ADVANCED SQLI | ghauri,sqli,second-order | L1531-1640
# NAV-RULE: no-insert-before
# =============================================================================
# ghauri focuses on second-order SQLi and advanced blind injection techniques
# that sqlmap may miss. Complements T02 rather than replacing it.
# =============================================================================
test_T08_ghauri() {
    local base_url="$1"
    log_step "11.T08" "ghauri Second-Order SQLi" "11_active_fuzz.sh"

    if ! _have ghauri; then
        log_warn "T08: ghauri not installed — skipping (install: pip3 install ghauri)"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] ghauri: ${base_url}"
        return 0
    fi

    local slug; slug="$(_slug "$base_url")"
    local out_file="${EVIDENCE_BASE}/$(ev_fname "fuzz-ghauri" "txt" "$slug")"

    local gh_flags=(
        --url="$base_url"
        --batch
        --level="${GHAURI_LEVEL:-1}"
        --crawl=2
        --forms
        --random-agent
    )
    [[ -n "$OPT_FUZZ_COOKIE" ]] && gh_flags+=(--cookie="$OPT_FUZZ_COOKIE")
    [[ -n "$OPT_FUZZ_PROXY"  ]] && gh_flags+=(--proxy="$OPT_FUZZ_PROXY")
    [[ "$DEPTH" == "deep"    ]] && gh_flags+=(--level=3 --second-url="$base_url")
    [[ "$TIER"  == "ghost"   ]] && gh_flags+=(--delay=2)

    log "T08: ghauri scanning ${base_url}"
    ghauri "${gh_flags[@]}" 2>&1 | tee "$out_file" | grep -iE "vulnerable|inject|found" &>> "$LOG_FILE" || true

    if grep -qiE "parameter '.*' is (vulnerable|injectable)|ghauri identified" "$out_file" 2>/dev/null; then
        local param; param="$(grep -ioP "parameter '\K[^']+" "$out_file" | head -1)"
        local tech; tech="$(grep -ioP "(Boolean|Error|Union|Time-based|Stacked)[- ]?based[^;]*" "$out_file" | head -1)"
        emit_finding "critical" \
            "SQL Injection (ghauri) — ${param:-parameter}" \
            "ghauri confirmed SQL injection in '${param:-unknown}' on ${base_url}. Technique: ${tech:-detected}. This tool focuses on second-order and advanced blind SQLi missed by standard tools. Evidence: ${out_file}" \
            "Use parameterised queries / prepared statements. Apply second-order injection review: verify all stored data is treated as untrusted when retrieved and used in subsequent queries." \
            "ghauri_${slug}_${SESSION_TS}.txt"
    fi

    log_ok "T08: ghauri complete | evidence: ${out_file}"
}

# =============================================================================
# MRK:11_T09 — T09 FFUF PAYLOAD FUZZING | ffuf,lfi,rfi,traversal | L1641-1770
# NAV-RULE: no-insert-before
# =============================================================================
# ffuf payload fuzzing for LFI, path traversal, and RFI.
# Uses SecLists if available; falls back to an inline wordlist.
# =============================================================================
test_T09_ffuf() {
    local base_url="$1"
    log_step "11.T09" "ffuf Payload Fuzzing (LFI/Traversal)" "11_active_fuzz.sh"

    if ! _have ffuf; then
        log_warn "T09: ffuf not installed — skipping (install: go install github.com/ffuf/ffuf/v2@latest)"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] ffuf: ${base_url}"
        return 0
    fi

    local slug; slug="$(_slug "$base_url")"

    # Locate LFI wordlist (prefer SecLists)
    local lfi_wl=""
    local _wl_candidates=(
        /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
        /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt
        /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
    )
    local _c
    for _c in "${_wl_candidates[@]}"; do
        [[ -f "$_c" ]] && lfi_wl="$_c" && break
    done

    # Inline minimal wordlist if SecLists absent
    if [[ -z "$lfi_wl" ]]; then
        lfi_wl="${EVIDENCE_BASE}/lfi_mini_wl.txt"
        cat > "$lfi_wl" <<'WORDLIST'
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../../../../../../etc/passwd
/etc/passwd
/etc/shadow
/etc/hosts
/proc/self/environ
/proc/version
/proc/cmdline
....//....//etc/passwd
....\/....\/etc/passwd
%2e%2e%2fetc%2fpasswd
%2e%2e/%2e%2e/etc/passwd
..%2Fetc%2Fpasswd
%2e%2e%2f%2e%2e%2fetc%2fpasswd
..%252Fetc%252Fpasswd
WORDLIST
        log_warn "T09: SecLists not found — using minimal inline LFI wordlist"
    fi

    # Build fuzz URL — inject FUZZ into first query param value or append ?file=FUZZ
    local fuzz_url
    if [[ "$base_url" == *"="* ]]; then
        # Replace last param value with FUZZ
        fuzz_url="$(echo "$base_url" | sed 's/=[^&]*$/=FUZZ/')"
    else
        fuzz_url="${base_url}?file=FUZZ"
    fi

    local out_json="${EVIDENCE_BASE}/$(ev_fname "fuzz-ffuf-lfi" "json" "$slug")"
    local ff_flags=(
        -u "$fuzz_url"
        -w "${lfi_wl}:FUZZ"
        -o "$out_json"
        -of json
        -t "${FFUF_THREADS:-50}"
        -timeout "${FFUF_TIMEOUT:-10}"
        -mc "200,500"
        -fr "404 Not Found"
        -s
        -r
    )
    [[ -n "$OPT_FUZZ_COOKIE" ]] && ff_flags+=(-H "Cookie: ${OPT_FUZZ_COOKIE}")
    [[ -n "$OPT_FUZZ_PROXY"  ]] && ff_flags+=(-x "$OPT_FUZZ_PROXY")
    [[ "$TIER" == "ghost"    ]] && ff_flags+=(-p "0-2" -t 5)
    [[ "$TIER" == "loud"     ]] && ff_flags+=(-t 150)

    log "T09: ffuf LFI fuzzing → ${fuzz_url}"
    ffuf "${ff_flags[@]}" &>> "$LOG_FILE" || true

    # Parse JSON results for hits indicating file disclosure
    local lfi_count=0
    if [[ -f "$out_json" ]] && _have python3; then
        while IFS='|' read -r payload status length; do
            [[ -z "$payload" ]] && continue
            emit_finding "high" \
                "Path Traversal / LFI — ${payload}" \
                "ffuf confirmed a successful response (HTTP ${status}, ${length} bytes) for LFI payload '${payload}' on ${fuzz_url}. Local file inclusion or path traversal may allow reading arbitrary server files including /etc/passwd, application source code, or credentials." \
                "Validate and sanitise all file path inputs against a strict allowlist. Never use user-supplied input directly in file system operations. Chroot the application process or use a virtual filesystem jail." \
                "ffuf_lfi_${slug}_${SESSION_TS}.json"
            lfi_count=$(( lfi_count + 1 ))
        done < <(python3 - "$out_json" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        data = json.load(f)
    for r in data.get("results", []):
        payload = r.get("input", {}).get("FUZZ", "").replace("|","")
        status  = r.get("status", 0)
        length  = r.get("length", 0)
        # Likely LFI if response is meaningful size (>100B) and not a generic error
        if length > 100:
            print(f"{payload}|{status}|{length}")
except Exception:
    sys.exit(0)
PYEOF
)
    fi

    log_ok "T09: ffuf complete — ${lfi_count} potential LFI/traversal hit(s) | evidence: ${out_json}"
}

# =============================================================================
# MRK:11_T10 — T10 CRLFUZZ CRLF INJECTION | crlf,header,injection | L1771-1860
# NAV-RULE: no-insert-before
# =============================================================================
test_T10_crlfuzz() {
    local base_url="$1"
    log_step "11.T10" "CRLFuzz CRLF Injection" "11_active_fuzz.sh"

    if ! _have crlfuzz; then
        log_warn "T10: crlfuzz not installed — skipping (install: go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest)"
        return 0
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] crlfuzz: ${base_url}"
        return 0
    fi

    local slug; slug="$(_slug "$base_url")"
    local out_file="${EVIDENCE_BASE}/$(ev_fname "fuzz-crlfuzz" "txt" "$slug")"

    local crlf_flags=(-u "$base_url")
    [[ -n "$OPT_FUZZ_COOKIE" ]] && crlf_flags+=(-H "Cookie: ${OPT_FUZZ_COOKIE}")
    [[ -n "$OPT_FUZZ_PROXY"  ]] && crlf_flags+=(-x "$OPT_FUZZ_PROXY")
    [[ "$TIER" == "ghost"    ]] && crlf_flags+=(-d 2)

    log "T10: crlfuzz scanning ${base_url}"
    crlfuzz "${crlf_flags[@]}" 2>&1 | tee "$out_file" | grep -iE "vuln|found|inject" &>> "$LOG_FILE" || true

    if grep -qiE "\[VULN\]|CRLF injection found|vulnerable" "$out_file" 2>/dev/null; then
        local vuln_url; vuln_url="$(grep -iEo 'https?://[^ ]*' "$out_file" | head -1)"
        emit_finding "medium" \
            "CRLF Injection at ${base_url}" \
            "crlfuzz confirmed CRLF injection on ${vuln_url:-$base_url}. An attacker can inject arbitrary HTTP headers (e.g., Set-Cookie) or split HTTP responses, enabling session fixation, XSS via reflected headers, and cache poisoning." \
            "Strip or reject CR (\\r) and LF (\\n) characters from all user-supplied data before including it in HTTP response headers. Use a framework that automatically sanitises header values." \
            "crlfuzz_${slug}_${SESSION_TS}.txt"
    fi

    log_ok "T10: crlfuzz complete | evidence: ${out_file}"
}

# =============================================================================
# MRK:11_TRUN — PER-TARGET DISPATCHER | dispatch,run,test | L1861-1930
# NAV-RULE: no-insert-before
# =============================================================================
per_target() {
    local url="$1"
    local line; line="$(printf '─%.0s' {1..52})"
    echo ""
    echo -e "${BOLD}${CYAN}${line}${NC}"
    echo -e "${BOLD}${CYAN}  Target: ${url}${NC}"
    echo -e "${BOLD}${CYAN}${line}${NC}"
    echo ""
    log "Starting active fuzz suite against: ${url}"

    _test_skip T01 || test_T01_burp_scan    "$url"
    _test_skip T02 || test_T02_sqlmap       "$url"
    _test_skip T03 || test_T03_dalfox       "$url"
    _test_skip T04 || test_T04_nuclei       "$url"
    _test_skip T05 || test_T05_commix       "$url"
    _test_skip T06 || test_T06_arjun        "$url"
    _test_skip T07 || test_T07_tplmap       "$url"
    _test_skip T08 || test_T08_ghauri       "$url"
    _test_skip T09 || test_T09_ffuf         "$url"
    _test_skip T10 || test_T10_crlfuzz      "$url"

    log "Finished fuzz suite for: ${url}"
}

# =============================================================================
# MRK:11_MAIN — MAIN | main,entry,loop | L1931-2060
# NAV-RULE: no-insert-before
# =============================================================================
main() {
    if [[ "$EUID" -ne 0 ]]; then
        echo "[ERROR] This script must be run as root."
        echo "        Run: sudo $0 $*"
        exit 1
    fi

    cd "${SCRIPT_DIR}"

    log_step "11" "Active Fuzz — Burp/sqlmap/dalfox/nuclei/commix/arjun/tplmap/ghauri/ffuf/CRLFuzz" "11_active_fuzz.sh"

    _setup_profile

    assemble_targets

    if [[ "${#TARGET_URLS[@]}" -eq 0 ]]; then
        log_warn "Step 11: No web targets found — nothing to fuzz. Exiting cleanly."
        exit 0
    fi

    scope_confirm

    # Print configuration summary
    local line; line="$(printf '═%.0s' {1..52})"
    echo -e "${GREEN}"
    echo "${line}"
    echo "  PT-Orc Step 11 — Active Fuzz"
    echo "  TechGuard."
    printf "  %-20s %s\n" "Project:"     "${PROJECT_NAME:-[see pt-orc.conf]}"
    printf "  %-20s %s\n" "Targets:"     "${#TARGET_URLS[@]} URL(s)"
    printf "  %-20s %s\n" "Profile:"     "${DEPTH}"
    printf "  %-20s %s\n" "Tier:"        "${TIER}"
    printf "  %-20s %s\n" "Burp API:"    "${OPT_BURP_URL}"
    printf "  %-20s %s\n" "sqlmap L/R:"  "${OPT_SQLMAP_LEVEL}/${OPT_SQLMAP_RISK}"
    printf "  %-20s %s\n" "nuclei sev:"  "${OPT_NUCLEI_SEV}"
    printf "  %-20s %s\n" "Findings:"    "${FINDINGS_FILE}"
    printf "  %-20s %s\n" "Evidence:"    "${EVIDENCE_BASE}/"
    echo "${line}"
    echo -e "${NC}"

    {
        echo "=== Step 11 Active Fuzz Start ==="
        echo "Project:  ${PROJECT_NAME:-[project]}"
        echo "Profile:  ${DEPTH}"
        echo "Tier:     ${TIER}"
        echo "Targets:  ${TARGET_URLS[*]}"
        echo "Session:  ${SESSION_TS}"
    } >> "$LOG_FILE" 2>/dev/null || true

    local start_ts; start_ts="$(date +%s)"
    local u
    for u in "${TARGET_URLS[@]}"; do
        per_target "$u"
    done
    local elapsed=$(( $(date +%s) - start_ts ))
    local mm=$(( elapsed / 60 ))
    local ss=$(( elapsed % 60 ))

    echo ""
    echo -e "${BOLD}${GREEN}$(printf '━%.0s' {1..52})${NC}"
    echo -e "${BOLD}${GREEN}  Step 11 Complete${NC}"
    echo -e "${BOLD}${GREEN}  Targets tested : ${#TARGET_URLS[@]}${NC}"
    echo -e "${BOLD}${GREEN}  Findings emitted: ${FINDING_COUNT}${NC}"
    echo -e "${BOLD}${GREEN}  Elapsed         : ${mm}m${ss}s${NC}"
    echo -e "${BOLD}${GREEN}  Findings file   : ${FINDINGS_FILE}${NC}"
    echo -e "${BOLD}${GREEN}  Evidence dir    : ${EVIDENCE_BASE}/${NC}"
    echo -e "${BOLD}${GREEN}$(printf '━%.0s' {1..52})${NC}"
    echo ""

    {
        echo "=== Step 11 Active Fuzz Complete ==="
        echo "Targets:  ${#TARGET_URLS[@]}"
        echo "Findings: ${FINDING_COUNT}"
        echo "Elapsed:  ${mm}m${ss}s"
        echo "File:     ${FINDINGS_FILE}"
    } >> "$LOG_FILE" 2>/dev/null || true

    exit 0
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
