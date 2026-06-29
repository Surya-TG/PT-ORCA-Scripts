#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:12_NAV_TOC — Section index | nav,toc,index | L5-53
# - MRK:12_ROOT    — ROOT CHECK                    | root,check,euid                    | L54-63   | ⚠ no-insert-before
# - MRK:12_CONF    — ENGAGEMENT CONFIGURATION      | conf,engagement,configuration      | L64-133  | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:12_LOG     — COLOURS AND LOGGING           | log,colours,logging                | L134-156 | ⚠ no-insert-before
# - MRK:12_ARGS    — ARGUMENT PARSING              | args,argument,parsing              | L157-196 | ⚠ no-insert-before
# - MRK:12_DB      — MSF DB HELPERS                | db,msf,helpers,web,ports           | L197-251 | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:12_CONFIRM — SCOPE CONFIRMATION            | confirm,scope,confirmation         | L252-266 | ⚠ no-insert-before; propose-before-edit
# - MRK:12_TARGETS — TARGET ASSEMBLY               | targets,target,assembly            | L267-301 | ⚠ no-insert-before; read-toc-first
# - MRK:12_FIND    — FINDING WRITER                | find,finding,writer,jsonl,jq       | L302-326 | ⚠ no-insert-before; read-toc-first
# - MRK:12_UTILS   — SHARED UTILITIES              | utils,shared,utilities,curl,proxy  | L327-392 | ⚠ no-insert-before
# - MRK:12_PROF    — PROFILE SETUP                 | prof,profile,setup,quick,deep      | L393-430 | ⚠ no-insert-before
# - MRK:12_T01     — T01 CSP DEEP ANALYSIS         | t01,csp,policy,unsafe,directive    | L431-545 | ⚠ read-toc-first
# - MRK:12_T02     — T02 SUBRESOURCE INTEGRITY     | t02,sri,integrity,cdn,script       | L546-625 | ⚠ read-toc-first
# - MRK:12_T03     — T03 CLICKJACKING DEEP         | t03,clickjack,frame,ancestors,xfo  | L626-700 | ⚠ read-toc-first
# - MRK:12_T04     — T04 CROSS-ORIGIN POLICIES     | t04,corp,coep,coop,crossorigin     | L701-780 | ⚠ read-toc-first
# - MRK:12_T05     — T05 CACHE SECURITY            | t05,cache,no-store,private,cdn     | L781-865 | ⚠ read-toc-first
# - MRK:12_T06     — T06 HEADER INFO DISCLOSURE    | t06,header,debug,xaspnet,runtime   | L866-945 | ⚠ read-toc-first
# - MRK:12_T07     — T07 COOKIE SECURITY DEEP      | t07,cookie,samesite,host,domain    | L946-1045|⚠ read-toc-first
# - MRK:12_T08     — T08 MIXED CONTENT             | t08,mixed,http,active,passive      | L1046-1120|⚠ read-toc-first; deep-only
# - MRK:12_TRUN    — PER-TARGET DISPATCHER         | trun,target,dispatcher,test        | L1121-1175|⚠ no-insert-before; read-toc-first
# - MRK:12_MAIN    — MAIN ENTRY POINT              | main,entry,point,summary           | L1176-1320|⚠ no-insert-before; read-toc-first
# NAV-LEN: 22 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-06-27

# =============================================================================
# 25_content_sec.sh — TechGuard. [VAPT-Advanced v1.0 — 2026-06-27]
# Content Security — Deep quality analysis beyond step 09 header presence sweep
# Coverage: CSP directive quality (unsafe-inline/eval/wildcard/data:/http: sources,
#   missing base-uri/form-action/object-src), Subresource Integrity on external
#   assets, clickjacking deep (frame-ancestors vs X-Frame-Options precedence,
#   ALLOW-FROM deprecated), cross-origin isolation policies (CORP/COEP/COOP),
#   cache security on authenticated endpoints (no-store, private, CDN leakage),
#   header information disclosure (X-Debug-Token HIGH, X-AspNet-Version, Via,
#   traceparent, X-Generator — avoids duplicating step 09 Server/X-Powered-By),
#   cookie security deep (__Secure-/__Host- prefix enforcement, Domain= scope,
#   Max-Age bounds, SameSite=None+!Secure combination), mixed content detection
#   on HTTPS pages (active scripts/iframes HIGH, passive images MEDIUM)
# Profiles: quick | standard (default) | deep
# Consumes: MSF DB web hosts or --host/--targets
# Produces: per-host evidence files + JSONL findings + markdown summary
# =============================================================================
# USAGE:
#   ./25_content_sec.sh [OPTIONS]
#
# OPTIONS:
#   --targets <file>              File with host:port entries (one per line)
#   --host <IP:PORT>              Single target (repeatable)
#   --from-db                     Pull web hosts from MSF DB (default if no targets)
#   --tier <ghost|normal|loud>    Controls delays between requests
#   --token <bearer>              Bearer token for cache/cookie probes on auth pages
#   --cookie <name=value>         Session cookie for authenticated probes
#   --profile <name>              quick|standard|deep (default: standard)
#   --intercept-proxy <url>       Proxy all curl requests through Burp/ZAP
#   --skip-test <N>               Skip test N (repeatable)
#   --only-test <N>               Run only test N (repeatable)
#   --yes                         Skip interactive scope confirmation
#   --dry-run                     Print commands without executing
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# MRK:12_ROOT — ROOT CHECK | root,check,euid | L54-63
# NAV-RULE: no-insert-before
# =============================================================================
if [[ "$EUID" -ne 0 ]] && [[ "${PTORC_ALLOW_NON_ROOT:-0}" != "1" ]]; then
    echo "[ERROR] This script must be run as root."
    echo "        Run: sudo $0 $*"
    exit 1
fi

# =============================================================================
# MRK:12_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration | L64-133
# NAV-RULE: no-insert-before; propose-before-edit; read-toc-first
# =============================================================================

[[ -f "${SCRIPT_DIR}/pt-orc.conf" ]] && source "${SCRIPT_DIR}/pt-orc.conf" \
    || echo "[WARN] pt-orc.conf not found in ${SCRIPT_DIR}"

[[ -f "${SCRIPT_DIR}/orc-common-lib.sh" ]] && source "${SCRIPT_DIR}/orc-common-lib.sh" \
    || echo "[WARN] orc-common-lib.sh not found — trail/notes writes disabled"

PROJ_SLUG="${PROJECT_NAME//[^A-Za-z0-9._-]/_}"
EVIDENCE_BASE="${SCAN_EVIDENCE_DIR:-${SCRIPT_DIR}/evidence}/${PROJ_SLUG}"

CURL_TIMEOUT="${CURL_TIMEOUT:-10}"
CURL_CONNECT=5

CURL_PROXY_ARGS=()

PROFILE="standard"
SKIP_TESTS=()
ONLY_TESTS=()

_T_ENABLED=()
for _i in $(seq 1 8); do _T_ENABLED[$_i]=1; done

TIER="${GLOBAL_TIER:-normal}"
FROM_DB=1
AUTO_YES=0
DRY_RUN=0

BEARER_TOKEN=""
COOKIE_HEADER=""

EXTRA_HOSTS=()
TARGETS_FILE=""

# Cross-test state (reset per target in test_target)
_CSP_HEADER=""
_MAIN_HTML=""

tier_delay() { case "$1" in ghost) echo 2;; evasion) echo 3;; normal) echo 0;; loud) echo 0;; *) echo 0;; esac; }

TLS_PORTS="443 8443 4443 9443 10443"

# =============================================================================
# MRK:12_LOG — COLOURS AND LOGGING | log,colours,logging | L134-156
# NAV-RULE: no-insert-before
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

_ts()  { date +'%Y%m%d_%H%M%S'; }
_now() { date +'%Y-%m-%d %H:%M:%S'; }

SESSION_TS="$(_ts)"
EV_TS="$(_ev_ts)"
[[ "$EVIDENCE_BASE" != /* ]] && EVIDENCE_BASE="$(pwd)/${EVIDENCE_BASE}"
mkdir -p "${EVIDENCE_BASE}/_sweep" "${SCRIPT_DIR}/working"
LOG_FILE="${EVIDENCE_BASE}/_sweep/content_sec_${SESSION_TS}.log"
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "25-contentsec-findings" "jsonl")"
: > "$FINDINGS_FILE"

log()     { local m="[$(_now)] $1";   echo -e "${BLUE}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()  { local m="[$(_now)] ✓ $1"; echo -e "${GREEN}${m}${NC}" >&2;   echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn(){ local m="[$(_now)] ⚠ $1"; echo -e "${YELLOW}${m}${NC}" >&2;  echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err() { local m="[$(_now)] ✗ $1"; echo -e "${RED}${m}${NC}" >&2;     echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_info(){ local m="[$(_now)]   $1"; echo -e "${CYAN}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_hi()  { local m="[$(_now)] ! $1"; echo -e "${MAGENTA}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }

# =============================================================================
# MRK:12_ARGS — ARGUMENT PARSING | args,argument,parsing | L157-196
# NAV-RULE: no-insert-before
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)           TARGETS_FILE="$2";         FROM_DB=0; shift 2 ;;
        --host)              EXTRA_HOSTS+=("$2");        FROM_DB=0; shift 2 ;;
        --from-db)           FROM_DB=1;                             shift   ;;
        --tier)              TIER="$2";                             shift 2 ;;
        --token)             BEARER_TOKEN="$2";                     shift 2 ;;
        --cookie)            COOKIE_HEADER="$2";                    shift 2 ;;
        --profile)           PROFILE="$2";                          shift 2 ;;
        --skip-test)         SKIP_TESTS+=("$2");                    shift 2 ;;
        --only-test)         ONLY_TESTS+=("$2");                    shift 2 ;;
        --intercept-proxy)   CURL_PROXY_ARGS=("-x" "$2");           shift 2 ;;
        --yes)               AUTO_YES=1;                            shift   ;;
        --dry-run)           DRY_RUN=1;                             shift   ;;
        *) log_err "Unknown argument: $1"; exit 1 ;;
    esac
done

# =============================================================================
# MRK:12_DB — MSF DB HELPERS | db,msf,helpers,web,ports | L197-251
# NAV-RULE: no-insert-before; propose-before-edit; read-toc-first
# =============================================================================

MSF_DB_CONF="/usr/share/metasploit-framework/config/database.yml"
MSF_DB_USER="msf"; MSF_DB_NAME="msf"; MSF_DB_HOST="127.0.0.1"; MSF_DB_PORT="5432"
MSF_DB_PASS="${MSF_DB_PASS:-}"

parse_db_conf() {
    [[ -f "$MSF_DB_CONF" ]] || return
    MSF_DB_USER=$(grep -m1 'username:' "$MSF_DB_CONF" | awk '{print $2}' | tr -d "'\"" || echo "msf")
    MSF_DB_NAME=$(grep -m1 'database:'  "$MSF_DB_CONF" | awk '{print $2}' | tr -d "'\"" || echo "msf")
    MSF_DB_PORT=$(grep -m1 'port:'      "$MSF_DB_CONF" | awk '{print $2}' | tr -d "'\"" || echo "5432")
    MSF_DB_HOST="127.0.0.1"
    if [[ -z "${MSF_DB_PASS}" ]]; then
        MSF_DB_PASS=$(grep -m1 'password:' "$MSF_DB_CONF" | awk '{print $2}' | tr -d "'\"" 2>/dev/null || true)
    fi
    export MSF_DB_PASS
}

db_query() {
    PGPASSWORD="${MSF_DB_PASS:-}" psql -h "$MSF_DB_HOST" -p "$MSF_DB_PORT" \
        -U "$MSF_DB_USER" -d "$MSF_DB_NAME" -t -A -c "$1" 2>/dev/null || true
}

get_web_hosts_from_db() {
    local wid; wid=$(db_query \
        "SELECT id FROM workspaces WHERE name='${PROJECT_NAME}' LIMIT 1;")
    if [[ -z "$wid" ]]; then
        log_warn "get_web_hosts_from_db: workspace '${PROJECT_NAME}' not found — trying CSV fallback"
        _get_web_hosts_csv; return
    fi
    local web_ports="80,443,8080,8443,4443,8888,9443,9200,10443,8006"
    local result
    result=$(db_query "SELECT host(h.address) || ':' || s.port \
              FROM services s JOIN hosts h ON s.host_id = h.id \
              WHERE h.workspace_id=${wid} \
              AND s.proto='tcp' AND s.state='open' \
              AND s.port IN (${web_ports}) \
              ORDER BY host(h.address), s.port;")
    if [[ -n "$result" ]]; then
        echo "$result"
    else
        log_warn "get_web_hosts_from_db: no web ports found — trying CSV fallback"
        _get_web_hosts_csv
    fi
}

_get_web_hosts_csv() {
    local csv
    csv=$(find "${EVIDENCE_BASE}/_exports" -name 'services_tcp_*.csv' 2>/dev/null | sort | tail -1)
    [[ -z "$csv" ]] && return
    awk -F',' 'NR>1 && ($3=="80"||$3=="443"||$3=="8080"||$3=="8443"||$3=="4443") {print $1":"$3}' "$csv" 2>/dev/null || true
}

# =============================================================================
# MRK:12_CONFIRM — SCOPE CONFIRMATION | confirm,scope,confirmation | L252-266
# NAV-RULE: no-insert-before; propose-before-edit
# =============================================================================

confirm_scope() {
    local hosts=("$@")
    log_warn "=== SCOPE CONFIRMATION — Content Security Review v1.0 ==="
    log_warn "Profile: ${PROFILE} | Tier: ${TIER} | Tests: T01-T08"
    log_warn "Targets (${#hosts[@]}):"
    for h in "${hosts[@]}"; do log_warn "  → $h"; done
    [[ "${AUTO_YES:-0}" -eq 1 ]] && { log_ok "Auto-confirmed (--yes)"; return 0; }
    echo -en "${YELLOW}Proceed with Content Security review against these targets? [y/N]: ${NC}" >&2
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { log_err "Aborted by user."; exit 0; }
}

# =============================================================================
# MRK:12_TARGETS — TARGET ASSEMBLY | targets,target,assembly | L267-301
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

assemble_targets() {
    local -a all=()
    if [[ -n "$TARGETS_FILE" && -f "$TARGETS_FILE" ]]; then
        while IFS= read -r line; do
            line="${line%%#*}"; line="${line// /}"
            [[ -n "$line" ]] && all+=("$line")
        done < "$TARGETS_FILE"
    fi
    for h in "${EXTRA_HOSTS[@]+"${EXTRA_HOSTS[@]}"}"; do
        all+=("$h")
    done
    if [[ "${FROM_DB:-0}" -eq 1 && "${#all[@]}" -eq 0 ]]; then
        parse_db_conf
        local db_hosts
        db_hosts=$(get_web_hosts_from_db)
        if [[ -n "$db_hosts" ]]; then
            while IFS= read -r line; do
                [[ -n "$line" ]] && all+=("$line")
            done <<< "$db_hosts"
        fi
    fi
    if [[ "${#all[@]}" -eq 0 ]]; then
        log_err "No targets found. Use --host, --targets, or --from-db with an active MSF workspace."
        exit 1
    fi
    printf '%s\n' "${all[@]}"
}

# =============================================================================
# MRK:12_FIND — FINDING WRITER | find,finding,writer,jsonl,jq | L302-326
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

_FIND_CTR=0

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="$5"
    (( _FIND_CTR++ )) || true
    local ip_slug="${_CURRENT_IP//./_}"
    local fid="f-25-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local ev_id="ev-25-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"25_content_sec","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
        "$fid" \
        "$(echo "$title" | sed 's/"/\\"/g')" \
        "$sev" \
        "${ev_tag:-$ev_id}" \
        "$(echo "$desc"  | sed 's/"/\\"/g')" \
        "$(echo "$rec"   | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_hi "FINDING [${sev^^}]: ${title}"
}

# =============================================================================
# MRK:12_UTILS — SHARED UTILITIES | utils,shared,utilities,curl,proxy | L327-392
# NAV-RULE: no-insert-before
# =============================================================================

_curl() {
    if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
        log_info "  [DRY-RUN] curl -sk --max-time ${CURL_TIMEOUT} ${CURL_PROXY_ARGS[*]+"${CURL_PROXY_ARGS[*]}"} $*"
        return 0
    fi
    curl -sk --max-time "$CURL_TIMEOUT" --connect-timeout "$CURL_CONNECT" \
        "${CURL_PROXY_ARGS[@]+"${CURL_PROXY_ARGS[@]}"}" "$@" 2>/dev/null || true
}

_curl_head() { _curl -I "$@"; }

_auth_args() {
    local -a args=()
    [[ -n "${BEARER_TOKEN:-}" ]] && args+=(-H "Authorization: Bearer ${BEARER_TOKEN}")
    [[ -n "${COOKIE_HEADER:-}" ]] && args+=(-H "Cookie: ${COOKIE_HEADER}")
    printf '%s\n' "${args[@]+"${args[@]}"}"
}

_scheme() {
    local port="$1"
    if echo "$TLS_PORTS" | grep -qw "$port"; then echo "https"; else echo "http"; fi
}

_save_ev() {
    local evfile="$1"; shift
    echo "$@" >> "$evfile" 2>/dev/null || true
}

_tier_sleep() {
    local d; d=$(tier_delay "$TIER")
    [[ "$d" -gt 0 ]] && sleep "$d"
}

_test_skip() {
    local n="$1"
    if [[ "${#ONLY_TESTS[@]}" -gt 0 ]]; then
        local found=0
        for o in "${ONLY_TESTS[@]}"; do [[ "$o" == "$n" ]] && found=1; done
        [[ "$found" -eq 0 ]] && return 0
    fi
    for s in "${SKIP_TESTS[@]+"${SKIP_TESTS[@]}"}"; do
        [[ "$s" == "$n" ]] && return 0
    done
    local enabled="${_T_ENABLED[$n]:-1}"
    [[ "$enabled" -eq 0 ]] && return 0
    return 1
}

# =============================================================================
# MRK:12_PROF — PROFILE SETUP | prof,profile,setup,quick,deep | L393-430
# NAV-RULE: no-insert-before
# =============================================================================

setup_profile() {
    log_info "Profile: ${PROFILE}"
    case "$PROFILE" in
        quick)
            # T01 (CSP), T05 (cache), T06 (header info) — fast, header-only reads
            for i in 2 3 4 7 8; do _T_ENABLED[$i]=0; done
            ;;
        standard)
            # All except T08 (mixed content — fetches + HTML parsing)
            _T_ENABLED[8]=0
            ;;
        deep)
            # All 8 tests enabled
            ;;
        *)
            log_warn "Unknown profile '${PROFILE}' — using standard"
            _T_ENABLED[8]=0
            ;;
    esac
    for s in "${SKIP_TESTS[@]+"${SKIP_TESTS[@]}"}"; do _T_ENABLED[$s]=0; done
}

# =============================================================================
# MRK:12_T01 — T01 CSP DEEP ANALYSIS | t01,csp,policy,unsafe,directive | L431-545
# NAV-RULE: read-toc-first
# =============================================================================

test_25_t01_csp() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "contentsec-t01-csp" "txt")"
    log "T01: CSP Deep Analysis — ${base_url}"
    _SUMMARY_CSP=0

    # Fetch headers from root — capture full header block
    local hdr_resp
    hdr_resp=$(_curl -D - -o /dev/null "${base_url}/" || true)
    echo "$hdr_resp" >> "$evfile"

    # Extract CSP header (Content-Security-Policy; ignore -Report-Only for attack surface)
    local csp
    csp=$(echo "$hdr_resp" | grep -i '^content-security-policy:' | grep -iv 'report-only' | head -1 | tr -d '\r')
    _CSP_HEADER="$csp"   # set cross-test state for T03, T08

    echo "[T01] CSP header: ${csp:0:400}" >> "$evfile"

    if [[ -z "$csp" ]]; then
        # Step 09 T08 already emits MEDIUM for missing CSP; emit INFO here to note absence
        # without duplicating the higher-severity finding from the baseline step.
        emit_finding "info" \
            "No Content-Security-Policy Header — Deep CSP Analysis Not Possible (${ip}:${port})" \
            "No Content-Security-Policy header was returned by ${base_url}. Step 09 baseline already flags this as a medium-severity finding. Without a CSP, XSS payloads execute without restriction and mixed content loads freely." \
            "Implement a strict CSP. Start with default-src 'self', add explicit allowlists for scripts, styles, and fonts, and prohibit unsafe-inline and unsafe-eval. Use report-to to monitor violations before enforcing." \
            "ev-25-${ip//./_}-t01-csp-absent"
        log_ok "T01: No CSP present — skipping quality checks"
        return
    fi

    # Pattern-match for dangerous directives within the CSP string
    # unsafe-inline in script-src (or default-src as fallback)
    if echo "$csp" | grep -qi "script-src[^;]*unsafe-inline\|default-src[^;]*unsafe-inline"; then
        _SUMMARY_CSP=1
        emit_finding "high" \
            "CSP Allows 'unsafe-inline' in Script Sources (${ip}:${port})" \
            "The Content-Security-Policy header contains 'unsafe-inline' in the script-src or default-src directive. This completely negates XSS protection: any inline script injected by an attacker executes without restriction, even with a CSP in place." \
            "Remove 'unsafe-inline' from script-src. Refactor inline event handlers and <script> blocks into external files. If inline scripts are unavoidable, use nonces (combined with 'strict-dynamic') or hash-based CSP to allow specific known scripts only." \
            "ev-25-${ip//./_}-t01-unsafe-inline"
    fi

    # unsafe-eval in script-src
    if echo "$csp" | grep -qi "script-src[^;]*unsafe-eval\|default-src[^;]*unsafe-eval"; then
        _SUMMARY_CSP=1
        emit_finding "high" \
            "CSP Allows 'unsafe-eval' — eval() and Function() Unrestricted (${ip}:${port})" \
            "The CSP contains 'unsafe-eval' in script-src. This permits eval(), setTimeout(string), setInterval(string), and new Function() — common XSS gadgets used in framework-level attacks. Prototype pollution payloads routinely rely on eval() for code execution." \
            "Remove 'unsafe-eval'. Replace dynamic code evaluation with safer alternatives: setTimeout(fn) instead of setTimeout(string), JSON.parse() instead of eval(). Audit and eliminate all eval/Function usages in the codebase." \
            "ev-25-${ip//./_}-t01-unsafe-eval"
    fi

    # Wildcard (*) as a script or default source
    if echo "$csp" | grep -qiP "script-src\s+[^;]*(?<!')\*(?!')\s*[;$]|default-src\s+[^;]*(?<!')\*(?!')" 2>/dev/null || \
       echo "$csp" | grep -qi "script-src \*\|default-src \*\|script-src '\*'"; then
        _SUMMARY_CSP=1
        emit_finding "high" \
            "CSP Uses Wildcard (*) as Script Source — Policy Completely Bypassed (${ip}:${port})" \
            "The CSP script-src or default-src directive contains a bare wildcard (*), allowing scripts to load from any origin. An attacker can host malicious scripts on any domain and the CSP provides no protection against their execution." \
            "Replace wildcard sources with explicit domain allowlists. Use 'self' for same-origin scripts and list each trusted external domain individually. Audit all script load origins via a CSP report-uri before enforcing the strict policy." \
            "ev-25-${ip//./_}-t01-wildcard"
    fi

    # data: URI in script-src
    if echo "$csp" | grep -qi "script-src[^;]*data:\|default-src[^;]*data:"; then
        _SUMMARY_CSP=1
        emit_finding "high" \
            "CSP Allows 'data:' URIs in Script Sources — XSS Bypass Vector (${ip}:${port})" \
            "The CSP permits 'data:' URIs in script-src or default-src. An attacker can inject a script tag with src=data:text/javascript;base64,... to execute arbitrary code while satisfying the CSP constraint." \
            "Remove 'data:' from script-src. Data URIs for scripts are never legitimate in a production CSP. If base64-encoded resources are needed, serve them from the application origin with a proper MIME type." \
            "ev-25-${ip//./_}-t01-data-uri"
    fi

    # http: scheme allowed as source (allows downgrade to plain HTTP script load)
    if echo "$csp" | grep -qiP "script-src\s+[^;]*\bhttp://" 2>/dev/null || \
       echo "$csp" | grep -qi "script-src http://\|default-src http://"; then
        _SUMMARY_CSP=1
        emit_finding "high" \
            "CSP Allows Plain HTTP Script Sources — Enables MitM Script Injection (${ip}:${port})" \
            "The CSP script-src directive lists an http:// origin. This allows scripts to be loaded over unencrypted HTTP, making them vulnerable to man-in-the-middle substitution even if the page itself is served over HTTPS." \
            "Replace all http:// script source origins with https:// equivalents. Audit CDN and third-party script URLs in the application and ensure they all support HTTPS." \
            "ev-25-${ip//./_}-t01-http-src"
    fi

    # Missing base-uri directive (allows base tag injection to hijack all relative URLs)
    if ! echo "$csp" | grep -qi "base-uri"; then
        emit_finding "medium" \
            "CSP Missing 'base-uri' Directive — Base Tag Injection Possible (${ip}:${port})" \
            "The CSP does not include a base-uri directive. Without it, an attacker who can inject an HTML base tag can redirect all relative URLs in the page — including script src attributes — to an attacker-controlled domain, bypassing the CSP allowlist." \
            "Add 'base-uri 'none'' or 'base-uri 'self'' to the CSP. Use 'none' if the application does not use a <base> tag; use 'self' if it does and must remain functional." \
            "ev-25-${ip//./_}-t01-base-uri"
    fi

    # Missing form-action directive (allows form submission to arbitrary URLs)
    if ! echo "$csp" | grep -qi "form-action"; then
        emit_finding "medium" \
            "CSP Missing 'form-action' Directive — Form Phishing Redirect Unrestricted (${ip}:${port})" \
            "The CSP does not specify a form-action directive. Without it, an attacker who can modify a form's action attribute (e.g., via XSS or DOM clobbering) can redirect form submissions — including credentials — to an attacker-controlled server. The default-src fallback does NOT cover form-action." \
            "Add 'form-action 'self'' to the CSP to restrict form submissions to the same origin. Expand the allowlist only for specific third-party payment or SSO providers that require form post." \
            "ev-25-${ip//./_}-t01-form-action"
    fi

    # Missing object-src (permits Flash/plugins if default-src is permissive)
    if ! echo "$csp" | grep -qi "object-src"; then
        if echo "$csp" | grep -qi "default-src \*\|default-src 'none'"; then
            : # wildcard already flagged above; 'none' is safe
        else
            emit_finding "medium" \
                "CSP Missing 'object-src' Directive — Plugin Execution Falls Back to default-src (${ip}:${port})" \
                "The CSP lacks an explicit object-src directive. Without it, object and embed tags (historically used by Flash/Silverlight and still exploitable in some browsers) are governed only by default-src. If default-src is permissive, plugins can load from untrusted origins." \
                "Add 'object-src 'none'' to the CSP. Modern applications have no legitimate use for browser plugins via object/embed tags." \
                "ev-25-${ip//./_}-t01-object-src"
        fi
    fi

    # Deprecated report-uri (should migrate to report-to)
    if echo "$csp" | grep -qi "report-uri" && ! echo "$csp" | grep -qi "report-to"; then
        emit_finding "low" \
            "CSP Uses Deprecated 'report-uri' — Migrate to 'report-to' Directive (${ip}:${port})" \
            "The CSP uses the deprecated report-uri directive without the newer report-to. The report-uri directive is deprecated in CSP Level 3 and is not supported for network error logging or grouped reports in modern browser reporting APIs." \
            "Migrate to the Reporting API: add a Report-To response header and use the 'report-to <group-name>' CSP directive. Keep report-uri as a fallback during transition for older browsers." \
            "ev-25-${ip//./_}-t01-report-uri"
    fi

    [[ "${_SUMMARY_CSP}" -eq 0 ]] && log_ok "T01: No critical CSP quality issues detected"
    log_info "T01: CSP quality analysis complete"
}

# =============================================================================
# MRK:12_T02 — T02 SUBRESOURCE INTEGRITY | t02,sri,integrity,cdn,script | L546-625
# NAV-RULE: read-toc-first
# =============================================================================

test_25_t02_sri() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "contentsec-t02-sri" "txt")"
    log "T02: Subresource Integrity — ${base_url}"
    _SUMMARY_SRI=0

    # Fetch main page HTML; store in cross-test state for T08 reuse
    _MAIN_HTML=$(_curl "${base_url}/" || true)
    echo "[T02] HTML length: ${#_MAIN_HTML}" >> "$evfile"
    echo "${_MAIN_HTML:0:3000}" >> "$evfile"

    if [[ -z "$_MAIN_HTML" ]]; then
        log_ok "T02: No HTML body returned — skipping SRI checks"
        return
    fi

    # Detect external script tags without integrity attribute
    # Match: <script src="http(s)://external-domain..."> where no integrity= present on same tag
    local ext_scripts_no_sri=0
    local ext_styles_no_sri=0
    local sri_no_crossorigin=0

    # Extract all script tags with external src
    while IFS= read -r script_tag; do
        [[ -z "$script_tag" ]] && continue
        # Skip same-origin references
        echo "$script_tag" | grep -qi "src=['\"]/" && continue
        echo "$script_tag" | grep -qi "src=['\"]${base_url}" && continue
        # External src present
        if ! echo "$script_tag" | grep -qi "integrity="; then
            echo "[T02] External script without SRI: ${script_tag:0:200}" >> "$evfile"
            (( ext_scripts_no_sri++ )) || true
        elif ! echo "$script_tag" | grep -qi "crossorigin"; then
            echo "[T02] SRI present but missing crossorigin: ${script_tag:0:200}" >> "$evfile"
            (( sri_no_crossorigin++ )) || true
        fi
    done < <(echo "$_MAIN_HTML" | grep -oi '<script[^>]*src=["\''http[^>]*>' 2>/dev/null || true)

    # Extract all external stylesheet link tags
    while IFS= read -r link_tag; do
        [[ -z "$link_tag" ]] && continue
        echo "$link_tag" | grep -qi "href=['\"]/" && continue
        echo "$link_tag" | grep -qi "href=['\"]${base_url}" && continue
        if ! echo "$link_tag" | grep -qi "integrity="; then
            echo "[T02] External stylesheet without SRI: ${link_tag:0:200}" >> "$evfile"
            (( ext_styles_no_sri++ )) || true
        fi
    done < <(echo "$_MAIN_HTML" | grep -oi '<link[^>]*rel=["\''stylesheet["\''[^>]*href=["\''http[^>]*>' 2>/dev/null || true)

    echo "[T02] External scripts without SRI: ${ext_scripts_no_sri}" >> "$evfile"
    echo "[T02] External stylesheets without SRI: ${ext_styles_no_sri}" >> "$evfile"
    echo "[T02] SRI without crossorigin: ${sri_no_crossorigin}" >> "$evfile"

    if [[ "$ext_scripts_no_sri" -gt 0 ]]; then
        _SUMMARY_SRI=1
        emit_finding "high" \
            "Subresource Integrity Missing on ${ext_scripts_no_sri} External Script(s) (${ip}:${port})" \
            "${ext_scripts_no_sri} external JavaScript file(s) are loaded without a Subresource Integrity (SRI) integrity attribute. If any of these CDN or third-party hosts is compromised, malicious code can be injected into the script file and will execute in the context of this application without detection." \
            "Add integrity and crossorigin='anonymous' attributes to all external script tags. Generate SRI hashes using: openssl dgst -sha384 -binary <file> | openssl base64 -A. Use a build tool plugin (webpack-subresource-integrity, sri-webpack-plugin) to automate this for bundled assets." \
            "ev-25-${ip//./_}-t02-sri-scripts"
    fi

    if [[ "$ext_styles_no_sri" -gt 0 ]]; then
        _SUMMARY_SRI=1
        emit_finding "medium" \
            "Subresource Integrity Missing on ${ext_styles_no_sri} External Stylesheet(s) (${ip}:${port})" \
            "${ext_styles_no_sri} external CSS file(s) are loaded without a SRI integrity attribute. Compromised CSS can exfiltrate form data via attribute selectors and background-image: url() tricks, or alter the page layout to mislead users." \
            "Add integrity and crossorigin='anonymous' attributes to all external <link rel='stylesheet'> tags. Generate hashes with openssl or a build tool plugin. Prefer self-hosting critical CSS to eliminate the CDN trust dependency." \
            "ev-25-${ip//./_}-t02-sri-styles"
    fi

    if [[ "$sri_no_crossorigin" -gt 0 ]]; then
        emit_finding "low" \
            "SRI Integrity Attribute Present But 'crossorigin' Missing — SRI Not Enforced (${ip}:${port})" \
            "${sri_no_crossorigin} script tag(s) have an integrity attribute but are missing crossorigin='anonymous'. Without the crossorigin attribute, the browser fetches the resource without CORS headers and cannot verify the integrity hash — the integrity check is silently skipped by the browser." \
            "Add crossorigin='anonymous' to all script and link tags that have an integrity attribute. Ensure the CDN serves the resource with Access-Control-Allow-Origin: * so the CORS request succeeds." \
            "ev-25-${ip//./_}-t02-sri-crossorigin"
    fi

    [[ "${_SUMMARY_SRI}" -eq 0 && "$ext_scripts_no_sri" -eq 0 && "$sri_no_crossorigin" -eq 0 ]] && \
        log_ok "T02: SRI checks passed — no external scripts without integrity attributes"
}

# =============================================================================
# MRK:12_T03 — T03 CLICKJACKING DEEP | t03,clickjack,frame,ancestors,xfo | L626-700
# NAV-RULE: read-toc-first
# =============================================================================

test_25_t03_clickjack() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "contentsec-t03-clickjack" "txt")"
    log "T03: Clickjacking Deep — ${base_url}"
    _SUMMARY_CLICKJACK=0

    # Re-use headers from root — fetch if we don't have them cached
    local hdr_resp
    hdr_resp=$(_curl -D - -o /dev/null "${base_url}/" || true)
    echo "$hdr_resp" >> "$evfile"

    local xfo; xfo=$(echo "$hdr_resp" | grep -i '^x-frame-options:' | head -1 | tr -d '\r')
    # _CSP_HEADER already set by T01; re-fetch headers here if T01 was skipped
    local csp="${_CSP_HEADER:-}"
    [[ -z "$csp" ]] && csp=$(echo "$hdr_resp" | grep -i '^content-security-policy:' | head -1 | tr -d '\r')

    local fa_directive; fa_directive=$(echo "$csp" | grep -oi "frame-ancestors[^;]*" || true)

    echo "[T03] X-Frame-Options: ${xfo:-'(absent)'}" >> "$evfile"
    echo "[T03] frame-ancestors: ${fa_directive:-'(absent)'}" >> "$evfile"

    # No protection at all: no frame-ancestors in CSP and no X-Frame-Options
    if [[ -z "$xfo" && -z "$fa_directive" ]]; then
        _SUMMARY_CLICKJACK=1
        emit_finding "high" \
            "Clickjacking — No Framing Protection (No X-Frame-Options or frame-ancestors) (${ip}:${port})" \
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is present on ${base_url}. Any website can embed this page in an invisible iframe and trick authenticated users into performing unintended actions (clickjacking / UI redressing)." \
            "Add a CSP frame-ancestors directive: 'Content-Security-Policy: frame-ancestors 'self';'. For legacy browser support, also add 'X-Frame-Options: SAMEORIGIN'. The CSP directive takes precedence over X-Frame-Options in modern browsers." \
            "ev-25-${ip//./_}-t03-no-frame-protection"

    # frame-ancestors present — check quality
    elif [[ -n "$fa_directive" ]]; then
        # Wildcard in frame-ancestors
        if echo "$fa_directive" | grep -q " \* "; then
            _SUMMARY_CLICKJACK=1
            emit_finding "high" \
                "CSP frame-ancestors Uses Wildcard — Framing Unrestricted (${ip}:${port})" \
                "The CSP frame-ancestors directive contains a bare wildcard (*), allowing any origin to frame the page. This is equivalent to having no clickjacking protection at all." \
                "Replace 'frame-ancestors *' with 'frame-ancestors 'self'' or an explicit allowlist of trusted embedding domains." \
                "ev-25-${ip//./_}-t03-fa-wildcard"
        else
            log_ok "T03: frame-ancestors directive present and restricted: ${fa_directive}"
        fi

        # X-Frame-Options also present alongside frame-ancestors (redundant but harmless)
        if [[ -n "$xfo" ]]; then
            emit_finding "low" \
                "Redundant X-Frame-Options Alongside CSP frame-ancestors (${ip}:${port})" \
                "Both X-Frame-Options and CSP frame-ancestors are set. Modern browsers use frame-ancestors exclusively, ignoring X-Frame-Options when a CSP is present. While harmless, maintaining both adds noise and can cause confusion during policy updates." \
                "Remove X-Frame-Options once frame-ancestors is confirmed working and tested. Keep X-Frame-Options only for IE11 compatibility if that browser is in scope." \
                "ev-25-${ip//./_}-t03-redundant-xfo"
        fi

    # Only X-Frame-Options, no CSP frame-ancestors
    elif [[ -n "$xfo" ]]; then
        # ALLOW-FROM is deprecated and not supported in Chrome/Firefox/Edge
        if echo "$xfo" | grep -qi "allow-from"; then
            _SUMMARY_CLICKJACK=1
            emit_finding "medium" \
                "X-Frame-Options Uses Deprecated ALLOW-FROM — No Protection in Modern Browsers (${ip}:${port})" \
                "X-Frame-Options: ALLOW-FROM is deprecated and is not honoured by Chrome, Firefox, or Edge. An attacker using a modern browser can freely embed this page in an iframe regardless of the ALLOW-FROM value." \
                "Replace X-Frame-Options: ALLOW-FROM with a CSP frame-ancestors directive, which supports per-origin allowlists and is honoured by all modern browsers: Content-Security-Policy: frame-ancestors 'self' https://trusted-parent.example.com." \
                "ev-25-${ip//./_}-t03-allow-from"
        elif echo "$xfo" | grep -qi "sameorigin\|deny"; then
            emit_finding "low" \
                "Clickjacking Protection via X-Frame-Options Only — CSP frame-ancestors Missing (${ip}:${port})" \
                "X-Frame-Options is set (${xfo}) but no CSP frame-ancestors directive is present. X-Frame-Options is a legacy mechanism that is superseded by frame-ancestors; some specification versions note it as obsolete. Additionally, X-Frame-Options cannot express allowlists of specific trusted origins." \
                "Add a CSP frame-ancestors directive that mirrors the X-Frame-Options intent. Keep X-Frame-Options for IE11 support if required." \
                "ev-25-${ip//./_}-t03-xfo-only"
        fi
    fi

    [[ "${_SUMMARY_CLICKJACK}" -eq 0 ]] && log_ok "T03: Clickjacking protection review complete"
}

# =============================================================================
# MRK:12_T04 — T04 CROSS-ORIGIN POLICIES | t04,corp,coep,coop,crossorigin | L701-780
# NAV-RULE: read-toc-first
# =============================================================================

test_25_t04_crossorigin() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "contentsec-t04-crossorigin" "txt")"
    log "T04: Cross-Origin Isolation Policies — ${base_url}"
    _SUMMARY_CROSSORIGIN=0

    local hdr_resp
    hdr_resp=$(_curl -D - -o /dev/null "${base_url}/" || true)
    echo "$hdr_resp" >> "$evfile"

    local corp; corp=$(echo  "$hdr_resp" | grep -i '^cross-origin-resource-policy:'   | head -1 | tr -d '\r')
    local coep; coep=$(echo  "$hdr_resp" | grep -i '^cross-origin-embedder-policy:'   | head -1 | tr -d '\r')
    local coop; coop=$(echo  "$hdr_resp" | grep -i '^cross-origin-opener-policy:'     | head -1 | tr -d '\r')

    echo "[T04] CORP: ${corp:-'(absent)'}" >> "$evfile"
    echo "[T04] COEP: ${coep:-'(absent)'}" >> "$evfile"
    echo "[T04] COOP: ${coop:-'(absent)'}" >> "$evfile"

    # COEP present but COOP absent → incomplete isolation (the more actionable finding)
    if [[ -n "$coep" && -z "$coop" ]]; then
        _SUMMARY_CROSSORIGIN=1
        emit_finding "medium" \
            "Incomplete Cross-Origin Isolation — COEP Set Without COOP (${ip}:${port})" \
            "Cross-Origin-Embedder-Policy (${coep}) is present but Cross-Origin-Opener-Policy is absent. Both COEP and COOP must be set together to achieve cross-origin isolation (required for SharedArrayBuffer and high-resolution timers). A partial configuration provides no isolation benefit and can cause unnecessary CORS failures." \
            "Add 'Cross-Origin-Opener-Policy: same-origin' to complement COEP. Verify that all embedded subresources serve either CORP: same-origin/same-site or COEP-compatible headers. Test in staging before deploying, as COEP+COOP breaks pages that embed cross-origin iframes without explicit opt-in." \
            "ev-25-${ip//./_}-t04-coep-no-coop"

    # COOP present but COEP absent → mirror case
    elif [[ -z "$coep" && -n "$coop" ]]; then
        _SUMMARY_CROSSORIGIN=1
        emit_finding "medium" \
            "Incomplete Cross-Origin Isolation — COOP Set Without COEP (${ip}:${port})" \
            "Cross-Origin-Opener-Policy (${coop}) is present but Cross-Origin-Embedder-Policy is absent. Without COEP, cross-origin isolation is not achieved. The COOP header alone prevents opener access between windows but does not enable the SharedArrayBuffer and Spectre mitigations that require full isolation." \
            "Add 'Cross-Origin-Embedder-Policy: require-corp' alongside COOP. Ensure all first-party subresources set CORP: same-origin and that cross-origin embeds use credentialless or opt in with CORP: cross-origin." \
            "ev-25-${ip//./_}-t04-coop-no-coep"

    # All three absent — INFO, not directly exploitable but relevant for modern browser security
    elif [[ -z "$corp" && -z "$coep" && -z "$coop" ]]; then
        emit_finding "info" \
            "Cross-Origin Isolation Headers Absent — Spectre Mitigations Unavailable (${ip}:${port})" \
            "None of CORP, COEP, or COOP headers are present. Without these headers, the application cannot achieve cross-origin isolation, which is required to safely enable SharedArrayBuffer and high-resolution timers. Browsers limit these APIs to isolated contexts to mitigate Spectre-class timing attacks." \
            "If the application uses SharedArrayBuffer or high-resolution performance APIs, add Cross-Origin-Opener-Policy: same-origin and Cross-Origin-Embedder-Policy: require-corp. For other applications, consider adding COOP: same-origin as a defence-in-depth measure against cross-window opener attacks." \
            "ev-25-${ip//./_}-t04-no-isolation"
    fi

    # CORP: cross-origin is explicitly permissive (defeats the policy purpose)
    if echo "$corp" | grep -qi "cross-origin"; then
        emit_finding "low" \
            "CORP Set to 'cross-origin' — Resource Loadable by Any Origin (${ip}:${port})" \
            "Cross-Origin-Resource-Policy: cross-origin explicitly allows any website to embed or fetch this resource. While this is sometimes intentional for public CDN assets, it should be verified that sensitive resources do not carry this header." \
            "Audit which resources carry CORP: cross-origin. For sensitive API responses or authenticated content, restrict to CORP: same-site or CORP: same-origin. Reserve cross-origin only for truly public static assets." \
            "ev-25-${ip//./_}-t04-corp-open"
    fi

    [[ "${_SUMMARY_CROSSORIGIN}" -eq 0 ]] && log_ok "T04: Cross-origin policy review complete"
}

# =============================================================================
# MRK:12_T05 — T05 CACHE SECURITY | t05,cache,no-store,private,cdn | L781-865
# NAV-RULE: read-toc-first
# =============================================================================

test_25_t05_cache() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "contentsec-t05-cache" "txt")"
    log "T05: Cache Security — ${base_url}"
    _SUMMARY_CACHE=0

    local -a auth_args=(); mapfile -t auth_args < <(_auth_args)

    # Authenticated/sensitive endpoint paths most likely to carry private data
    local sensitive_paths=(
        "/api/me"           "/api/profile"      "/api/account"
        "/api/user"         "/api/settings"     "/dashboard"
        "/admin"            "/api/v1/me"         "/api/v1/profile"
        "/account"          "/profile"           "/user/settings"
    )

    local flagged_nostore=0 flagged_private=0 flagged_smaxage=0

    for path in "${sensitive_paths[@]}"; do
        local hdr_resp code
        hdr_resp=$(_curl -D - -o /dev/null "${auth_args[@]+"${auth_args[@]}"}" "${base_url}${path}" || true)
        code=$(echo "$hdr_resp" | grep -m1 '^HTTP/' | awk '{print $2}' | tr -d '\r')
        [[ "$code" != "200" && "$code" != "201" ]] && continue

        local cache_hdr; cache_hdr=$(echo "$hdr_resp" | grep -i '^cache-control:' | head -1 | tr -d '\r')
        echo "[T05] ${path}: HTTP ${code} | Cache-Control: ${cache_hdr:-'(absent)'}" >> "$evfile"

        # Missing no-store on authenticated page → HIGH (private data may be cached by browser/proxy)
        if [[ "$flagged_nostore" -eq 0 ]] && ! echo "$cache_hdr" | grep -qi "no-store"; then
            flagged_nostore=1
            _SUMMARY_CACHE=1
            emit_finding "high" \
                "Cache-Control: no-store Missing on Authenticated Endpoint (${ip}:${port})" \
                "Authenticated endpoint ${base_url}${path} returned HTTP 200 without Cache-Control: no-store. The response may be stored by browser caches, shared proxy caches, or CDN nodes. A subsequent user on a shared device or a user who views browser history can access cached private data without re-authentication." \
                "Set 'Cache-Control: no-store, no-cache, must-revalidate' on all responses that carry authenticated or sensitive data. Do not rely on Cache-Control: private alone — it does not prevent browser disk caching. Apply these headers in the application layer for all /api/*, /dashboard, /admin, and /profile routes." \
                "ev-25-${ip//./_}-t05-no-store"
        fi

        # Missing private: allows shared/CDN caches to store the response
        if [[ "$flagged_private" -eq 0 ]] && \
           ! echo "$cache_hdr" | grep -qi "private\|no-store"; then
            flagged_private=1
            _SUMMARY_CACHE=1
            emit_finding "medium" \
                "Cache-Control Missing 'private' Directive on Authenticated Endpoint (${ip}:${port})" \
                "Authenticated endpoint ${base_url}${path} returned HTTP 200 without Cache-Control: private. Responses without the private directive can be stored by shared caches (reverse proxies, CDN edge nodes). Another user whose request is served the cached response receives the previous user's private data." \
                "Add 'Cache-Control: private, no-store' to all authenticated API responses. Configure your CDN or reverse proxy to honour Cache-Control: private and bypass caching for these routes." \
                "ev-25-${ip//./_}-t05-missing-private"
        fi

        # s-maxage without private → CDN will cache the response as shared
        if [[ "$flagged_smaxage" -eq 0 ]] && \
           echo "$cache_hdr" | grep -qi "s-maxage" && \
           ! echo "$cache_hdr" | grep -qi "private\|no-store"; then
            flagged_smaxage=1
            _SUMMARY_CACHE=1
            emit_finding "high" \
                "Cache-Control: s-maxage Without 'private' — CDN Caches Private Response (${ip}:${port})" \
                "Authenticated endpoint ${base_url}${path} sets Cache-Control: s-maxage without the private directive. The s-maxage directive explicitly targets shared/CDN caches and without private, CDN nodes will store and serve this response to other users." \
                "Remove s-maxage from authenticated responses, or combine it with Cache-Control: private (which overrides s-maxage for shared caches). Add no-store for fully private endpoints." \
                "ev-25-${ip//./_}-t05-smaxage"
        fi

        # Pragma: no-cache without Cache-Control (legacy, unreliable in HTTP/1.1+)
        local pragma; pragma=$(echo "$hdr_resp" | grep -i '^pragma:' | head -1 | tr -d '\r')
        if echo "$pragma" | grep -qi "no-cache" && [[ -z "$cache_hdr" ]]; then
            emit_finding "low" \
                "Cache Controlled Only via Pragma: no-cache — Cache-Control Header Absent (${ip}:${port})" \
                "Endpoint ${base_url}${path} uses Pragma: no-cache without a Cache-Control header. Pragma: no-cache is an HTTP/1.0 legacy header; HTTP/1.1 caches use Cache-Control exclusively and may ignore Pragma." \
                "Add an explicit Cache-Control header. Use Cache-Control: no-store, no-cache, must-revalidate for sensitive pages. Remove reliance on Pragma: no-cache." \
                "ev-25-${ip//./_}-t05-pragma"
            break
        fi
        _tier_sleep
    done

    [[ "${_SUMMARY_CACHE}" -eq 0 ]] && log_ok "T05: Cache security checks passed on probed endpoints"
}

# =============================================================================
# MRK:12_T06 — T06 HEADER INFO DISCLOSURE | t06,header,debug,xaspnet,runtime | L866-945
# NAV-RULE: read-toc-first
# Note: deliberately omits Server and X-Powered-By — already covered by step 09 T08.
# =============================================================================

test_25_t06_hdrinfo() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "contentsec-t06-hdrinfo" "txt")"
    log "T06: Header Information Disclosure — ${base_url}"
    _SUMMARY_HDRINFO=0

    local hdr_resp
    hdr_resp=$(_curl -D - -o /dev/null "${base_url}/" || true)
    echo "$hdr_resp" >> "$evfile"

    # X-Debug-Token / X-Debug-Token-Link (Symfony debug toolbar)
    local debug_tok; debug_tok=$(echo "$hdr_resp" | grep -i '^x-debug-token' | head -1 | tr -d '\r')
    if [[ -n "$debug_tok" ]]; then
        _SUMMARY_HDRINFO=1
        emit_finding "high" \
            "Symfony Debug Toolbar Exposed — X-Debug-Token Header Present (${ip}:${port})" \
            "The response contains '${debug_tok}'. This header is emitted by the Symfony debug toolbar and indicates the application is running in debug mode. The X-Debug-Token-Link header provides a URL to the full profiler, which exposes stack traces, SQL queries, environment variables, service container configuration, and session data to unauthenticated visitors." \
            "Disable debug mode in production: set APP_ENV=prod in your .env file and ensure APP_DEBUG=false. Remove the debug profiler bundle from the production dependency list. Never deploy an application with debug mode enabled." \
            "ev-25-${ip//./_}-t06-debug-token"
    fi

    # X-AspNet-Version / X-AspNetMvc-Version
    local aspnet_ver; aspnet_ver=$(echo "$hdr_resp" | grep -i '^x-aspnet\|^x-aspnetmvc' | head -1 | tr -d '\r')
    if [[ -n "$aspnet_ver" ]]; then
        emit_finding "low" \
            "ASP.NET Version Disclosed via Response Header (${ip}:${port})" \
            "Header '${aspnet_ver}' reveals the exact ASP.NET or ASP.NET MVC runtime version. Attackers use version strings to look up known CVEs and target patch-level vulnerabilities." \
            "Suppress version headers in web.config: set <httpRuntime enableVersionHeader='false'/> and remove X-AspNetMvc-Version in Application_Start by calling MvcHandler.DisableMvcResponseHeader = true." \
            "ev-25-${ip//./_}-t06-aspnet-ver"
    fi

    # X-Runtime (Ruby on Rails response time benchmark — discloses tech stack)
    local runtime; runtime=$(echo "$hdr_resp" | grep -i '^x-runtime:' | head -1 | tr -d '\r')
    if [[ -n "$runtime" ]]; then
        emit_finding "low" \
            "Ruby on Rails Fingerprint — X-Runtime Header Disclosed (${ip}:${port})" \
            "'${runtime}' reveals this application runs on Ruby on Rails. Combined with version information from other sources, this aids targeted exploitation of framework-level CVEs." \
            "Suppress X-Runtime in production: add 'config.middleware.delete ActionDispatch::RequestId' or configure Rack to strip the header before sending." \
            "ev-25-${ip//./_}-t06-xruntime"
    fi

    # Via header (proxy chain disclosure)
    local via_hdr; via_hdr=$(echo "$hdr_resp" | grep -i '^via:' | head -1 | tr -d '\r')
    if [[ -n "$via_hdr" ]]; then
        emit_finding "low" \
            "Internal Proxy Chain Disclosed via 'Via' Header (${ip}:${port})" \
            "'${via_hdr}' reveals the intermediate proxy or load-balancer chain, including hostnames or software versions. Attackers use this information to fingerprint the network topology and target proxy-specific vulnerabilities." \
            "Configure reverse proxies and load balancers to strip or genericise the Via header before forwarding to clients. In nginx: proxy_hide_header Via; In HAProxy: option forwardfor, rspidel ^Via:." \
            "ev-25-${ip//./_}-t06-via"
    fi

    # traceparent / tracestate (distributed tracing — leaks internal request IDs)
    local traceparent; traceparent=$(echo "$hdr_resp" | grep -i '^traceparent:\|^tracestate:' | head -1 | tr -d '\r')
    if [[ -n "$traceparent" ]]; then
        emit_finding "low" \
            "Distributed Tracing Headers Exposed to Clients (${ip}:${port})" \
            "'${traceparent}' is returned in the response. Trace IDs leak internal request correlation identifiers and may reveal infrastructure topology to clients. Trace context should propagate only between internal services." \
            "Strip traceparent and tracestate headers at the edge/API gateway before sending responses to external clients. Configure the tracing exporter to add headers only on outbound internal calls, not on final client-facing responses." \
            "ev-25-${ip//./_}-t06-traceparent"
    fi

    # X-Generator (CMS fingerprint: Drupal, WordPress plugin headers, etc.)
    local generator; generator=$(echo "$hdr_resp" | grep -i '^x-generator:\|^x-drupal-cache:\|^x-drupal-dynamic-cache:\|^x-wp-' | head -1 | tr -d '\r')
    if [[ -n "$generator" ]]; then
        emit_finding "low" \
            "CMS / Framework Fingerprint via Response Header (${ip}:${port})" \
            "'${generator}' reveals the content management system or framework. CMS-specific headers (X-Generator, X-Drupal-Cache, X-WP-*) enable targeted attacks against known CMS vulnerabilities and default configurations." \
            "Remove or suppress CMS-specific response headers via server-side configuration. For Drupal: add ResponseHeaderParameters in settings.php. For WordPress: use a security plugin or modify the theme's functions.php to suppress headers." \
            "ev-25-${ip//./_}-t06-generator"
    fi

    # X-Varnish / X-Cache (CDN/cache layer fingerprinting)
    local varnish_hdr; varnish_hdr=$(echo "$hdr_resp" | grep -i '^x-varnish:\|^x-cache:\|^x-cache-hits:' | head -1 | tr -d '\r')
    if [[ -n "$varnish_hdr" ]]; then
        emit_finding "low" \
            "Cache Layer Fingerprinted via Response Header (${ip}:${port})" \
            "'${varnish_hdr}' indicates the presence and behaviour of an intermediate caching layer (Varnish, CloudFront, Fastly, etc.). Cache-layer fingerprinting aids web cache poisoning attacks and cache-deception exploitation." \
            "Strip internal cache diagnostic headers (X-Varnish, X-Cache, X-Cache-Hits) at the CDN/edge before delivering responses to clients. These are useful for internal debugging but should not be exposed publicly." \
            "ev-25-${ip//./_}-t06-cache-fingerprint"
    fi

    [[ "${_SUMMARY_HDRINFO}" -eq 0 ]] && log_ok "T06: No high-severity header information disclosure detected"
}

# =============================================================================
# MRK:12_T07 — T07 COOKIE SECURITY DEEP | t07,cookie,samesite,host,domain | L946-1045
# NAV-RULE: read-toc-first
# Note: avoids duplicating step 23 T07 (Secure/HttpOnly/SameSite presence checks).
#   Focuses on: __Secure-/__Host- prefix enforcement, Domain= scope, Max-Age bounds,
#   SameSite=None + !Secure combination.
# =============================================================================

test_25_t07_cookie() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "contentsec-t07-cookie" "txt")"
    log "T07: Cookie Security Deep — ${base_url}"
    _SUMMARY_COOKIE=0

    local scheme; scheme=$(_scheme "$port")

    # Collect Set-Cookie headers from several common paths
    local cookie_paths=("/" "/login" "/api/auth/login" "/auth" "/dashboard" "/account")
    local all_cookies=""
    for path in "${cookie_paths[@]}"; do
        local hdr_resp
        hdr_resp=$(_curl -D - -o /dev/null "${base_url}${path}" || true)
        local cookies; cookies=$(echo "$hdr_resp" | grep -i '^set-cookie:' | tr -d '\r')
        if [[ -n "$cookies" ]]; then
            all_cookies+="${cookies}"$'\n'
            echo "[T07] Set-Cookie from ${path}:" >> "$evfile"
            echo "$cookies" >> "$evfile"
        fi
        _tier_sleep
    done

    if [[ -z "$all_cookies" ]]; then
        log_ok "T07: No Set-Cookie headers found on probed paths"
        return
    fi

    # Check 1: SameSite=None without Secure (allows cross-site cookie sending over HTTP)
    while IFS= read -r cookie_line; do
        [[ -z "$cookie_line" ]] && continue
        if echo "$cookie_line" | grep -qi "samesite=none" && \
           ! echo "$cookie_line" | grep -qi "; *secure\b"; then
            _SUMMARY_COOKIE=1
            emit_finding "high" \
                "Cookie SameSite=None Without Secure — Cross-Site Cookie Sent Over HTTP (${ip}:${port})" \
                "A cookie with SameSite=None is set without the Secure flag: $(echo "$cookie_line" | head -c 200). Per RFC 6265bis, browsers should reject SameSite=None cookies that lack the Secure attribute. However, some older browsers silently accept them, allowing the cookie to be sent on plain HTTP cross-site requests — defeating the CSRF protection SameSite=None intends to provide." \
                "All cookies with SameSite=None must also include the Secure flag. Audit why SameSite=None is required — it should only be used for cross-site embeds such as payment widgets or iframe integrations. Default to SameSite=Strict or SameSite=Lax." \
                "ev-25-${ip//./_}-t07-samesite-none"
            break
        fi
    done <<< "$all_cookies"

    # Check 2: __Secure- prefix without Secure flag (prefix semantics violated)
    while IFS= read -r cookie_line; do
        [[ -z "$cookie_line" ]] && continue
        if echo "$cookie_line" | grep -qi "set-cookie: *__secure-" && \
           ! echo "$cookie_line" | grep -qi "; *secure\b"; then
            _SUMMARY_COOKIE=1
            emit_finding "medium" \
                "Cookie with __Secure- Prefix Missing Secure Flag — Prefix Enforcement Violated (${ip}:${port})" \
                "A cookie uses the __Secure- prefix but lacks the Secure attribute: $(echo "$cookie_line" | head -c 200). The __Secure- prefix is intended to guarantee the cookie is only sent over HTTPS. Without the Secure flag, the prefix constraint is not enforced by the browser and the cookie may be sent over plain HTTP." \
                "All cookies with the __Secure- prefix must set the Secure attribute. If the Secure flag cannot be set (e.g., HTTP-only development environment), rename the cookie to remove the prefix until HTTPS is enforced." \
                "ev-25-${ip//./_}-t07-secure-prefix"
            break
        fi
    done <<< "$all_cookies"

    # Check 3: __Host- prefix enforcement (__Host- requires: Secure, no Domain=, Path=/)
    while IFS= read -r cookie_line; do
        [[ -z "$cookie_line" ]] && continue
        if echo "$cookie_line" | grep -qi "set-cookie: *__host-"; then
            local host_ok=1
            ! echo "$cookie_line" | grep -qi "; *secure\b"  && host_ok=0
            echo  "$cookie_line"  | grep -qi "; *domain="    && host_ok=0
            ! echo "$cookie_line" | grep -qi "; *path=/"     && host_ok=0
            if [[ "$host_ok" -eq 0 ]]; then
                _SUMMARY_COOKIE=1
                emit_finding "medium" \
                    "Cookie with __Host- Prefix Has Invalid Attributes — Prefix Enforcement Violated (${ip}:${port})" \
                    "A cookie uses the __Host- prefix but does not satisfy all required attributes (Secure flag, no Domain= attribute, Path=/): $(echo "$cookie_line" | head -c 200). The __Host- prefix is intended to guarantee host-only binding, preventing subdomain cookie injection. Invalid attribute combinations are silently ignored by some browsers, removing the security guarantee." \
                    "Ensure __Host- cookies include: Secure, no Domain attribute, and Path=/. Test with browser cookie-prefix validation tools before deploying." \
                    "ev-25-${ip//./_}-t07-host-prefix"
                break
            fi
        fi
    done <<< "$all_cookies"

    # Check 4: Domain= set to root domain with leading dot (over-broad scope)
    while IFS= read -r cookie_line; do
        [[ -z "$cookie_line" ]] && continue
        if echo "$cookie_line" | grep -qi "; *domain=\." || \
           echo "$cookie_line" | grep -Eqi "; *domain=[a-z0-9-]+\.[a-z]{2,}[^.]"; then
            # Distinguish over-broad (.example.com) from host-only (no Domain)
            if echo "$cookie_line" | grep -qi "; *domain=\."; then
                emit_finding "medium" \
                    "Cookie Domain Scope Over-Broad — Leading Dot Allows Subdomain Access (${ip}:${port})" \
                    "A cookie sets Domain=.example.com (leading dot), which makes it accessible to all subdomains of the root domain: $(echo "$cookie_line" | head -c 200). If any subdomain is compromised (XSS, subdomain takeover), the attacker can read or overwrite this cookie." \
                    "Set cookies without a Domain attribute to make them host-only (accessible only to the exact host that set them). Only set Domain= when cross-subdomain cookie sharing is explicitly required, and use the most restrictive subdomain scope possible." \
                    "ev-25-${ip//./_}-t07-domain-scope"
                break
            fi
        fi
    done <<< "$all_cookies"

    # Check 5: Max-Age / Expires excessively long for session cookies (> 30 days)
    local max_age_seconds=0 expires_far=0
    while IFS= read -r cookie_line; do
        [[ -z "$cookie_line" ]] && continue
        local max_age; max_age=$(echo "$cookie_line" | grep -oi "max-age=[0-9]*" | head -1 | cut -d= -f2)
        if [[ -n "$max_age" ]] && [[ "$max_age" -gt 2592000 ]]; then
            max_age_seconds="$max_age"
            expires_far=1
            break
        fi
    done <<< "$all_cookies"

    if [[ "$expires_far" -eq 1 ]]; then
        local days=$(( max_age_seconds / 86400 ))
        emit_finding "low" \
            "Session Cookie Max-Age Exceeds 30 Days — Persistent Exposure Window (${ip}:${port})" \
            "A cookie has Max-Age=${max_age_seconds} (${days} days). Long-lived session cookies extend the window during which a stolen cookie can be replayed. If the user's device is compromised or the cookie is logged, the attacker has months to exploit the session." \
            "Limit session cookie lifetimes to the shortest duration that meets usability requirements. For authentication cookies, 24 hours is typical. Implement sliding expiry (re-issue the cookie on activity) rather than a long fixed max-age. Pair with short-lived JWTs and refresh token rotation for APIs." \
            "ev-25-${ip//./_}-t07-maxage"
    fi

    [[ "${_SUMMARY_COOKIE}" -eq 0 ]] && log_ok "T07: No deep cookie security issues detected"
}

# =============================================================================
# MRK:12_T08 — T08 MIXED CONTENT | t08,mixed,http,active,passive | L1046-1120
# NAV-RULE: read-toc-first; deep-only
# =============================================================================

test_25_t08_mixed() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "contentsec-t08-mixed" "txt")"
    log "T08: Mixed Content Detection — ${base_url}"
    _SUMMARY_MIXED=0

    local scheme; scheme=$(_scheme "$port")
    if [[ "$scheme" != "https" ]]; then
        log_ok "T08: Target is plain HTTP — mixed content not applicable"
        return
    fi

    # Use HTML fetched by T02 if available; otherwise fetch now
    local page_html="${_MAIN_HTML:-}"
    if [[ -z "$page_html" ]]; then
        page_html=$(_curl "${base_url}/" || true)
    fi
    echo "[T08] HTML length: ${#page_html}" >> "$evfile"

    if [[ -z "$page_html" ]]; then
        log_ok "T08: No HTML body returned — skipping mixed content analysis"
        return
    fi

    # Check if CSP contains upgrade-insecure-requests (mitigates mixed content)
    local upgrade_csp=0
    local csp="${_CSP_HEADER:-}"
    echo "$csp" | grep -qi "upgrade-insecure-requests" && upgrade_csp=1
    echo "[T08] upgrade-insecure-requests in CSP: ${upgrade_csp}" >> "$evfile"

    # Active mixed content: scripts and iframes loaded over HTTP on HTTPS page
    local active_mixed=()
    while IFS= read -r match; do
        [[ -n "$match" ]] && active_mixed+=("$match")
    done < <(echo "$page_html" | grep -oi 'src=["\'']\?http://[^"'\''>]*' 2>/dev/null | \
        grep -i '\.js\b\|<script\|<iframe\|<embed\|<object' | head -10 || true)

    # Also scan raw script src and iframe src for http://
    while IFS= read -r match; do
        [[ -n "$match" ]] && active_mixed+=("$match")
    done < <(echo "$page_html" | grep -oi '<script[^>]*src=["\'']\?http://[^"'\''>]*' | head -10 || true)

    while IFS= read -r match; do
        [[ -n "$match" ]] && active_mixed+=("$match")
    done < <(echo "$page_html" | grep -oi '<iframe[^>]*src=["\'']\?http://[^"'\''>]*' | head -10 || true)

    # Passive mixed content: images, CSS, audio loaded over HTTP
    local passive_mixed=()
    while IFS= read -r match; do
        [[ -n "$match" ]] && passive_mixed+=("$match")
    done < <(echo "$page_html" | grep -oi '<img[^>]*src=["\'']\?http://[^"'\''>]*\|<link[^>]*href=["\'']\?http://[^"'\''>]*\.css' | head -10 || true)

    echo "[T08] Active mixed content found: ${#active_mixed[@]}" >> "$evfile"
    echo "[T08] Passive mixed content found: ${#passive_mixed[@]}" >> "$evfile"
    for m in "${active_mixed[@]+"${active_mixed[@]}"}";  do echo "[T08] Active: ${m:0:200}" >> "$evfile"; done
    for m in "${passive_mixed[@]+"${passive_mixed[@]}"}"; do echo "[T08] Passive: ${m:0:200}" >> "$evfile"; done

    if [[ "${#active_mixed[@]}" -gt 0 ]]; then
        if [[ "$upgrade_csp" -eq 1 ]]; then
            emit_finding "medium" \
                "Active Mixed Content Detected — Mitigated by upgrade-insecure-requests (${ip}:${port})" \
                "${#active_mixed[@]} HTTP script(s) or iframe(s) found on the HTTPS page ${base_url}. These would be blocked or upgraded to HTTPS by the CSP upgrade-insecure-requests directive. However, relying on the CSP as the sole protection is fragile — a missing header or CSP bypass re-exposes the active mixed content." \
                "Fix the source URLs: change all http:// script and iframe src attributes to https://. Do not rely on upgrade-insecure-requests as a permanent solution; it should be a temporary migration aid only." \
                "ev-25-${ip//./_}-t08-active-mixed-mitigated"
        else
            _SUMMARY_MIXED=1
            emit_finding "high" \
                "Active Mixed Content — HTTP Scripts/Iframes on HTTPS Page (${ip}:${port})" \
                "${#active_mixed[@]} script or iframe resource(s) are loaded over plain HTTP on the HTTPS page ${base_url}. Modern browsers block active mixed content, but the existence of these references indicates the application was built assuming HTTP delivery. An attacker who can perform a network MitM can substitute any of these HTTP resources with malicious content." \
                "Change all script/iframe src attributes from http:// to https://. Add Content-Security-Policy: upgrade-insecure-requests as a temporary measure during migration. Audit the full page source and JavaScript-injected resources, not only the HTML document." \
                "ev-25-${ip//./_}-t08-active-mixed"
        fi
    fi

    if [[ "${#passive_mixed[@]}" -gt 0 && "$upgrade_csp" -eq 0 ]]; then
        _SUMMARY_MIXED=1
        emit_finding "medium" \
            "Passive Mixed Content — HTTP Images/CSS on HTTPS Page (${ip}:${port})" \
            "${#passive_mixed[@]} image or stylesheet resource(s) are loaded over plain HTTP on the HTTPS page ${base_url}. Passive mixed content is not blocked by browsers but degrades the security of the HTTPS connection: the resources are visible to network observers and can be substituted by a MitM attacker to alter page appearance or exfiltrate data via CSS attribute selectors." \
            "Update all passive resource URLs from http:// to https://. Add 'Content-Security-Policy: upgrade-insecure-requests' to instruct browsers to upgrade all HTTP sub-resource loads to HTTPS automatically during migration." \
            "ev-25-${ip//./_}-t08-passive-mixed"
    fi

    [[ "${_SUMMARY_MIXED}" -eq 0 ]] && log_ok "T08: No unmitigated mixed content detected"
}

# =============================================================================
# MRK:12_TRUN — PER-TARGET DISPATCHER | trun,target,dispatcher,test | L1121-1175
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

test_target() {
    local host_port="$1"
    local ip port
    IFS=':' read -r ip port <<< "$host_port"
    [[ -z "$port" ]] && port="80"
    _CURRENT_IP="$ip"

    local scheme; scheme=$(_scheme "$port")
    local base_url="${scheme}://${ip}:${port}"
    local ev_dir="${EVIDENCE_BASE}/${ip}_${port}"
    mkdir -p "$ev_dir"

    log "========================================================"
    log "Target: ${base_url}"
    log "========================================================"

    local reach_code
    reach_code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}/" || true)
    if [[ "$reach_code" == "000" ]]; then
        log_warn "Target ${base_url} unreachable (curl exit 000) — skipping"
        return
    fi
    log_ok "Target reachable: HTTP ${reach_code}"

    # Reset per-target cross-test state
    _CSP_HEADER=""; _MAIN_HTML=""
    _SUMMARY_CSP=0; _SUMMARY_SRI=0;         _SUMMARY_CLICKJACK=0
    _SUMMARY_CROSSORIGIN=0; _SUMMARY_CACHE=0; _SUMMARY_HDRINFO=0
    _SUMMARY_COOKIE=0; _SUMMARY_MIXED=0
    _FIND_AT_START="${_FIND_CTR}"

    # Dispatch tests
    _test_skip 1 || test_25_t01_csp         "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 2 || test_25_t02_sri         "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 3 || test_25_t03_clickjack   "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 4 || test_25_t04_crossorigin "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 5 || test_25_t05_cache       "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 6 || test_25_t06_hdrinfo     "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 7 || test_25_t07_cookie      "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 8 || test_25_t08_mixed       "$base_url" "$ev_dir" "$ip" "$port"

    local target_finds=$(( _FIND_CTR - _FIND_AT_START ))
    log_ok "Target ${base_url} complete — ${target_finds} finding(s)"

    echo "SUMMARY_ROW|${ip}|${port}|${target_finds}|${_SUMMARY_CSP}|${_SUMMARY_SRI}|${_SUMMARY_CLICKJACK}|${_SUMMARY_CROSSORIGIN}|${_SUMMARY_CACHE}|${_SUMMARY_HDRINFO}|${_SUMMARY_COOKIE}|${_SUMMARY_MIXED}"
}

# =============================================================================
# MRK:12_MAIN — MAIN ENTRY POINT | main,entry,point,summary | L1176-1320
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

main() {
    log "PT-Orc 25_content_sec.sh v1.0 — Content Security Deep Analysis"
    log "Session: ${SESSION_TS} | Profile: ${PROFILE} | Tier: ${TIER}"
    [[ "${#CURL_PROXY_ARGS[@]}" -gt 0 ]] && log_info "Intercept proxy: ${CURL_PROXY_ARGS[*]}"
    [[ -n "${BEARER_TOKEN:-}"  ]] && log_info "Bearer token provided (cache/cookie probes)"

    setup_profile

    local -a targets
    mapfile -t targets < <(assemble_targets)

    confirm_scope "${targets[@]}"

    if command -v trail_phase_start &>/dev/null; then
        trail_phase_start "25_content_sec" "Content Security v1.0" "${#targets[@]} targets"
    fi

    local summary_rows=()

    for host_port in "${targets[@]}"; do
        local row
        row=$(test_target "$host_port")
        while IFS= read -r line; do
            if [[ "$line" == SUMMARY_ROW* ]]; then
                summary_rows+=("$line")
            fi
        done <<< "$row"
    done

    # ── Markdown summary ──────────────────────────────────────────────────────
    local summary_md="${SCRIPT_DIR}/working/$(ev_fname "25-contentsec-summary" "md")"
    {
        echo "# Content Security Review Summary — ${PROJECT_NAME:-unknown}"
        echo ""
        echo "**Date:** $(date +'%Y-%m-%d %H:%M:%S')"
        echo "**Profile:** ${PROFILE} | **Tier:** ${TIER} | **Tests:** T01-T08"
        echo "**Targets:** ${#targets[@]}"
        [[ "${#CURL_PROXY_ARGS[@]}" -gt 0 ]] && echo "**Proxy:** ${CURL_PROXY_ARGS[*]}"
        echo ""
        echo "## Coverage — Content Security Controls"
        echo ""
        echo "| # | Control | Test | Profile | Status |"
        echo "|---|---------|------|---------|--------|"
        echo "| T01 | CSP | Deep directive quality analysis | quick+ | $([ "${_T_ENABLED[1]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T02 | SRI | External script/style integrity | standard+ | $([ "${_T_ENABLED[2]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T03 | Clickjacking | frame-ancestors vs X-Frame-Options | standard+ | $([ "${_T_ENABLED[3]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T04 | Cross-Origin | CORP / COEP / COOP isolation policies | standard+ | $([ "${_T_ENABLED[4]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T05 | Cache | no-store / private / CDN leakage | quick+ | $([ "${_T_ENABLED[5]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T06 | Headers | Debug token / ASP.NET / Via / traceparent | quick+ | $([ "${_T_ENABLED[6]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T07 | Cookies | __Secure-/__Host- prefix / Domain scope / Max-Age | standard+ | $([ "${_T_ENABLED[7]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T08 | Mixed Content | HTTP assets on HTTPS pages | deep only | $([ "${_T_ENABLED[8]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped (deep only)") |"
        echo ""
        echo "## Per-Target Results"
        echo ""
        echo "| Host | Port | Finds | CSP | SRI | Clickjack | CrossOrigin | Cache | HdrInfo | Cookie | Mixed |"
        echo "|------|------|-------|-----|-----|-----------|-------------|-------|---------|--------|-------|"
        for row in "${summary_rows[@]+"${summary_rows[@]}"}"; do
            IFS='|' read -r _ rip rport rfinds rcsp rsri rclk rcro rcache rhdr rcook rmix <<< "$row"
            local fc; fc="$( [[ "${rcsp:-0}"   -eq 1 ]] && echo "⚠" || echo "—")"
            local fs; fs="$( [[ "${rsri:-0}"   -eq 1 ]] && echo "⚠" || echo "—")"
            local fk; fk="$( [[ "${rclk:-0}"   -eq 1 ]] && echo "⚠" || echo "—")"
            local fo; fo="$( [[ "${rcro:-0}"   -eq 1 ]] && echo "⚠" || echo "—")"
            local fa; fa="$( [[ "${rcache:-0}" -eq 1 ]] && echo "⚠" || echo "—")"
            local fh; fh="$( [[ "${rhdr:-0}"   -eq 1 ]] && echo "⚠" || echo "—")"
            local fco; fco="$([[ "${rcook:-0}" -eq 1 ]] && echo "⚠" || echo "—")"
            local fm; fm="$( [[ "${rmix:-0}"   -eq 1 ]] && echo "⚠" || echo "—")"
            echo "| ${rip} | ${rport} | ${rfinds} | ${fc} | ${fs} | ${fk} | ${fo} | ${fa} | ${fh} | ${fco} | ${fm} |"
        done
        echo ""
        echo "## Total Findings: ${_FIND_CTR}"
        echo ""
        echo "### Findings File"
        echo "\`${FINDINGS_FILE}\`"
        echo ""
        echo "### Evidence Directory"
        echo "\`${EVIDENCE_BASE}\`"
        echo ""
        echo "---"
        echo "*Generated by PT-Orc 25_content_sec.sh v1.0 — TechGuard Labs*"
        echo "*Profile: ${PROFILE} | CSP/SRI/Clickjacking/CORP-COEP-COOP/Cache/Headers/Cookies/MixedContent*"
    } > "$summary_md"

    log_ok "Summary: ${summary_md}"
    log_ok "Findings: ${FINDINGS_FILE} (${_FIND_CTR} total)"
    log_ok "Evidence: ${EVIDENCE_BASE}"

    if command -v trail_phase_end &>/dev/null; then
        trail_phase_end "25_content_sec" "${_FIND_CTR} findings" "$summary_md"
    fi

    cat "$summary_md"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
