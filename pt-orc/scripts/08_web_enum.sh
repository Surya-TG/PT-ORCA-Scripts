#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:08_NAV_TOC — Section index | nav,toc,index | L5-71
# - MRK:08_ROOT — ROOT CHECK | root,check,euid | L72-81 | ⚠ no-insert-before
# - MRK:08_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration,config,curl | L82-132 | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:08_LOG — COLOURS AND LOGGING | log,colours,logging | L133-155 | ⚠ no-insert-before
# - MRK:08_ARGS — ARGUMENT PARSING | args,argument,parsing | L156-183 | ⚠ no-insert-before
# - MRK:08_DB — MSF DB HELPERS | db,msf,helpers,web,ports | L184-235 | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:08_CONFIRM — SCOPE CONFIRMATION | confirm,scope,confirmation | L236-252 | ⚠ no-insert-before; propose-before-edit
# - MRK:08_TARGETS — TARGET ASSEMBLY | targets,target,assembly | L253-280 | ⚠ no-insert-before; read-toc-first
# - MRK:08_FIND — FINDING WRITER | find,finding,writer,jsonl,jq | L281-327 | ⚠ no-insert-before; read-toc-first
# - MRK:08_UTILS — SHARED UTILITIES | utils,shared,utilities,curl,proxy | L328-368 | ⚠ no-insert-before
# - MRK:08_PROF — PROFILE SETUP | prof,profile,setup,quick,deep | L369-396 | ⚠ no-insert-before
# - MRK:08_T01 — T01 HEADERS & FINGERPRINT | t01,headers,fingerprint,tech,ww | L397-468 | ⚠ read-toc-first
# - MRK:08_T02 — T02 SECURITY HEADERS & CSP | t02,security,headers,csp,hsts | L469-559 | ⚠ read-toc-first
# - MRK:08_T03 — T03 CORS MISCONFIG | t03,cors,misconfig,origin,access | L560-620 | ⚠ read-toc-first
# - MRK:08_T04 — T04 WAF DETECTION | t04,waf,detection,firewall,fingerprint | L621-685 | ⚠ read-toc-first
# - MRK:08_T05 — T05 DIRECTORY DISCOVERY | t05,directory,discovery,gobuster,ffuf | L686-757 | ⚠ read-toc-first
# - MRK:08_T06 — T06 NIKTO | t06,nikto,scanner,vuln | L758-808 | ⚠ read-toc-first
# - MRK:08_T07 — T07 JS ANALYSIS | t07,js,analysis,javascript,secrets | L809-900 | ⚠ read-toc-first
# - MRK:08_T08 — T08 API ENDPOINT DISCOVERY | t08,api,endpoint,discovery,endpoints | L901-958 | ⚠ read-toc-first
# - MRK:08_T09 — T09 SENSITIVE FILE EXPOSURE | t09,sensitive,exposure,backup,git | L959-1024 | ⚠ read-toc-first
# - MRK:08_T10 — T10 VHOST DISCOVERY | t10,vhost,discovery,virtual,host | L1025-1074 | ⚠ read-toc-first
# - MRK:08_T11 — T11 403 BYPASS | t11,bypass,forbidden,path | L1075-1141 | ⚠ read-toc-first
# - MRK:08_T12 — T12 COOKIE SECURITY | t12,cookie,security,secure,httponly | L1142-1234 | ⚠ read-toc-first
# - MRK:08_T13 — T13 OPEN REDIRECT | t13,open,redirect,param,location | L1235-1275 | ⚠ read-toc-first
# - MRK:08_T14 — T14 LOGIN PAGE ANALYSIS | t14,login,page,analysis,auth | L1276-1352 | ⚠ read-toc-first
# - MRK:08_T15 — T15 CMS DETECTION | t15,cms,detection,wordpress,drupal | L1353-1430 | ⚠ read-toc-first
# - MRK:08_T16 — T16 GRAPHQL | t16,graphql,introspection,batch | L1431-1468 | ⚠ read-toc-first
# - MRK:08_T17 — T17 OAUTH2/OIDC | t17,oauth2,oidc,oauth,openid | L1469-1516 | ⚠ read-toc-first
# - MRK:08_T18 — T18 CLIENT-SIDE SECURITY | t18,client,side,security,csp | L1517-1588 | ⚠ read-toc-first
# - MRK:08_TRUN — PER-TARGET DISPATCHER | trun,target,dispatcher,test | L1589-1654 | ⚠ no-insert-before; read-toc-first
# - MRK:08_MAIN — MAIN ENTRY POINT | main,entry,point,summary | L1655-1765 | ⚠ no-insert-before; read-toc-first
# NAV-LEN: 30 entries | Integrity-hash: 9b32b1e69cccd051 | Last-indexed: 2026-06-16T08:30:52Z

# =============================================================================
# 08_web_enum.sh — TechGuard. [VAPT-Advanced v2.0 — 2026-06-09]
# Web service enumeration — DB-driven, modular, advanced pentest coverage
# Tests: headers/fingerprint, security headers/CSP, CORS, WAF detection,
#   directory discovery, Nikto, JavaScript analysis, API endpoints,
#   sensitive files, vhost discovery, 403 bypass, cookie security,
#   open redirect, login analysis, CMS detection, GraphQL, OAuth2/OIDC,
#   client-side security indicators
# Profiles: quick | standard (default) | deep
# Proxy:    --intercept-proxy http://127.0.0.1:8080 (Burp/ZAP)
# Consumes: MSF DB (web hosts from 03_comp_scan) or --host/--targets
# Produces: per-host evidence files + JSONL findings + markdown summary
# =============================================================================
# USAGE:
#   ./08_web_enum.sh [OPTIONS]
#
# OPTIONS:
#   --targets <file>          File with host:port entries (one per line)
#   --host <IP:PORT>          Single target (repeatable)
#   --from-db                 Pull web hosts from MSF DB (default)
#   --tier <n>                ghost|normal|loud — controls tool aggressiveness
#   --profile <name>          quick|standard|deep (default: standard)
#   --wordlist <path>         Gobuster/ffuf wordlist (default: dirb/common.txt)
#   --ext <list>              File extensions for gobuster (default: php,asp,aspx,jsp,txt,html,bak,zip)
#   --skip-test <N>           Skip test N (repeatable)
#   --only-test <N>           Run only test N (repeatable)
#   --intercept-proxy <url>   Proxy all curl requests through Burp/ZAP
#   --yes                     Skip scope confirmation
#   --dry-run                 Print commands without executing
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# MRK:08_ROOT — ROOT CHECK | root,check,euid | L72-81
# NAV-RULE: no-insert-before
# =============================================================================
if [[ "$EUID" -ne 0 ]] && [[ "${PTORC_ALLOW_NON_ROOT:-0}" != "1" ]]; then
    echo "[ERROR] This script must be run as root."
    echo "        Run: sudo $0 $*"
    exit 1
fi

# =============================================================================
# MRK:08_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration,config,curl | L82-132
# NAV-RULE: no-insert-before; propose-before-edit; read-toc-first
# =============================================================================

[[ -f "${SCRIPT_DIR}/pt-orc.conf" ]] && source "${SCRIPT_DIR}/pt-orc.conf" \
    || echo "[WARN] pt-orc.conf not found in ${SCRIPT_DIR}"

[[ -f "${SCRIPT_DIR}/orc-common-lib.sh" ]] && source "${SCRIPT_DIR}/orc-common-lib.sh" \
    || echo "[WARN] orc-common-lib.sh not found"

PROJ_SLUG="${PROJECT_NAME//[^A-Za-z0-9._-]/_}"
EVIDENCE_BASE="${SCAN_EVIDENCE_DIR:-${SCRIPT_DIR}/evidence}/${PROJ_SLUG}"

CURL_TIMEOUT="${CURL_TIMEOUT:-10}"
CURL_CONNECT=5
GOBUSTER_TIMEOUT="${GOBUSTER_TIMEOUT:-300}"
NIKTO_TIMEOUT="${NIKTO_TIMEOUT:-120}"
WHATWEB_TIMEOUT="${WHATWEB_TIMEOUT:-30}"
FFUF_TIMEOUT="${FFUF_TIMEOUT:-120}"

# Default wordlist
WORDLIST="${WORDLIST:-/usr/share/wordlists/dirb/common.txt}"
GOBUSTER_EXT="${GOBUSTER_EXT:-php,asp,aspx,jsp,txt,html,bak,zip,json,xml,conf,config,yml,yaml}"

# Proxy args
CURL_PROXY_ARGS=()

# Profile and test selection
PROFILE="standard"
SKIP_TESTS=()
ONLY_TESTS=()

_T_ENABLED=()
for _i in $(seq 1 18); do _T_ENABLED[$_i]=1; done

# Target options
TIER="${GLOBAL_TIER:-normal}"
FROM_DB=1
AUTO_YES=0
DRY_RUN=0

EXTRA_HOSTS=()
TARGETS_FILE=""

# Tier helpers
tier_delay() { case "$1" in ghost) echo 2;; evasion) echo 3;; normal) echo 0;; loud) echo 0;; *) echo 0;; esac; }
gobuster_threads() { case "$1" in ghost) echo 2;; evasion) echo 1;; normal) echo 10;; loud) echo 30;; *) echo 5;; esac; }
whatweb_aggression() { case "$1" in ghost|evasion) echo 1;; loud) echo 4;; *) echo 2;; esac; }
TLS_PORTS="443 8443 4443 9443 10443"

# =============================================================================
# MRK:08_LOG — COLOURS AND LOGGING | log,colours,logging | L133-155
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
LOG_FILE="${EVIDENCE_BASE}/_sweep/web_enum_${SESSION_TS}.log"

log()     { local m="[$(_now)] $1";   echo -e "${BLUE}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()  { local m="[$(_now)] ✓ $1"; echo -e "${GREEN}${m}${NC}" >&2;   echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn(){ local m="[$(_now)] ⚠ $1"; echo -e "${YELLOW}${m}${NC}" >&2;  echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err() { local m="[$(_now)] ✗ $1"; echo -e "${RED}${m}${NC}" >&2;     echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_info(){ local m="[$(_now)]   $1"; echo -e "${CYAN}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_hi()  { local m="[$(_now)] ! $1"; echo -e "${MAGENTA}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }

# =============================================================================
# MRK:08_ARGS — ARGUMENT PARSING | args,argument,parsing | L156-183
# NAV-RULE: no-insert-before
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)          TARGETS_FILE="$2";          FROM_DB=0; shift 2 ;;
        --host)             EXTRA_HOSTS+=("$2");         FROM_DB=0; shift 2 ;;
        --from-db)          FROM_DB=1;                              shift   ;;
        --tier)             TIER="$2";                              shift 2 ;;
        --profile)          PROFILE="$2";                           shift 2 ;;
        --wordlist)         WORDLIST="$2";                          shift 2 ;;
        --ext)              GOBUSTER_EXT="$2";                      shift 2 ;;
        --skip-test)        SKIP_TESTS+=("$2");                     shift 2 ;;
        --only-test)        ONLY_TESTS+=("$2");                     shift 2 ;;
        --intercept-proxy)  CURL_PROXY_ARGS=("-x" "$2");            shift 2 ;;
        --yes)              AUTO_YES=1;                             shift   ;;
        --dry-run)          DRY_RUN=1;                              shift   ;;
        # Legacy compat flags
        --skip-gobuster)    SKIP_TESTS+=(5);                        shift   ;;
        --skip-nikto)       SKIP_TESTS+=(6);                        shift   ;;
        --skip-api)         SKIP_TESTS+=(8);                        shift   ;;
        --fast)             PROFILE="quick";                        shift   ;;
        *) log_err "Unknown argument: $1"; exit 1 ;;
    esac
done

# =============================================================================
# MRK:08_DB — MSF DB HELPERS | db,msf,helpers,web,ports | L184-235
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
        log_warn "workspace '${PROJECT_NAME}' not found — CSV fallback"
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
    if [[ -n "$result" ]]; then echo "$result"
    else log_warn "no web ports in DB — CSV fallback"; _get_web_hosts_csv; fi
}

_get_web_hosts_csv() {
    local csv
    csv=$(find "${EVIDENCE_BASE}/_exports" -name 'services_tcp_*.csv' 2>/dev/null | sort | tail -1)
    [[ -z "$csv" ]] && return
    awk -F',' 'NR>1 && ($3=="80"||$3=="443"||$3=="8080"||$3=="8443"||$3=="4443") {print $1":"$3}' "$csv" 2>/dev/null || true
}

# =============================================================================
# MRK:08_CONFIRM — SCOPE CONFIRMATION | confirm,scope,confirmation | L236-252
# NAV-RULE: no-insert-before; propose-before-edit
# =============================================================================

confirm_scope() {
    local hosts=("$@")
    log_warn "=== SCOPE CONFIRMATION — Web Enum v2.0 ==="
    log_warn "Profile: ${PROFILE} | Tier: ${TIER} | Tests: T01-T18"
    log_warn "Targets (${#hosts[@]}):"
    for h in "${hosts[@]}"; do log_warn "  → $h"; done
    [[ "${AUTO_YES:-0}" -eq 1 ]] && { log_ok "Auto-confirmed (--yes)"; return 0; }
    echo -en "${YELLOW}Proceed with web enumeration against these targets? [y/N]: ${NC}" >&2
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { log_err "Aborted by user."; exit 0; }
}

# =============================================================================
# MRK:08_TARGETS — TARGET ASSEMBLY | targets,target,assembly | L253-280
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
    for h in "${EXTRA_HOSTS[@]+"${EXTRA_HOSTS[@]}"}"; do all+=("$h"); done
    if [[ "${FROM_DB:-0}" -eq 1 && "${#all[@]}" -eq 0 ]]; then
        parse_db_conf
        local db_hosts; db_hosts=$(get_web_hosts_from_db)
        if [[ -n "$db_hosts" ]]; then
            while IFS= read -r line; do [[ -n "$line" ]] && all+=("$line"); done <<< "$db_hosts"
        fi
    fi
    if [[ "${#all[@]}" -eq 0 ]]; then
        log_err "No targets. Use --host, --targets, or --from-db."
        exit 1
    fi
    # Dedup — MSF DB can return the same ip:port multiple times across scan passes
    local -A _seen=()
    local -a deduped=()
    for _e in "${all[@]}"; do
        [[ -z "${_seen[$_e]+x}" ]] && { _seen[$_e]=1; deduped+=("$_e"); }
    done
    printf '%s\n' "${deduped[@]}"
}

# =============================================================================
# MRK:08_FIND — FINDING WRITER | find,finding,writer,jsonl,jq | L281-327
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

_FIND_CTR=0
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "06-webenum-findings" "jsonl")"

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="$5"
    (( _FIND_CTR++ )) || true
    local ip_slug="${_CURRENT_IP//./_}"
    local fid="f-06-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local ev_id="ev-06-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"08_web_enum","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
        "$fid" \
        "$(echo "$title" | sed 's/"/\\"/g')" \
        "$sev" \
        "${ev_tag:-$ev_id}" \
        "$(echo "$desc"  | sed 's/"/\\"/g')" \
        "$(echo "$rec"   | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_hi "FINDING [${sev^^}]: ${title}"
}

write_web_exports() {
    # writes one JSON record per target to evidence/_exports/ for downstream steps (06_wpscan, 12_report_pack)
    [[ $# -eq 0 ]] && return 0
    local export_dir="${EVIDENCE_BASE}/_exports"
    mkdir -p "$export_dir"
    local export_file="${export_dir}/$(ev_fname "06-web-export" "jsonl")"
    for row in "$@"; do
        IFS='|' read -r _ rip rport rfinds rcors rwaf rdirs rapi rcms <<< "$row"
        local scheme="http"
        [[ "$rport" =~ ^(443|4443|8443)$ ]] && scheme="https"
        printf '{"ip":"%s","port":"%s","scheme":"%s","base_url":"%s","cms":"%s","waf":"%s","cors_vuln":%s,"dirs_found":%s,"api_exposed":%s,"findings":%s}\n' \
            "${rip}" "${rport}" "${scheme}" "${scheme}://${rip}:${rport}" \
            "${rcms:-none}" "${rwaf:-none}" \
            "$([[ "${rcors:-0}" -eq 1 ]] && echo 1 || echo 0)" \
            "$([[ "${rdirs:-0}" -eq 1 ]] && echo 1 || echo 0)" \
            "$([[ "${rapi:-0}"  -eq 1 ]] && echo 1 || echo 0)" \
            "${rfinds:-0}" >> "$export_file"
    done
    log_ok "Web export: ${export_file} (${#@} entries)"
}

# =============================================================================
# MRK:08_UTILS — SHARED UTILITIES | utils,shared,utilities,curl,proxy | L328-368
# NAV-RULE: no-insert-before
# =============================================================================

_curl() {
    if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
        log_info "  [DRY-RUN] curl $*"
        return 0
    fi
    curl -sk --max-time "$CURL_TIMEOUT" --connect-timeout "$CURL_CONNECT" \
        "${CURL_PROXY_ARGS[@]+"${CURL_PROXY_ARGS[@]}"}" "$@" 2>/dev/null || true
}

_scheme() { echo "$TLS_PORTS" | grep -qw "$1" && echo "https" || echo "http"; }

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
    for s in "${SKIP_TESTS[@]+"${SKIP_TESTS[@]}"}"; do [[ "$s" == "$n" ]] && return 0; done
    [[ "${_T_ENABLED[$n]:-1}" -eq 0 ]] && return 0
    return 1
}

# Detect TLS for non-standard port
_detect_tls() {
    local ip="$1" port="$2"
    echo "$TLS_PORTS" | grep -qw "$port" && echo "https" && return
    timeout 6 bash -c "echo | openssl s_client -connect '${ip}:${port}' -servername '${ip}' 2>/dev/null | grep -q 'SSL-Session'" \
        >/dev/null 2>&1 && echo "https" || echo "http"
}

# =============================================================================
# MRK:08_PROF — PROFILE SETUP | prof,profile,setup,quick,deep | L369-396
# NAV-RULE: no-insert-before
# =============================================================================

setup_profile() {
    log_info "Profile: ${PROFILE}"
    case "$PROFILE" in
        quick)
            # Headers, security headers, CORS, WAF, tech fingerprint only
            for i in 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do _T_ENABLED[$i]=0; done
            ;;
        standard)
            # Skip: vhost (10 — noisy), 403 bypass (11), parameter discovery handled in 08
            _T_ENABLED[10]=0
            _T_ENABLED[11]=0
            ;;
        deep)
            # All 18 tests
            ;;
        *)
            log_warn "Unknown profile '${PROFILE}' — using standard"
            _T_ENABLED[10]=0; _T_ENABLED[11]=0
            ;;
    esac
    for s in "${SKIP_TESTS[@]+"${SKIP_TESTS[@]}"}"; do _T_ENABLED[$s]=0; done
}

# =============================================================================
# MRK:08_T01 — T01 HEADERS & FINGERPRINT | t01,headers,fingerprint,tech,ww | L397-468
# NAV-RULE: read-toc-first
# =============================================================================

test_01_headers_fingerprint() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t01_headers.txt"
    log "T01: HTTP Headers & Technology Fingerprint — ${base_url}"

    # Full header capture
    local headers_resp; headers_resp=$(_curl -D - -o /dev/null "${base_url}/" || true)
    echo "[T01] Full headers:" >> "$evfile"
    echo "$headers_resp" >> "$evfile"

    # Server banner
    local server; server=$(echo "$headers_resp" | grep -i "^Server:" | head -1 | tr -d '\r' || true)
    local xpb; xpb=$(echo "$headers_resp" | grep -i "^X-Powered-By:" | head -1 | tr -d '\r' || true)
    local via; via=$(echo "$headers_resp" | grep -i "^Via:" | head -1 | tr -d '\r' || true)
    local xgen; xgen=$(echo "$headers_resp" | grep -i "^X-Generator:" | head -1 | tr -d '\r' || true)
    local xaspnet; xaspnet=$(echo "$headers_resp" | grep -i "^X-AspNet-Version:" | head -1 | tr -d '\r' || true)

    local fingerprint=""
    [[ -n "$server"  ]] && { fingerprint+="Server: ${server}; "; echo "[T01] ${server}" >> "$evfile"; }
    [[ -n "$xpb"     ]] && { fingerprint+="X-Powered-By: ${xpb}; "; echo "[T01] ${xpb}" >> "$evfile"; }
    [[ -n "$via"     ]] && { fingerprint+="Via: ${via}; "; echo "[T01] ${via}" >> "$evfile"; }
    [[ -n "$xgen"    ]] && { fingerprint+="X-Generator: ${xgen}; "; echo "[T01] ${xgen}" >> "$evfile"; }
    [[ -n "$xaspnet" ]] && { fingerprint+="X-AspNet-Version: ${xaspnet}; "; echo "[T01] ${xaspnet}" >> "$evfile"; }

    if [[ -n "$fingerprint" ]]; then
        emit_finding "info" \
            "Server/Technology Version Disclosure via HTTP Headers (${ip}:${port})" \
            "HTTP response headers reveal technology details: ${fingerprint}. Disclosed version information aids attackers in selecting targeted exploits." \
            "Suppress or genericize Server, X-Powered-By, X-Generator, X-AspNet-Version headers. Use ServerTokens Prod (Apache) or server_tokens off (Nginx)." \
            "ev-06-${ip//./_}-t01-banner"
    fi

    # WhatWeb fingerprint
    local whatweb_out="${ev_dir}/$(ev_fname "whatweb" "txt" "${ip}-${port}")"
    if command -v whatweb &>/dev/null && [[ "${DRY_RUN:-0}" -eq 0 ]]; then
        timeout "$WHATWEB_TIMEOUT" whatweb --color=never \
            -a "$(whatweb_aggression "$TIER")" "${base_url}" \
            >> "$whatweb_out" 2>&1 || true
        log_ok "T01: WhatWeb → ${whatweb_out}"
        # Extract interesting detections
        local interesting; interesting=$(grep -oE "(WordPress|Drupal|Joomla|Laravel|Django|Rails|Spring|Angular|React|Vue|jQuery|Bootstrap|PHP\/[0-9.]+|Apache\/[0-9.]+|nginx\/[0-9.]+|IIS\/[0-9.]+)" "$whatweb_out" 2>/dev/null | sort -u | tr '\n' ' ' || true)
        [[ -n "$interesting" ]] && log_info "T01: Detected — ${interesting}"
        echo "[T01] WhatWeb findings: ${interesting}" >> "$evfile"
    else
        log_info "T01: WhatWeb not available — header-only fingerprint"
    fi

    # robots.txt and sitemap
    for meta_path in "/robots.txt" "/sitemap.xml" "/sitemap_index.xml"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${meta_path}" || true)
        echo "[T01] ${meta_path} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201)$ ]]; then
            local content; content=$(_curl "${base_url}${meta_path}" | head -c 512 || true)
            echo "[T01] ${meta_path}: ${content:0:200}" >> "$evfile"
            # Check for disallowed paths leaked in robots.txt
            if echo "$content" | grep -qi "Disallow:"; then
                emit_finding "info" \
                    "robots.txt Exposes Sensitive Path Hints (${ip}:${port})" \
                    "robots.txt at ${base_url}${meta_path} lists Disallow entries that may reveal internal path structure: ${content:0:200}" \
                    "Review robots.txt for sensitive path disclosures. Do not rely on robots.txt as a security control — it is publicly readable." \
                    "ev-06-${ip//./_}-t01-robots"
            fi
        fi
    done
    _SUMMARY_TECH="${interesting:-unknown}"
}

# =============================================================================
# MRK:08_T02 — T02 SECURITY HEADERS & CSP | t02,security,headers,csp,hsts | L469-559
# NAV-RULE: read-toc-first
# =============================================================================

test_02_security_headers() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t02_sec_headers.txt"
    log "T02: Security Headers & CSP Analysis — ${base_url}"

    local headers_resp; headers_resp=$(_curl -D - -o /dev/null "${base_url}/" || true)
    echo "$headers_resp" >> "$evfile"

    # Required headers
    declare -A required
    required["Strict-Transport-Security"]="missing HSTS — downgrade attacks possible"
    required["Content-Security-Policy"]="missing CSP — XSS attacks possible"
    required["X-Content-Type-Options"]="missing — MIME sniffing attacks"
    required["X-Frame-Options"]="missing — clickjacking attacks"
    required["Referrer-Policy"]="missing — URL leakage"
    required["Permissions-Policy"]="missing — feature abuse"
    required["Cross-Origin-Opener-Policy"]="missing — cross-origin attacks"
    required["Cross-Origin-Resource-Policy"]="missing — data theft"
    required["Cache-Control"]="missing/permissive — sensitive data caching"

    local missing_list=""
    local present_count=0
    for hdr in "${!required[@]}"; do
        if echo "$headers_resp" | grep -qi "^${hdr}:"; then
            local val; val=$(echo "$headers_resp" | grep -i "^${hdr}:" | head -1 | tr -d '\r' || true)
            echo "[T02] PRESENT: ${val}" >> "$evfile"
            (( present_count++ )) || true
        else
            missing_list+="${hdr}; "
            echo "[T02] MISSING: ${hdr} — ${required[$hdr]}" >> "$evfile"
        fi
    done

    if [[ -n "$missing_list" ]]; then
        emit_finding "medium" \
            "Missing Security Response Headers (${ip}:${port})" \
            "The following security headers are absent from ${base_url}: ${missing_list}. Each exposes XSS, clickjacking, MIME sniffing, or data leakage risks." \
            "Add all recommended headers in web server or application configuration. Reference: OWASP Secure Headers Project. Start with: Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options." \
            "ev-06-${ip//./_}-t02-headers"
        _SUMMARY_HEADERS="${#required[@]} missing: $(echo "$missing_list" | tr ';' '\n' | grep -c '.')"
    else
        log_ok "T02: All security headers present"
        _SUMMARY_HEADERS="all present"
    fi

    # CSP deep analysis
    local csp; csp=$(echo "$headers_resp" | grep -i "^Content-Security-Policy:" | head -1 | tr -d '\r' || true)
    if [[ -n "$csp" ]]; then
        echo "[T02] CSP: ${csp}" >> "$evfile"
        local csp_issues=""
        # Dangerous directives
        echo "$csp" | grep -qi "unsafe-inline" && csp_issues+="'unsafe-inline' in CSP (XSS bypass); "
        echo "$csp" | grep -qi "unsafe-eval"   && csp_issues+="'unsafe-eval' in CSP (code injection); "
        echo "$csp" | grep -qi "\*"            && csp_issues+="wildcard (*) source allows any origin; "
        echo "$csp" | grep -qi "data:"         && csp_issues+="data: URI source (XSS vector); "
        # Missing directives
        echo "$csp" | grep -qi "default-src" || csp_issues+="missing default-src directive; "
        echo "$csp" | grep -qi "frame-ancestors" || csp_issues+="missing frame-ancestors (use over X-Frame-Options); "
        echo "$csp" | grep -qi "upgrade-insecure-requests" || true  # advisory only

        if [[ -n "$csp_issues" ]]; then
            emit_finding "medium" \
                "Weak Content Security Policy — Bypassable Directives (${ip}:${port})" \
                "CSP is present but contains weak directives: ${csp_issues}. CSP: ${csp:0:200}" \
                "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for legitimate inline scripts. Use CSP Evaluator (csp-evaluator.withgoogle.com) to grade the policy. Add frame-ancestors 'none' or 'self'." \
                "ev-06-${ip//./_}-t02-csp-weak"
        fi
    fi

    # HSTS deep analysis
    local hsts; hsts=$(echo "$headers_resp" | grep -i "^Strict-Transport-Security:" | head -1 | tr -d '\r' || true)
    if [[ -n "$hsts" ]]; then
        echo "[T02] HSTS: ${hsts}" >> "$evfile"
        local max_age; max_age=$(echo "$hsts" | grep -oE "max-age=[0-9]+" | cut -d= -f2 || true)
        if [[ -n "$max_age" && "$max_age" -lt 31536000 ]]; then
            emit_finding "low" \
                "HSTS max-age Too Short — ${max_age}s (${ip}:${port})" \
                "HSTS max-age of ${max_age} seconds is below the recommended minimum of 31536000 (1 year). Short max-age allows downgrade attacks after expiry." \
                "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload" \
                "ev-06-${ip//./_}-t02-hsts-short"
        fi
        echo "$hsts" | grep -qi "includeSubDomains" || log_info "T02: HSTS missing includeSubDomains"
        echo "$hsts" | grep -qi "preload"           || log_info "T02: HSTS missing preload"
    fi
}

# =============================================================================
# MRK:08_T03 — T03 CORS MISCONFIG | t03,cors,misconfig,origin,access | L560-620
# NAV-RULE: read-toc-first
# =============================================================================

test_03_cors() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t03_cors.txt"
    log "T03: CORS Misconfiguration — ${base_url}"
    _SUMMARY_CORS=0

    local malicious_origins=("https://evil.com" "https://attacker.io"
                              "null" "https://${ip}.evil.com"
                              "https://evil${ip//./-}.com"
                              "https://not${ip}.example.com")

    for origin in "${malicious_origins[@]}"; do
        local resp; resp=$(_curl -D - -H "Origin: ${origin}" "${base_url}/" || true)
        local acao; acao=$(echo "$resp" | grep -i "^Access-Control-Allow-Origin:" | head -1 | tr -d '\r' || true)
        local acac; acac=$(echo "$resp" | grep -i "^Access-Control-Allow-Credentials:" | head -1 | tr -d '\r' || true)
        echo "[T03] Origin: ${origin}" >> "$evfile"
        echo "[T03]   ACAO: ${acao:-<not set>}" >> "$evfile"
        echo "[T03]   ACAC: ${acac:-<not set>}" >> "$evfile"

        if echo "$acao" | grep -qi "$origin" || echo "$acao" | grep -q '\*'; then
            local cred_flag=""; echo "$acac" | grep -qi "true" && cred_flag=" with credentials=true"
            _SUMMARY_CORS=1
            emit_finding "high" \
                "CORS Misconfiguration — Arbitrary Origin Reflected${cred_flag} (${ip}:${port})" \
                "Server reflects arbitrary origin '${origin}' in ACAO${cred_flag}. ACAO: '${acao}' ACAC: '${acac}'. Enables cross-origin data theft from authenticated sessions." \
                "Maintain an explicit origin allowlist. Never dynamically reflect the Origin header. Combine CORS with CSRF protection for state-changing endpoints." \
                "ev-06-${ip//./_}-t03-cors"
        fi
        _tier_sleep
    done

    # Preflight CORS check (OPTIONS)
    local preflight_resp; preflight_resp=$(_curl -X OPTIONS \
        -H "Origin: https://evil.com" \
        -H "Access-Control-Request-Method: POST" \
        -H "Access-Control-Request-Headers: Authorization,Content-Type" \
        -D - -o /dev/null "${base_url}/" || true)
    local preflight_acao; preflight_acao=$(echo "$preflight_resp" | grep -i "^Access-Control-Allow-Origin:" | head -1 | tr -d '\r' || true)
    local acam; acam=$(echo "$preflight_resp" | grep -i "^Access-Control-Allow-Methods:" | head -1 | tr -d '\r' || true)
    local acah; acah=$(echo "$preflight_resp" | grep -i "^Access-Control-Allow-Headers:" | head -1 | tr -d '\r' || true)
    echo "[T03] Preflight ACAO: ${preflight_acao:-<not set>}" >> "$evfile"
    echo "[T03] Preflight ACAM: ${acam:-<not set>}" >> "$evfile"
    echo "[T03] Preflight ACAH: ${acah:-<not set>}" >> "$evfile"

    if echo "$preflight_acao" | grep -qi "evil.com"; then
        _SUMMARY_CORS=1
        emit_finding "high" \
            "CORS Preflight Reflects Attacker Origin (${ip}:${port})" \
            "OPTIONS preflight returns ACAO: ${preflight_acao} for evil.com. Allows pre-authorized cross-origin POST with Authorization headers." \
            "Fix CORS origin validation to use a server-side allowlist for both simple and preflight requests." \
            "ev-06-${ip//./_}-t03-cors-preflight"
    fi

    [[ "${_SUMMARY_CORS:-0}" -eq 0 ]] && log_ok "T03: No CORS misconfiguration detected"
}

# =============================================================================
# MRK:08_T04 — T04 WAF DETECTION | t04,waf,detection,firewall,fingerprint | L621-685
# NAV-RULE: read-toc-first
# =============================================================================

test_04_waf_detection() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t04_waf.txt"
    log "T04: WAF Detection & Fingerprinting — ${base_url}"
    _SUMMARY_WAF="none"

    # wafw00f if available
    if command -v wafw00f &>/dev/null && [[ "${DRY_RUN:-0}" -eq 0 ]]; then
        local waf_out; waf_out=$(timeout 30 wafw00f -a "${base_url}" 2>&1 || true)
        echo "[T04] wafw00f: ${waf_out}" >> "$evfile"
        log_info "T04: wafw00f → ${waf_out:0:100}"
        if echo "$waf_out" | grep -qiE "(detected|protected by|is behind)"; then
            local waf_name; waf_name=$(echo "$waf_out" | grep -iE "(detected|protected by|is behind)" | head -1 || true)
            _SUMMARY_WAF="${waf_name:0:60}"
            emit_finding "info" \
                "WAF Detected — ${waf_name:0:60} (${ip}:${port})" \
                "A Web Application Firewall was detected: ${waf_out:0:200}. WAF presence affects exploitability of other findings but is not itself a vulnerability." \
                "Verify WAF rules cover OWASP Top 10. Ensure WAF operates in blocking mode (not detection-only). Test WAF bypass techniques during authorized testing." \
                "ev-06-${ip//./_}-t04-waf"
        fi
    fi

    # Manual WAF fingerprinting via header analysis
    local headers_resp; headers_resp=$(_curl -D - -o /dev/null "${base_url}/" || true)
    declare -A waf_headers
    waf_headers["X-Sucuri-ID"]="Sucuri WAF"
    waf_headers["X-Mod-Security"]="ModSecurity"
    waf_headers["X-Powered-By-Plesk"]="Plesk WAF"
    waf_headers["cf-ray"]="Cloudflare"
    waf_headers["X-Akamai-Transformed"]="Akamai"
    waf_headers["X-Cdn"]="CDN/WAF"
    waf_headers["X-Incapsula-Session"]="Imperva Incapsula"
    waf_headers["X-SL-CompState"]="SiteLock"

    for hdr in "${!waf_headers[@]}"; do
        if echo "$headers_resp" | grep -qi "^${hdr}:"; then
            local waf_val; waf_val=$(echo "$headers_resp" | grep -i "^${hdr}:" | head -1 | tr -d '\r' || true)
            echo "[T04] WAF header: ${waf_val}" >> "$evfile"
            _SUMMARY_WAF="${waf_headers[$hdr]}"
            log_info "T04: WAF identified via header: ${waf_headers[$hdr]}"
        fi
    done

    # Probe with malicious payload to check WAF blocking behavior
    local probe_resp; probe_resp=$(_curl -o /dev/null -w "%{http_code}" \
        "${base_url}/?q=<script>alert(1)</script>&id=1' OR 1=1--" || true)
    echo "[T04] Malicious probe → HTTP ${probe_resp}" >> "$evfile"
    if [[ "$probe_resp" =~ ^(403|406|429|503)$ ]]; then
        log_info "T04: WAF blocking probe (HTTP ${probe_resp})"
        _SUMMARY_WAF="${_SUMMARY_WAF:-active (blocking)}"
    elif [[ "$probe_resp" =~ ^(200|301|302)$ ]]; then
        log_warn "T04: Malicious payload not blocked (HTTP ${probe_resp}) — WAF may be absent or in detection mode"
        emit_finding "medium" \
            "Malicious Payload Probe Not Blocked — No WAF or WAF in Detection Mode (${ip}:${port})" \
            "A request containing XSS and SQLi payloads was not blocked (HTTP ${probe_resp}). This suggests the absence of a WAF or a WAF configured in detection-only mode." \
            "Deploy a WAF in blocking mode. Consider cloud WAF options (Cloudflare, AWS WAF, Akamai). Test WAF rules against OWASP Core Rule Set." \
            "ev-06-${ip//./_}-t04-no-waf"
    fi
}

# =============================================================================
# MRK:08_T05 — T05 DIRECTORY DISCOVERY | t05,directory,discovery,gobuster,ffuf | L686-757
# NAV-RULE: read-toc-first
# =============================================================================

test_05_directory_discovery() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t05_dirs.txt"
    log "T05: Directory / Path Discovery — ${base_url}"
    _SUMMARY_DIRS=0

    if [[ ! -f "$WORDLIST" ]]; then
        log_warn "T05: Wordlist not found: ${WORDLIST} — skipping directory brute force"
        return
    fi

    # Gobuster
    if command -v gobuster &>/dev/null && [[ "${DRY_RUN:-0}" -eq 0 ]]; then
        local gb_out="${ev_dir}/$(ev_fname "gobuster" "txt" "${ip}-${port}")"
        local threads; threads=$(gobuster_threads "$TIER")
        local -a gb_flags=(-k -q)
        [[ "$TIER" == "ghost" || "$TIER" == "evasion" ]] && gb_flags+=("--delay" "2000ms")

        {
            echo "# Gobuster — ${base_url}"
            echo "# Wordlist: ${WORDLIST} | Extensions: ${GOBUSTER_EXT} | Threads: ${threads}"
            echo "---"
            timeout "$GOBUSTER_TIMEOUT" gobuster dir \
                -u "${base_url}" \
                -w "${WORDLIST}" \
                -x "${GOBUSTER_EXT}" \
                -t "$threads" \
                --timeout "${CURL_TIMEOUT}s" \
                "${gb_flags[@]}" \
                2>&1 || true
        } | tee "$gb_out"

        local found_count; found_count=$(grep -cE "^/" "$gb_out" 2>/dev/null || true)
        echo "[T05] Gobuster found ${found_count} paths" >> "$evfile"
        log_ok "T05: Gobuster → ${gb_out} (${found_count} paths)"

        # Flag high-value paths
        local hot_paths; hot_paths=$(grep -E "^/(admin|backup|config|db|secret|private|internal|api|swagger|debug|test|dev|staging|phpinfo|\.env|\.git)" "$gb_out" 2>/dev/null | head -10 || true)
        if [[ -n "$hot_paths" ]]; then
            _SUMMARY_DIRS=1
            emit_finding "medium" \
                "Sensitive Directories/Files Found via Brute Force (${ip}:${port})" \
                "Directory enumeration revealed sensitive paths at ${base_url}: ${hot_paths:0:300}. These may expose admin interfaces, configuration files, or development artifacts." \
                "Restrict access to administrative and development paths via authentication and IP allowlisting. Remove development artifacts from production deployments." \
                "ev-06-${ip//./_}-t05-dirs"
        fi
    fi

    # ffuf for additional coverage (faster, more configurable)
    if command -v ffuf &>/dev/null && [[ "${DRY_RUN:-0}" -eq 0 ]] && [[ "$PROFILE" == "deep" ]]; then
        local ffuf_wl="${WORDLIST}"
        local ffuf_out="${ev_dir}/$(ev_fname "ffuf" "txt" "${ip}-${port}")"
        {
            echo "# ffuf — ${base_url}"
            echo "---"
            timeout "$FFUF_TIMEOUT" ffuf \
                -u "${base_url}/FUZZ" \
                -w "$ffuf_wl" \
                -mc 200,201,301,302,401,403 \
                -ac \
                -s \
                2>&1 || true
        } | tee "$ffuf_out"
        log_ok "T05: ffuf → ${ffuf_out}"
    fi
}

# =============================================================================
# MRK:08_T06 — T06 NIKTO | t06,nikto,scanner,vuln | L758-808
# NAV-RULE: read-toc-first
# =============================================================================

test_06_nikto() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "nikto" "txt" "${ip}-${port}")"
    log "T06: Nikto Scan — ${base_url}"

    # Skip nikto in evasion tier (too noisy)
    if [[ "$TIER" == "evasion" ]]; then
        log_info "T06: Evasion tier — Nikto skipped"
        return
    fi

    if ! command -v nikto &>/dev/null; then
        log_warn "T06: nikto not installed"
        return
    fi

    [[ "${DRY_RUN:-0}" -eq 1 ]] && { log_info "T06: [DRY-RUN] nikto -h ${base_url}"; return; }

    local scheme; scheme=$(_scheme "$port")
    local nikto_ssl_flag=(); [[ "$scheme" == "https" ]] && nikto_ssl_flag=("-ssl")

    {
        echo "# Nikto — ${base_url}"
        echo "---"
        timeout "$NIKTO_TIMEOUT" nikto \
            -h "${ip}" \
            -p "$port" \
            "${nikto_ssl_flag[@]+"${nikto_ssl_flag[@]}"}" \
            -nointeractive \
            -Format txt \
            2>&1 || true
    } | tee "$evfile"

    local nikto_vuln_count; nikto_vuln_count=$(grep -cE "^\+" "$evfile" 2>/dev/null || true)
    log_ok "T06: Nikto → ${evfile} (${nikto_vuln_count} items)"

    if [[ "$nikto_vuln_count" -gt 0 ]]; then
        local nikto_summary; nikto_summary=$(grep "^\+" "$evfile" | head -5 | tr '\n' ' ' || true)
        emit_finding "low" \
            "Nikto Scanner Findings — ${nikto_vuln_count} Items (${ip}:${port})" \
            "Nikto identified ${nikto_vuln_count} notable items on ${base_url}. Summary: ${nikto_summary:0:250}. Full output: ${evfile}" \
            "Review each Nikto finding individually. Prioritize findings related to outdated software, dangerous HTTP methods, and configuration issues." \
            "ev-06-${ip//./_}-t06-nikto"
    fi
}

# =============================================================================
# MRK:08_T07 — T07 JS ANALYSIS | t07,js,analysis,javascript,secrets | L809-900
# NAV-RULE: read-toc-first
# =============================================================================

test_07_js_analysis() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t07_js.txt"
    log "T07: JavaScript Analysis — ${base_url}"

    # Discover JS files from page source
    local page_src; page_src=$(_curl "${base_url}/" | head -c 50000 || true)
    local js_urls=()

    # Extract JS src attributes
    while IFS= read -r line; do
        [[ -n "$line" ]] && js_urls+=("$line")
    done < <(echo "$page_src" | grep -oE 'src="[^"]*\.js[^"]*"' | grep -oE '"[^"]*"' | tr -d '"' | grep -v "^http" | head -20 || true)

    # Also check common JS paths
    local common_js_paths=("/app.js" "/main.js" "/bundle.js" "/vendor.js"
                           "/assets/js/app.js" "/static/js/main.js"
                           "/js/app.js" "/js/main.js" "/js/bundle.js"
                           "/dist/bundle.js" "/dist/main.js"
                           "/api.js" "/config.js")
    for jspath in "${common_js_paths[@]}"; do
        local jscode; jscode=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${jspath}" || true)
        [[ "$jscode" == "200" ]] && js_urls+=("$jspath")
    done

    echo "[T07] JS files to analyze: ${js_urls[*]:-none}" >> "$evfile"

    local secrets_found=""
    local api_endpoints=""

    for jspath in "${js_urls[@]+"${js_urls[@]}"}"; do
        local jsurl; [[ "$jspath" =~ ^https?:// ]] && jsurl="$jspath" || jsurl="${base_url}${jspath}"
        local js_content; js_content=$(_curl "$jsurl" | head -c 100000 || true)
        [[ -z "$js_content" ]] && continue
        echo "[T07] Analyzing: ${jspath}" >> "$evfile"

        # Secret patterns
        local patterns=(
            "apikey|api_key|API_KEY"
            "secret|SECRET"
            "password|PASSWORD"
            "token|TOKEN"
            "auth|AUTH"
            "aws_access_key|AKIA[0-9A-Z]{16}"
            "private_key|privateKey"
            "client_secret|clientSecret"
            "database_url|DATABASE_URL"
            "mongodb://|postgresql://|mysql://"
        )

        for pat in "${patterns[@]}"; do
            local matches; matches=$(echo "$js_content" | grep -oiE "${pat}['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9+/._-]{8,}" | head -3 || true)
            if [[ -n "$matches" ]]; then
                secrets_found+="${jspath}: ${matches}; "
                echo "[T07] SECRET: ${matches}" >> "$evfile"
            fi
        done

        # API endpoint extraction
        local endpoints; endpoints=$(echo "$js_content" | grep -oE '["'"'"'](/api/[a-zA-Z0-9/_-]+|/v[0-9]+/[a-zA-Z0-9/_-]+)["'"'"']' | sort -u | head -20 || true)
        if [[ -n "$endpoints" ]]; then
            api_endpoints+="${jspath}: ${endpoints}; "
            echo "[T07] API endpoints: ${endpoints}" >> "$evfile"
        fi
        _tier_sleep
    done

    if [[ -n "$secrets_found" ]]; then
        emit_finding "critical" \
            "Credentials / API Keys Exposed in JavaScript Files (${ip}:${port})" \
            "Secrets or credentials found in client-side JavaScript: ${secrets_found:0:300}. These are readable by any user visiting the application." \
            "Never embed credentials, API keys, or tokens in client-side code. Use server-side proxying for API calls. Move sensitive configuration to environment variables that are never exposed to the browser. Implement secret scanning in CI/CD (GitLeaks, Truffelhog)." \
            "ev-06-${ip//./_}-t07-js-secrets"
    fi

    if [[ -n "$api_endpoints" ]]; then
        log_info "T07: API endpoints found in JS: ${api_endpoints:0:150}"
        emit_finding "info" \
            "API Endpoints Discovered via JavaScript Analysis (${ip}:${port})" \
            "Client-side JavaScript reveals internal API endpoint paths: ${api_endpoints:0:250}. These endpoints should be assessed for authentication, authorization, and input validation." \
            "Review all discovered API endpoints for proper authentication and authorization controls. Add discovered paths to the 08_app_api_review scope." \
            "ev-06-${ip//./_}-t07-js-endpoints"
    fi

    [[ -z "${secrets_found}${api_endpoints}" ]] && log_ok "T07: No secrets or sensitive endpoints in JS"
}

# =============================================================================
# MRK:08_T08 — T08 API ENDPOINT DISCOVERY | t08,api,endpoint,discovery,endpoints | L901-958
# NAV-RULE: read-toc-first
# =============================================================================

test_08_api_discovery() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t08_api.txt"
    log "T08: API Endpoint Discovery — ${base_url}"
    _SUMMARY_API=0

    local api_paths=(
        # OpenAPI / Swagger
        "/swagger.json" "/swagger.yaml" "/swagger/v1/swagger.json"
        "/api-docs" "/api-docs.json" "/openapi.json" "/openapi.yaml"
        "/v1/api-docs" "/v2/api-docs" "/v3/api-docs"
        # Auth endpoints
        "/oauth/token" "/oauth/authorize" "/auth/token" "/auth/login"
        "/api/auth" "/api/login" "/api/v1/auth/login"
        # Common REST patterns
        "/api" "/api/v1" "/api/v2" "/api/v3"
        "/rest" "/rest/v1" "/rest/api"
        # Admin/internal
        "/api/admin" "/api/internal" "/api/private"
        # Spring Actuator
        "/actuator" "/actuator/health" "/actuator/env" "/actuator/metrics"
        "/actuator/beans" "/actuator/mappings" "/actuator/configprops"
        # Health/metrics
        "/health" "/healthz" "/ready" "/readyz" "/metrics" "/status"
        # Debug
        "/debug" "/debug/vars" "/debug/pprof" "/phpinfo.php"
        # Misc
        "/api/graphql" "/graphql" "/api/schema"
    )

    local exposed_apis=""
    for path in "${api_paths[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${path}" || true)
        echo "[T08] ${path} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201)$ ]]; then
            exposed_apis+="${path}(${code}) "
            _SUMMARY_API=1
            log_info "T08: Found → ${path} (${code})"
        fi
        _tier_sleep
    done

    if [[ -n "$exposed_apis" ]]; then
        emit_finding "medium" \
            "API / Admin Endpoints Publicly Accessible (${ip}:${port})" \
            "The following API or admin endpoints are publicly accessible on ${base_url}: ${exposed_apis}. These may expose sensitive functionality, data, or configuration." \
            "Gate all API discovery endpoints behind authentication. Remove actuator/debug endpoints from production. Restrict /actuator to localhost or internal networks only." \
            "ev-06-${ip//./_}-t08-api"
    else
        log_ok "T08: No unauthenticated API endpoints found"
    fi
}

# =============================================================================
# MRK:08_T09 — T09 SENSITIVE FILE EXPOSURE | t09,sensitive,exposure,backup,git | L959-1024
# NAV-RULE: read-toc-first
# =============================================================================

test_09_sensitive_files() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t09_sensitive.txt"
    log "T09: Sensitive File Exposure — ${base_url}"

    local sensitive_paths=(
        # Environment / config
        "/.env" "/.env.local" "/.env.production" "/.env.backup" "/.env.dev"
        "/config.php" "/config.inc.php" "/configuration.php"
        "/config.json" "/config.yaml" "/config.yml" "/settings.py"
        "/application.properties" "/application.yml" "/appsettings.json"
        # VCS
        "/.git/config" "/.git/HEAD" "/.git/index" "/.git/COMMIT_EDITMSG"
        "/.svn/entries" "/.hg/hgrc"
        # Database backups
        "/backup.sql" "/database.sql" "/db.sql" "/dump.sql" "/data.sql"
        "/backup.tar.gz" "/backup.zip" "/site.tar.gz" "/www.tar.gz"
        # Credentials
        "/.htpasswd" "/credentials.json" "/secrets.json" "/secrets.yaml"
        "/id_rsa" "/id_dsa" "/.ssh/id_rsa" "/server.key" "/private.key"
        # Web server
        "/.htaccess" "/web.config" "/nginx.conf" "/apache.conf"
        # Logs
        "/error_log" "/access_log" "/error.log" "/access.log"
        "/logs/error.log" "/log/error.log" "/application.log"
        # Common backup patterns
        "/index.php.bak" "/index.php~" "/index.php.old"
        "/wp-config.php.bak" "/config.php.bak"
        # Source code exposure
        "/source.zip" "/source.tar.gz" "/.DS_Store" "/Thumbs.db"
        # PHP info
        "/phpinfo.php" "/info.php" "/test.php" "/php.php"
        # DS_Store / package files
        "/package.json" "/package-lock.json" "/composer.json" "/composer.lock"
        "/Gemfile" "/Gemfile.lock" "/requirements.txt" "/Pipfile"
        # Security files
        "/.well-known/security.txt" "/security.txt"
    )

    local exposed=""
    for path in "${sensitive_paths[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${path}" || true)
        echo "[T09] ${path} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201)$ ]]; then
            local body; body=$(_curl "${base_url}${path}" | head -c 256 || true)
            echo "[T09] ${path}: ${body:0:150}" >> "$evfile"
            exposed+="${path}; "
            local sev="medium"
            echo "$path" | grep -qE "\.(env|sql|key|htpasswd|git|svn)$|/(\.git|\.env|id_rsa|secrets|credentials)" && sev="critical"
            emit_finding "$sev" \
                "Sensitive File Exposed — ${path} (${ip}:${port})" \
                "File ${path} is publicly accessible (HTTP ${code}). Content: ${body:0:100}" \
                "Remove sensitive files from web root. Add deny rules in server config. Implement file-extension and path-based access controls." \
                "ev-06-${ip//./_}-t09-file"
        fi
        _tier_sleep
    done

    [[ -z "$exposed" ]] && log_ok "T09: No sensitive files exposed"
}

# =============================================================================
# MRK:08_T10 — T10 VHOST DISCOVERY | t10,vhost,discovery,virtual,host | L1025-1074
# NAV-RULE: read-toc-first
# =============================================================================

test_10_vhost_discovery() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t10_vhost.txt"
    log "T10: Virtual Host Discovery — ${base_url}"

    local domain="${TARGET_DOMAINS:-}"
    [[ -z "$domain" ]] && { log_info "T10: No TARGET_DOMAINS set — using IP-based vhost probes"; domain="$ip"; }

    local base_domain; base_domain=$(echo "$domain" | awk -F'.' '{if(NF>=2) print $(NF-1)"."$NF; else print $0}')

    # Common subdomains/vhosts to probe
    local vhost_prefixes=("admin" "api" "dev" "staging" "test" "internal" "vpn"
                          "mail" "smtp" "ftp" "remote" "portal" "dashboard"
                          "app" "apps" "beta" "old" "legacy" "backup"
                          "auth" "sso" "login" "secure" "private" "corp")

    # Baseline response for comparison
    local baseline_code; baseline_code=$(_curl -o /dev/null -w "%{http_code}" \
        -H "Host: notexist-$(date +%s).${base_domain}" "${base_url}/" || true)
    echo "[T10] Baseline (nonexistent host) → HTTP ${baseline_code}" >> "$evfile"

    local found_vhosts=""
    for prefix in "${vhost_prefixes[@]}"; do
        local vhost="${prefix}.${base_domain}"
        local code; code=$(_curl -o /dev/null -w "%{http_code}" \
            -H "Host: ${vhost}" "${base_url}/" || true)
        echo "[T10] Host: ${vhost} → HTTP ${code}" >> "$evfile"
        if [[ "$code" != "$baseline_code" && "$code" =~ ^(200|201|301|302|401|403)$ ]]; then
            found_vhosts+="${vhost}(${code}) "
            log_info "T10: Potential vhost: ${vhost} → ${code}"
        fi
        _tier_sleep
    done

    if [[ -n "$found_vhosts" ]]; then
        emit_finding "medium" \
            "Virtual Host Discovery — Hidden Subdomains Found (${ip}:${port})" \
            "Virtual host enumeration revealed hosts responding differently from baseline on ${ip}: ${found_vhosts}. These may expose staging, admin, or internal applications not linked from the main site." \
            "Audit all virtual hosts for proper authentication and hardening. Ensure staging/dev vhosts are not publicly accessible. Use separate TLS certificates rather than shared server blocks." \
            "ev-06-${ip//./_}-t10-vhost"
    else
        log_ok "T10: No additional virtual hosts detected"
    fi
}

# =============================================================================
# MRK:08_T11 — T11 403 BYPASS | t11,bypass,forbidden,path | L1075-1141
# NAV-RULE: read-toc-first
# =============================================================================

test_11_403_bypass() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t11_403bypass.txt"
    log "T11: 403 Forbidden Bypass Techniques — ${base_url}"

    local forbidden_paths=("/admin" "/admin/" "/config" "/.env" "/server-status" "/api/admin" "/internal")

    for fpath in "${forbidden_paths[@]}"; do
        local base_code; base_code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${fpath}" || true)
        [[ "$base_code" != "403" ]] && continue
        echo "[T11] ${fpath} → 403 baseline" >> "$evfile"

        # Bypass techniques
        local bypass_tests=(
            "PATH_NORM1:${fpath}/."
            "PATH_NORM2:${fpath}/./"
            "PATH_CASE:${fpath^^}"
            "PATH_DOUBLE://${fpath}"
            "PATH_ENCODE:/${fpath//\//\%2F}"
            "HEADER_XORIG:${fpath} + X-Original-URL"
            "HEADER_XREW:${fpath} + X-Rewrite-URL"
            "HEADER_XFF:${fpath} + X-Forwarded-For: 127.0.0.1"
            "HEADER_PROTO:${fpath} + X-Custom-IP-Authorization: 127.0.0.1"
            "HEADER_CLIENT:${fpath} + X-ProxyUser-Ip: 127.0.0.1"
            "METHOD_POST:${fpath} POST"
        )

        for test in "${bypass_tests[@]}"; do
            local test_name; test_name="${test%%:*}"
            local code=""

            case "$test_name" in
                PATH_NORM1) code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${fpath}/." || true) ;;
                PATH_NORM2) code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${fpath}/./" || true) ;;
                PATH_CASE)  code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${fpath^^}" || true) ;;
                PATH_DOUBLE) code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}//${fpath#/}" || true) ;;
                HEADER_XORIG) code=$(_curl -o /dev/null -w "%{http_code}" \
                    -H "X-Original-URL: ${fpath}" "${base_url}/" || true) ;;
                HEADER_XREW) code=$(_curl -o /dev/null -w "%{http_code}" \
                    -H "X-Rewrite-URL: ${fpath}" "${base_url}/" || true) ;;
                HEADER_XFF) code=$(_curl -o /dev/null -w "%{http_code}" \
                    -H "X-Forwarded-For: 127.0.0.1" "${base_url}${fpath}" || true) ;;
                HEADER_PROTO) code=$(_curl -o /dev/null -w "%{http_code}" \
                    -H "X-Custom-IP-Authorization: 127.0.0.1" "${base_url}${fpath}" || true) ;;
                HEADER_CLIENT) code=$(_curl -o /dev/null -w "%{http_code}" \
                    -H "X-ProxyUser-Ip: 127.0.0.1" "${base_url}${fpath}" || true) ;;
                METHOD_POST) code=$(_curl -X POST -o /dev/null -w "%{http_code}" "${base_url}${fpath}" || true) ;;
            esac

            echo "[T11] ${test_name} ${fpath} → HTTP ${code}" >> "$evfile"
            if [[ "$code" =~ ^(200|201)$ ]]; then
                emit_finding "high" \
                    "403 Bypass Successful — ${test_name} on ${fpath} (${ip}:${port})" \
                    "Access control bypass: ${fpath} returns 403 normally but ${test_name} technique returned HTTP ${code}. The access restriction is implemented at the path-matching layer and is bypassable." \
                    "Implement access controls at the application layer (not just URL matching). Validate X-Original-URL and X-Rewrite-URL are not trusted from external clients. Use deny-by-default at the application/middleware level." \
                    "ev-06-${ip//./_}-t11-403bypass"
            fi
            _tier_sleep
        done
    done
}

# =============================================================================
# MRK:08_T12 — T12 COOKIE SECURITY | t12,cookie,security,secure,httponly | L1142-1234
# NAV-RULE: read-toc-first
# =============================================================================

test_12_cookie_security() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t12_cookies.txt"
    log "T12: Cookie Security Analysis — ${base_url}"

    local headers_resp; headers_resp=$(_curl -D - -o /dev/null "${base_url}/" || true)
    echo "[T12] Response headers:" >> "$evfile"
    echo "$headers_resp" >> "$evfile"

    local cookies; cookies=$(echo "$headers_resp" | grep -i "^Set-Cookie:" || true)
    if [[ -z "$cookies" ]]; then
        log_info "T12: No Set-Cookie headers found on root"
        # Try login path
        cookies=$(_curl -D - -o /dev/null -X POST "${base_url}/login" 2>/dev/null | grep -i "^Set-Cookie:" || true)
    fi

    if [[ -z "$cookies" ]]; then
        log_ok "T12: No cookies set"
        return
    fi

    echo "[T12] Cookies: ${cookies}" >> "$evfile"

    local scheme; scheme=$(_scheme "$port")
    local missing_secure="" missing_httponly="" missing_samesite="" no_prefix=""

    while IFS= read -r cookie_line; do
        [[ -z "$cookie_line" ]] && continue
        local cookie_name; cookie_name=$(echo "$cookie_line" | grep -oP "(?<=Set-Cookie: )[^;=]+" || true)
        echo "[T12] Cookie: ${cookie_name}" >> "$evfile"

        # Secure flag (required for HTTPS)
        if [[ "$scheme" == "https" ]] && ! echo "$cookie_line" | grep -qi "; Secure"; then
            missing_secure+="${cookie_name}; "
        fi

        # HttpOnly flag
        if ! echo "$cookie_line" | grep -qi "; HttpOnly"; then
            missing_httponly+="${cookie_name}; "
        fi

        # SameSite
        if ! echo "$cookie_line" | grep -qi "; SameSite="; then
            missing_samesite+="${cookie_name}; "
        else
            # Check SameSite=None without Secure
            if echo "$cookie_line" | grep -qi "SameSite=None" && ! echo "$cookie_line" | grep -qi "; Secure"; then
                emit_finding "medium" \
                    "Cookie SameSite=None Without Secure Flag (${ip}:${port})" \
                    "Cookie '${cookie_name}' has SameSite=None but is missing the Secure flag. This combination is invalid and may expose the cookie over HTTP." \
                    "Add Secure flag to all SameSite=None cookies. SameSite=None requires Secure per RFC 6265bis." \
                    "ev-06-${ip//./_}-t12-samesite-none"
            fi
        fi

        # __Host- and __Secure- prefix checks
        if echo "$cookie_name" | grep -q "^session\|^auth\|^token\|^PHPSESSID\|^JSESSIONID\|^ASP.NET_SessionId"; then
            if ! echo "$cookie_name" | grep -q "^__Host-\|^__Secure-"; then
                no_prefix+="${cookie_name}; "
            fi
        fi
    done <<< "$cookies"

    [[ -n "$missing_secure"   ]] && emit_finding "high" \
        "Session Cookie Missing Secure Flag (${ip}:${port})" \
        "Cookies missing Secure flag over HTTPS: ${missing_secure}. Cookies without Secure flag can be transmitted over HTTP." \
        "Add Secure flag to all session cookies. For HTTPS-only applications, all cookies should have Secure." \
        "ev-06-${ip//./_}-t12-secure"

    [[ -n "$missing_httponly" ]] && emit_finding "medium" \
        "Session Cookie Missing HttpOnly Flag (${ip}:${port})" \
        "Cookies missing HttpOnly flag: ${missing_httponly}. Cookies without HttpOnly are accessible via JavaScript, enabling theft via XSS." \
        "Add HttpOnly flag to all session cookies. Only cookies deliberately accessed via JavaScript should omit HttpOnly." \
        "ev-06-${ip//./_}-t12-httponly"

    [[ -n "$missing_samesite" ]] && emit_finding "medium" \
        "Session Cookie Missing SameSite Attribute (${ip}:${port})" \
        "Cookies missing SameSite: ${missing_samesite}. Without SameSite, cookies are sent in cross-site requests, enabling CSRF attacks." \
        "Set SameSite=Lax (default recommended) or SameSite=Strict for all session cookies. Use SameSite=None only for intentionally cross-site cookies." \
        "ev-06-${ip//./_}-t12-samesite"

    [[ -n "$no_prefix" ]] && emit_finding "low" \
        "Session Cookies Not Using __Host- or __Secure- Prefix (${ip}:${port})" \
        "Session cookies ${no_prefix} do not use the __Host- or __Secure- cookie prefix. These prefixes enforce Secure, Path=/, and no Domain attribute, preventing subdomain cookie injection." \
        "Rename session cookies to use __Host- prefix (strictest) or __Secure- prefix for better security boundaries." \
        "ev-06-${ip//./_}-t12-cookie-prefix"
}

# =============================================================================
# MRK:08_T13 — T13 OPEN REDIRECT | t13,open,redirect,param,location | L1235-1275
# NAV-RULE: read-toc-first
# =============================================================================

test_13_open_redirect() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t13_redirect.txt"
    log "T13: Open Redirect Detection — ${base_url}"

    local redirect_params=("redirect" "redirect_uri" "redirect_url" "url" "next" "return"
                           "return_url" "returnUrl" "returnTo" "goto" "dest" "destination"
                           "target" "redir" "ref" "referer" "continue" "to" "from"
                           "forward" "location" "callback" "back" "out" "link")

    local redirect_targets=("https://evil.com" "//evil.com" "https://evil.com%2F%40${ip}"
                             "https://${ip}.evil.com" "\x2Fevil.com" "///evil.com")

    local found_redirect=""
    for param in "${redirect_params[@]}"; do
        for target in "${redirect_targets[@]}"; do
            local resp; resp=$(_curl -D - -o /dev/null "${base_url}/?${param}=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${target}'))" 2>/dev/null || echo "$target")" || true)
            local location; location=$(echo "$resp" | grep -i "^Location:" | head -1 | tr -d '\r' || true)
            echo "[T13] ${param}=${target} → ${location:-no redirect}" >> "$evfile"

            if echo "$location" | grep -qi "evil.com"; then
                found_redirect+="${param}→${target}; "
                emit_finding "medium" \
                    "Open Redirect via Parameter '${param}' (${ip}:${port})" \
                    "Parameter '${param}' with value '${target}' triggers redirect to: ${location}. Open redirects enable phishing by redirecting users from legitimate domains to attacker-controlled sites." \
                    "Validate redirect targets against an allowlist of permitted domains. Never use user-supplied URLs directly in Location headers. Prefer relative URLs or path-only redirects." \
                    "ev-06-${ip//./_}-t13-redirect"
                break 2
            fi
            _tier_sleep
        done
    done

    [[ -z "$found_redirect" ]] && log_ok "T13: No open redirects detected"
}

# =============================================================================
# MRK:08_T14 — T14 LOGIN PAGE ANALYSIS | t14,login,page,analysis,auth | L1276-1352
# NAV-RULE: read-toc-first
# =============================================================================

test_14_login_analysis() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t14_login.txt"
    log "T14: Login Page Analysis — ${base_url}"

    local login_paths=("/login" "/signin" "/admin/login" "/user/login"
                       "/auth/login" "/wp-login.php" "/administrator"
                       "/admin" "/panel" "/cp" "/control" "/dashboard")

    local found_login=""
    for lpath in "${login_paths[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${lpath}" || true)
        echo "[T14] ${lpath} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|301|302)$ ]]; then
            found_login+="${lpath}(${code}) "
        fi
        _tier_sleep
    done

    if [[ -n "$found_login" ]]; then
        log_info "T14: Login pages: ${found_login}"

        # Test for username enumeration via response differences
        local valid_resp; valid_resp=$(_curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
            -d "username=admin&password=wrongpassword123" \
            -D - -o /dev/null "${base_url}/login" || true)
        local invalid_resp; invalid_resp=$(_curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
            -d "username=nonexistentuser9999&password=wrongpassword123" \
            -D - -o /dev/null "${base_url}/login" || true)

        local valid_code; valid_code=$(echo "$valid_resp" | grep -m1 "^HTTP" | awk '{print $2}' || true)
        local invalid_code; invalid_code=$(echo "$invalid_resp" | grep -m1 "^HTTP" | awk '{print $2}' || true)
        echo "[T14] admin/wrong → HTTP ${valid_code}" >> "$evfile"
        echo "[T14] nonexistent/wrong → HTTP ${invalid_code}" >> "$evfile"

        if [[ "$valid_code" != "$invalid_code" ]]; then
            emit_finding "medium" \
                "Username Enumeration via Login Response Difference (${ip}:${port})" \
                "Login endpoint returns different responses for valid (HTTP ${valid_code}) vs invalid (HTTP ${invalid_code}) usernames. Attackers can enumerate valid accounts." \
                "Return identical responses for all authentication failures regardless of whether the username exists. Use the same error message, response code, and timing for all failures." \
                "ev-06-${ip//./_}-t14-user-enum"
        fi

        # Check for account lockout
        local lockout_triggered=0
        for i in $(seq 1 6); do
            local lo_code; lo_code=$(_curl -X POST -H "Content-Type: application/x-www-form-urlencoded" \
                -d "username=admin&password=wrongpass${i}" \
                -o /dev/null -w "%{http_code}" "${base_url}/login" || true)
            echo "[T14] Lockout test ${i} → HTTP ${lo_code}" >> "$evfile"
            [[ "$lo_code" =~ ^(429|423|403)$ ]] && { lockout_triggered=1; break; }
            _tier_sleep
        done

        if [[ "$lockout_triggered" -eq 0 ]]; then
            emit_finding "medium" \
                "No Account Lockout on Login Page (${ip}:${port})" \
                "Login endpoint ${base_url}/login did not trigger lockout or rate limiting after 6 consecutive failed attempts. This enables brute-force attacks." \
                "Implement account lockout after N failed attempts (5-10 recommended). Add CAPTCHA after initial failures. Implement progressive delays. Log and alert on repeated failures from same IP." \
                "ev-06-${ip//./_}-t14-lockout"
        fi

        emit_finding "info" \
            "Login Page Detected (${ip}:${port})" \
            "Login/admin pages found at ${base_url}: ${found_login}. These should be assessed for credential strength, MFA enforcement, and brute-force protections." \
            "Require MFA for all privileged accounts. Implement account lockout and CAPTCHA. Restrict admin login to internal networks or VPN where possible." \
            "ev-06-${ip//./_}-t14-login-found"
    else
        log_ok "T14: No login pages found at standard paths"
    fi
}

# =============================================================================
# MRK:08_T15 — T15 CMS DETECTION | t15,cms,detection,wordpress,drupal | L1353-1430
# NAV-RULE: read-toc-first
# =============================================================================

test_15_cms_detection() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t15_cms.txt"
    log "T15: CMS Detection — ${base_url}"

    local detected_cms=""

    # WordPress fingerprinting
    local wp_code; wp_code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}/wp-login.php" || true)
    local wp_readme; wp_readme=$(_curl -o /dev/null -w "%{http_code}" "${base_url}/readme.html" || true)
    local wp_api; wp_api=$(_curl -o /dev/null -w "%{http_code}" "${base_url}/wp-json/wp/v2/users" || true)
    echo "[T15] WordPress: wp-login.php=${wp_code} readme.html=${wp_readme} wp-json/users=${wp_api}" >> "$evfile"

    if [[ "$wp_code" == "200" || "$wp_readme" == "200" ]]; then
        detected_cms="WordPress"
        # WordPress user enumeration via REST API
        if [[ "$wp_api" == "200" ]]; then
            local users_body; users_body=$(_curl "${base_url}/wp-json/wp/v2/users" | head -c 512 || true)
            echo "[T15] WP user list: ${users_body:0:200}" >> "$evfile"
            emit_finding "medium" \
                "WordPress User Enumeration via REST API (${ip}:${port})" \
                "WordPress REST API at ${base_url}/wp-json/wp/v2/users returns user list: ${users_body:0:150}. Usernames can be used for brute-force attacks." \
                "Disable user enumeration via REST API: add 'remove_filter' for wp/v2/users endpoint, or use a security plugin (Wordfence). Rename the default 'admin' account." \
                "ev-06-${ip//./_}-t15-wp-users"
        fi
        # Version detection
        local wp_ver; wp_ver=$(_curl "${base_url}/readme.html" | grep -oE "Version [0-9.]+" | head -1 || true)
        emit_finding "info" \
            "WordPress CMS Detected ${wp_ver:-(version unknown)} (${ip}:${port})" \
            "WordPress installation detected at ${base_url}. ${wp_ver:+Version: $wp_ver.} WordPress sites require regular core, plugin, and theme updates." \
            "Keep WordPress core, plugins, and themes updated. Use WPScan (09_wpscan.sh) for full WordPress security assessment." \
            "ev-06-${ip//./_}-t15-wordpress"
    fi

    # Drupal fingerprinting
    local drupal_code; drupal_code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}/user/login" || true)
    local drupal_gen; drupal_gen=$(_curl -D - -o /dev/null "${base_url}/" || true | grep -i "X-Generator: Drupal" || true)
    if [[ "$drupal_code" == "200" || -n "$drupal_gen" ]]; then
        detected_cms="Drupal"
        emit_finding "info" \
            "Drupal CMS Detected (${ip}:${port})" \
            "Drupal installation detected at ${base_url}. Check for Drupalgeddon (CVE-2018-7600, CVE-2019-6340) and SA advisories." \
            "Update Drupal core to latest stable. Run Drupal security advisories scan. Restrict /user/login to internal if possible." \
            "ev-06-${ip//./_}-t15-drupal"
    fi

    # Joomla fingerprinting
    local joomla_code; joomla_code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}/administrator/index.php" || true)
    if [[ "$joomla_code" == "200" ]]; then
        detected_cms="Joomla"
        emit_finding "info" \
            "Joomla CMS Detected (${ip}:${port})" \
            "Joomla admin panel detected at ${base_url}/administrator/index.php." \
            "Restrict Joomla admin path to internal networks. Enable Joomla two-factor authentication. Check Joomla security advisories." \
            "ev-06-${ip//./_}-t15-joomla"
    fi

    # Generic CMS via generator meta tag
    if [[ -z "$detected_cms" ]]; then
        local gen_meta; gen_meta=$(_curl "${base_url}/" | grep -oi '<meta name="generator" content="[^"]*"' | head -1 || true)
        [[ -n "$gen_meta" ]] && { detected_cms=$(echo "$gen_meta" | grep -oP 'content="\K[^"]+' || true)
            emit_finding "info" \
                "CMS/Framework Detected via Generator Meta — ${detected_cms} (${ip}:${port})" \
                "Generator meta tag reveals: ${gen_meta}. Technology disclosure aids targeted exploitation." \
                "Remove or genericize the generator meta tag in production." \
                "ev-06-${ip//./_}-t15-generator"; }
    fi

    [[ -n "$detected_cms" ]] && log_info "T15: CMS detected: ${detected_cms}"
    [[ -z "$detected_cms" ]] && log_ok "T15: No well-known CMS detected"
    _SUMMARY_CMS="${detected_cms:-none}"
}

# =============================================================================
# MRK:08_T16 — T16 GRAPHQL | t16,graphql,introspection,batch | L1431-1468
# NAV-RULE: read-toc-first
# =============================================================================

test_16_graphql() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t16_graphql.txt"
    log "T16: GraphQL Detection & Introspection — ${base_url}"

    local gql_paths=("/graphql" "/api/graphql" "/graphiql" "/playground"
                     "/gql" "/api/gql" "/v1/graphql" "/query")

    local found_gql=""
    for path in "${gql_paths[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${path}" || true)
        echo "[T16] ${path} → HTTP ${code}" >> "$evfile"
        [[ ! "$code" =~ ^(200|201|400)$ ]] && continue

        # Introspection query
        local intro_resp; intro_resp=$(_curl -X POST -H "Content-Type: application/json" \
            -d '{"query":"{__schema{types{name}}}"}' "${base_url}${path}" | head -c 512 || true)
        echo "[T16] Introspection: ${intro_resp:0:300}" >> "$evfile"

        if echo "$intro_resp" | grep -q "__schema"; then
            found_gql+="${path} "
            emit_finding "medium" \
                "GraphQL Introspection Enabled — Full Schema Exposed (${ip}:${port})" \
                "GraphQL introspection is enabled at ${base_url}${path}. Attackers can enumerate all types, queries, mutations, and field names." \
                "Disable introspection in production: Apollo Server introspection:false, or graphql-disable-introspection middleware. Implement field-level authorization." \
                "ev-06-${ip//./_}-t16-graphql"
        fi
        _tier_sleep
    done

    [[ -z "$found_gql" ]] && log_ok "T16: No GraphQL endpoint detected"
}

# =============================================================================
# MRK:08_T17 — T17 OAUTH2/OIDC | t17,oauth2,oidc,oauth,openid | L1469-1516
# NAV-RULE: read-toc-first
# =============================================================================

test_17_oauth_oidc() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t17_oauth.txt"
    log "T17: OAuth2 / OIDC Discovery — ${base_url}"

    local wellknown_paths=(
        "/.well-known/openid-configuration"
        "/.well-known/oauth-authorization-server"
        "/.well-known/jwks.json"
        "/oauth/token"
        "/oauth/authorize"
        "/oauth/introspect"
        "/oauth/revoke"
        "/auth/realms/master/.well-known/openid-configuration"  # Keycloak
        "/connect/discovery"  # IdentityServer
        "/.well-known/uma2-configuration"
    )

    for path in "${wellknown_paths[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${path}" || true)
        echo "[T17] ${path} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|201)$ ]]; then
            local body; body=$(_curl "${base_url}${path}" | head -c 512 || true)
            echo "[T17] ${path}: ${body:0:300}" >> "$evfile"

            emit_finding "info" \
                "OAuth2/OIDC Endpoint Discovered — ${path} (${ip}:${port})" \
                "OAuth2/OIDC metadata endpoint accessible at ${base_url}${path}: ${body:0:200}. This reveals authorization endpoints, JWKS URLs, supported flows, and token endpoints." \
                "Verify OIDC configuration: enforce PKCE for authorization code flow, validate state parameter, restrict redirect_uri to allowlisted values, use short-lived tokens, rotate signing keys regularly." \
                "ev-06-${ip//./_}-t17-oidc"

            # Check JWKS exposure
            local jwks_url; jwks_url=$(echo "$body" | grep -o '"jwks_uri":"[^"]*"' | cut -d'"' -f4 || true)
            if [[ -n "$jwks_url" ]]; then
                local jwks_resp; jwks_resp=$(_curl "$jwks_url" | head -c 512 || true)
                echo "[T17] JWKS: ${jwks_resp:0:200}" >> "$evfile"
                log_info "T17: JWKS exposed at ${jwks_url}"
            fi
        fi
        _tier_sleep
    done
}

# =============================================================================
# MRK:08_T18 — T18 CLIENT-SIDE SECURITY | t18,client,side,security,csp | L1517-1588
# NAV-RULE: read-toc-first
# =============================================================================

test_18_client_side_security() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/t18_clientside.txt"
    log "T18: Client-Side Security Indicators — ${base_url}"

    local page_src; page_src=$(_curl "${base_url}/" | head -c 100000 || true)
    echo "[T18] Page source (first 1000): ${page_src:0:1000}" >> "$evfile"

    # SRI (Subresource Integrity) check — external scripts without integrity attribute
    local ext_scripts_no_sri
    ext_scripts_no_sri=$(echo "$page_src" | grep -oP '<script[^>]+src="https://(?!'"${ip//./\\.}"')[^"]*"[^>]*>' | \
        grep -v "integrity=" | head -10 || true)
    if [[ -n "$ext_scripts_no_sri" ]]; then
        emit_finding "medium" \
            "External Scripts Without Subresource Integrity (SRI) (${ip}:${port})" \
            "Scripts loaded from external CDNs lack SRI integrity attributes: ${ext_scripts_no_sri:0:200}. Supply chain compromise of the CDN could inject malicious code." \
            "Add integrity and crossorigin attributes to all external script/link tags. Use sri-gen or webpack-subresource-integrity to automate SRI generation." \
            "ev-06-${ip//./_}-t18-sri"
    fi

    # Mixed content detection (HTTP resources on HTTPS page)
    local scheme; scheme=$(_scheme "$port")
    if [[ "$scheme" == "https" ]]; then
        local mixed_content
        mixed_content=$(echo "$page_src" | grep -oP 'src="http://[^"]*"' | head -5 || true)
        mixed_content+=$(echo "$page_src" | grep -oP "href='http://[^']*'" | head -5 || true)
        if [[ -n "$mixed_content" ]]; then
            emit_finding "medium" \
                "Mixed Content — HTTP Resources on HTTPS Page (${ip}:${port})" \
                "HTTPS page at ${base_url} loads HTTP resources: ${mixed_content:0:200}. Mixed content bypasses HTTPS protection and may expose user data." \
                "Update all resource URLs to HTTPS. Use protocol-relative URLs (//) or HTTPS-only URLs. Enable upgrade-insecure-requests in CSP." \
                "ev-06-${ip//./_}-t18-mixed-content"
        fi
    fi

    # Inline event handlers (XSS risk, CSP bypass indicator)
    local inline_events
    inline_events=$(echo "$page_src" | grep -oP 'on(click|load|error|mouseover|submit|change)="[^"]*"' | head -5 || true)
    if [[ -n "$inline_events" ]]; then
        emit_finding "low" \
            "Inline Event Handlers Detected — CSP Bypass Risk (${ip}:${port})" \
            "Inline JavaScript event handlers found: ${inline_events:0:200}. These indicate 'unsafe-inline' is required in CSP, weakening XSS protections." \
            "Refactor inline event handlers to addEventListener() calls in external JS files. This enables a strict CSP without 'unsafe-inline'." \
            "ev-06-${ip//./_}-t18-inline-events"
    fi

    # postMessage usage detection (DOM XSS risk)
    local pm_usage
    pm_usage=$(echo "$page_src" | grep -c "postMessage\|addEventListener.*message" 2>/dev/null || true)
    if [[ "$pm_usage" -gt 0 ]]; then
        log_info "T18: postMessage usage detected (${pm_usage} occurrences) — manual DOM XSS review recommended"
        echo "[T18] postMessage occurrences: ${pm_usage}" >> "$evfile"
    fi

    # Clickjacking: X-Frame-Options vs CSP frame-ancestors
    local headers_resp; headers_resp=$(_curl -D - -o /dev/null "${base_url}/" || true)
    local xfo; xfo=$(echo "$headers_resp" | grep -i "^X-Frame-Options:" | head -1 | tr -d '\r' || true)
    local csp; csp=$(echo "$headers_resp" | grep -i "^Content-Security-Policy:" | head -1 | tr -d '\r' || true)
    if [[ -z "$xfo" ]] && ! echo "$csp" | grep -qi "frame-ancestors"; then
        emit_finding "medium" \
            "Clickjacking Protection Missing — No X-Frame-Options or CSP frame-ancestors (${ip}:${port})" \
            "Neither X-Frame-Options nor CSP frame-ancestors is set at ${base_url}. The page can be framed by any domain, enabling clickjacking attacks." \
            "Add Content-Security-Policy: frame-ancestors 'self'; (preferred) or X-Frame-Options: SAMEORIGIN. CSP frame-ancestors takes precedence over X-Frame-Options in modern browsers." \
            "ev-06-${ip//./_}-t18-clickjacking"
    fi
}

# =============================================================================
# MRK:08_TRUN — PER-TARGET DISPATCHER | trun,target,dispatcher,test | L1589-1654
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

test_target() {
    local host_port="$1"
    local ip; ip=$(echo "$host_port" | cut -d: -f1)
    local port; port=$(echo "$host_port" | cut -d: -f2)
    [[ -z "$port" ]] && port=80

    _CURRENT_IP="$ip"

    local scheme; scheme=$(_detect_tls "$ip" "$port")
    local base_url="${scheme}://${ip}:${port}"

    local ip_slug="${ip//./_}"
    local ev_dir="${EVIDENCE_BASE}/${ip_slug}_${port}"
    mkdir -p "$ev_dir"

    log "========================================================"
    log "TARGET: ${base_url} | Profile: ${PROFILE} | Tier: ${TIER}"
    log "========================================================"

    local reach_code; reach_code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}/" || true)
    if [[ "$reach_code" == "000" ]]; then
        log_warn "Target ${base_url} unreachable — skipping"
        return
    fi
    log_ok "Target reachable: HTTP ${reach_code}"

    # Initialize summary fields
    _SUMMARY_TECH="?"
    _SUMMARY_HEADERS="?"
    _SUMMARY_CORS=0
    _SUMMARY_WAF="none"
    _SUMMARY_DIRS=0
    _SUMMARY_API=0
    _SUMMARY_CMS="none"
    _FIND_AT_START="${_FIND_CTR}"

    _test_skip 1  || test_01_headers_fingerprint  "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 2  || test_02_security_headers      "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 3  || test_03_cors                  "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 4  || test_04_waf_detection         "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 5  || test_05_directory_discovery   "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 6  || test_06_nikto                 "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 7  || test_07_js_analysis           "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 8  || test_08_api_discovery         "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 9  || test_09_sensitive_files       "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 10 || test_10_vhost_discovery       "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 11 || test_11_403_bypass            "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 12 || test_12_cookie_security       "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 13 || test_13_open_redirect         "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 14 || test_14_login_analysis        "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 15 || test_15_cms_detection         "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 16 || test_16_graphql               "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 17 || test_17_oauth_oidc            "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 18 || test_18_client_side_security  "$base_url" "$ev_dir" "$ip" "$port"

    local target_finds=$(( _FIND_CTR - _FIND_AT_START ))
    log_ok "Target ${base_url} complete — ${target_finds} finding(s)"

    echo "SUMMARY_ROW|${ip}|${port}|${target_finds}|${_SUMMARY_CORS}|${_SUMMARY_WAF}|${_SUMMARY_DIRS}|${_SUMMARY_API}|${_SUMMARY_CMS}"
}

# =============================================================================
# MRK:08_MAIN — MAIN ENTRY POINT | main,entry,point,summary | L1655-1765
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

main() {
    log "PT-Orc 08_web_enum.sh v2.0 — Advanced Web Enumeration"
    log "Session: ${SESSION_TS} | Profile: ${PROFILE} | Tier: ${TIER}"
    [[ "${#CURL_PROXY_ARGS[@]}" -gt 0 ]] && log_info "Intercept proxy: ${CURL_PROXY_ARGS[*]}"
    log_info "Wordlist: ${WORDLIST}"

    setup_profile

    local -a targets; mapfile -t targets < <(assemble_targets)

    confirm_scope "${targets[@]}"

    if command -v trail_phase_start &>/dev/null; then
        trail_phase_start "08_web_enum" "Web Enum v2.0" "${#targets[@]} targets"
    fi

    local summary_rows=()
    for host_port in "${targets[@]}"; do
        local row; row=$(test_target "$host_port")
        while IFS= read -r line; do
            [[ "$line" == SUMMARY_ROW* ]] && summary_rows+=("$line")
        done <<< "$row"
    done

    # test_target runs in subshell; sync counter from the written file
    [[ -f "$FINDINGS_FILE" ]] && _FIND_CTR=$(wc -l < "$FINDINGS_FILE") || _FIND_CTR=0

    write_web_exports "${summary_rows[@]+"${summary_rows[@]}"}"

    # ── Markdown summary ─────────────────────────────────────────────────────
    local summary_md="${SCRIPT_DIR}/working/$(ev_fname "06-webenum-summary" "md")"
    {
        echo "# Web Enumeration Summary — ${PROJECT_NAME:-unknown}"
        echo ""
        echo "**Date:** $(date +'%Y-%m-%d %H:%M:%S')"
        echo "**Profile:** ${PROFILE} | **Tier:** ${TIER} | **Tests:** T01-T18"
        echo "**Targets:** ${#targets[@]} | **Wordlist:** ${WORDLIST}"
        echo ""
        echo "## Coverage"
        echo ""
        echo "| # | Test | Status |"
        echo "|---|------|--------|"
        local test_names=(
            "T01:Headers & Tech Fingerprint"
            "T02:Security Headers & CSP Analysis"
            "T03:CORS Misconfiguration"
            "T04:WAF Detection & Fingerprint"
            "T05:Directory / Path Discovery (Gobuster+ffuf)"
            "T06:Nikto Scanner"
            "T07:JavaScript Analysis & Secret Extraction"
            "T08:API Endpoint Discovery"
            "T09:Sensitive File Exposure"
            "T10:Virtual Host Discovery"
            "T11:403 Bypass Techniques"
            "T12:Cookie Security Analysis"
            "T13:Open Redirect Detection"
            "T14:Login Page Analysis"
            "T15:CMS Detection"
            "T16:GraphQL Introspection"
            "T17:OAuth2 / OIDC Discovery"
            "T18:Client-Side Security Indicators"
        )
        for entry in "${test_names[@]}"; do
            local tnum; tnum=$(echo "$entry" | cut -d: -f1 | tr -d 'T')
            local tname; tname=$(echo "$entry" | cut -d: -f2-)
            echo "| ${entry%%:*} | ${tname} | $([ "${_T_ENABLED[$tnum]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        done
        echo ""
        echo "## Per-Target Results"
        echo ""
        echo "| Host | Port | Findings | CORS | WAF | Dir Hits | API Exposed | CMS |"
        echo "|------|------|----------|------|-----|----------|-------------|-----|"
        for row in "${summary_rows[@]+"${summary_rows[@]}"}"; do
            IFS='|' read -r _ rip rport rfinds rcors rwaf rdirs rapi rcms <<< "$row"
            local fc; fc="$( [[ "${rcors:-0}" -eq 1 ]] && echo "⚠ Yes" || echo "OK")"
            local fd; fd="$( [[ "${rdirs:-0}" -eq 1 ]] && echo "⚠ Yes" || echo "OK")"
            local fa; fa="$( [[ "${rapi:-0}"  -eq 1 ]] && echo "⚠ Yes" || echo "OK")"
            echo "| ${rip} | ${rport} | ${rfinds} | ${fc} | ${rwaf:-none} | ${fd} | ${fa} | ${rcms:-none} |"
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
        echo "*Generated by PT-Orc 08_web_enum.sh v2.0 — TechGuard Labs*"
    } > "$summary_md"

    log_ok "Summary: ${summary_md}"
    log_ok "Findings: ${FINDINGS_FILE} (${_FIND_CTR} total)"
    log_ok "Evidence: ${EVIDENCE_BASE}"

    if command -v trail_phase_end &>/dev/null; then
        trail_phase_end "08_web_enum" "${_FIND_CTR} findings" "$summary_md"
    fi

    cat "$summary_md"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
