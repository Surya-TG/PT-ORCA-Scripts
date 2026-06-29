#!/usr/bin/env bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:19_NAV_TOC — Section index | nav,toc,index | L5-28
# - MRK:19_T01 — T01 MySQL/MariaDB (port 3306) | t01,mysql,mariadb,3306 | LXXXX-XXXX
# - MRK:19_T02 — T02 MSSQL (port 1433) | t02,mssql,sqlserver,1433 | LXXXX-XXXX
# - MRK:19_T03 — T03 PostgreSQL (port 5432) | t03,postgresql,postgres,5432 | LXXXX-XXXX
# - MRK:19_T04 — T04 Oracle (port 1521) | t04,oracle,tns,1521 | LXXXX-XXXX
# - MRK:19_T05 — T05 Redis (port 6379) | t05,redis,6379 | LXXXX-XXXX
# - MRK:19_T06 — T06 MongoDB (port 27017) | t06,mongodb,mongo,27017 | LXXXX-XXXX
# - MRK:19_T07 — T07 Elasticsearch (port 9200) | t07,elasticsearch,elastic,9200 | LXXXX-XXXX
# NAV-LEN: 7 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-06-25

# =============================================================================
# 19_database_audit.sh — Database Service Exposure & Default Credential Audit
# TechGuard Labs | PT-Orc Suite v0.8
# =============================================================================
# NAV: MRK:19_TOC (this block) | MRK:19_ROOT | MRK:19_CONF | MRK:19_LOG
#      MRK:19_ARGS | MRK:19_CONFIRM | MRK:19_TARGETS
#      MRK:19_FIND | MRK:19_UTILS | MRK:19_PROF
#      MRK:19_T01 — T01 MySQL/MariaDB
#      MRK:19_T02 — T02 MSSQL
#      MRK:19_T03 — T03 PostgreSQL
#      MRK:19_T04 — T04 Oracle
#      MRK:19_T05 — T05 Redis
#      MRK:19_T06 — T06 MongoDB
#      MRK:19_T07 — T07 Elasticsearch
#      MRK:19_TRUN | MRK:19_MAIN
# =============================================================================

# - MRK:19_ROOT
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# - MRK:19_CONF
CONF_FILE="${SCRIPT_DIR}/pt-orc.conf"
[[ -f "$CONF_FILE" ]] || { echo "[FATAL] pt-orc.conf not found at ${CONF_FILE}"; exit 1; }
# shellcheck source=pt-orc.conf
source "$CONF_FILE"

LIB_FILE="${SCRIPT_DIR}/orc-common-lib.sh"
[[ -f "$LIB_FILE" ]] && source "$LIB_FILE"

PROJ_SLUG="${PROJECT_NAME//[^A-Za-z0-9._-]/_}"
EVIDENCE_BASE="${SCRIPT_DIR}/evidence/${PROJ_SLUG}"
DRY_RUN=0
SCAN_PROFILE="${SCAN_PROFILE:-standard}"

# DB-specific conf defaults (may be overridden in pt-orc.conf)
DB_TARGETS="${DB_TARGETS:-}"
DB_CRED_SPRAY_ENABLED="${DB_CRED_SPRAY_ENABLED:-0}"
DB_TIMEOUT="${DB_TIMEOUT:-20}"

# - MRK:19_LOG
_R='\033[0;31m'; _G='\033[0;32m'; _Y='\033[1;33m'; _B='\033[0;34m'; _C='\033[0;36m'; _W='\033[1;37m'; _N='\033[0m'
SESSION_TS="$(date +%Y%m%d_%H%M%S)"
EV_TS="$(date +'%Y-%m-%d-%H-%M-%S')"
LOG_FILE="${SCRIPT_DIR}/working/${PROJ_SLUG}_19_db_${SESSION_TS}.log"
mkdir -p "${SCRIPT_DIR}/working" "${EVIDENCE_BASE}"

_log()    { local ts; ts="$(date +%H:%M:%S)"; printf "[%s] %s\n" "$ts" "$*" | tee -a "$LOG_FILE"; }
log_ok()  { printf "${_G}[+]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_inf() { printf "${_B}[*]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_wrn() { printf "${_Y}[!]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_err() { printf "${_R}[-]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_dry() { printf "${_C}[DRY]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }

# - MRK:19_ARGS
_SKIP_CONFIRM=0
_ONLY_TESTS=()
_SKIP_TESTS=()
_CLI_TARGETS=""

_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Database Service Exposure & Default Credential Audit (step 19)

Scans DB_TARGETS (or TARGET_IPS/TARGET_SUBNETS from pt-orc.conf) for common
database services and checks for unauthenticated access, version disclosure,
and default credentials.

Options:
  --targets <IPs/CIDRs>   Scan targets (space-separated; overrides DB_TARGETS from conf)
  -p, --profile <name>    Scan profile: quick|standard|deep  [default: standard]
                            quick    = T05,T06,T07 (unauthenticated/banner only)
                            standard = T01,T02,T03,T05,T06,T07
                            deep     = all (T01-T07)
  --only <T01,T05,...>    Run only specified tests
  --skip <T04,T06,...>    Skip specified tests
  -y, --yes               Skip confirmation prompt
  --dry-run               Print actions without executing
  -h, --help              Show this help

Credential spray (T01-T04) is gated by DB_CRED_SPRAY_ENABLED=1 in pt-orc.conf.
nmap NSE scripts always run regardless of that setting.

WARNING: --profile deep includes Oracle TNS SID brute (T04). Only run within
         authorised scope and agreed engagement window.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)      _CLI_TARGETS="$2"; shift 2 ;;
        -p|--profile)   SCAN_PROFILE="$2"; shift 2 ;;
        --only)         IFS=',' read -ra _ONLY_TESTS <<< "$2"; shift 2 ;;
        --skip)         IFS=',' read -ra _SKIP_TESTS <<< "$2"; shift 2 ;;
        -y|--yes)       _SKIP_CONFIRM=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -h|--help)      _usage; exit 0 ;;
        *)              log_err "Unknown option: $1"; _usage; exit 1 ;;
    esac
done

# CLI --targets overrides conf DB_TARGETS
[[ -n "$_CLI_TARGETS" ]] && DB_TARGETS="$_CLI_TARGETS"

# - MRK:19_CONFIRM
_confirm() {
    [[ "$_SKIP_CONFIRM" -eq 1 ]] && return 0
    local target_display="${DB_TARGETS:-${TARGET_IPS:-} ${TARGET_SUBNETS:-}}"
    printf "\n${_Y}[CONFIRM]${_N} Database Audit. Profile: ${_W}%s${_N}\n" "$SCAN_PROFILE"
    printf "  Project      : %s\n" "$PROJECT_NAME"
    printf "  Targets      : %s\n" "${target_display// +/ }"
    printf "  Cred spray   : %s\n" "$( [[ "$DB_CRED_SPRAY_ENABLED" -eq 1 ]] && echo "ENABLED (T01-T04)" || echo "disabled (nmap NSE only)" )"
    printf "  DB timeout   : %ss\n" "$DB_TIMEOUT"
    printf "\n  ${_R}WARNING:${_N} This script sends active packets to database services.\n"
    printf "  Only run within authorised scope and agreed engagement window.\n"
    printf "\n  Continue? [y/N] "
    read -r _ans
    [[ "${_ans,,}" == "y" ]] || { log_err "Aborted by user."; exit 0; }
}

# - MRK:19_TARGETS
_validate_config() {
    local ok=1
    local combined="${DB_TARGETS:-}${TARGET_IPS:-}${TARGET_SUBNETS:-}"
    if [[ -z "${combined// /}" ]]; then
        log_err "No targets defined. Set DB_TARGETS, TARGET_IPS, or TARGET_SUBNETS in pt-orc.conf, or use --targets."
        ok=0
    fi
    [[ "$ok" -eq 1 ]]
}

# Build a flat list of scan targets
_build_target_list() {
    local targets=""
    if [[ -n "${DB_TARGETS:-}" ]]; then
        targets="$DB_TARGETS"
    else
        [[ -n "${TARGET_IPS:-}"      ]] && targets+=" ${TARGET_IPS}"
        [[ -n "${TARGET_SUBNETS:-}"  ]] && targets+=" ${TARGET_SUBNETS}"
    fi
    echo "${targets}" | tr ' ' '\n' | grep -v '^$' | sort -u
}

# Discover which DB ports are open per host
# Populates _OPEN_PORTS associative array: _OPEN_PORTS[host]="3306 27017 ..."
declare -A _OPEN_PORTS

_discover_db_ports() {
    local target_list
    mapfile -t target_list < <(_build_target_list)

    if [[ ${#target_list[@]} -eq 0 ]]; then
        log_err "Target list is empty — cannot scan."
        return 1
    fi

    local port_list="1433,1521,3306,5432,6379,9200,27017,28017"
    local ev_f="${EVIDENCE_BASE}/$(ev_fname "db-portscan" "txt")"

    log_inf "Scanning for database services: ports ${port_list}"
    log_inf "Targets: ${target_list[*]}"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_dry "nmap -sV --open -p ${port_list} -oG - ${target_list[*]}"
        # Populate dummy for dry-run so tests have something to iterate
        for host in "${target_list[@]}"; do
            _OPEN_PORTS["$host"]="3306 1433 5432 1521 6379 27017 9200"
        done
        return 0
    fi

    {
        echo "=== DB Port Discovery ==="
        echo "Date: $(date)"
        echo "Targets: ${target_list[*]}"
        echo "Ports: ${port_list}"
        echo ""
    } > "$ev_f"

    if ! _check_tool nmap; then
        log_wrn "nmap not found — attempting basic nc port checks"
        for host in "${target_list[@]}"; do
            local open_on_host=""
            for port in 1433 1521 3306 5432 6379 9200 27017 28017; do
                if timeout 3 bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; then
                    open_on_host+=" ${port}"
                    echo "OPEN: ${host}:${port}" | tee -a "$ev_f"
                fi
            done
            open_on_host="${open_on_host# }"
            [[ -n "$open_on_host" ]] && _OPEN_PORTS["$host"]="$open_on_host"
        done
        return 0
    fi

    local nmap_out
    nmap_out=$(timeout 300 nmap -sV --open -p "$port_list" -oG - \
        "${target_list[@]}" 2>/dev/null || true)
    echo "$nmap_out" >> "$ev_f"

    # Parse grepable output: "Host: 1.2.3.4 (hostname)\tPorts: 3306/open/tcp..."
    while IFS= read -r line; do
        [[ "$line" =~ ^Host: ]] || continue
        local host
        host=$(echo "$line" | awk '{print $2}')
        local ports_field
        ports_field=$(echo "$line" | grep -oE 'Ports:[^\t]+' || true)
        local open_ports=""
        while IFS= read -r pentry; do
            local pnum
            pnum=$(echo "$pentry" | cut -d'/' -f1)
            [[ -n "$pnum" ]] && open_ports+=" ${pnum}"
        done < <(echo "$ports_field" | grep -oE '[0-9]+/open/tcp[^,]*' || true)
        open_ports="${open_ports# }"
        if [[ -n "$open_ports" ]]; then
            _OPEN_PORTS["$host"]="$open_ports"
            log_ok "  ${host}: open db ports → ${open_ports}"
        fi
    done <<< "$nmap_out"

    local total_hosts="${#_OPEN_PORTS[@]}"
    log_inf "Discovery complete: ${total_hosts} host(s) with open database ports"
    log_ok "  Port scan evidence → ${ev_f}"
}

_host_has_port() {
    local host="$1" port="$2"
    local ports="${_OPEN_PORTS[$host]:-}"
    [[ "$ports" =~ (^| )${port}( |$) ]]
}

# - MRK:19_FIND
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "19-db-findings" "jsonl")"
_FIND_CTR=0
: > "$FINDINGS_FILE"

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="${5:-}"
    (( _FIND_CTR++ )) || true
    local fid
    fid="f-19-db-$(printf '%04d' "$_FIND_CTR")"
    local ev_id="${ev_tag:-${fid}-ev}"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"19_database_audit","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
        "$fid" \
        "$(echo "$title" | sed 's/"/\\"/g')" \
        "$sev" \
        "$ev_id" \
        "$(echo "$desc" | sed 's/"/\\"/g')" \
        "$(echo "$rec"  | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_wrn "FINDING [${sev^^}] ${title}"
}

# - MRK:19_UTILS
_check_tool() {
    local tool="$1"
    command -v "$tool" &>/dev/null
}

_ev_file() {
    local tag="$1" host="${2:-}"
    local safe_host="${host//./_}"
    if [[ -n "$safe_host" ]]; then
        echo "${EVIDENCE_BASE}/$(ev_fname "db-${tag}" "txt" "$safe_host")"
    else
        echo "${EVIDENCE_BASE}/$(ev_fname "db-${tag}" "txt")"
    fi
}

declare -A _T_ENABLED
_test_skip() {
    local n="$1"
    [[ "${_T_ENABLED[$n]:-1}" -eq 0 ]] && return 0
    return 1
}

_apply_cli_filters() {
    if [[ ${#_ONLY_TESTS[@]} -gt 0 ]]; then
        for k in "${!_T_ENABLED[@]}"; do _T_ENABLED[$k]=0; done
        for t in "${_ONLY_TESTS[@]}"; do _T_ENABLED["${t^^}"]=1; done
    fi
    for t in "${_SKIP_TESTS[@]+"${_SKIP_TESTS[@]}"}"; do
        _T_ENABLED["${t^^}"]=0
    done
}

# - MRK:19_PROF
setup_profile() {
    local prof="${1:-standard}"
    for n in T01 T02 T03 T04 T05 T06 T07; do
        _T_ENABLED[$n]=1
    done
    case "$prof" in
        quick)
            # Quick: unauthenticated/banner probes only (Redis, MongoDB, Elasticsearch)
            for n in T01 T02 T03 T04; do _T_ENABLED[$n]=0; done ;;
        standard)
            # Standard: MySQL, MSSQL, PostgreSQL + unauthenticated; skip Oracle
            _T_ENABLED[T04]=0 ;;
        deep)
            # All enabled
            : ;;
        *)
            log_wrn "Unknown profile '${prof}' — defaulting to standard"
            _T_ENABLED[T04]=0 ;;
    esac
    _apply_cli_filters
}

# =============================================================================
# TESTS
# =============================================================================

# - MRK:19_T01 — T01 MySQL/MariaDB (port 3306)
test_T01_mysql() {
    local host="$1"
    local ev_f; ev_f="$(_ev_file "mysql" "$host")"

    log_inf "[T01] MySQL/MariaDB audit → ${host}:3306"

    if ! _host_has_port "$host" 3306; then
        log_inf "  [T01] port 3306 not open on ${host} — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "nmap NSE mysql-empty-password,mysql-databases,mysql-users ${host}:3306"
        log_dry "mysql -h ${host} -u root -p'' -e 'show databases' (if DB_CRED_SPRAY_ENABLED)"
        return
    }

    {
        echo "=== T01 MySQL/MariaDB Audit ==="
        echo "Host: ${host}  Port: 3306"
        echo "Date: $(date)"
        echo ""
    } > "$ev_f"

    # ── NSE scan (always runs) ───────────────────────────────────────────────
    if _check_tool nmap; then
        log_inf "  Running nmap NSE: mysql-empty-password,mysql-databases,mysql-users"
        local nse_out
        nse_out=$(timeout "$DB_TIMEOUT" nmap -sV -p 3306 \
            --script mysql-empty-password,mysql-databases,mysql-users \
            -oN - "$host" 2>/dev/null || true)
        echo "--- NSE Output ---" >> "$ev_f"
        echo "$nse_out" >> "$ev_f"

        if echo "$nse_out" | grep -qi 'mysql-empty-password.*root\|account.*root.*Empty'; then
            emit_finding "critical" \
                "MySQL: Root Account with Empty Password on ${host}" \
                "nmap NSE confirmed MySQL root account accepts authentication with an empty password on ${host}:3306. Full database access is possible without credentials." \
                "Set a strong password for all MySQL/MariaDB accounts: ALTER USER 'root'@'%' IDENTIFIED BY '<strong-password>'; Disable remote root login. Bind MySQL to 127.0.0.1 if external access is not required." \
                "mysql_empty_root_${host//./_}"
        fi

        local db_list
        db_list=$(echo "$nse_out" | grep -A30 'mysql-databases:' | grep -E '^\s+\|' | sed 's/.*| //' | head -20 || true)
        if [[ -n "$db_list" ]]; then
            emit_finding "high" \
                "MySQL: Database Listing via NSE on ${host}" \
                "nmap NSE mysql-databases successfully enumerated MySQL databases on ${host}:3306: $(echo "$db_list" | tr '\n' ', ' | sed 's/,$//'). Unauthenticated or anonymous listing exposes schema names to attackers." \
                "Restrict SHOW DATABASES privilege to authenticated accounts only. Revoke global SELECT from anonymous users. Audit MySQL user table for blank passwords." \
                "mysql_db_list_${host//./_}"
        fi

        local user_list
        user_list=$(echo "$nse_out" | grep -A30 'mysql-users:' | grep -E '^\s+\|' | sed 's/.*| //' | head -20 || true)
        if [[ -n "$user_list" ]]; then
            emit_finding "medium" \
                "MySQL: User Enumeration via NSE on ${host}" \
                "nmap NSE mysql-users enumerated MySQL user accounts on ${host}:3306: $(echo "$user_list" | tr '\n' ', ' | sed 's/,$//'). Account names can be used to target credential attacks." \
                "Restrict the SELECT privilege on mysql.user to DBA accounts only. Audit all MySQL accounts and remove unused ones." \
                "mysql_user_list_${host//./_}"
        fi
    else
        log_wrn "  nmap not found — skipping NSE checks for T01"
    fi

    # ── Credential spray (gated by DB_CRED_SPRAY_ENABLED) ───────────────────
    if [[ "${DB_CRED_SPRAY_ENABLED:-0}" -ne 1 ]]; then
        log_inf "  DB_CRED_SPRAY_ENABLED=0 — skipping MySQL credential attempts"
        return
    fi

    if ! _check_tool mysql; then
        log_wrn "  mysql client not found — cannot attempt credential spray"
        return
    fi

    log_inf "  Attempting MySQL default credentials (root/blank, root/root, root/mysql, admin/admin)"
    {
        echo ""
        echo "--- Credential Spray ---"
    } >> "$ev_f"

    local -a cred_pairs=("root:" "root:root" "root:mysql" "admin:admin")
    local found_creds=""
    for pair in "${cred_pairs[@]}"; do
        local uname="${pair%%:*}"
        local passwd="${pair#*:}"
        local mysql_out
        mysql_out=$(timeout "$DB_TIMEOUT" mysql -h "$host" -u "$uname" -p"${passwd}" \
            --connect-timeout=5 -e "show databases;" 2>&1 || true)
        echo "[TRY] ${uname}/${passwd:-<blank>}: $(echo "$mysql_out" | head -3)" >> "$ev_f"
        if echo "$mysql_out" | grep -qiE '^Database|information_schema|performance_schema'; then
            found_creds="${uname}/${passwd:-<blank>}"
            local db_count
            db_count=$(echo "$mysql_out" | grep -v '^Database' | grep -c '\S' || echo 0)
            emit_finding "critical" \
                "MySQL: Default Credential Access on ${host} (${uname}/${passwd:-<blank>})" \
                "MySQL on ${host}:3306 accepted login with default credentials ${uname}/${passwd:-<blank>}. ${db_count} database(s) listed. Full database read/write access is achievable without prior knowledge." \
                "Change all MySQL account passwords immediately. Remove blank-password accounts: DELETE FROM mysql.user WHERE authentication_string=''; Bind MySQL to localhost if remote access is not required. Enforce password policy via validate_password plugin." \
                "mysql_default_creds_${host//./_}"
            log_wrn "  MYSQL DEFAULT CREDS WORK: ${found_creds} on ${host}"
            break
        fi
    done
    [[ -z "$found_creds" ]] && log_ok "  MySQL credential spray: no default creds accepted on ${host}"
    log_ok "  [T01] MySQL audit complete → ${ev_f}"
}

# - MRK:19_T02 — T02 MSSQL (port 1433)
test_T02_mssql() {
    local host="$1"
    local ev_f; ev_f="$(_ev_file "mssql" "$host")"

    log_inf "[T02] MSSQL audit → ${host}:1433"

    if ! _host_has_port "$host" 1433; then
        log_inf "  [T02] port 1433 not open on ${host} — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "nmap NSE ms-sql-info,ms-sql-empty-password,ms-sql-config ${host}:1433"
        log_dry "impacket-mssqlclient sa@${host} (if DB_CRED_SPRAY_ENABLED)"
        return
    }

    {
        echo "=== T02 MSSQL Audit ==="
        echo "Host: ${host}  Port: 1433"
        echo "Date: $(date)"
        echo ""
    } > "$ev_f"

    # ── NSE scan (always runs) ───────────────────────────────────────────────
    if _check_tool nmap; then
        log_inf "  Running nmap NSE: ms-sql-info,ms-sql-empty-password,ms-sql-config"
        local nse_out
        nse_out=$(timeout "$DB_TIMEOUT" nmap -sV -p 1433 \
            --script ms-sql-info,ms-sql-empty-password,ms-sql-config \
            -oN - "$host" 2>/dev/null || true)
        echo "--- NSE Output ---" >> "$ev_f"
        echo "$nse_out" >> "$ev_f"

        if echo "$nse_out" | grep -qi 'ms-sql-empty-password\|Login.*sa.*succeeded\|Login succeeded'; then
            emit_finding "critical" \
                "MSSQL: SA Account with Empty Password on ${host}" \
                "nmap NSE confirmed MSSQL SA (System Administrator) account accepts authentication with an empty password on ${host}:1433. Full database server control is possible without credentials." \
                "Set a strong password for the SA account: ALTER LOGIN sa WITH PASSWORD = '<strong-password>'; Disable the SA account if not required. Enable Windows Authentication only where possible." \
                "mssql_empty_sa_${host//./_}"
        fi

        local version_info
        version_info=$(echo "$nse_out" | grep -iE 'Product:|Version:|Version name:' | head -5 | tr '\n' '; ' || true)
        if [[ -n "$version_info" ]]; then
            emit_finding "medium" \
                "MSSQL: Version Disclosure on ${host}" \
                "MSSQL version information disclosed via NSE on ${host}:1433: ${version_info}. Version details help attackers identify applicable CVEs and patch status." \
                "Apply latest MSSQL cumulative updates and service packs. Restrict MSSQL port 1433 to authorised management IPs only. Disable SQL Server Browser service if not required." \
                "mssql_version_${host//./_}"
        fi
    else
        log_wrn "  nmap not found — skipping NSE checks for T02"
    fi

    # ── Credential spray (gated by DB_CRED_SPRAY_ENABLED) ───────────────────
    if [[ "${DB_CRED_SPRAY_ENABLED:-0}" -ne 1 ]]; then
        log_inf "  DB_CRED_SPRAY_ENABLED=0 — skipping MSSQL credential attempts"
        return
    fi

    if ! _check_tool impacket-mssqlclient; then
        log_wrn "  impacket-mssqlclient not found — cannot attempt MSSQL credential spray"
        return
    fi

    log_inf "  Attempting MSSQL default credentials (sa/blank, sa/sa, sa/password)"
    {
        echo ""
        echo "--- Credential Spray ---"
    } >> "$ev_f"

    local -a mssql_pairs=("sa:" "sa:sa" "sa:password")
    local found_mssql_creds=""
    for pair in "${mssql_pairs[@]}"; do
        local uname="${pair%%:*}"
        local passwd="${pair#*:}"
        local mssql_out
        mssql_out=$(timeout "$DB_TIMEOUT" impacket-mssqlclient \
            "${uname}:${passwd}@${host}" -windows-auth 2>&1 <<< "SELECT @@version; exit" || true)
        # Also try SQL auth (non-windows)
        if ! echo "$mssql_out" | grep -qi 'Microsoft SQL Server\|Version'; then
            mssql_out=$(timeout "$DB_TIMEOUT" impacket-mssqlclient \
                "${uname}:${passwd}@${host}" 2>&1 <<< "SELECT @@version; exit" || true)
        fi
        echo "[TRY] ${uname}/${passwd:-<blank>}: $(echo "$mssql_out" | head -3)" >> "$ev_f"

        if echo "$mssql_out" | grep -qi 'Microsoft SQL Server'; then
            found_mssql_creds="${uname}/${passwd:-<blank>}"

            # Check for xp_cmdshell
            local xcmd_out
            xcmd_out=$(timeout "$DB_TIMEOUT" impacket-mssqlclient \
                "${uname}:${passwd}@${host}" 2>&1 <<< "EXEC sp_configure 'xp_cmdshell'; exit" || true)
            echo "--- xp_cmdshell config ---" >> "$ev_f"
            echo "$xcmd_out" >> "$ev_f"

            local xcmd_enabled=0
            echo "$xcmd_out" | grep -qiE 'xp_cmdshell.*1\s*$|run_value.*1' && xcmd_enabled=1

            emit_finding "critical" \
                "MSSQL: Default Credential Access on ${host} (${uname}/${passwd:-<blank>})" \
                "MSSQL on ${host}:1433 accepted login with default credentials ${uname}/${passwd:-<blank>}. Full database server access is possible. xp_cmdshell enabled: ${xcmd_enabled}." \
                "Change SA and all default MSSQL account passwords. Disable SA account if not needed. Restrict MSSQL to localhost or management VLAN. Enable SQL Server Audit. Use Windows Authentication exclusively where possible." \
                "mssql_default_creds_${host//./_}"
            log_wrn "  MSSQL DEFAULT CREDS WORK: ${found_mssql_creds} on ${host}"

            if [[ "$xcmd_enabled" -eq 1 ]]; then
                emit_finding "critical" \
                    "MSSQL: xp_cmdshell Enabled on ${host}" \
                    "MSSQL extended stored procedure xp_cmdshell is enabled on ${host}:1433. Combined with database access, this allows operating-system command execution as the SQL Server service account." \
                    "Disable xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; Enable 'surface area configuration' restrictions. If xp_cmdshell is required operationally, restrict execution to specific accounts via GRANT EXECUTE." \
                    "mssql_xcmdshell_${host//./_}"
                log_wrn "  MSSQL xp_cmdshell is ENABLED on ${host} — OS command execution possible"
            fi
            break
        fi
    done
    [[ -z "$found_mssql_creds" ]] && log_ok "  MSSQL credential spray: no default creds accepted on ${host}"
    log_ok "  [T02] MSSQL audit complete → ${ev_f}"
}

# - MRK:19_T03 — T03 PostgreSQL (port 5432)
test_T03_postgresql() {
    local host="$1"
    local ev_f; ev_f="$(_ev_file "postgresql" "$host")"

    log_inf "[T03] PostgreSQL audit → ${host}:5432"

    if ! _host_has_port "$host" 5432; then
        log_inf "  [T03] port 5432 not open on ${host} — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "nmap NSE pgsql-brute ${host}:5432"
        log_dry "psql -h ${host} -U postgres (if DB_CRED_SPRAY_ENABLED)"
        return
    }

    {
        echo "=== T03 PostgreSQL Audit ==="
        echo "Host: ${host}  Port: 5432"
        echo "Date: $(date)"
        echo ""
    } > "$ev_f"

    # ── NSE scan (always runs) ───────────────────────────────────────────────
    if _check_tool nmap; then
        log_inf "  Running nmap NSE: pgsql-brute (tiny list: postgres/postgres, postgres/blank)"
        # Create a minimal brute list in a temp file
        local brute_list
        brute_list=$(mktemp /tmp/pg_brute_XXXXXX.lst)
        printf "postgres\t\npostgres\tpostgres\n" > "$brute_list"

        local nse_out
        nse_out=$(timeout "$DB_TIMEOUT" nmap -sV -p 5432 \
            --script pgsql-brute \
            --script-args "brute.firstonly=true,userdb=${brute_list},passdb=${brute_list}" \
            -oN - "$host" 2>/dev/null || true)
        rm -f "$brute_list"
        echo "--- NSE Output ---" >> "$ev_f"
        echo "$nse_out" >> "$ev_f"

        if echo "$nse_out" | grep -qi 'Valid credentials\|Login correct\|postgres.*Valid'; then
            emit_finding "critical" \
                "PostgreSQL: Default Credentials Accepted via NSE on ${host}" \
                "nmap NSE pgsql-brute confirmed default credentials are accepted on ${host}:5432. The postgres superuser account is accessible with default or blank password." \
                "Change the postgres superuser password: ALTER USER postgres WITH ENCRYPTED PASSWORD '<strong-password>'; Configure pg_hba.conf to require md5 or scram-sha-256 for all connections. Restrict the listen_addresses parameter." \
                "pgsql_default_creds_nse_${host//./_}"
        fi

        # Version check from banner
        local pg_version
        pg_version=$(echo "$nse_out" | grep -iE 'PostgreSQL|version' | head -3 | tr '\n' '; ' || true)
        if [[ -n "$pg_version" ]]; then
            log_inf "  PostgreSQL version info: ${pg_version}"
            echo "Version info: ${pg_version}" >> "$ev_f"
        fi
    else
        log_wrn "  nmap not found — skipping NSE checks for T03"
    fi

    # ── Credential spray (gated by DB_CRED_SPRAY_ENABLED) ───────────────────
    if [[ "${DB_CRED_SPRAY_ENABLED:-0}" -ne 1 ]]; then
        log_inf "  DB_CRED_SPRAY_ENABLED=0 — skipping PostgreSQL credential attempts"
        return
    fi

    if ! _check_tool psql; then
        log_wrn "  psql client not found — cannot attempt PostgreSQL credential spray"
        return
    fi

    log_inf "  Attempting PostgreSQL default credentials (postgres/postgres, postgres/blank)"
    {
        echo ""
        echo "--- Credential Spray ---"
    } >> "$ev_f"

    local -a pg_pairs=("postgres:" "postgres:postgres")
    local found_pg_creds=""
    for pair in "${pg_pairs[@]}"; do
        local uname="${pair%%:*}"
        local passwd="${pair#*:}"
        local pg_out
        pg_out=$(PGPASSWORD="${passwd}" timeout "$DB_TIMEOUT" psql \
            -h "$host" -U "$uname" -c '\l' 2>&1 || true)
        echo "[TRY] ${uname}/${passwd:-<blank>}: $(echo "$pg_out" | head -3)" >> "$ev_f"

        if echo "$pg_out" | grep -qiE 'List of databases|Name.*Owner|template0|template1'; then
            found_pg_creds="${uname}/${passwd:-<blank>}"
            local db_count
            db_count=$(echo "$pg_out" | grep -cE '^\s+\w' || echo 0)

            # Check pg_hba.conf trust mode indicators
            local trust_out
            trust_out=$(PGPASSWORD="${passwd}" timeout "$DB_TIMEOUT" psql \
                -h "$host" -U "$uname" -c "SHOW hba_file;" 2>&1 | head -5 || true)
            echo "hba_file: ${trust_out}" >> "$ev_f"

            emit_finding "critical" \
                "PostgreSQL: Default Credential Access on ${host} (${uname}/${passwd:-<blank>})" \
                "PostgreSQL on ${host}:5432 accepted login with default credentials ${uname}/${passwd:-<blank>}. ${db_count} database(s) visible. The 'trust' authentication mode in pg_hba.conf may be enabled, allowing password-free access from network ranges." \
                "Change the postgres superuser password immediately. Review pg_hba.conf for 'trust' entries and replace with 'scram-sha-256'. Bind PostgreSQL to localhost (listen_addresses = 'localhost') unless remote access is required with proper authentication." \
                "pgsql_default_creds_${host//./_}"
            log_wrn "  POSTGRESQL DEFAULT CREDS WORK: ${found_pg_creds} on ${host}"
            break
        fi
    done

    # Check for trust auth mode (passwordless access attempt)
    if [[ -z "$found_pg_creds" ]]; then
        local trust_out
        trust_out=$(timeout "$DB_TIMEOUT" psql -h "$host" -U postgres -c '\l' 2>&1 || true)
        echo "[TRY] postgres/no-prompt: $(echo "$trust_out" | head -2)" >> "$ev_f"
        if echo "$trust_out" | grep -qiE 'List of databases|template0|template1'; then
            emit_finding "critical" \
                "PostgreSQL: Trust Authentication (No Password) on ${host}" \
                "PostgreSQL on ${host}:5432 accepted connection as postgres without any password prompt, indicating 'trust' authentication is configured in pg_hba.conf for network access. No credentials required for superuser access." \
                "Immediately change pg_hba.conf 'trust' entries to 'scram-sha-256' or 'md5'. Set a password for the postgres superuser. Restart PostgreSQL to apply changes." \
                "pgsql_trust_auth_${host//./_}"
            log_wrn "  POSTGRESQL TRUST AUTH (no password) confirmed on ${host}"
        else
            log_ok "  PostgreSQL credential spray: no default creds accepted on ${host}"
        fi
    fi
    log_ok "  [T03] PostgreSQL audit complete → ${ev_f}"
}

# - MRK:19_T04 — T04 Oracle (port 1521)
test_T04_oracle() {
    local host="$1"
    local ev_f; ev_f="$(_ev_file "oracle" "$host")"

    log_inf "[T04] Oracle TNS audit → ${host}:1521"

    if ! _host_has_port "$host" 1521; then
        log_inf "  [T04] port 1521 not open on ${host} — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "nmap NSE oracle-tns-version,oracle-sid-brute ${host}:1521"
        log_dry "sqlplus sys/oracle@${host}/ORCL (if DB_CRED_SPRAY_ENABLED)"
        return
    }

    {
        echo "=== T04 Oracle TNS Audit ==="
        echo "Host: ${host}  Port: 1521"
        echo "Date: $(date)"
        echo ""
    } > "$ev_f"

    # ── NSE scan (always runs) ───────────────────────────────────────────────
    if _check_tool nmap; then
        log_inf "  Running nmap NSE: oracle-tns-version,oracle-sid-brute (SIDs: ORCL,XE,PROD,DB)"
        local nse_out
        nse_out=$(timeout "$DB_TIMEOUT" nmap -sV -p 1521 \
            --script oracle-tns-version,oracle-sid-brute \
            --script-args "oracle-sid-brute.sidfile=/dev/stdin" \
            -oN - "$host" 2>/dev/null \
            < <(printf 'ORCL\nXE\nPROD\nDB\n') || true)
        # Fallback without sidfile stdin if that fails
        if [[ -z "$nse_out" ]]; then
            nse_out=$(timeout "$DB_TIMEOUT" nmap -sV -p 1521 \
                --script oracle-tns-version \
                -oN - "$host" 2>/dev/null || true)
        fi
        echo "--- NSE Output ---" >> "$ev_f"
        echo "$nse_out" >> "$ev_f"

        # TNS version disclosure
        local tns_version
        tns_version=$(echo "$nse_out" | grep -iE 'Version:|oracle.*version|TNS Version' | head -3 | tr '\n' '; ' || true)
        if [[ -n "$tns_version" ]]; then
            emit_finding "low" \
                "Oracle: TNS Listener Version Disclosure on ${host}" \
                "Oracle TNS Listener version information disclosed on ${host}:1521: ${tns_version}. Version disclosure aids attackers in identifying applicable CVEs and TNS poison attack applicability." \
                "Configure sqlnet.ora with VALID_NODE_CHECKING to restrict access. Set SEC_PROTOCOL_ERROR_TRACE_ACTION=NONE in sqlnet.ora to suppress version banners. Apply latest Oracle Critical Patch Update." \
                "oracle_tns_version_${host//./_}"
            log_inf "  Oracle TNS version: ${tns_version}"
        fi

        # Valid SID discovery
        local valid_sids
        valid_sids=$(echo "$nse_out" | grep -iE 'SID.*Found|SID:.*Valid|\[+\].*SID' | \
            grep -oiE 'ORCL|XE|PROD|DB' | sort -u | tr '\n' ' ' || true)
        if [[ -n "$valid_sids" ]]; then
            emit_finding "medium" \
                "Oracle: Valid SID(s) Discovered on ${host}: ${valid_sids}" \
                "Oracle TNS SID brute-force identified valid SID(s) on ${host}:1521: ${valid_sids}. Valid SIDs are required for credential attacks and complete Oracle access." \
                "Restrict SID enumeration via Oracle Connection Manager. Enable SEC_RETURN_SERVER_RELEASE_BANNER=FALSE. Use dynamic service names instead of static SIDs where possible. Apply TNS listener password." \
                "oracle_valid_sid_${host//./_}"
            log_wrn "  Oracle valid SIDs found: ${valid_sids} on ${host}"
        fi
    else
        log_wrn "  nmap not found — skipping NSE checks for T04"
    fi

    # ── Credential spray (gated by DB_CRED_SPRAY_ENABLED) ───────────────────
    if [[ "${DB_CRED_SPRAY_ENABLED:-0}" -ne 1 ]]; then
        log_inf "  DB_CRED_SPRAY_ENABLED=0 — skipping Oracle credential attempts"
        return
    fi

    if ! _check_tool sqlplus; then
        log_wrn "  sqlplus not found — cannot attempt Oracle credential spray"
        return
    fi

    log_inf "  Attempting Oracle default credentials (sys/oracle, system/manager) across common SIDs"
    {
        echo ""
        echo "--- Credential Spray ---"
    } >> "$ev_f"

    local -a oracle_pairs=("sys:oracle" "system:manager")
    local -a oracle_sids=("ORCL" "XE" "PROD" "DB")
    local found_oracle_creds=""
    for pair in "${oracle_pairs[@]}"; do
        local uname="${pair%%:*}"
        local passwd="${pair#*:}"
        for sid in "${oracle_sids[@]}"; do
            local ora_out
            ora_out=$(timeout "$DB_TIMEOUT" sqlplus -L \
                "${uname}/${passwd}@${host}:1521/${sid}" \
                <<< "SELECT 'ORACLE_CONNECTED' FROM DUAL; EXIT;" 2>&1 || true)
            echo "[TRY] ${uname}/${passwd}@${sid}: $(echo "$ora_out" | grep -v '^$' | head -2)" >> "$ev_f"

            if echo "$ora_out" | grep -qi 'ORACLE_CONNECTED\|Connected to\|Session altered'; then
                found_oracle_creds="${uname}/${passwd}@${sid}"
                emit_finding "critical" \
                    "Oracle: Default Credential Access on ${host} (${uname}/${passwd}@${sid})" \
                    "Oracle Database on ${host}:1521 accepted login with default credentials ${uname}/${passwd} for SID ${sid}. Full database access with ${uname^^} privileges is confirmed." \
                    "Change all default Oracle account passwords immediately using ALTER USER. Lock unused default accounts (DBCA hardening). Apply Oracle Critical Patch Updates. Restrict listener to authorised IP ranges via sqlnet.ora VALID_NODE_CHECKING." \
                    "oracle_default_creds_${host//./_}"
                log_wrn "  ORACLE DEFAULT CREDS WORK: ${found_oracle_creds} on ${host}"
                break 2
            fi
        done
    done
    [[ -z "$found_oracle_creds" ]] && log_ok "  Oracle credential spray: no default creds accepted on ${host}"
    log_ok "  [T04] Oracle audit complete → ${ev_f}"
}

# - MRK:19_T05 — T05 Redis (port 6379)
test_T05_redis() {
    local host="$1"
    local ev_f; ev_f="$(_ev_file "redis" "$host")"

    log_inf "[T05] Redis audit → ${host}:6379"

    if ! _host_has_port "$host" 6379; then
        log_inf "  [T05] port 6379 not open on ${host} — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "redis-cli -h ${host} ping; CONFIG GET dir; KEYS * (limit 20); INFO server"
        return
    }

    {
        echo "=== T05 Redis Audit ==="
        echo "Host: ${host}  Port: 6379"
        echo "Date: $(date)"
        echo ""
    } > "$ev_f"

    if ! _check_tool redis-cli; then
        log_wrn "  redis-cli not found — attempting raw TCP banner grab"
        local banner
        banner=$(timeout "$DB_TIMEOUT" bash -c \
            "echo -e 'PING\r\n' | nc -w5 ${host} 6379" 2>/dev/null | head -3 || true)
        echo "Banner: ${banner}" >> "$ev_f"
        if echo "$banner" | grep -qi '+PONG\|Redis'; then
            emit_finding "critical" \
                "Redis: Unauthenticated Access Confirmed on ${host} (banner check)" \
                "Redis on ${host}:6379 responded to PING without authentication. The instance is accessible without requirepass being set. All cached data, keys, and configuration are exposed." \
                "Set requirepass in redis.conf. Bind Redis to 127.0.0.1 (bind 127.0.0.1 in redis.conf). Upgrade to Redis 6+ and enable ACL-based authentication. Block port 6379 at the firewall from untrusted networks." \
                "redis_unauth_banner_${host//./_}"
            log_wrn "  Redis PONG received without auth (banner) on ${host}"
        fi
        return
    fi

    # ── PING test ────────────────────────────────────────────────────────────
    local ping_result
    ping_result=$(timeout "$DB_TIMEOUT" redis-cli -h "$host" -p 6379 PING 2>/dev/null || true)
    echo "PING result: ${ping_result}" >> "$ev_f"

    if [[ "${ping_result}" != "+PONG" && "${ping_result}" != "PONG" ]]; then
        log_ok "  Redis: no PONG received — likely requirepass is set or port not responding"
        log_ok "  [T05] Redis audit complete → ${ev_f}"
        return
    fi

    log_wrn "  Redis PONG received without auth on ${host} — unauthenticated access confirmed"
    emit_finding "critical" \
        "Redis: Unauthenticated Access on ${host}:6379" \
        "Redis on ${host}:6379 responded to PING without authentication (no requirepass configured). The Redis instance is fully accessible without credentials, exposing all stored data and server configuration." \
        "Set a strong requirepass in redis.conf. Bind Redis to 127.0.0.1. Enable Redis ACL (Redis 6+). Block port 6379 at the network perimeter. Disable CONFIG command if not needed: rename-command CONFIG ''." \
        "redis_unauth_${host//./_}"

    # ── CONFIG GET dir (file write primitive) ───────────────────────────────
    local config_dir
    config_dir=$(timeout "$DB_TIMEOUT" redis-cli -h "$host" -p 6379 CONFIG GET dir 2>/dev/null || true)
    echo "CONFIG GET dir: ${config_dir}" >> "$ev_f"
    local config_dbfile
    config_dbfile=$(timeout "$DB_TIMEOUT" redis-cli -h "$host" -p 6379 CONFIG GET dbfilename 2>/dev/null || true)
    echo "CONFIG GET dbfilename: ${config_dbfile}" >> "$ev_f"

    if [[ -n "$config_dir" ]]; then
        emit_finding "high" \
            "Redis: CONFIG GET dir Accessible — File Write Primitive on ${host}" \
            "Unauthenticated Redis on ${host}:6379 allows CONFIG GET/SET. The save directory is: $(echo "$config_dir" | tail -1). An attacker can redirect RDB saves to arbitrary paths (e.g., /root/.ssh/authorized_keys) to achieve OS persistence or privilege escalation." \
            "Disable the CONFIG command: rename-command CONFIG '' in redis.conf. Set requirepass. Bind to localhost. Run Redis as a dedicated low-privilege user without write access to sensitive system paths." \
            "redis_config_get_${host//./_}"
        log_wrn "  Redis CONFIG GET dir works — file-write RCE primitive available on ${host}"
    fi

    # ── KEYS * (limit 20) ───────────────────────────────────────────────────
    local keys_out
    keys_out=$(timeout "$DB_TIMEOUT" redis-cli -h "$host" -p 6379 \
        KEYS '*' 2>/dev/null | head -20 || true)
    echo "KEYS * (first 20): ${keys_out}" >> "$ev_f"

    if [[ -n "$keys_out" ]]; then
        local key_count
        key_count=$(echo "$keys_out" | grep -c '\S' || echo 0)
        emit_finding "high" \
            "Redis: Key Listing Accessible — ${key_count} Key(s) on ${host}" \
            "Unauthenticated Redis on ${host}:6379 allows KEYS enumeration. ${key_count} key(s) listed (first 20 shown in evidence). Cached sessions, tokens, or sensitive application data may be directly readable." \
            "Set requirepass. Use Redis ACL (Redis 6+) to restrict keyspace access per user. Audit all stored keys for sensitive data. Implement application-level encryption for sensitive cached values." \
            "redis_keys_${host//./_}"
        log_wrn "  Redis KEYS enumeration: ${key_count} key(s) exposed on ${host}"
    fi

    # ── INFO server ─────────────────────────────────────────────────────────
    local info_out
    info_out=$(timeout "$DB_TIMEOUT" redis-cli -h "$host" -p 6379 INFO server 2>/dev/null | head -30 || true)
    echo "INFO server: ${info_out}" >> "$ev_f"

    # Check requirepass status from INFO
    local auth_status
    auth_status=$(echo "$info_out" | grep -i 'requirepass\|auth_required\|noauth\|aclfile' | head -3 || true)
    [[ -n "$auth_status" ]] && echo "Auth status: ${auth_status}" >> "$ev_f"

    local redis_ver
    redis_ver=$(echo "$info_out" | grep -i 'redis_version' | head -1 || true)
    [[ -n "$redis_ver" ]] && log_inf "  Redis server: ${redis_ver}"

    log_ok "  [T05] Redis audit complete → ${ev_f}"
}

# - MRK:19_T06 — T06 MongoDB (port 27017)
test_T06_mongodb() {
    local host="$1"
    local ev_f; ev_f="$(_ev_file "mongodb" "$host")"

    log_inf "[T06] MongoDB audit → ${host}:27017"

    if ! _host_has_port "$host" 27017 && ! _host_has_port "$host" 28017; then
        log_inf "  [T06] ports 27017/28017 not open on ${host} — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "curl http://${host}:27017 (version banner); mongosh/mongo --host ${host} --eval 'show dbs' (no auth)"
        log_dry "curl http://${host}:28017 (HTTP interface)"
        return
    }

    {
        echo "=== T06 MongoDB Audit ==="
        echo "Host: ${host}  Port: 27017 / 28017"
        echo "Date: $(date)"
        echo ""
    } > "$ev_f"

    # ── HTTP banner on port 27017 ────────────────────────────────────────────
    if _check_tool curl; then
        local banner_out
        banner_out=$(timeout "$DB_TIMEOUT" curl -sk --max-time 5 "http://${host}:27017" 2>/dev/null | head -10 || true)
        echo "--- HTTP Banner :27017 ---" >> "$ev_f"
        echo "${banner_out:-no response}" >> "$ev_f"

        local mongo_version
        mongo_version=$(echo "$banner_out" | grep -oiE '"version":"[^"]*"|MongoDB [0-9]+\.[0-9]+' | head -2 | tr '\n' ' ' || true)
        if [[ -n "$mongo_version" ]]; then
            log_inf "  MongoDB version banner: ${mongo_version}"
            echo "Version: ${mongo_version}" >> "$ev_f"
        fi

        # ── HTTP interface port 28017 ────────────────────────────────────────
        if _host_has_port "$host" 28017; then
            log_inf "  Checking MongoDB HTTP interface on :28017"
            local http_out
            http_out=$(timeout "$DB_TIMEOUT" curl -sk --max-time 5 "http://${host}:28017/" 2>/dev/null | head -20 || true)
            echo "--- HTTP Interface :28017 ---" >> "$ev_f"
            echo "${http_out:-no response}" >> "$ev_f"

            if echo "$http_out" | grep -qiE 'mongodb|listDatabases|serverStatus|<title>'; then
                emit_finding "high" \
                    "MongoDB: HTTP Interface (port 28017) Accessible on ${host}" \
                    "MongoDB HTTP REST interface is accessible on ${host}:28017 without authentication. This interface exposes server status, database statistics, and administrative information." \
                    "Disable the MongoDB HTTP interface: set net.http.enabled: false in mongod.conf. This interface was removed in MongoDB 3.6+ but may be enabled on older instances. Apply firewall rules to block port 28017." \
                    "mongodb_http_interface_${host//./_}"
                log_wrn "  MongoDB HTTP interface accessible on ${host}:28017"
            fi
        fi
    fi

    # ── Unauthenticated mongosh/mongo access ────────────────────────────────
    local mongo_tool=""
    _check_tool mongosh && mongo_tool="mongosh"
    [[ -z "$mongo_tool" ]] && _check_tool mongo && mongo_tool="mongo"

    if [[ -z "$mongo_tool" ]]; then
        log_wrn "  mongosh/mongo not found — attempting raw TCP banner grab"
        local tcp_banner
        tcp_banner=$(timeout "$DB_TIMEOUT" bash -c \
            "echo -e '' | nc -w5 ${host} 27017" 2>/dev/null | strings | head -5 || true)
        echo "TCP banner: ${tcp_banner}" >> "$ev_f"
        if echo "$tcp_banner" | grep -qi 'MongoDB\|mongod\|version'; then
            emit_finding "high" \
                "MongoDB: Version Banner Disclosed on ${host}:27017" \
                "MongoDB version banner is visible via raw TCP on ${host}:27017. Version information aids attackers in targeting known CVEs." \
                "Apply network-level restrictions (firewall) to limit MongoDB access to authorised hosts. Enable --auth and enforce authentication. Apply latest MongoDB patches." \
                "mongodb_banner_${host//./_}"
        fi
        log_ok "  [T06] MongoDB audit complete (limited — no mongo client) → ${ev_f}"
        return
    fi

    # Try unauthenticated connection
    log_inf "  Attempting unauthenticated MongoDB access via ${mongo_tool}"
    local mongo_out
    local mongo_cmd="db.adminCommand({listDatabases:1}).databases.forEach(function(d){print(d.name)})"
    if [[ "$mongo_tool" == "mongosh" ]]; then
        mongo_out=$(timeout "$DB_TIMEOUT" mongosh --host "$host" --port 27017 --quiet \
            --norc --eval "$mongo_cmd" 2>/dev/null || true)
    else
        mongo_out=$(timeout "$DB_TIMEOUT" mongo --host "$host" --port 27017 --quiet \
            --eval "$mongo_cmd" 2>/dev/null || true)
    fi
    echo "--- Unauthenticated listDatabases ---" >> "$ev_f"
    echo "${mongo_out:-no output}" >> "$ev_f"

    if echo "$mongo_out" | grep -qiE '^admin$|^local$|^config$|[a-zA-Z_][a-zA-Z0-9_]*'; then
        local db_count
        db_count=$(echo "$mongo_out" | grep -c '\S' || echo 0)
        emit_finding "critical" \
            "MongoDB: Unauthenticated Access — ${db_count} Database(s) Listed on ${host}" \
            "MongoDB on ${host}:27017 accepted connection without authentication. ${db_count} database(s) enumerated: $(echo "$mongo_out" | tr '\n' ', ' | sed 's/,$//'). All data may be readable and writable without credentials." \
            "Enable MongoDB authentication: security.authorization: enabled in mongod.conf. Create admin user and remove keyFile-less configs. Bind MongoDB to 127.0.0.1 or trusted interfaces. Apply network ACLs to restrict port 27017 to application servers only." \
            "mongodb_unauth_${host//./_}"
        log_wrn "  MONGODB UNAUTHENTICATED ACCESS: ${db_count} databases on ${host}"
    elif echo "$mongo_out" | grep -qi 'Unauthorized\|Authentication\|requires auth'; then
        log_ok "  MongoDB: authentication is enforced on ${host}"
        echo "Auth enforced — access denied" >> "$ev_f"
    else
        log_inf "  MongoDB: ambiguous response — check evidence manually"
    fi
    log_ok "  [T06] MongoDB audit complete → ${ev_f}"
}

# - MRK:19_T07 — T07 Elasticsearch (port 9200)
test_T07_elasticsearch() {
    local host="$1"
    local ev_f; ev_f="$(_ev_file "elasticsearch" "$host")"

    log_inf "[T07] Elasticsearch audit → ${host}:9200"

    if ! _host_has_port "$host" 9200; then
        log_inf "  [T07] port 9200 not open on ${host} — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "curl -sk http://${host}:9200/ (version); /_cat/indices?v; /_cluster/health; /_nodes"
        return
    }

    {
        echo "=== T07 Elasticsearch Audit ==="
        echo "Host: ${host}  Port: 9200"
        echo "Date: $(date)"
        echo ""
    } > "$ev_f"

    if ! _check_tool curl; then
        log_wrn "  curl not found — cannot audit Elasticsearch T07"
        return
    fi

    # ── Root endpoint (version check) ───────────────────────────────────────
    log_inf "  Fetching Elasticsearch root endpoint"
    local root_out
    root_out=$(timeout "$DB_TIMEOUT" curl -sk --max-time 10 "http://${host}:9200/" 2>/dev/null || true)
    echo "--- Root Endpoint ---" >> "$ev_f"
    echo "${root_out:-no response}" >> "$ev_f"

    local es_accessible=0
    if echo "$root_out" | grep -qiE '"tagline"\s*:\s*"You Know, for Search"|"cluster_name"|"version"'; then
        es_accessible=1
        local es_version
        es_version=$(echo "$root_out" | grep -oE '"number"\s*:\s*"[^"]*"' | head -1 | tr -d ' ' || true)
        emit_finding "critical" \
            "Elasticsearch: Unauthenticated Access on ${host}:9200" \
            "Elasticsearch on ${host}:9200 returned cluster information without authentication. Version info: ${es_version:-unknown}. All stored data, indices, and cluster configuration are exposed without credentials." \
            "Enable Elasticsearch Security (X-Pack): xpack.security.enabled: true in elasticsearch.yml. Require TLS (xpack.security.transport.ssl.enabled: true). Bind to localhost or restrict via firewall. Apply latest Elasticsearch security patches." \
            "elasticsearch_unauth_${host//./_}"
        log_wrn "  ELASTICSEARCH UNAUTHENTICATED ACCESS on ${host}:9200"

        if [[ -n "$es_version" ]]; then
            emit_finding "low" \
                "Elasticsearch: Version Disclosure on ${host}:9200 (${es_version})" \
                "Elasticsearch version string is exposed in the unauthenticated root response: ${es_version}. Version details help identify applicable CVEs (e.g., Log4Shell in ES 7.x, RCE via Groovy/Painless scripting in older versions)." \
                "Enable authentication to prevent unauthenticated version disclosure. Apply Elasticsearch security baseline." \
                "elasticsearch_version_${host//./_}"
        fi
    else
        log_ok "  Elasticsearch root endpoint requires auth or not responding on ${host}"
        log_ok "  [T07] Elasticsearch audit complete → ${ev_f}"
        return
    fi

    # ── /_cat/indices (index listing) ───────────────────────────────────────
    log_inf "  Fetching index listing via /_cat/indices"
    local indices_out
    indices_out=$(timeout "$DB_TIMEOUT" curl -sk --max-time 10 \
        "http://${host}:9200/_cat/indices?v" 2>/dev/null | head -50 || true)
    echo "--- /_cat/indices ---" >> "$ev_f"
    echo "${indices_out:-no response}" >> "$ev_f"

    if echo "$indices_out" | grep -qiE '^(green|yellow|red)\s+open'; then
        local index_count
        index_count=$(echo "$indices_out" | grep -cE '^(green|yellow|red)\s+open' || echo 0)
        emit_finding "high" \
            "Elasticsearch: Index Listing Accessible — ${index_count} Index/Indices on ${host}" \
            "Unauthenticated access to /_cat/indices on ${host}:9200 returned ${index_count} index/indices. Application data including user records, logs, and business data stored in these indices is fully accessible without credentials." \
            "Enable X-Pack security (xpack.security.enabled: true). Create user roles with minimum required index permissions. Encrypt data at rest. Rotate any data that may have been accessed while the cluster was open." \
            "elasticsearch_indices_${host//./_}"
        log_wrn "  Elasticsearch: ${index_count} index/indices exposed on ${host}"
    fi

    # ── /_cluster/health ────────────────────────────────────────────────────
    log_inf "  Fetching cluster health via /_cluster/health"
    local health_out
    health_out=$(timeout "$DB_TIMEOUT" curl -sk --max-time 10 \
        "http://${host}:9200/_cluster/health" 2>/dev/null || true)
    echo "--- /_cluster/health ---" >> "$ev_f"
    echo "${health_out:-no response}" >> "$ev_f"

    local cluster_name
    cluster_name=$(echo "$health_out" | grep -oE '"cluster_name"\s*:\s*"[^"]*"' | cut -d'"' -f4 || true)
    local cluster_status
    cluster_status=$(echo "$health_out" | grep -oE '"status"\s*:\s*"[^"]*"' | cut -d'"' -f4 || true)
    [[ -n "$cluster_name" ]] && log_inf "  Elasticsearch cluster: ${cluster_name} (status: ${cluster_status:-unknown})"

    # ── /_nodes ─────────────────────────────────────────────────────────────
    log_inf "  Fetching node information via /_nodes"
    local nodes_out
    nodes_out=$(timeout "$DB_TIMEOUT" curl -sk --max-time 10 \
        "http://${host}:9200/_nodes" 2>/dev/null | head -100 || true)
    echo "--- /_nodes ---" >> "$ev_f"
    echo "${nodes_out:-no response}" >> "$ev_f"

    local node_count
    node_count=$(echo "$nodes_out" | grep -oE '"total"\s*:\s*[0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0)
    [[ -n "$node_count" ]] && log_inf "  Elasticsearch: ${node_count} node(s) in cluster"

    log_ok "  [T07] Elasticsearch audit complete → ${ev_f}"
}

# =============================================================================
# - MRK:19_TRUN
# =============================================================================
_run_tests() {
    local total_before="$_FIND_CTR"
    local hosts_tested=0

    if [[ ${#_OPEN_PORTS[@]} -eq 0 ]]; then
        log_wrn "No hosts with open database ports discovered — no tests to run."
        return
    fi

    for host in "${!_OPEN_PORTS[@]}"; do
        log_inf "=== Testing database services on: ${host} ==="
        (( hosts_tested++ )) || true

        _test_skip T01 || test_T01_mysql       "$host"
        _test_skip T02 || test_T02_mssql       "$host"
        _test_skip T03 || test_T03_postgresql  "$host"
        _test_skip T04 || test_T04_oracle      "$host"
        _test_skip T05 || test_T05_redis       "$host"
        _test_skip T06 || test_T06_mongodb     "$host"
        _test_skip T07 || test_T07_elasticsearch "$host"

        local host_findings=$(( _FIND_CTR - total_before ))
        echo "SUMMARY_ROW|${host}|findings=${host_findings}" | tee -a "$LOG_FILE"
    done

    log_ok "Tested ${hosts_tested} host(s). Total findings: $(( _FIND_CTR - total_before ))"
}

# =============================================================================
# - MRK:19_MAIN
# =============================================================================
main() {
    printf "\n${_W}╔══════════════════════════════════════════════════════╗${_N}\n"
    printf "${_W}║  PT-Orc  ·  Step 19: Database Service Audit          ║${_N}\n"
    printf "${_W}╚══════════════════════════════════════════════════════╝${_N}\n\n"

    log_inf "Project      : ${PROJECT_NAME}"
    log_inf "Profile      : ${SCAN_PROFILE}"
    log_inf "DB Targets   : ${DB_TARGETS:-<from TARGET_IPS/TARGET_SUBNETS>}"
    log_inf "Cred spray   : $( [[ "$DB_CRED_SPRAY_ENABLED" -eq 1 ]] && echo "ENABLED (T01-T04)" || echo "disabled" )"
    log_inf "DB timeout   : ${DB_TIMEOUT}s"
    log_inf "Session      : ${SESSION_TS}"
    log_inf "Log          : ${LOG_FILE}"
    log_inf "Findings     : ${FINDINGS_FILE}"

    _validate_config || exit 1
    setup_profile "$SCAN_PROFILE"
    _confirm

    command -v trail_phase_start &>/dev/null && trail_phase_start "19_database_audit"

    _discover_db_ports

    _run_tests

    command -v trail_phase_end &>/dev/null && trail_phase_end "19_database_audit"

    # Summary report
    local report_f="${SCRIPT_DIR}/working/$(ev_fname "19-db-summary" "md")"
    {
        printf "# Database Audit Summary — %s\n\n" "$PROJECT_NAME"
        printf "**Profile:** %s  **Cred spray:** %s  **Session:** %s\n\n" \
            "$SCAN_PROFILE" \
            "$( [[ "$DB_CRED_SPRAY_ENABLED" -eq 1 ]] && echo "enabled" || echo "disabled" )" \
            "$SESSION_TS"
        printf "| Host | Open DB Ports | Findings |\n|------|---------------|----------|\n"
        local grand_total=0
        for host in "${!_OPEN_PORTS[@]}"; do
            local h_ports="${_OPEN_PORTS[$host]}"
            local h_findings
            h_findings=$(grep -c "\"phase\":\"19_database_audit\"" "$FINDINGS_FILE" 2>/dev/null || echo 0)
            printf "| %s | %s | %s |\n" "$host" "$h_ports" "$h_findings"
            (( grand_total += h_findings )) || true
        done
        printf "\n**Total Findings:** %d\n" "$_FIND_CTR"
        printf "\nFindings JSONL: \`%s\`\n" "$FINDINGS_FILE"
        printf "\nEvidence dir  : \`%s\`\n" "$EVIDENCE_BASE"
    } > "$report_f"

    printf "\n${_G}[DONE]${_N} Database audit complete.\n"
    printf "  Hosts scanned : %d (with open db ports)\n" "${#_OPEN_PORTS[@]}"
    printf "  Findings      : %d\n" "$_FIND_CTR"
    printf "  Summary       : %s\n" "$report_f"
    printf "  Evidence      : %s\n\n" "$EVIDENCE_BASE"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
