#!/usr/bin/env bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:19_NAV_TOC — Section index | nav,toc,index | L5-28
# - MRK:19_T01 — T01 SMB SHARE SECRET SPIDER | t01,smb,share,secret,spider | L29-29
# - MRK:19_T02 — T02 WEB EXPOSED SENSITIVE FILES | t02,web,exposed,sensitive,files | L30-30
# - MRK:19_T03 — T03 GIT SECRET SCAN | t03,git,secret,scan | L31-31
# - MRK:19_T04 — T04 DEBUG ENDPOINT SECRET EXPOSURE | t04,debug,endpoint,secret | L32-32
# - MRK:19_T05 — T05 EXPOSED BACKUP AND DUMP FILES | t05,backup,dump,exposed | L33-33
# NAV-LEN: 5 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-06-25

# =============================================================================
# 20_secrets_scan.sh — Secrets & Credential Exposure Scanning
# TechGuard Labs | PT-Orc Suite v0.8
# =============================================================================
# NAV: MRK:19_TOC (this block) | MRK:19_ROOT | MRK:19_CONF | MRK:19_LOG
#      MRK:19_ARGS | MRK:19_CONFIRM | MRK:19_TARGETS
#      MRK:19_FIND | MRK:19_UTILS | MRK:19_PROF
#      MRK:19_T01 — T01 SMB SHARE SECRET SPIDER
#      MRK:19_T02 — T02 WEB EXPOSED SENSITIVE FILES
#      MRK:19_T03 — T03 GIT SECRET SCAN
#      MRK:19_T04 — T04 DEBUG ENDPOINT SECRET EXPOSURE
#      MRK:19_T05 — T05 EXPOSED BACKUP AND DUMP FILES
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

# Conf defaults — vars may not exist in pt-orc.conf yet
SECRETS_SMB_TARGETS="${SECRETS_SMB_TARGETS:-}"
SECRETS_SMB_USER="${SECRETS_SMB_USER:-}"
SECRETS_SMB_PASS="${SECRETS_SMB_PASS:-}"
SECRETS_TIMEOUT="${SECRETS_TIMEOUT:-15}"

# - MRK:19_LOG
_R='\033[0;31m'; _G='\033[0;32m'; _Y='\033[1;33m'; _B='\033[0;34m'; _C='\033[0;36m'; _W='\033[1;37m'; _N='\033[0m'
SESSION_TS="$(date +%Y%m%d_%H%M%S)"
EV_TS="$(date +'%Y-%m-%d-%H-%M-%S')"
LOG_FILE="${SCRIPT_DIR}/working/${PROJ_SLUG}_20_secrets_${SESSION_TS}.log"
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

_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Secrets & Credential Exposure Scanning (step 20)

Probes SMB shares, web endpoints, git repositories, debug interfaces, and
backup files for exposed credentials and sensitive configuration material.

Options:
  --targets <IP[,IP...]>   Comma-separated target IPs/domains (overrides conf)
  --smb-user <user>        SMB username for authenticated share spider
  --smb-pass <pass>        SMB password for authenticated share spider
  -p, --profile <name>     Scan profile: quick|standard|deep  [default: standard]
  --only <T01,T03,...>     Run only specified tests
  --skip <T03,...>         Skip specified tests
  -y, --yes                Skip confirmation prompt
  --dry-run                Print actions without executing
  -h, --help               Show this help

Profiles:
  quick    — T02, T04
  standard — T01, T02, T04, T05
  deep     — T01, T02, T03, T04, T05

Conf vars (pt-orc.conf):
  SECRETS_SMB_TARGETS  comma/space list of IPs for T01 (default: TARGET_IPS + TARGET_SUBNETS)
  SECRETS_SMB_USER     SMB username for authenticated spider
  SECRETS_SMB_PASS     SMB password
  SECRETS_TIMEOUT      per-probe timeout in seconds  [default: 15]
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)
            # Accept comma or space separated; store back as space-separated
            SECRETS_SMB_TARGETS="${2//,/ }"; shift 2 ;;
        --smb-user)   SECRETS_SMB_USER="$2"; shift 2 ;;
        --smb-pass)   SECRETS_SMB_PASS="$2"; shift 2 ;;
        -p|--profile) SCAN_PROFILE="$2"; shift 2 ;;
        --only)       IFS=',' read -ra _ONLY_TESTS <<< "$2"; shift 2 ;;
        --skip)       IFS=',' read -ra _SKIP_TESTS <<< "$2"; shift 2 ;;
        -y|--yes)     _SKIP_CONFIRM=1; shift ;;
        --dry-run)    DRY_RUN=1; shift ;;
        -h|--help)    _usage; exit 0 ;;
        *)            log_err "Unknown option: $1"; _usage; exit 1 ;;
    esac
done

# - MRK:19_CONFIRM
_confirm() {
    [[ "$_SKIP_CONFIRM" -eq 1 ]] && return 0

    # Build a display list of enabled tests
    local enabled_list=""
    for t in T01 T02 T03 T04 T05; do
        [[ "${_T_ENABLED[$t]:-1}" -eq 1 ]] && enabled_list+=" ${t}"
    done

    printf "\n${_Y}[CONFIRM]${_N} Secrets & credential exposure scan. Profile: ${_W}%s${_N}\n" "$SCAN_PROFILE"
    printf "  Project  : %s\n" "$PROJECT_NAME"
    printf "  Tests    : %s\n" "${enabled_list# }"
    printf "  SMB User : %s\n" "${SECRETS_SMB_USER:-<none — unauthenticated only>}"
    printf "  Timeout  : %ss per probe\n" "$SECRETS_TIMEOUT"
    printf "\n  ${_R}WARNING:${_N} This script actively probes hosts for sensitive files.\n"
    printf "  Only run within authorised scope and agreed engagement window.\n"
    printf "\n  Continue? [y/N] "
    read -r _ans
    [[ "${_ans,,}" == "y" ]] || { log_err "Aborted by user."; exit 0; }
}

# - MRK:19_TARGETS
_validate_config() {
    local all_targets=""
    [[ -n "${SECRETS_SMB_TARGETS:-}" ]] && all_targets="$SECRETS_SMB_TARGETS"
    [[ -n "${TARGET_IPS:-}" ]]          && all_targets+=" $TARGET_IPS"
    [[ -n "${TARGET_SUBNETS:-}" ]]      && all_targets+=" $TARGET_SUBNETS"
    [[ -n "${TARGET_DOMAINS:-}" ]]      && all_targets+=" $TARGET_DOMAINS"

    if [[ -z "${all_targets// /}" ]]; then
        log_wrn "No targets configured. Set TARGET_IPS / TARGET_DOMAINS in pt-orc.conf or use --targets."
    fi
    # Not a fatal error — the script may still be useful with partial config
    return 0
}

# Build web target list: TARGET_IPS + TARGET_DOMAINS (space-separated words)
_web_targets() {
    local -a out=()
    local word
    for word in ${TARGET_IPS:-} ${TARGET_DOMAINS:-}; do
        out+=("$word")
    done
    printf '%s\n' "${out[@]+"${out[@]}"}"
}

# Build SMB target list
_smb_targets() {
    local -a out=()
    local word
    if [[ -n "${SECRETS_SMB_TARGETS:-}" ]]; then
        for word in ${SECRETS_SMB_TARGETS}; do out+=("$word"); done
    else
        for word in ${TARGET_IPS:-} ${TARGET_SUBNETS:-}; do out+=("$word"); done
    fi
    printf '%s\n' "${out[@]+"${out[@]}"}"
}

# - MRK:19_FIND
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "20-secrets-findings" "jsonl")"
_FIND_CTR=0
: > "$FINDINGS_FILE"

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="${5:-}"
    (( _FIND_CTR++ )) || true
    local fid
    fid="f-20-sec-$(printf '%04d' "$_FIND_CTR")"
    local ev_id="${ev_tag:-${fid}-ev}"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"20_secrets_scan","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
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
    local tag="$1"
    echo "${EVIDENCE_BASE}/$(ev_fname "sec-${tag}" "txt")"
}

# Credential pattern regex — matches common secret assignments
_CRED_REGEX='password[[:space:]]*=[[:space:]]*[^[:space:]]|passwd[[:space:]]*=[[:space:]]*[^[:space:]]|api_key[[:space:]]*=[[:space:]]*[^[:space:]]|secret[[:space:]]*=[[:space:]]*[^[:space:]]|token[[:space:]]*=[[:space:]]*[^[:space:]]'

# Check up to 4KB of a file (path) for credential patterns; returns 0 if found
_has_cred_pattern() {
    local content="$1"
    echo "$content" | grep -qiE "$_CRED_REGEX"
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
    for n in T01 T02 T03 T04 T05; do
        _T_ENABLED[$n]=1
    done
    case "$prof" in
        quick)
            # quick: web sensitive file probe + debug endpoints only
            for n in T01 T03 T05; do _T_ENABLED[$n]=0; done ;;
        standard)
            # standard: everything except git secret scan
            _T_ENABLED[T03]=0 ;;
        deep)
            # All tests enabled
            : ;;
        *)
            log_wrn "Unknown profile '${prof}' — defaulting to standard"
            _T_ENABLED[T03]=0 ;;
    esac
    _apply_cli_filters
}

# Shared array: web hosts where /.git/config returned HTTP 200 (populated by T02, read by T03)
_DISCOVERED_GIT_HOSTS=()

# =============================================================================
# TESTS
# =============================================================================

# - MRK:19_T01 — T01 SMB SHARE SECRET SPIDER
test_T01_smb_secret_spider() {
    local ev_f; ev_f="$(_ev_file "t01-smb-spider")"

    log_inf "[T01] SMB share secret spider"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "smbmap -H <target> [+creds]; smbclient spider for secrets"; return; }

    {
        echo "=== T01 SMB Share Secret Spider ==="
        echo "Timestamp: $(date)"
        echo "SMB user: ${SECRETS_SMB_USER:-<unauthenticated>}"
    } > "$ev_f"

    if ! _check_tool smbmap; then
        log_wrn "  smbmap not found — install smbmap for T01"
        echo "[T01] smbmap not available" >> "$ev_f"
        return
    fi
    if ! _check_tool smbclient; then
        log_wrn "  smbclient not found — install samba-client for T01"
        echo "[T01] smbclient not available" >> "$ev_f"
        return
    fi

    # Sensitive filename patterns (used with grep over listing output)
    local -a secret_patterns=(
        '\.env$' '\.env\.' '\.env\.local$' '\.env\.backup$'
        '\.config$' 'id_rsa$' '\.pem$' '\.key$' '\.pfx$'
        'web\.config$' 'appsettings.*\.json$' 'database\.yml$' 'secrets\.yml$'
        '\.htpasswd$' '^passwd$' '^shadow$' '\.bak$' '\.sql$'
        'credentials' 'password'
    )

    local _smb_share_ctr=0
    local _smb_readable_ctr=0
    local _smb_cred_ctr=0

    while IFS= read -r target; do
        [[ -z "$target" ]] && continue
        log_inf "  T01: probing ${target}"
        echo "--- Target: ${target} ---" >> "$ev_f"

        # ---- unauthenticated smbmap ----
        local smbmap_null_out
        smbmap_null_out=$(timeout "$SECRETS_TIMEOUT" smbmap -H "$target" 2>&1 | head -80 || true)
        echo "  [smbmap null] ${target}:" >> "$ev_f"
        echo "$smbmap_null_out" >> "$ev_f"

        # ---- authenticated smbmap (if creds provided) ----
        local smbmap_auth_out=""
        if [[ -n "${SECRETS_SMB_USER:-}" ]]; then
            smbmap_auth_out=$(timeout "$SECRETS_TIMEOUT" smbmap -H "$target" \
                -u "$SECRETS_SMB_USER" -p "${SECRETS_SMB_PASS:-}" 2>&1 | head -80 || true)
            echo "  [smbmap auth] ${target}:" >> "$ev_f"
            echo "$smbmap_auth_out" >> "$ev_f"
        fi

        # Combine listing output for share parsing
        local combined_out="${smbmap_null_out}${smbmap_auth_out}"

        # Check if host responded at all
        if ! echo "$combined_out" | grep -qiE 'READ|WRITE|Disk|IPC\$|ADMIN\$'; then
            log_inf "  T01: ${target} — no SMB shares accessible or host unreachable"
            continue
        fi

        # Emit medium finding: share enumerable
        (( _smb_share_ctr++ )) || true
        emit_finding "medium" \
            "SMB Shares Enumerable: ${target}" \
            "SMB share listing was possible on ${target} (unauthenticated or with provided credentials). Share names and permissions are visible, which aids targeting for credential/file theft." \
            "Restrict anonymous SMB access. Disable SMB null sessions via GPO: Network Access: Do not allow anonymous enumeration of SAM accounts and shares. Require SMB signing." \
            "sec-smb-enum-${target//[^A-Za-z0-9]/-}"

        # Extract readable share names from smbmap output
        # smbmap format: "\tShareName\tDisk\tComment\tREAD ONLY" or "READ, WRITE"
        local -a readable_shares=()
        while IFS= read -r line; do
            local sharename
            sharename=$(echo "$line" | awk '{print $1}' | tr -d '[:space:]')
            [[ -z "$sharename" || "$sharename" =~ ^\- ]] && continue
            # Skip standard shares that are never interesting for file hunting
            [[ "$sharename" =~ ^(IPC\$|print\$|PRINT\$)$ ]] && continue
            if echo "$line" | grep -qiE 'READ|WRITE'; then
                readable_shares+=("$sharename")
            fi
        done < <(echo "$combined_out" | grep -E 'READ|WRITE' | grep -v 'smbmap\|Host:')

        if [[ ${#readable_shares[@]} -eq 0 ]]; then
            log_inf "  T01: ${target} — no readable shares found"
            continue
        fi

        log_ok "  T01: ${target} readable shares: ${readable_shares[*]}"
        (( _smb_readable_ctr++ )) || true
        emit_finding "high" \
            "SMB Readable Share(s) Found: ${target} [${readable_shares[*]}]" \
            "Shares [${readable_shares[*]}] on ${target} are readable. Files may contain sensitive credentials or configuration material accessible without elevated rights." \
            "Review ACLs on all readable shares. Remove unnecessary read access. Audit share contents for sensitive files. Enable SMB access logging." \
            "sec-smb-readable-${target//[^A-Za-z0-9]/-}"

        # ---- Spider each readable share for sensitive filenames ----
        local share
        for share in "${readable_shares[@]}"; do
            log_inf "  T01: spidering //${target}/${share} ..."
            echo "  [spider] //${target}/${share}" >> "$ev_f"

            # Get full recursive file listing from the share
            local smbclient_args=("-N")
            [[ -n "${SECRETS_SMB_USER:-}" ]] && smbclient_args=("-U" "${SECRETS_SMB_USER}%${SECRETS_SMB_PASS:-}")

            local listing
            listing=$(timeout 60 smbclient "//${target}/${share}" \
                "${smbclient_args[@]}" \
                -c "recurse on; ls" 2>&1 | head -500 || true)
            echo "$listing" >> "$ev_f"

            # Check listing against sensitive patterns
            local pat hit_files=""
            for pat in "${secret_patterns[@]}"; do
                local matches
                matches=$(echo "$listing" | grep -iE "$pat" | grep -v '^\s*\.' | head -5 || true)
                [[ -n "$matches" ]] && hit_files+="${matches}"$'\n'
            done

            if [[ -z "$hit_files" ]]; then
                log_inf "  T01: //${target}/${share} — no sensitive filenames found"
                continue
            fi

            log_wrn "  T01: //${target}/${share} — sensitive filename(s) found"
            echo "  [sensitive hits] //${target}/${share}:" >> "$ev_f"
            echo "$hit_files" >> "$ev_f"

            # For the first hit, attempt to download first 4KB and check for cred patterns
            local first_file
            first_file=$(echo "$hit_files" | grep -Eo '[A-Za-z0-9_/\\. -]+\.(env|config|pem|key|pfx|bak|sql|json|yml|htpasswd|xml)' | head -1 | tr -d '\r' | sed 's/^[[:space:]]*//' || true)
            if [[ -n "$first_file" ]]; then
                local tmp_dl
                tmp_dl=$(mktemp /tmp/orc-smb-XXXXXX 2>/dev/null || echo "/tmp/orc-smb-$$")
                local get_out
                get_out=$(timeout 20 smbclient "//${target}/${share}" \
                    "${smbclient_args[@]}" \
                    -c "get \"${first_file}\" ${tmp_dl}" 2>&1 || true)
                if [[ -s "$tmp_dl" ]]; then
                    local content
                    content=$(head -c 4096 "$tmp_dl" 2>/dev/null || true)
                    echo "  [file sample] ${first_file} (first 4KB):" >> "$ev_f"
                    echo "$content" >> "$ev_f"
                    if _has_cred_pattern "$content"; then
                        log_wrn "  T01: CREDENTIAL PATTERN found in //${target}/${share}/${first_file}"
                        (( _smb_cred_ctr++ )) || true
                        emit_finding "critical" \
                            "Credential Content in SMB Share File: //${target}/${share}/${first_file}" \
                            "A credential pattern (password=, api_key=, secret=, token=, passwd=) was detected in //${target}/${share}/${first_file} on ${target}. Plaintext credentials in share files can enable immediate privilege escalation or lateral movement." \
                            "Remove credential material from files stored on network shares. Use secrets management vaults (HashiCorp Vault, AWS Secrets Manager). Audit all SMB share contents. Rotate any exposed credentials immediately." \
                            "sec-smb-cred-${target//[^A-Za-z0-9]/-}"
                    else
                        emit_finding "high" \
                            "Sensitive Config File Readable via SMB: //${target}/${share}/${first_file}" \
                            "A file matching a sensitive naming pattern (${first_file}) was readable on share //${target}/${share}. Even without detected credential patterns in the first 4KB, this file may contain secrets." \
                            "Remove or restrict access to sensitive configuration and key files on network shares. Review file ACLs. Use dedicated secrets management." \
                            "sec-smb-sensfile-${target//[^A-Za-z0-9]/-}"
                    fi
                fi
                rm -f "$tmp_dl" 2>/dev/null || true
            fi
        done
    done < <(_smb_targets)

    log_ok "  T01 complete — ${_smb_share_ctr} host(s) with enumerable shares, ${_smb_readable_ctr} readable, ${_smb_cred_ctr} credential hit(s)"
}

# - MRK:19_T02 — T02 WEB EXPOSED SENSITIVE FILES
test_T02_web_sensitive_files() {
    local ev_f; ev_f="$(_ev_file "t02-web-sensitive")"

    log_inf "[T02] Web exposed sensitive files"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "curl probe sensitive paths on each web target × {80,443,8080,8443}"; return; }

    {
        echo "=== T02 Web Exposed Sensitive Files ==="
        echo "Timestamp: $(date)"
    } > "$ev_f"

    if ! _check_tool curl; then
        log_wrn "  curl not found — T02 requires curl"
        echo "[T02] curl not available" >> "$ev_f"
        return
    fi

    local -a sensitive_paths=(
        "/.env"
        "/.env.local"
        "/.env.backup"
        "/.env.production"
        "/config.php"
        "/config.php.bak"
        "/wp-config.php.bak"
        "/database.yml"
        "/database.php"
        "/settings.py"
        "/local_settings.py"
        "/appsettings.json"
        "/web.config.bak"
        "/id_rsa"
        "/.ssh/id_rsa"
        "/backup.zip"
        "/backup.tar.gz"
        "/dump.sql"
        "/.git/config"
    )

    local -a ports=(80 443 8080 8443)
    local _t02_cred_ctr=0
    local _t02_hit_ctr=0

    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        echo "--- Host: ${host} ---" >> "$ev_f"

        local port
        for port in "${ports[@]}"; do
            local scheme="http"
            [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
            local base_url="${scheme}://${host}:${port}"

            local path
            for path in "${sensitive_paths[@]}"; do
                local url="${base_url}${path}"
                local tmp_body
                tmp_body=$(mktemp /tmp/orc-web-XXXXXX 2>/dev/null || echo "/tmp/orc-web-$$-${RANDOM}")

                local http_info
                http_info=$(timeout "$SECRETS_TIMEOUT" curl -sk \
                    --max-time "$SECRETS_TIMEOUT" \
                    --max-filesize 524288 \
                    -o "$tmp_body" \
                    -w "%{http_code}:%{size_download}" \
                    "$url" 2>/dev/null || echo "000:0")

                local http_code size_dl
                http_code="${http_info%%:*}"
                size_dl="${http_info##*:}"

                if [[ "$http_code" == "200" ]] && [[ "${size_dl:-0}" -gt 0 ]]; then
                    log_wrn "  T02: HTTP 200 → ${url} (${size_dl} bytes)"
                    echo "  HIT: ${url} [${http_code}] ${size_dl}B" >> "$ev_f"
                    (( _t02_hit_ctr++ )) || true

                    # Track /.git/config hits for T03
                    if [[ "$path" == "/.git/config" ]]; then
                        _DISCOVERED_GIT_HOSTS+=("${host}:${port}")
                    fi

                    # Download first 2KB for credential check
                    local content
                    content=$(head -c 2048 "$tmp_body" 2>/dev/null || true)
                    echo "  [first 2KB of ${path}]:" >> "$ev_f"
                    echo "$content" >> "$ev_f"

                    if _has_cred_pattern "$content"; then
                        (( _t02_cred_ctr++ )) || true
                        emit_finding "critical" \
                            "Credential Content in Web-Accessible File: ${url}" \
                            "A credential pattern (password=, api_key=, secret=, token=) was found in the web-accessible file ${url}. Exposure of this file via HTTP allows unauthenticated credential theft." \
                            "Remove or relocate sensitive configuration files outside the web root. Enforce deny-all rules for config file extensions in the web server. Rotate any exposed credentials immediately." \
                            "sec-web-cred-${http_code}-${host//[^A-Za-z0-9]/-}-${port}"
                    else
                        # Classify by file type
                        local sev="high"
                        local file_class="sensitive configuration file"
                        if echo "$path" | grep -qiE '\.bak$|backup\.|\.zip$|\.tar\.gz$|dump\.sql$'; then
                            sev="medium"
                            file_class="backup/dump file"
                        fi
                        emit_finding "$sev" \
                            "$(echo "$file_class" | sed 's/\b./\u&/g') Exposed via HTTP: ${url}" \
                            "The ${file_class} ${path} returned HTTP 200 (${size_dl} bytes) on ${host}:${port}. This file may contain credentials or sensitive system configuration even though no credential regex matched the first 2KB." \
                            "Deny direct HTTP access to sensitive files using web server configuration (Nginx: location ~ '\\.(env|key|pem|bak|sql|config)' { deny all; }). Move configuration outside the web root." \
                            "sec-web-${sev}-${host//[^A-Za-z0-9]/-}-${port}-${path//[^A-Za-z0-9]/-}"
                    fi
                fi

                rm -f "$tmp_body" 2>/dev/null || true
            done
        done
    done < <(_web_targets)

    log_ok "  T02 complete — ${_t02_hit_ctr} sensitive file(s) exposed, ${_t02_cred_ctr} with credential content"
}

# - MRK:19_T03 — T03 GIT SECRET SCAN
test_T03_git_secret_scan() {
    local ev_f; ev_f="$(_ev_file "t03-git-secrets")"

    log_inf "[T03] Git secret scan"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "trufflehog/gitleaks + regex scan on discovered git dirs"; return; }

    {
        echo "=== T03 Git Secret Scan ==="
        echo "Timestamp: $(date)"
    } > "$ev_f"

    local _t03_hit_ctr=0
    local _t03_verified_ctr=0

    # Collect git dirs to scan: evidence directories + cloned git dirs
    local -a git_dirs=()

    # 1. Any .git directories found under EVIDENCE_BASE (e.g. from earlier steps that
    #    cloned or downloaded repo content)
    while IFS= read -r gitdir; do
        git_dirs+=("$(dirname "$gitdir")")
    done < <(find "$EVIDENCE_BASE" -maxdepth 4 -type d -name ".git" 2>/dev/null)

    # 2. T02 discovered web /.git/config hits → try to download the git repo
    if [[ ${#_DISCOVERED_GIT_HOSTS[@]} -gt 0 ]]; then
        local hostport
        for hostport in "${_DISCOVERED_GIT_HOSTS[@]}"; do
            local gh="${hostport%%:*}"
            local gp="${hostport##*:}"
            local scheme="http"
            [[ "$gp" == "443" || "$gp" == "8443" ]] && scheme="https"
            local git_url="${scheme}://${gh}:${gp}/.git"
            local clone_dir="${EVIDENCE_BASE}/git-clone-${gh//[^A-Za-z0-9]/-}-${gp}"

            log_inf "  T03: exposed .git found at ${git_url} — fetching key objects"
            mkdir -p "$clone_dir"
            echo "  [git exposure] ${git_url}" >> "$ev_f"

            # Download HEAD, config, COMMIT_EDITMSG for quick inspection
            local obj_path
            for obj_path in "config" "HEAD" "COMMIT_EDITMSG" "index"; do
                local obj_url="${scheme}://${gh}:${gp}/.git/${obj_path}"
                local obj_file="${clone_dir}/${obj_path//\//_}"
                timeout "$SECRETS_TIMEOUT" curl -sk --max-time "$SECRETS_TIMEOUT" \
                    -o "$obj_file" "$obj_url" 2>/dev/null || true
                if [[ -s "$obj_file" ]]; then
                    echo "  [${obj_path}]:" >> "$ev_f"
                    head -c 1024 "$obj_file" >> "$ev_f"
                fi
            done

            emit_finding "critical" \
                "Exposed .git Directory: ${scheme}://${gh}:${gp}/.git/" \
                "The .git directory is publicly accessible at ${scheme}://${gh}:${gp}/.git/. A complete git repository can be reconstructed using tools like git-dumper, exposing full source code history and any secrets ever committed." \
                "Deny web access to .git directories immediately (Nginx: location ~ /\\.git { deny all; }). Rotate all secrets that may have appeared in commit history. Use git-secrets or trufflehog to audit historical commits." \
                "sec-git-exposed-${gh//[^A-Za-z0-9]/-}-${gp}"

            git_dirs+=("$clone_dir")
        done
    fi

    # 3. Check TARGET_DOMAINS for common git directory patterns
    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        # Check if we already found a .git for this host in _DISCOVERED_GIT_HOSTS
        local already=0
        local hp
        for hp in "${_DISCOVERED_GIT_HOSTS[@]+"${_DISCOVERED_GIT_HOSTS[@]}"}"; do
            [[ "$hp" == "${host}:"* ]] && already=1 && break
        done
        [[ "$already" -eq 1 ]] && continue

        # Additional local filesystem check for web roots under /var/www etc.
        local possible_dir
        for possible_dir in \
            "/var/www/html/${host}" \
            "/var/www/${host}" \
            "/srv/www/${host}" \
            "/opt/app/${host}"; do
            if [[ -d "${possible_dir}/.git" ]]; then
                log_inf "  T03: found local .git at ${possible_dir}"
                git_dirs+=("$possible_dir")
            fi
        done
    done < <(_web_targets)

    if [[ ${#git_dirs[@]} -eq 0 ]]; then
        log_inf "  T03: no git directories to scan"
        echo "[T03] No git directories found for scanning" >> "$ev_f"
        return
    fi

    local gdir
    for gdir in "${git_dirs[@]}"; do
        [[ -z "$gdir" || ! -d "$gdir" ]] && continue
        log_inf "  T03: scanning ${gdir}"
        echo "--- Git scan: ${gdir} ---" >> "$ev_f"

        # ---- trufflehog (preferred) ----
        if _check_tool trufflehog; then
            log_inf "  T03: trufflehog filesystem scan on ${gdir}"
            local th_out
            th_out=$(timeout 120 trufflehog filesystem --directory "$gdir" \
                --json 2>&1 | head -200 || true)
            echo "[trufflehog]" >> "$ev_f"
            echo "$th_out" >> "$ev_f"

            if echo "$th_out" | grep -qi '"Verified":true\|"verified":true'; then
                local verified_count
                verified_count=$(echo "$th_out" | grep -ci '"Verified":true\|"verified":true' || echo 1)
                (( _t03_verified_ctr += verified_count )) || true
                emit_finding "critical" \
                    "Trufflehog: Verified Secret(s) in Git Repository: ${gdir}" \
                    "trufflehog detected ${verified_count} verified (live/active) secret(s) in the repository at ${gdir}. These credentials are confirmed active and can be used immediately by an attacker." \
                    "Immediately revoke and rotate all verified secrets. Remove secrets from git history using git-filter-repo or BFG Repo Cleaner. Implement pre-commit hooks (git-secrets, detect-secrets) to prevent future exposure." \
                    "sec-git-trufflehog-verified-${gdir//[^A-Za-z0-9]/-}"
                (( _t03_hit_ctr++ )) || true
            elif echo "$th_out" | grep -qi '"DetectorName"\|"detector_name"'; then
                emit_finding "high" \
                    "Trufflehog: Potential Secret Pattern(s) in Git Repository: ${gdir}" \
                    "trufflehog found potential secret patterns in ${gdir}. Verification status is unconfirmed; manual review is required to determine if credentials are active." \
                    "Review trufflehog findings and rotate any confirmed credentials. Audit full git history. Integrate secret scanning into CI/CD pipeline." \
                    "sec-git-trufflehog-potential-${gdir//[^A-Za-z0-9]/-}"
                (( _t03_hit_ctr++ )) || true
            fi
        fi

        # ---- gitleaks ----
        if _check_tool gitleaks; then
            log_inf "  T03: gitleaks detect on ${gdir}"
            local gl_out
            gl_out=$(timeout 120 gitleaks detect --source "$gdir" \
                --report-format json --no-banner 2>&1 | head -200 || true)
            echo "[gitleaks]" >> "$ev_f"
            echo "$gl_out" >> "$ev_f"

            if echo "$gl_out" | grep -qi '"RuleID"\|"ruleID"\|leaks found'; then
                local leak_count
                leak_count=$(echo "$gl_out" | grep -ci '"RuleID"\|"ruleID"' || echo 1)
                emit_finding "high" \
                    "Gitleaks: Secret Leak(s) Detected in Repository: ${gdir} (${leak_count} finding(s))" \
                    "gitleaks detected ${leak_count} potential secret(s) in ${gdir}. Secrets in git history are accessible to anyone who can clone the repository." \
                    "Rotate all secrets identified by gitleaks. Purge sensitive data from git history using git-filter-repo. Enable gitleaks as a pre-commit and CI/CD gate." \
                    "sec-git-gitleaks-${gdir//[^A-Za-z0-9]/-}"
                (( _t03_hit_ctr++ )) || true
            fi
        fi

        # ---- Regex fallback scan (always runs) ----
        log_inf "  T03: regex scan on ${gdir}"
        local regex_hits=""

        # AWS Access Key ID
        local aws_keys
        aws_keys=$(grep -rE 'AKIA[0-9A-Z]{16}' "$gdir" --include="*.py" --include="*.js" \
            --include="*.env" --include="*.json" --include="*.yml" --include="*.yaml" \
            --include="*.conf" --include="*.cfg" --include="*.txt" \
            -l 2>/dev/null | head -5 || true)
        [[ -n "$aws_keys" ]] && regex_hits+="AWS key files: ${aws_keys}"$'\n'

        # Private keys
        local priv_keys
        priv_keys=$(grep -rEl -- '-----BEGIN.*(PRIVATE KEY|RSA|DSA|EC|OPENSSH)' \
            "$gdir" 2>/dev/null | head -5 || true)
        [[ -n "$priv_keys" ]] && regex_hits+="Private key files: ${priv_keys}"$'\n'

        # Generic credential assignment patterns
        local cred_hits
        cred_hits=$(grep -rEil \
            'password[[:space:]]*=[[:space:]]*[^[:space:]]|api_key[[:space:]]*=[[:space:]]*[^[:space:]]|secret[[:space:]]*=[[:space:]]*[^[:space:]]|token[[:space:]]*=.*[A-Za-z0-9]{16}' \
            "$gdir" 2>/dev/null | grep -v '\.git/' | head -10 || true)
        [[ -n "$cred_hits" ]] && regex_hits+="Credential pattern files: ${cred_hits}"$'\n'

        if [[ -n "$regex_hits" ]]; then
            echo "[regex hits]" >> "$ev_f"
            echo "$regex_hits" >> "$ev_f"
            emit_finding "high" \
                "Secret Pattern Match in Git Content: ${gdir}" \
                "Regex scanning of ${gdir} found files containing AWS keys (AKIA...), private key headers, or credential assignment patterns. Details: ${regex_hits:0:400}" \
                "Review all flagged files. Rotate any live credentials. Use trufflehog or gitleaks for comprehensive history scanning. Implement detect-secrets or git-secrets hooks." \
                "sec-git-regex-${gdir//[^A-Za-z0-9]/-}"
            (( _t03_hit_ctr++ )) || true
        else
            log_ok "  T03: ${gdir} — no secret patterns found by regex scan"
        fi
    done

    log_ok "  T03 complete — ${_t03_hit_ctr} repository finding(s), ${_t03_verified_ctr} verified secret(s)"
}

# - MRK:19_T04 — T04 DEBUG ENDPOINT SECRET EXPOSURE
test_T04_debug_endpoints() {
    local ev_f; ev_f="$(_ev_file "t04-debug-endpoints")"

    log_inf "[T04] Debug endpoint secret exposure"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "curl probe /actuator/env, /debug/vars, /jolokia, /swagger-ui etc."; return; }

    {
        echo "=== T04 Debug Endpoint Secret Exposure ==="
        echo "Timestamp: $(date)"
    } > "$ev_f"

    if ! _check_tool curl; then
        log_wrn "  curl not found — T04 requires curl"
        echo "[T04] curl not available" >> "$ev_f"
        return
    fi

    local -a debug_paths=(
        "/actuator/env"
        "/actuator/configprops"
        "/actuator/mappings"
        "/actuator/health"
        "/actuator/info"
        "/debug/vars"
        "/debug/pprof"
        "/__debug__"
        "/console"
        "/h2-console"
        "/jolokia/list"
        "/swagger-ui.html"
        "/swagger-ui/index.html"
        "/api-docs"
        "/v2/api-docs"
        "/v3/api-docs"
        "/graphql"
    )

    # Paths where credential content is likely if endpoint returns 200
    local -a cred_paths=("/actuator/env" "/actuator/configprops")

    local -a ports=(80 443 8080 8443)
    local _t04_debug_ctr=0
    local _t04_cred_ctr=0
    local _t04_schema_ctr=0

    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        echo "--- Host: ${host} ---" >> "$ev_f"

        local port
        for port in "${ports[@]}"; do
            local scheme="http"
            [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
            local base_url="${scheme}://${host}:${port}"

            local path
            for path in "${debug_paths[@]}"; do
                local url="${base_url}${path}"
                local tmp_body
                tmp_body=$(mktemp /tmp/orc-dbg-XXXXXX 2>/dev/null || echo "/tmp/orc-dbg-$$-${RANDOM}")

                local http_info
                http_info=$(timeout "$SECRETS_TIMEOUT" curl -sk \
                    --max-time "$SECRETS_TIMEOUT" \
                    --max-filesize 262144 \
                    -H "Content-Type: application/json" \
                    -o "$tmp_body" \
                    -w "%{http_code}:%{size_download}" \
                    "$url" 2>/dev/null || echo "000:0")

                # For GraphQL, also try introspection query via POST
                if [[ "$path" == "/graphql" ]]; then
                    local gql_tmp
                    gql_tmp=$(mktemp /tmp/orc-gql-XXXXXX 2>/dev/null || echo "/tmp/orc-gql-$$-${RANDOM}")
                    local gql_info
                    gql_info=$(timeout "$SECRETS_TIMEOUT" curl -sk \
                        --max-time "$SECRETS_TIMEOUT" \
                        -X POST \
                        -H "Content-Type: application/json" \
                        -d '{"query":"{ __schema { types { name } } }"}' \
                        -o "$gql_tmp" \
                        -w "%{http_code}:%{size_download}" \
                        "$url" 2>/dev/null || echo "000:0")
                    local gql_code="${gql_info%%:*}"
                    local gql_size="${gql_info##*:}"
                    if [[ "$gql_code" == "200" ]] && [[ "${gql_size:-0}" -gt 0 ]]; then
                        local gql_body
                        gql_body=$(head -c 2048 "$gql_tmp" 2>/dev/null || true)
                        if echo "$gql_body" | grep -qi '"__schema"\|"types"'; then
                            echo "  HIT (GraphQL introspection): ${url} [${gql_code}]" >> "$ev_f"
                            echo "$gql_body" >> "$ev_f"
                            (( _t04_schema_ctr++ )) || true
                            emit_finding "medium" \
                                "GraphQL Introspection Enabled: ${url}" \
                                "GraphQL introspection is enabled at ${url}. The complete API schema — all types, queries, mutations, and fields — is publicly accessible. This aids attackers in discovering undocumented endpoints and data structures." \
                                "Disable GraphQL introspection in production environments. Restrict access to introspection queries to authenticated users or developer environments only." \
                                "sec-graphql-introspect-${host//[^A-Za-z0-9]/-}-${port}"
                        fi
                    fi
                    rm -f "$gql_tmp" 2>/dev/null || true
                fi

                local http_code size_dl
                http_code="${http_info%%:*}"
                size_dl="${http_info##*:}"

                if [[ "$http_code" == "200" ]] && [[ "${size_dl:-0}" -gt 0 ]]; then
                    local content
                    content=$(head -c 4096 "$tmp_body" 2>/dev/null || true)

                    echo "  HIT: ${url} [${http_code}] ${size_dl}B" >> "$ev_f"
                    echo "  [first 4KB]:" >> "$ev_f"
                    echo "$content" >> "$ev_f"

                    (( _t04_debug_ctr++ )) || true

                    # Check actuator/env and configprops for unmasked credential values
                    local is_cred_path=0
                    local cp
                    for cp in "${cred_paths[@]}"; do
                        [[ "$path" == "$cp" ]] && is_cred_path=1 && break
                    done

                    if [[ "$is_cred_path" -eq 1 ]]; then
                        # Spring Boot actuator masks with "****" or [*]; flag if we see
                        # a property key containing password/secret/key/token with a
                        # non-masked value
                        local unmasked
                        unmasked=$(echo "$content" | \
                            python3 -c "
import sys, json, re
try:
    data = json.load(sys.stdin)
    props = data.get('propertySources', data.get('properties', {}))
    if isinstance(props, list):
        for src in props:
            for k, v in src.get('properties', {}).items():
                if re.search(r'password|secret|key|token', k, re.I):
                    val = v.get('value', '') if isinstance(v, dict) else str(v)
                    if val and val not in ('****', '******', '[*]', 'null', 'None', ''):
                        print(f'{k} = {val[:60]}')
    elif isinstance(props, dict):
        for k, v in props.items():
            if re.search(r'password|secret|key|token', k, re.I):
                if str(v) not in ('****', '******', '[*]', 'null', 'None', ''):
                    print(f'{k} = {str(v)[:60]}')
except Exception:
    pass
" 2>/dev/null || grep -iE '"(password|secret|key|token)"[[:space:]]*:[[:space:]]*"[^*\[]' \
                              <<< "$content" | head -5 || true)

                        if [[ -n "$unmasked" ]]; then
                            log_wrn "  T04: unmasked credentials in ${url}"
                            echo "  [CRED LEAK] ${url}:" >> "$ev_f"
                            echo "$unmasked" >> "$ev_f"
                            (( _t04_cred_ctr++ )) || true
                            emit_finding "critical" \
                                "Credentials Exposed via Spring Actuator: ${url}" \
                                "Unmasked credential values were returned by ${url}. Spring Boot actuator /env or /configprops is disclosing application secrets (passwords, API keys, tokens) without authentication." \
                                "Require authentication for all actuator endpoints (management.endpoints.web.exposure.include=health,info only). Set management.endpoint.env.keys-to-sanitize to include all secret property names. Rotate all exposed credentials." \
                                "sec-actuator-cred-${host//[^A-Za-z0-9]/-}-${port}"
                        else
                            # Actuator open but credentials masked — still a High finding
                            emit_finding "high" \
                                "Spring Actuator Endpoint Exposed (Unauthenticated): ${url}" \
                                "Actuator endpoint ${url} is accessible without authentication. While credential values appear masked, other endpoints (/mappings, /configprops, /heapdump) may leak sensitive runtime state, routing, or memory." \
                                "Restrict all actuator endpoints behind authentication. Limit exposed endpoints to /health and /info via management.endpoints.web.exposure.include. Never expose actuator on the public interface." \
                                "sec-actuator-open-${host//[^A-Za-z0-9]/-}-${port}"
                        fi
                    elif [[ "$path" == "/swagger-ui.html" || "$path" == "/swagger-ui/index.html" \
                         || "$path" == "/api-docs" || "$path" == "/v2/api-docs" \
                         || "$path" == "/v3/api-docs" ]]; then
                        (( _t04_schema_ctr++ )) || true
                        emit_finding "medium" \
                            "API Schema / Swagger UI Exposed: ${url}" \
                            "The API documentation/schema at ${url} is publicly accessible. Swagger/OpenAPI exposure reveals all API endpoints, parameters, and data models, significantly reducing reconnaissance effort for an attacker." \
                            "Restrict API documentation to authenticated users or internal networks. Disable Swagger UI in production builds unless explicitly required. Require API key or OAuth scope for /api-docs access." \
                            "sec-swagger-${host//[^A-Za-z0-9]/-}-${port}"
                    elif [[ "$path" == "/jolokia/list" ]]; then
                        (( _t04_debug_ctr++ )) || true
                        emit_finding "high" \
                            "Jolokia JMX Endpoint Exposed: ${url}" \
                            "The Jolokia JMX-over-HTTP bridge is accessible at ${url} without authentication. Jolokia exposes JMX MBeans, enabling server-side request forgery (SSRF) via the 'exec' command, information disclosure, and in some versions remote code execution." \
                            "Restrict Jolokia access to localhost or an internal management network. Require authentication (jolokia.config.policyLocation). Disable exec and write operations if Jolokia is needed for monitoring only." \
                            "sec-jolokia-${host//[^A-Za-z0-9]/-}-${port}"
                    elif [[ "$path" == "/console" || "$path" == "/h2-console" ]]; then
                        (( _t04_debug_ctr++ )) || true
                        emit_finding "high" \
                            "H2 / Spring Web Console Exposed: ${url}" \
                            "An interactive console (H2 database or Spring shell) was found at ${url}. These consoles often permit arbitrary SQL execution or command execution, leading to full application/server compromise." \
                            "Disable H2 web console in production (spring.h2.console.enabled=false). Restrict console access to localhost. Remove debug/developer dependencies from production builds." \
                            "sec-console-${host//[^A-Za-z0-9]/-}-${port}"
                    elif [[ "$path" == "/debug/vars" || "$path" == "/debug/pprof" \
                         || "$path" == "/__debug__" ]]; then
                        (( _t04_debug_ctr++ )) || true
                        emit_finding "high" \
                            "Go / Application Debug Endpoint Exposed: ${url}" \
                            "Debug endpoint ${url} is publicly accessible. Go pprof and expvar endpoints expose runtime memory, goroutine stacks, CPU profiles, and application variables — useful for attackers to map internal application state." \
                            "Never expose pprof or debug endpoints on production interfaces. Use a separate management listener bound to localhost. Require authentication or IP allowlisting." \
                            "sec-debug-${host//[^A-Za-z0-9]/-}-${port}"
                    else
                        emit_finding "high" \
                            "Debug/Admin Endpoint Accessible: ${url}" \
                            "The endpoint ${url} returned HTTP 200 (${size_dl} bytes). Debug and administration endpoints should not be reachable without authentication from the test network." \
                            "Restrict access to administrative and debug endpoints. Require authentication and apply network-layer controls (IP allowlist). Audit all management endpoints before production deployment." \
                            "sec-debug-generic-${host//[^A-Za-z0-9]/-}-${port}-${path//[^A-Za-z0-9]/-}"
                    fi
                fi

                rm -f "$tmp_body" 2>/dev/null || true
            done
        done
    done < <(_web_targets)

    log_ok "  T04 complete — ${_t04_debug_ctr} debug endpoint(s) open, ${_t04_cred_ctr} with credentials, ${_t04_schema_ctr} API schema(s) exposed"
}

# - MRK:19_T05 — T05 EXPOSED BACKUP AND DUMP FILES
test_T05_backup_dump_files() {
    local ev_f; ev_f="$(_ev_file "t05-backup-dumps")"

    log_inf "[T05] Exposed backup and dump files"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "curl probe backup paths, SQL dumps, archives, phpMyAdmin, WEB-INF"; return; }

    {
        echo "=== T05 Exposed Backup and Dump Files ==="
        echo "Timestamp: $(date)"
    } > "$ev_f"

    if ! _check_tool curl; then
        log_wrn "  curl not found — T05 requires curl"
        echo "[T05] curl not available" >> "$ev_f"
        return
    fi

    # Directory paths to check for listing
    local -a dir_paths=(
        "/backup/"
        "/backups/"
        "/db_backup/"
        "/dump/"
        "/old/"
        "/bak/"
    )

    # SQL dump filenames
    local -a sql_paths=(
        "/dump.sql"
        "/backup.sql"
        "/db.sql"
        "/database.sql"
        "/data.sql"
        "/site.sql"
        "/${PROJECT_NAME:-app}.sql"
    )

    # Archive filenames
    local -a archive_paths=(
        "/backup.zip"
        "/backup.tar.gz"
        "/site.zip"
        "/www.zip"
        "/html.zip"
        "/public.zip"
        "/backup.tar"
        "/db.zip"
        "/data.tar.gz"
    )

    # Miscellaneous sensitive paths
    local -a misc_paths=(
        "/phpMyAdmin/"
        "/phpmyadmin/"
        "/pma/"
        "/adminer.php"
        "/.DS_Store"
        "/WEB-INF/web.xml"
        "/META-INF/MANIFEST.MF"
    )

    local -a ports=(80 443 8080 8443)
    local _t05_sql_ctr=0
    local _t05_archive_ctr=0
    local _t05_dirlist_ctr=0
    local _t05_misc_ctr=0

    while IFS= read -r host; do
        [[ -z "$host" ]] && continue
        echo "--- Host: ${host} ---" >> "$ev_f"

        local port
        for port in "${ports[@]}"; do
            local scheme="http"
            [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
            local base_url="${scheme}://${host}:${port}"

            # ---- Directory listing check ----
            local dir_path
            for dir_path in "${dir_paths[@]}"; do
                local dir_url="${base_url}${dir_path}"
                local tmp_dir
                tmp_dir=$(mktemp /tmp/orc-dir-XXXXXX 2>/dev/null || echo "/tmp/orc-dir-$$-${RANDOM}")

                local http_info
                http_info=$(timeout "$SECRETS_TIMEOUT" curl -sk \
                    --max-time "$SECRETS_TIMEOUT" \
                    -o "$tmp_dir" \
                    -w "%{http_code}:%{size_download}" \
                    "$dir_url" 2>/dev/null || echo "000:0")

                local http_code size_dl
                http_code="${http_info%%:*}"
                size_dl="${http_info##*:}"

                if [[ "$http_code" == "200" ]] && [[ "${size_dl:-0}" -gt 0 ]]; then
                    local dir_content
                    dir_content=$(head -c 4096 "$tmp_dir" 2>/dev/null || true)
                    echo "  HIT: ${dir_url} [${http_code}] ${size_dl}B" >> "$ev_f"

                    # Check for directory listing indicators
                    if echo "$dir_content" | grep -qiE 'Index of|Parent Directory|<title>.*listing|href=".*\.(sql|zip|tar|bak|gz)"'; then
                        log_wrn "  T05: directory listing enabled at ${dir_url}"
                        echo "  [dir listing detected]:" >> "$ev_f"
                        echo "$dir_content" >> "$ev_f"
                        (( _t05_dirlist_ctr++ )) || true
                        emit_finding "medium" \
                            "Directory Listing Enabled on Backup Path: ${dir_url}" \
                            "Directory listing is enabled at ${dir_url}. All backup and dump files stored in this directory are enumerable and downloadable without authentication." \
                            "Disable directory indexing in the web server configuration (Apache: Options -Indexes; Nginx: autoindex off;). Restrict access to backup directories by IP or require authentication." \
                            "sec-dirlist-${host//[^A-Za-z0-9]/-}-${port}-${dir_path//[^A-Za-z0-9]/-}"
                    fi
                fi
                rm -f "$tmp_dir" 2>/dev/null || true
            done

            # ---- SQL dump files ----
            local sql_path
            for sql_path in "${sql_paths[@]}"; do
                local sql_url="${base_url}${sql_path}"
                local tmp_sql
                tmp_sql=$(mktemp /tmp/orc-sql-XXXXXX 2>/dev/null || echo "/tmp/orc-sql-$$-${RANDOM}")

                local http_info
                http_info=$(timeout "$SECRETS_TIMEOUT" curl -sk \
                    --max-time "$SECRETS_TIMEOUT" \
                    --max-filesize 1048576 \
                    -o "$tmp_sql" \
                    -w "%{http_code}:%{size_download}" \
                    "$sql_url" 2>/dev/null || echo "000:0")

                local http_code size_dl
                http_code="${http_info%%:*}"
                size_dl="${http_info##*:}"

                if [[ "$http_code" == "200" ]] && [[ "${size_dl:-0}" -gt 100 ]]; then
                    local sql_header
                    sql_header=$(head -c 512 "$tmp_sql" 2>/dev/null || true)
                    # Verify it looks like a SQL dump
                    if echo "$sql_header" | grep -qiE 'CREATE TABLE|INSERT INTO|mysqldump|-- MySQL|-- PostgreSQL|PRAGMA|BEGIN TRANSACTION'; then
                        log_wrn "  T05: SQL dump accessible at ${sql_url} (${size_dl} bytes)"
                        echo "  HIT [SQL dump]: ${sql_url} [${http_code}] ${size_dl}B" >> "$ev_f"
                        echo "  [header]:" >> "$ev_f"
                        echo "$sql_header" >> "$ev_f"
                        (( _t05_sql_ctr++ )) || true
                        emit_finding "critical" \
                            "Downloadable SQL Database Dump: ${sql_url}" \
                            "A SQL database dump (${size_dl} bytes) is publicly downloadable at ${sql_url}. SQL dumps typically contain full database schema, all user records, password hashes, and potentially plaintext credentials. This is a critical data exposure." \
                            "Remove all SQL dumps from the web root immediately. Store database backups outside the web-accessible directory. Enforce strict web server ACLs for any backup locations. Rotate all credentials that may have been stored in the database." \
                            "sec-sqldump-${host//[^A-Za-z0-9]/-}-${port}-${sql_path//[^A-Za-z0-9]/-}"
                    fi
                fi
                rm -f "$tmp_sql" 2>/dev/null || true
            done

            # ---- Archive files ----
            local arc_path
            for arc_path in "${archive_paths[@]}"; do
                local arc_url="${base_url}${arc_path}"
                local tmp_arc
                tmp_arc=$(mktemp /tmp/orc-arc-XXXXXX 2>/dev/null || echo "/tmp/orc-arc-$$-${RANDOM}")

                local http_info
                http_info=$(timeout "$SECRETS_TIMEOUT" curl -sk \
                    --max-time "$SECRETS_TIMEOUT" \
                    --max-filesize 262144 \
                    -o "$tmp_arc" \
                    -w "%{http_code}:%{size_download}" \
                    "$arc_url" 2>/dev/null || echo "000:0")

                local http_code size_dl
                http_code="${http_info%%:*}"
                size_dl="${http_info##*:}"

                if [[ "$http_code" == "200" ]] && [[ "${size_dl:-0}" -gt 100 ]]; then
                    # Check magic bytes: ZIP = 50 4B 03 04, gzip = 1F 8B, tar = 75 73 74 61 72
                    local is_archive=0
                    if command -v file &>/dev/null; then
                        local ftype
                        ftype=$(file -b "$tmp_arc" 2>/dev/null || true)
                        echo "$ftype" | grep -qiE 'Zip archive|gzip compressed|POSIX tar|GNU tar' && is_archive=1
                    else
                        # Fallback: check magic bytes
                        local magic
                        magic=$(od -An -N4 -tx1 "$tmp_arc" 2>/dev/null | tr -d ' \n' || true)
                        [[ "$magic" == "504b0304"* || "$magic" == "1f8b"* ]] && is_archive=1
                    fi

                    if [[ "$is_archive" -eq 1 ]]; then
                        log_wrn "  T05: backup archive accessible at ${arc_url} (${size_dl} bytes)"
                        echo "  HIT [archive]: ${arc_url} [${http_code}] ${size_dl}B" >> "$ev_f"
                        (( _t05_archive_ctr++ )) || true
                        emit_finding "high" \
                            "Downloadable Backup Archive: ${arc_url}" \
                            "A backup archive (${size_dl} bytes) is publicly accessible at ${arc_url}. Archives may contain full application source code, configuration files, credentials, and database contents." \
                            "Remove backup archives from the web root immediately. Store backups in a non-web-accessible location. Review archive contents for exposed credentials and rotate as necessary. Implement automated backup cleanup." \
                            "sec-archive-${host//[^A-Za-z0-9]/-}-${port}-${arc_path//[^A-Za-z0-9]/-}"
                    fi
                fi
                rm -f "$tmp_arc" 2>/dev/null || true
            done

            # ---- Miscellaneous sensitive paths ----
            local misc_path
            for misc_path in "${misc_paths[@]}"; do
                local misc_url="${base_url}${misc_path}"
                local tmp_misc
                tmp_misc=$(mktemp /tmp/orc-misc-XXXXXX 2>/dev/null || echo "/tmp/orc-misc-$$-${RANDOM}")

                local http_info
                http_info=$(timeout "$SECRETS_TIMEOUT" curl -sk \
                    --max-time "$SECRETS_TIMEOUT" \
                    --max-filesize 131072 \
                    -o "$tmp_misc" \
                    -w "%{http_code}:%{size_download}" \
                    "$misc_url" 2>/dev/null || echo "000:0")

                local http_code size_dl
                http_code="${http_info%%:*}"
                size_dl="${http_info##*:}"

                if [[ "$http_code" == "200" ]] && [[ "${size_dl:-0}" -gt 0 ]]; then
                    local misc_content
                    misc_content=$(head -c 2048 "$tmp_misc" 2>/dev/null || true)
                    echo "  HIT [misc]: ${misc_url} [${http_code}] ${size_dl}B" >> "$ev_f"
                    echo "  [content excerpt]:" >> "$ev_f"
                    echo "$misc_content" >> "$ev_f"
                    (( _t05_misc_ctr++ )) || true

                    case "$misc_path" in
                        /phpMyAdmin/|/phpmyadmin/|/pma/)
                            emit_finding "high" \
                                "phpMyAdmin Interface Publicly Accessible: ${misc_url}" \
                                "phpMyAdmin (or a PMA variant) is accessible at ${misc_url}. Exposed database administration interfaces are frequently targeted for credential brute-force and CVE exploitation, potentially leading to full database and system compromise." \
                                "Restrict phpMyAdmin access to trusted IP ranges or an authenticated VPN. Remove phpMyAdmin from production servers where not operationally required. Keep phpMyAdmin updated and protected by HTTP Basic Auth as a secondary layer." \
                                "sec-phpmyadmin-${host//[^A-Za-z0-9]/-}-${port}" ;;
                        /adminer.php)
                            emit_finding "high" \
                                "Adminer Database Interface Publicly Accessible: ${misc_url}" \
                                "Adminer is accessible at ${misc_url}. Like phpMyAdmin, Adminer is a database administration tool that should never be exposed publicly. It can be used to dump databases, execute SQL, or exploit known Adminer CVEs (e.g. CVE-2021-21311)." \
                                "Remove adminer.php from the web root. If required for maintenance, restrict by IP or authentication. Never deploy Adminer on production web servers." \
                                "sec-adminer-${host//[^A-Za-z0-9]/-}-${port}" ;;
                        /.DS_Store)
                            # Parse .DS_Store for filenames
                            local ds_files
                            ds_files=$(strings "$tmp_misc" 2>/dev/null | grep -E '^[A-Za-z0-9_. -]{2,50}$' | head -20 || true)
                            echo "  [DS_Store filenames]: ${ds_files}" >> "$ev_f"
                            emit_finding "medium" \
                                "macOS .DS_Store File Exposed: ${misc_url}" \
                                ".DS_Store is publicly accessible at ${misc_url}. This macOS metadata file contains a directory listing of files that were present when the Mac created the file, revealing hidden files, configuration names, and folder structure even if those files have since been removed." \
                                "Delete .DS_Store files from the web root and version control (.gitignore: .DS_Store). Block access via web server configuration: location = /.DS_Store { deny all; }." \
                                "sec-dsstore-${host//[^A-Za-z0-9]/-}-${port}" ;;
                        /WEB-INF/web.xml)
                            emit_finding "high" \
                                "WEB-INF/web.xml Accessible: ${misc_url}" \
                                "The Java EE deployment descriptor web.xml is accessible at ${misc_url}. This file exposes servlet mappings, security constraints, filter configurations, and may reference database credentials or JNDI connection strings." \
                                "Configure the web server or reverse proxy to deny direct access to WEB-INF/ and META-INF/ directories. These should never be web-accessible in a correctly configured Java application server." \
                                "sec-webinf-${host//[^A-Za-z0-9]/-}-${port}" ;;
                        /META-INF/MANIFEST.MF)
                            emit_finding "medium" \
                                "META-INF/MANIFEST.MF Exposed: ${misc_url}" \
                                "Java MANIFEST.MF is accessible at ${misc_url}. This file discloses application version, build information, class-path entries, and potentially signing certificates. Useful for targeted CVE identification." \
                                "Deny access to META-INF/ at the web server or reverse proxy level. Review MANIFEST.MF for sensitive information before deployment." \
                                "sec-manifest-${host//[^A-Za-z0-9]/-}-${port}" ;;
                    esac
                fi
                rm -f "$tmp_misc" 2>/dev/null || true
            done
        done
    done < <(_web_targets)

    log_ok "  T05 complete — ${_t05_sql_ctr} SQL dump(s), ${_t05_archive_ctr} archive(s), ${_t05_dirlist_ctr} directory listing(s), ${_t05_misc_ctr} miscellaneous hit(s)"
}

# =============================================================================
# - MRK:19_TRUN
# =============================================================================
_run_tests() {
    local find_before="$_FIND_CTR"

    log_inf "=== Secrets & Credential Exposure Scan ==="

    _test_skip T01 || test_T01_smb_secret_spider
    _test_skip T02 || test_T02_web_sensitive_files
    _test_skip T03 || test_T03_git_secret_scan
    _test_skip T04 || test_T04_debug_endpoints
    _test_skip T05 || test_T05_backup_dump_files

    local find_delta=$(( _FIND_CTR - find_before ))
    echo "SUMMARY_ROW|secrets_scan|findings=${find_delta}"
}

# =============================================================================
# - MRK:19_MAIN
# =============================================================================
main() {
    printf "\n${_W}╔══════════════════════════════════════════════════════╗${_N}\n"
    printf "${_W}║  PT-Orc  ·  Step 20: Secrets & Credential Exposure   ║${_N}\n"
    printf "${_W}╚══════════════════════════════════════════════════════╝${_N}\n\n"

    log_inf "Project  : ${PROJECT_NAME}"
    log_inf "Profile  : ${SCAN_PROFILE}"
    log_inf "Timeout  : ${SECRETS_TIMEOUT}s per probe"
    log_inf "Session  : ${SESSION_TS}"
    log_inf "Log      : ${LOG_FILE}"

    _validate_config
    setup_profile "$SCAN_PROFILE"
    _confirm

    command -v trail_phase_start &>/dev/null && trail_phase_start "20_secrets_scan"

    local row
    row=$(_run_tests)
    local total_findings
    total_findings=$(echo "$row" | grep -oE 'findings=[0-9]+' | grep -oE '[0-9]+' || echo 0)

    command -v trail_phase_end &>/dev/null && trail_phase_end "20_secrets_scan"

    # Summary report
    local report_f="${SCRIPT_DIR}/working/$(ev_fname "20-secrets-summary" "md")"
    {
        printf "# Secrets Scan Summary — %s\n\n" "$PROJECT_NAME"
        printf "| Phase | Findings |\n|-------|----------|\n"
        local finds_col
        finds_col=$(echo "$row" | grep -oE 'findings=[0-9]+')
        printf "| secrets_scan | %s |\n" "$finds_col"
        printf "\n**Total Findings:** %d\n" "$total_findings"
        printf "\nFindings JSONL: \`%s\`\n" "$FINDINGS_FILE"
        printf "\nEvidence dir  : \`%s\`\n" "$EVIDENCE_BASE"
    } > "$report_f"

    printf "\n${_G}[DONE]${_N} Secrets & credential exposure scan complete.\n"
    printf "  Findings : %d\n" "$total_findings"
    printf "  Summary  : %s\n" "$report_f"
    printf "  Evidence : %s\n\n" "$EVIDENCE_BASE"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
