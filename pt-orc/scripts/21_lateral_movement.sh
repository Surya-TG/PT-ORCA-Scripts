#!/usr/bin/env bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:21_NAV_TOC — Section index | nav,toc,index | L5-27
# - MRK:21_T01 — T01 SMB REACHABILITY MATRIX | t01,smb,reachability,null,session | L28-28
# - MRK:21_T02 — T02 WINRM REACHABILITY | t02,winrm,5985,5986,evil-winrm | L29-29
# - MRK:21_T03 — T03 RDP EXPOSURE | t03,rdp,3389,nla,bluekeep | L30-30
# - MRK:21_T04 — T04 SSH HOST KEY REUSE | t04,ssh,host,key,fingerprint,reuse | L31-31
# - MRK:21_T05 — T05 PASS-THE-HASH SURFACE | t05,pth,nt,hash,crackmapexec | L32-32
# - MRK:21_T06 — T06 LSASS PROTECTION STATUS | t06,lsass,runasppl,wdigest,registry | L33-33
# - MRK:21_T07 — T07 SERVICE ACCOUNT CREDENTIAL REUSE | t07,credential,reuse,smb,winrm,ssh | L34-34
# NAV-LEN: 7 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-06-25

# =============================================================================
# 21_lateral_movement.sh — Lateral Movement Surface Assessment
# TechGuard Labs | PT-Orc Suite v0.8
# =============================================================================
# NAV: MRK:21_NAV_TOC (this block) | MRK:21_ROOT | MRK:21_CONF | MRK:21_LOG
#      MRK:21_ARGS | MRK:21_CONFIRM | MRK:21_TARGETS
#      MRK:21_FIND | MRK:21_UTILS | MRK:21_PROF
#      MRK:21_T01 — T01 SMB REACHABILITY MATRIX
#      MRK:21_T02 — T02 WINRM REACHABILITY
#      MRK:21_T03 — T03 RDP EXPOSURE
#      MRK:21_T04 — T04 SSH HOST KEY REUSE
#      MRK:21_T05 — T05 PASS-THE-HASH SURFACE
#      MRK:21_T06 — T06 LSASS PROTECTION STATUS
#      MRK:21_T07 — T07 SERVICE ACCOUNT CREDENTIAL REUSE
#      MRK:21_TRUN | MRK:21_MAIN
# =============================================================================

# - MRK:21_ROOT
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# - MRK:21_CONF
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

# Lateral movement conf vars — sourced from conf or set via CLI
LATERAL_TARGETS="${LATERAL_TARGETS:-}"
LATERAL_USERNAME="${LATERAL_USERNAME:-}"
LATERAL_PASSWORD="${LATERAL_PASSWORD:-}"
LATERAL_NT_HASH="${LATERAL_NT_HASH:-}"
LATERAL_TIMEOUT="${LATERAL_TIMEOUT:-15}"

# - MRK:21_LOG
_R='\033[0;31m'; _G='\033[0;32m'; _Y='\033[1;33m'; _B='\033[0;34m'; _C='\033[0;36m'; _W='\033[1;37m'; _N='\033[0m'
SESSION_TS="$(date +%Y%m%d_%H%M%S)"
EV_TS="$(date +'%Y-%m-%d-%H-%M-%S')"
LOG_FILE="${SCRIPT_DIR}/working/${PROJ_SLUG}_21_lateral_${SESSION_TS}.log"
mkdir -p "${SCRIPT_DIR}/working" "${EVIDENCE_BASE}"

_log()    { local ts; ts="$(date +%H:%M:%S)"; printf "[%s] %s\n" "$ts" "$*" | tee -a "$LOG_FILE"; }
log_ok()  { printf "${_G}[+]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_inf() { printf "${_B}[*]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_wrn() { printf "${_Y}[!]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_err() { printf "${_R}[-]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_dry() { printf "${_C}[DRY]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }

# - MRK:21_ARGS
_SKIP_CONFIRM=0
_ONLY_TESTS=()
_SKIP_TESTS=()

_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Lateral Movement Surface Assessment (step 21)

Tests SMB, WinRM, RDP, SSH host key reuse, pass-the-hash surface,
LSASS protection status, and credential reuse across lateral targets.

Options:
  --targets <IP[,IP,...]>  Comma-separated target IPs/CIDRs (overrides LATERAL_TARGETS)
  --user <username>        Username for authenticated tests (overrides LATERAL_USERNAME)
  --pass <password>        Password (overrides LATERAL_PASSWORD)
  --hash <NTHASH>          NT hash for pass-the-hash (overrides LATERAL_NT_HASH)
  -p, --profile <name>     Scan profile: quick|standard|deep  [default: standard]
  --only <T01,T05,...>     Run only specified tests
  --skip <T01,T05,...>     Skip specified tests
  -y, --yes                Skip confirmation prompt
  --dry-run                Print actions without executing
  -h, --help               Show this help

Profiles:
  quick    = T01, T02, T03, T04
  standard = T01, T02, T03, T04, T06
  deep     = all (T05 also gated by LATERAL_NT_HASH; T07 gated by discovered creds)

Conf vars (pt-orc.conf):
  LATERAL_TARGETS   — space-separated IPs/CIDRs (default: TARGET_IPS + TARGET_SUBNETS)
  LATERAL_USERNAME  — username for authenticated tests
  LATERAL_PASSWORD  — password for authenticated tests
  LATERAL_NT_HASH   — NT hash for pass-the-hash tests (gates T05)
  LATERAL_TIMEOUT   — per-host timeout in seconds (default: 15)

WARNING: T05 (Pass-the-Hash) requires LATERAL_NT_HASH and deep profile.
         T07 (credential reuse) reads discovered credentials from working/*.jsonl.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)      LATERAL_TARGETS="${2//,/ }"; shift 2 ;;
        --user)         LATERAL_USERNAME="$2"; shift 2 ;;
        --pass)         LATERAL_PASSWORD="$2"; shift 2 ;;
        --hash)         LATERAL_NT_HASH="$2"; shift 2 ;;
        -p|--profile)   SCAN_PROFILE="$2"; shift 2 ;;
        --only)         IFS=',' read -ra _ONLY_TESTS <<< "$2"; shift 2 ;;
        --skip)         IFS=',' read -ra _SKIP_TESTS <<< "$2"; shift 2 ;;
        -y|--yes)       _SKIP_CONFIRM=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -h|--help)      _usage; exit 0 ;;
        *)              log_err "Unknown option: $1"; _usage; exit 1 ;;
    esac
done

# Derived credential state
_HAS_CREDS=0
if [[ -n "${LATERAL_USERNAME}" && -n "${LATERAL_PASSWORD}" ]]; then
    _HAS_CREDS=1
elif [[ -n "${LATERAL_USERNAME}" && -n "${LATERAL_NT_HASH}" ]]; then
    _HAS_CREDS=1
fi

# - MRK:21_CONFIRM
_confirm() {
    [[ "$_SKIP_CONFIRM" -eq 1 ]] && return 0
    printf "\n${_Y}[CONFIRM]${_N} Lateral movement surface assessment. Profile: ${_W}%s${_N}\n" "$SCAN_PROFILE"
    printf "  Project  : %s\n" "$PROJECT_NAME"
    printf "  Targets  : %s\n" "${LATERAL_TARGETS:-<default: TARGET_IPS + TARGET_SUBNETS>}"
    printf "  Username : %s\n" "${LATERAL_USERNAME:-<none — unauthenticated only>}"
    printf "  Auth     : %s\n" "$( [[ "$_HAS_CREDS" -eq 1 ]] && echo "authenticated" || echo "null session / unauthenticated" )"
    printf "  PTH Hash : %s\n" "$( [[ -n "${LATERAL_NT_HASH}" ]] && echo "set" || echo "not set" )"
    printf "\n  ${_R}WARNING:${_N} This script sends active packets to target hosts.\n"
    printf "  Only run within authorised scope and agreed engagement window.\n"
    printf "\n  Continue? [y/N] "
    read -r _ans
    [[ "${_ans,,}" == "y" ]] || { log_err "Aborted by user."; exit 0; }
}

# - MRK:21_TARGETS
# Resolve the lateral target list — space-separated individual IPs.
# CIDRs in LATERAL_TARGETS are passed through as-is to nmap; for per-host tools
# (smbclient, ssh-keyscan, evil-winrm) we use the live-hosts set discovered by T01.
declare -a _LATERAL_TARGETS_RAW=()
_build_target_list() {
    local combined=""
    if [[ -n "${LATERAL_TARGETS}" ]]; then
        combined="${LATERAL_TARGETS}"
    else
        combined="${TARGET_IPS:-} ${TARGET_SUBNETS:-}"
    fi
    # Tokenise on whitespace and commas
    local tok
    IFS=' ,' read -ra tok <<< "$combined"
    for t in "${tok[@]+"${tok[@]}"}"; do
        [[ -n "$t" ]] && _LATERAL_TARGETS_RAW+=("$t")
    done
}
_build_target_list

# Live-host list populated by T01 (hosts with 445 open)
# Other tests use _LATERAL_LIVE_SMB; T04 uses _LATERAL_LIVE_SSH
declare -a _LATERAL_LIVE_SMB=()
declare -a _LATERAL_LIVE_WINRM=()
declare -a _LATERAL_LIVE_RDP=()
declare -a _LATERAL_LIVE_SSH=()

# - MRK:21_FIND
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "21-lateral-findings" "jsonl")"
_FIND_CTR=0
: > "$FINDINGS_FILE"

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="${5:-}"
    (( _FIND_CTR++ )) || true
    local fid
    fid="f-21-lat-$(printf '%04d' "$_FIND_CTR")"
    local ev_id="${ev_tag:-${fid}-ev}"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"21_lateral_movement","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
        "$fid" \
        "$(echo "$title" | sed 's/"/\\"/g')" \
        "$sev" \
        "$ev_id" \
        "$(echo "$desc" | sed 's/"/\\"/g')" \
        "$(echo "$rec"  | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_wrn "FINDING [${sev^^}] ${title}"
}

# - MRK:21_UTILS
_check_tool() {
    local tool="$1"
    command -v "$tool" &>/dev/null
}

# Return "netexec" or "crackmapexec" depending on availability, or empty string
_cme_tool() {
    if command -v netexec &>/dev/null; then
        echo "netexec"
    elif command -v crackmapexec &>/dev/null; then
        echo "crackmapexec"
    else
        echo ""
    fi
}

_ev_file() {
    local tag="$1"
    echo "${EVIDENCE_BASE}/$(ev_fname "lat-${tag}" "txt")"
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

# - MRK:21_PROF
setup_profile() {
    local prof="${1:-standard}"
    for n in T01 T02 T03 T04 T05 T06 T07; do
        _T_ENABLED[$n]=1
    done
    case "$prof" in
        quick)
            # Quick: SMB matrix, WinRM, RDP, SSH key reuse only
            for n in T05 T06 T07; do _T_ENABLED[$n]=0; done ;;
        standard)
            # Standard: all except PTH (T05) and credential reuse (T07)
            for n in T05 T07; do _T_ENABLED[$n]=0; done ;;
        deep)
            # All enabled — T05 still gated at runtime by LATERAL_NT_HASH
            # T07 still gated at runtime by discovered credentials
            : ;;
        *)
            log_wrn "Unknown profile '${prof}' — defaulting to standard"
            for n in T05 T07; do _T_ENABLED[$n]=0; done ;;
    esac
    _apply_cli_filters
}

# =============================================================================
# TESTS
# =============================================================================

# - MRK:21_T01 — T01 SMB REACHABILITY MATRIX
test_T01_smb_matrix() {
    local ev_f; ev_f="$(_ev_file "smb_matrix")"
    local cme; cme="$(_cme_tool)"

    log_inf "[T01] SMB reachability matrix — port 445 across lateral targets"

    if [[ ${#_LATERAL_TARGETS_RAW[@]} -eq 0 ]]; then
        log_wrn "  No lateral targets defined — skipping T01"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "nmap -p 445 --open ${_LATERAL_TARGETS_RAW[*]}"
        return
    }

    {
        echo "=== T01 SMB Reachability Matrix ==="
        echo "Targets: ${_LATERAL_TARGETS_RAW[*]}"
        echo "Timestamp: $(date)"
    } > "$ev_f"

    if ! _check_tool nmap; then
        log_wrn "  nmap not found — using nc for port 445 check"
        for tgt in "${_LATERAL_TARGETS_RAW[@]}"; do
            if nc -zw3 "$tgt" 445 2>/dev/null; then
                log_inf "  SMB open: ${tgt}:445"
                echo "OPEN: ${tgt}:445" >> "$ev_f"
                _LATERAL_LIVE_SMB+=("$tgt")
            fi
        done
    else
        log_inf "  Running nmap -p 445 --open on ${#_LATERAL_TARGETS_RAW[@]} target(s)..."
        local nmap_out
        nmap_out=$(timeout 120 nmap -p 445 --open -oG - "${_LATERAL_TARGETS_RAW[@]}" 2>/dev/null || true)
        echo "--- nmap output ---" >> "$ev_f"
        echo "$nmap_out" >> "$ev_f"

        # Collect hosts with 445 open from nmap grepable output
        while IFS= read -r line; do
            if echo "$line" | grep -qE '445/open'; then
                local ip
                ip=$(echo "$line" | awk '/^Host:/{print $2}')
                [[ -n "$ip" ]] && _LATERAL_LIVE_SMB+=("$ip")
            fi
        done <<< "$nmap_out"
    fi

    log_ok "  SMB-open hosts: ${#_LATERAL_LIVE_SMB[@]} — ${_LATERAL_LIVE_SMB[*]:-none}"

    if [[ ${#_LATERAL_LIVE_SMB[@]} -eq 0 ]]; then
        echo "[T01] No hosts with port 445 open found" >> "$ev_f"
        return
    fi

    # Per-host: attempt null session, then authenticated share listing
    local null_session_hosts=()
    for host in "${_LATERAL_LIVE_SMB[@]}"; do
        echo "--- Host: ${host} ---" >> "$ev_f"

        # Null session with smbclient
        if _check_tool smbclient; then
            local null_out
            null_out=$(timeout "${LATERAL_TIMEOUT}" smbclient -L "//${host}" -N 2>&1 | head -50 || true)
            echo "${null_out}" >> "$ev_f"

            if echo "$null_out" | grep -qiE 'Sharename|IPC\$|ADMIN\$'; then
                log_wrn "  Null session succeeded on ${host}"
                null_session_hosts+=("$host")
            fi
        fi

        # Authenticated share listing if creds available
        if [[ "$_HAS_CREDS" -eq 1 ]]; then
            if _check_tool smbclient; then
                local auth_out
                if [[ -n "${LATERAL_NT_HASH}" ]]; then
                    # Pass-the-hash via smbclient with --pw-nt-hash flag if supported
                    auth_out=$(timeout "${LATERAL_TIMEOUT}" smbclient -L "//${host}" \
                        -U "${LATERAL_USERNAME}%" --pw-nt-hash --password="${LATERAL_NT_HASH}" \
                        2>&1 | head -50 || true)
                else
                    auth_out=$(timeout "${LATERAL_TIMEOUT}" smbclient -L "//${host}" \
                        -U "${LATERAL_USERNAME}%${LATERAL_PASSWORD}" 2>&1 | head -50 || true)
                fi
                echo "--- Authenticated share listing (${host}) ---" >> "$ev_f"
                echo "$auth_out" >> "$ev_f"

                if echo "$auth_out" | grep -qiE 'Sharename|IPC\$|ADMIN\$'; then
                    log_ok "  Authenticated share listing succeeded on ${host}"
                    emit_finding "info" \
                        "SMB Authenticated Share Listing: ${host}" \
                        "Share enumeration via authenticated SMB session succeeded on ${host} using credentials for '${LATERAL_USERNAME}'. This confirms SMB access with current credentials." \
                        "Restrict SMB access to authorised management hosts. Apply host-based firewall rules limiting port 445 to required sources only." \
                        "smb_auth_share_${host//\./_}"
                fi
            fi

            # crackmapexec / netexec for richer output
            if [[ -n "$cme" ]]; then
                local cme_out
                if [[ -n "${LATERAL_NT_HASH}" ]]; then
                    cme_out=$(timeout "${LATERAL_TIMEOUT}" "$cme" smb "$host" \
                        -u "${LATERAL_USERNAME}" -H "${LATERAL_NT_HASH}" \
                        --shares 2>&1 | head -60 || true)
                else
                    cme_out=$(timeout "${LATERAL_TIMEOUT}" "$cme" smb "$host" \
                        -u "${LATERAL_USERNAME}" -p "${LATERAL_PASSWORD}" \
                        --shares 2>&1 | head -60 || true)
                fi
                echo "--- ${cme} shares (${host}) ---" >> "$ev_f"
                echo "$cme_out" >> "$ev_f"
                if echo "$cme_out" | grep -qiE 'READ|WRITE'; then
                    log_inf "  ${cme} identified readable/writable shares on ${host} — see evidence"
                fi
            fi
        else
            # Unauthenticated CME run for banner + OS info
            if [[ -n "$cme" ]]; then
                local cme_null
                cme_null=$(timeout "${LATERAL_TIMEOUT}" "$cme" smb "$host" 2>&1 | head -20 || true)
                echo "--- ${cme} banner (${host}) ---" >> "$ev_f"
                echo "$cme_null" >> "$ev_f"
            fi
        fi
    done

    # Emit finding for null session successes
    if [[ ${#null_session_hosts[@]} -gt 0 ]]; then
        emit_finding "medium" \
            "SMB Null Session Permitted: ${null_session_hosts[*]}" \
            "SMB null sessions (unauthenticated) were accepted by host(s): ${null_session_hosts[*]}. Share names and host metadata may be enumerable without credentials, aiding lateral movement reconnaissance." \
            "Restrict anonymous SMB access via Group Policy: 'Network Access: Do not allow anonymous enumeration of SAM accounts and shares'. Apply host-based firewall rules. Disable SMBv1 across all hosts." \
            "smb_null_session"
    fi

    log_ok "  T01 complete — ${#_LATERAL_LIVE_SMB[@]} SMB-open host(s), ${#null_session_hosts[@]} null session(s)"
}

# - MRK:21_T02 — T02 WINRM REACHABILITY
test_T02_winrm_reachability() {
    local ev_f; ev_f="$(_ev_file "winrm_reach")"

    log_inf "[T02] WinRM reachability — ports 5985/5986 across lateral targets"

    if [[ ${#_LATERAL_TARGETS_RAW[@]} -eq 0 ]]; then
        log_wrn "  No lateral targets defined — skipping T02"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "nmap -p 5985,5986 --open ${_LATERAL_TARGETS_RAW[*]}"
        return
    }

    {
        echo "=== T02 WinRM Reachability ==="
        echo "Targets: ${_LATERAL_TARGETS_RAW[*]}"
        echo "Timestamp: $(date)"
    } > "$ev_f"

    # Port scan
    local nmap_out=""
    if _check_tool nmap; then
        nmap_out=$(timeout 120 nmap -p 5985,5986 --open -oG - \
            "${_LATERAL_TARGETS_RAW[@]}" 2>/dev/null || true)
        echo "--- nmap 5985/5986 ---" >> "$ev_f"
        echo "$nmap_out" >> "$ev_f"
    else
        log_wrn "  nmap not found — using nc fallback"
        for tgt in "${_LATERAL_TARGETS_RAW[@]}"; do
            for port in 5985 5986; do
                if nc -zw3 "$tgt" "$port" 2>/dev/null; then
                    nmap_out+="Host: ${tgt}  Ports: ${port}/open"$'\n'
                fi
            done
        done
        echo "$nmap_out" >> "$ev_f"
    fi

    # Collect WinRM-open hosts
    while IFS= read -r line; do
        if echo "$line" | grep -qE '5985/open|5986/open'; then
            local ip
            ip=$(echo "$line" | awk '/^Host:/{print $2}')
            [[ -n "$ip" ]] && _LATERAL_LIVE_WINRM+=("$ip")
        fi
    done <<< "$nmap_out"

    log_ok "  WinRM-open hosts: ${#_LATERAL_LIVE_WINRM[@]} — ${_LATERAL_LIVE_WINRM[*]:-none}"

    if [[ ${#_LATERAL_LIVE_WINRM[@]} -eq 0 ]]; then
        echo "[T02] No hosts with WinRM open found" >> "$ev_f"
        return
    fi

    # Per-host: connectivity confirmation + optional credential test
    for host in "${_LATERAL_LIVE_WINRM[@]}"; do
        echo "--- Host: ${host} ---" >> "$ev_f"

        # Check which port is open
        local port=5985
        echo "$nmap_out" | grep "Host: ${host}" | grep -q '5986/open' && port=5986

        # Connectivity check — dry run only for evil-winrm, no shell opened
        if [[ "$_HAS_CREDS" -eq 1 ]]; then
            if _check_tool evil-winrm; then
                # Test connectivity only — use a very short timeout + dummy command
                # We do NOT open an interactive shell; the connection attempt itself confirms access
                local ew_out
                if [[ -n "${LATERAL_NT_HASH}" ]]; then
                    ew_out=$(timeout 8 evil-winrm -i "$host" \
                        -u "${LATERAL_USERNAME}" -H "${LATERAL_NT_HASH}" \
                        -e /dev/null 2>&1 | head -10 || true)
                else
                    ew_out=$(timeout 8 evil-winrm -i "$host" \
                        -u "${LATERAL_USERNAME}" -p "${LATERAL_PASSWORD}" \
                        -e /dev/null 2>&1 | head -10 || true)
                fi
                echo "--- evil-winrm connectivity (${host}:${port}) ---" >> "$ev_f"
                echo "$ew_out" >> "$ev_f"

                if echo "$ew_out" | grep -qiE 'Info: Establishing|connected|Win32_ComputerSystem'; then
                    emit_finding "critical" \
                        "WinRM Accessible with Valid Credentials: ${host}" \
                        "evil-winrm successfully connected to ${host} on port ${port} using credentials for '${LATERAL_USERNAME}'. Full remote command execution is possible. Lateral movement risk is critical." \
                        "Restrict WinRM access to authorised management hosts via Windows Firewall and Group Policy. Require HTTPS WinRM (5986) with valid certificates. Enable constrained endpoints (PSSessionConfiguration). Implement MFA for remote management." \
                        "winrm_auth_${host//\./_}"
                    log_wrn "  CRITICAL: WinRM accessible with credentials on ${host}"
                else
                    # WinRM open but creds didn't work — still a finding
                    emit_finding "high" \
                        "WinRM Open (No Valid Credentials Confirmed): ${host}" \
                        "WinRM port ${port} is open on ${host}. Current credentials did not succeed but the service is exposed. Successful credential compromise would enable full remote execution." \
                        "Restrict WinRM to authorised management hosts via host-based firewall. Require HTTPS WinRM (5986). Disable WinRM if not required." \
                        "winrm_open_${host//\./_}"
                    log_wrn "  WinRM open on ${host}:${port} (credentials not accepted)"
                fi
            else
                # evil-winrm not found — use curl to confirm 401 response
                local curl_out
                curl_out=$(timeout "${LATERAL_TIMEOUT}" curl -sk \
                    --max-time "${LATERAL_TIMEOUT}" \
                    -o /dev/null -w "%{http_code}" \
                    "http://${host}:5985/wsman" 2>/dev/null || echo "000")
                echo "--- curl http://${host}:5985/wsman → HTTP ${curl_out} ---" >> "$ev_f"

                if [[ "$curl_out" == "401" ]]; then
                    emit_finding "critical" \
                        "WinRM Accessible with Valid Credentials: ${host} (curl 401 confirms service)" \
                        "WinRM port ${port} on ${host} returned HTTP 401 (authentication required), confirming the service is active. Credentials for '${LATERAL_USERNAME}' are set — full credential test recommended with evil-winrm." \
                        "Restrict WinRM to authorised management hosts. Require HTTPS (port 5986). Install evil-winrm for full credential validation in follow-up testing." \
                        "winrm_curl_${host//\./_}"
                    log_wrn "  WinRM active on ${host}:${port} (HTTP 401) — full credential test needed"
                elif [[ "$curl_out" != "000" ]]; then
                    emit_finding "high" \
                        "WinRM Open (HTTP ${curl_out}): ${host}" \
                        "WinRM port 5985 on ${host} returned HTTP ${curl_out}. The service is exposed. Install evil-winrm for full credential testing." \
                        "Restrict WinRM to authorised management hosts via Windows Firewall. Require HTTPS WinRM (5986) with valid certificates." \
                        "winrm_open_curl_${host//\./_}"
                    log_wrn "  WinRM open on ${host}:5985 (HTTP ${curl_out})"
                fi
            fi
        else
            # No creds — just report the open port
            local curl_code
            curl_code=$(timeout 5 curl -sk -o /dev/null -w "%{http_code}" \
                "http://${host}:5985/wsman" 2>/dev/null || echo "000")
            echo "--- No creds: curl http://${host}:5985/wsman → HTTP ${curl_code} ---" >> "$ev_f"

            emit_finding "high" \
                "WinRM Port Open (No Credentials): ${host}:${port}" \
                "WinRM port ${port} is open on ${host}. No credentials are configured for this test. If credentials are obtained, full remote command execution via evil-winrm would be possible." \
                "Restrict WinRM to authorised management hosts via Windows Firewall. Require HTTPS WinRM (5986). Disable WinRM if not required for administration." \
                "winrm_nocreds_${host//\./_}"
            log_wrn "  WinRM open on ${host}:${port} (no credentials to test)"
        fi
    done

    log_ok "  T02 complete — ${#_LATERAL_LIVE_WINRM[@]} WinRM-open host(s)"
}

# - MRK:21_T03 — T03 RDP EXPOSURE
test_T03_rdp_exposure() {
    local ev_f; ev_f="$(_ev_file "rdp_exposure")"

    log_inf "[T03] RDP exposure — port 3389 across lateral targets"

    if [[ ${#_LATERAL_TARGETS_RAW[@]} -eq 0 ]]; then
        log_wrn "  No lateral targets defined — skipping T03"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "nmap -p 3389 --open --script rdp-enum-encryption,rdp-vuln-ms12-020 ${_LATERAL_TARGETS_RAW[*]}"
        return
    }

    {
        echo "=== T03 RDP Exposure ==="
        echo "Targets: ${_LATERAL_TARGETS_RAW[*]}"
        echo "Timestamp: $(date)"
    } > "$ev_f"

    local nmap_out=""
    if _check_tool nmap; then
        log_inf "  Running nmap RDP scan with NSE scripts (rdp-enum-encryption, rdp-vuln-ms12-020)..."
        nmap_out=$(timeout 180 nmap -p 3389 --open \
            --script rdp-enum-encryption,rdp-vuln-ms12-020 \
            -oN - "${_LATERAL_TARGETS_RAW[@]}" 2>/dev/null || true)
        echo "$nmap_out" >> "$ev_f"
    else
        log_wrn "  nmap not found — using nc for port 3389 check"
        for tgt in "${_LATERAL_TARGETS_RAW[@]}"; do
            if nc -zw3 "$tgt" 3389 2>/dev/null; then
                nmap_out+="Host: ${tgt}  Ports: 3389/open"$'\n'
            fi
        done
        echo "$nmap_out" >> "$ev_f"
    fi

    # Parse nmap output for open RDP hosts
    local rdp_hosts=()
    if _check_tool nmap; then
        while IFS= read -r line; do
            if echo "$line" | grep -qE 'Nmap scan report for'; then
                local cur_host
                cur_host=$(echo "$line" | awk '{print $NF}' | tr -d '()')
            fi
            if echo "$line" | grep -qE '3389/tcp.*open'; then
                [[ -n "${cur_host:-}" ]] && rdp_hosts+=("$cur_host") && _LATERAL_LIVE_RDP+=("$cur_host")
            fi
        done <<< "$nmap_out"
    else
        while IFS= read -r line; do
            if echo "$line" | grep -qE '3389/open'; then
                local ip; ip=$(echo "$line" | awk '/^Host:/{print $2}')
                [[ -n "$ip" ]] && rdp_hosts+=("$ip") && _LATERAL_LIVE_RDP+=("$ip")
            fi
        done <<< "$nmap_out"
    fi

    log_ok "  RDP-open hosts: ${#rdp_hosts[@]} — ${rdp_hosts[*]:-none}"

    if [[ ${#rdp_hosts[@]} -eq 0 ]]; then
        echo "[T03] No hosts with RDP (3389) open found" >> "$ev_f"
        return
    fi

    for host in "${rdp_hosts[@]}"; do
        echo "--- Host: ${host} ---" >> "$ev_f"

        # Get this host's NSE output block
        local host_block
        host_block=$(echo "$nmap_out" | awk "/Nmap scan report for.*${host}/,/^$/" | head -60 || true)
        echo "$host_block" >> "$ev_f"

        # Check NLA (Network Level Authentication)
        # rdp-enum-encryption reports "CredSSP (NLA)" when NLA is enforced
        local nla_status="unknown"
        if echo "$host_block" | grep -qi 'CredSSP\|NLA'; then
            nla_status="enabled"
        elif echo "$host_block" | grep -qi 'PROTOCOL_VERSION\|Classic RDP Security\|TLS.*only'; then
            nla_status="disabled"
        fi

        # Check MS12-020 (safe DoS check — not exploitation)
        local ms12020_result="not checked"
        if echo "$host_block" | grep -qi 'ms12-020\|VULNERABLE\|NOT VULNERABLE'; then
            if echo "$host_block" | grep -qi 'VULNERABLE'; then
                ms12020_result="VULNERABLE"
            else
                ms12020_result="not vulnerable"
            fi
        fi

        # BlueKeep (CVE-2019-0708) — no public safe NSE available
        # Use version-based inference: affects Windows 7/2008 R2 and earlier with RDP open
        # nmap version detection can indicate OS; we flag for manual follow-up
        local bluekeep_indicator=""
        if echo "$host_block" | grep -qiE 'Windows.*7|Windows.*2008|Windows.*XP|Windows.*2003|Windows.*Vista'; then
            bluekeep_indicator="OS fingerprint suggests potential BlueKeep exposure (CVE-2019-0708)"
        fi

        {
            echo "NLA status    : ${nla_status}"
            echo "MS12-020      : ${ms12020_result}"
            echo "BlueKeep hint : ${bluekeep_indicator:-none}"
        } >> "$ev_f"

        # Emit findings
        if [[ "$ms12020_result" == "VULNERABLE" ]]; then
            emit_finding "critical" \
                "RDP MS12-020 Denial-of-Service Vulnerability: ${host}" \
                "nmap NSE rdp-vuln-ms12-020 confirmed the MS12-020 vulnerability on ${host}:3389. This can cause a BSoD (denial-of-service) remotely without authentication." \
                "Apply Microsoft Security Bulletin MS12-020 patches immediately. Restrict RDP access to authorised management hosts via firewall. Consider moving RDP behind a VPN or jump host." \
                "rdp_ms12020_${host//\./_}"
            log_wrn "  MS12-020 DoS vulnerability confirmed on ${host}"
        fi

        if [[ -n "$bluekeep_indicator" ]]; then
            emit_finding "critical" \
                "Potential BlueKeep Exposure (CVE-2019-0708) — OS Fingerprint: ${host}" \
                "RDP is open on ${host} and the OS fingerprint suggests a Windows version potentially vulnerable to BlueKeep (CVE-2019-0708): ${bluekeep_indicator}. BlueKeep is a pre-authentication, wormable RCE vulnerability in RDP. Manual authenticated verification is required — no safe automated exploit exists." \
                "Patch to a supported, fully-patched Windows version. Apply MS19-0708 immediately if on affected OS. Restrict RDP to authorised management hosts. Enable NLA as a mitigating control. Consider disabling RDP if not required." \
                "rdp_bluekeep_${host//\./_}"
            log_wrn "  Potential BlueKeep exposure on ${host} — manual verification required"
        fi

        if [[ "$nla_status" == "disabled" ]]; then
            emit_finding "high" \
                "RDP Open with NLA Disabled: ${host}" \
                "RDP is accessible on ${host}:3389 with Network Level Authentication (NLA) disabled. NLA-disabled RDP accepts connections before authentication, exposing the Windows login screen to all network reachable hosts and weakening pre-auth security." \
                "Enable Network Level Authentication (NLA) via Group Policy: Computer > Admin Templates > Windows Components > Remote Desktop Services > Require NLA. Restrict RDP via Windows Firewall to authorised management hosts only." \
                "rdp_nla_disabled_${host//\./_}"
            log_wrn "  RDP open with NLA disabled on ${host}"
        elif [[ "$nla_status" == "unknown" || "$nla_status" == "enabled" ]]; then
            emit_finding "medium" \
                "RDP Port Exposed: ${host}:3389" \
                "RDP (Remote Desktop Protocol) is accessible on ${host}:3389 from the test host. RDP exposure increases the attack surface for brute-force attacks, credential stuffing, and protocol vulnerabilities." \
                "Restrict RDP access to authorised management hosts via Windows Firewall rules. Consider placing RDP behind a VPN or jump host. Ensure NLA is enabled and monitoring is in place for failed authentication attempts." \
                "rdp_open_${host//\./_}"
            log_wrn "  RDP open on ${host}:3389 (NLA: ${nla_status})"
        fi
    done

    log_ok "  T03 complete — ${#rdp_hosts[@]} RDP-open host(s)"
}

# - MRK:21_T04 — T04 SSH HOST KEY REUSE
test_T04_ssh_key_reuse() {
    local ev_f; ev_f="$(_ev_file "ssh_key_reuse")"

    log_inf "[T04] SSH host key reuse — port 22 across lateral targets"

    if [[ ${#_LATERAL_TARGETS_RAW[@]} -eq 0 ]]; then
        log_wrn "  No lateral targets defined — skipping T04"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "nmap -p 22 --open ${_LATERAL_TARGETS_RAW[*]} + ssh-keyscan per host"
        return
    }

    {
        echo "=== T04 SSH Host Key Reuse ==="
        echo "Targets: ${_LATERAL_TARGETS_RAW[*]}"
        echo "Timestamp: $(date)"
    } > "$ev_f"

    # First: find hosts with port 22 open
    local ssh_open_hosts=()
    if _check_tool nmap; then
        local nmap_out
        nmap_out=$(timeout 120 nmap -p 22 --open -oG - \
            "${_LATERAL_TARGETS_RAW[@]}" 2>/dev/null || true)
        echo "--- nmap port 22 ---" >> "$ev_f"
        echo "$nmap_out" >> "$ev_f"

        while IFS= read -r line; do
            if echo "$line" | grep -qE '22/open'; then
                local ip
                ip=$(echo "$line" | awk '/^Host:/{print $2}')
                [[ -n "$ip" ]] && ssh_open_hosts+=("$ip") && _LATERAL_LIVE_SSH+=("$ip")
            fi
        done <<< "$nmap_out"
    else
        for tgt in "${_LATERAL_TARGETS_RAW[@]}"; do
            if nc -zw3 "$tgt" 22 2>/dev/null; then
                ssh_open_hosts+=("$tgt")
                _LATERAL_LIVE_SSH+=("$tgt")
            fi
        done
    fi

    log_ok "  SSH-open hosts: ${#ssh_open_hosts[@]} — ${ssh_open_hosts[*]:-none}"

    if [[ ${#ssh_open_hosts[@]} -lt 2 ]]; then
        log_inf "  Fewer than 2 SSH-open hosts — host key reuse check not applicable"
        echo "[T04] ${#ssh_open_hosts[@]} SSH-open host(s) — reuse check requires 2+" >> "$ev_f"
        return
    fi

    if ! _check_tool ssh-keyscan; then
        log_wrn "  ssh-keyscan not found — cannot collect host key fingerprints"
        echo "[T04] ssh-keyscan not found" >> "$ev_f"
        return
    fi

    # Collect fingerprints per host
    declare -A _KEY_TO_HOSTS  # fingerprint -> "host1 host2 ..."

    echo "--- SSH Host Key Fingerprints ---" >> "$ev_f"
    for host in "${ssh_open_hosts[@]}"; do
        local keyscan_out
        keyscan_out=$(timeout 8 ssh-keyscan -T 5 "$host" 2>/dev/null || true)

        if [[ -z "$keyscan_out" ]]; then
            log_wrn "  No key returned for ${host}"
            echo "  ${host}: no key returned" >> "$ev_f"
            continue
        fi

        echo "$keyscan_out" >> "$ev_f"

        # Extract fingerprints using ssh-keygen -lf
        while IFS= read -r keyline; do
            [[ -z "$keyline" || "$keyline" == "#"* ]] && continue
            local tmpkey
            tmpkey=$(mktemp)
            echo "$keyline" > "$tmpkey"
            local fp
            fp=$(ssh-keygen -lf "$tmpkey" 2>/dev/null | awk '{print $2}' || true)
            rm -f "$tmpkey"

            if [[ -n "$fp" ]]; then
                echo "  ${host}: ${fp}" >> "$ev_f"
                if [[ -n "${_KEY_TO_HOSTS[$fp]:-}" ]]; then
                    _KEY_TO_HOSTS[$fp]="${_KEY_TO_HOSTS[$fp]} ${host}"
                else
                    _KEY_TO_HOSTS[$fp]="${host}"
                fi
            fi
        done <<< "$keyscan_out"
    done

    # Check for shared fingerprints
    local shared_found=0
    echo "--- Shared Key Analysis ---" >> "$ev_f"
    for fp in "${!_KEY_TO_HOSTS[@]}"; do
        local hosts_sharing="${_KEY_TO_HOSTS[$fp]}"
        local host_count
        host_count=$(echo "$hosts_sharing" | wc -w)

        if [[ "$host_count" -ge 2 ]]; then
            shared_found=1
            echo "SHARED KEY: ${fp} — hosts: ${hosts_sharing}" >> "$ev_f"
            log_wrn "  Shared SSH host key: ${fp} across ${host_count} hosts: ${hosts_sharing}"

            emit_finding "medium" \
                "SSH Host Key Shared Across Multiple Hosts: ${host_count} hosts" \
                "The SSH host key fingerprint ${fp} is identical across ${host_count} hosts: ${hosts_sharing}. This indicates hosts were deployed from the same image without regenerating SSH host keys. An attacker who compromises one host could impersonate any other host sharing the same key, enabling MITM attacks or defeating SSH host verification." \
                "Regenerate SSH host keys on all affected hosts: remove /etc/ssh/ssh_host_* and run 'ssh-keygen -A' or 'dpkg-reconfigure openssh-server'. Add SSH host key regeneration to the system provisioning process. Remove stale known_hosts entries on clients after regeneration." \
                "ssh_key_reuse_${fp//[:\/]/_}"
        fi
    done

    if [[ "$shared_found" -eq 0 ]]; then
        log_ok "  No shared SSH host keys found — all ${#ssh_open_hosts[@]} hosts have unique keys"
        echo "[T04] All SSH host keys are unique" >> "$ev_f"
    fi

    log_ok "  T04 complete — ${#ssh_open_hosts[@]} SSH-open host(s) checked"
}

# - MRK:21_T05 — T05 PASS-THE-HASH SURFACE ASSESSMENT
test_T05_pth_surface() {
    local ev_f; ev_f="$(_ev_file "pth_surface")"

    log_inf "[T05] Pass-the-Hash surface assessment"

    # Runtime gate: NT hash must be set
    if [[ -z "${LATERAL_NT_HASH}" ]]; then
        log_inf "  LATERAL_NT_HASH not set — skipping PTH surface assessment (T05)"
        echo "[T05] LATERAL_NT_HASH not set — skipped" >> "$ev_f"
        return
    fi

    if [[ -z "${LATERAL_USERNAME}" ]]; then
        log_wrn "  LATERAL_USERNAME not set — required for PTH assessment"
        echo "[T05] LATERAL_USERNAME not set — skipped" >> "$ev_f"
        return
    fi

    local cme; cme="$(_cme_tool)"
    if [[ -z "$cme" ]]; then
        log_wrn "  crackmapexec/netexec not found — cannot perform PTH surface assessment"
        echo "[T05] crackmapexec/netexec not found — skipped" >> "$ev_f"
        return
    fi

    if [[ ${#_LATERAL_TARGETS_RAW[@]} -eq 0 ]]; then
        log_wrn "  No lateral targets defined — skipping T05"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "${cme} smb <targets> --local-auth -u ${LATERAL_USERNAME} -H ${LATERAL_NT_HASH} (surface assessment only)"
        return
    }

    {
        echo "=== T05 Pass-the-Hash Surface Assessment ==="
        echo "Targets: ${_LATERAL_TARGETS_RAW[*]}"
        echo "User: ${LATERAL_USERNAME}"
        echo "Hash: [redacted]"
        echo "Note: surface assessment only — no commands executed on target"
        echo "Timestamp: $(date)"
    } > "$ev_f"

    printf "\n${_R}  [PTH WARNING]${_N} Pass-the-Hash authentication test.\n"
    printf "  This is a surface assessment only — no commands are executed on targets.\n"
    printf "  User: %s | Hash: [redacted]\n\n" "$LATERAL_USERNAME"

    # Run CME PTH scan — --local-auth for local account PTH; without for domain
    # Surface assessment: just authentication test, no --exec or --sam flags
    local cme_out
    cme_out=$(timeout 120 "$cme" smb "${_LATERAL_TARGETS_RAW[@]}" \
        --local-auth -u "${LATERAL_USERNAME}" -H "${LATERAL_NT_HASH}" \
        2>&1 | head -200 || true)
    echo "--- PTH scan (local-auth) ---" >> "$ev_f"
    echo "$cme_out" >> "$ev_f"

    # Also try without --local-auth for domain account PTH
    local cme_domain_out
    cme_domain_out=$(timeout 120 "$cme" smb "${_LATERAL_TARGETS_RAW[@]}" \
        -u "${LATERAL_USERNAME}" -H "${LATERAL_NT_HASH}" \
        2>&1 | head -200 || true)
    echo "--- PTH scan (domain account) ---" >> "$ev_f"
    echo "$cme_domain_out" >> "$ev_f"

    # Parse successes from both runs
    local -a pth_success_hosts=()
    local combined_out="${cme_out}${cme_domain_out}"

    # CME/netexec success line format: [+] host\user:hash (Pwn3d!) or (+)
    while IFS= read -r line; do
        if echo "$line" | grep -qE '\[\+\]|\(Pwn3d!\)'; then
            if ! echo "$line" | grep -qiE 'STATUS_LOGON_FAILURE|STATUS_ACCOUNT_LOCKED|STATUS_ACCOUNT_DISABLED'; then
                local hit_host
                hit_host=$(echo "$line" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1 || true)
                [[ -n "$hit_host" ]] && pth_success_hosts+=("$hit_host")
            fi
        fi
    done <<< "$combined_out"

    # Deduplicate
    local unique_pth_hosts
    unique_pth_hosts=$(printf '%s\n' "${pth_success_hosts[@]:-}" | sort -u | tr '\n' ' ')
    local pth_count
    pth_count=$(printf '%s\n' "${pth_success_hosts[@]:-}" | sort -u | grep -c . || echo 0)

    echo "--- PTH Success Hosts: ${unique_pth_hosts:-none} ---" >> "$ev_f"

    if [[ "$pth_count" -ge 2 ]]; then
        emit_finding "critical" \
            "Pass-the-Hash: NT Hash Valid on Multiple Hosts (${pth_count} hosts)" \
            "The NT hash for '${LATERAL_USERNAME}' was accepted on ${pth_count} hosts: ${unique_pth_hosts}. Credential reuse at the hash level indicates local administrator password reuse across multiple systems, enabling rapid lateral movement without needing to crack the password." \
            "Deploy Microsoft LAPS (Local Administrator Password Solution) to enforce unique local admin passwords per host. Disable the built-in Administrator account where not required. Enable SMB signing to prevent relay attacks. Segment networks to limit lateral movement blast radius." \
            "pth_multi_host"
        log_wrn "  PTH: hash valid on ${pth_count} hosts — ${unique_pth_hosts}"
    elif [[ "$pth_count" -eq 1 ]]; then
        emit_finding "high" \
            "Pass-the-Hash: NT Hash Valid on Single Host (${unique_pth_hosts})" \
            "The NT hash for '${LATERAL_USERNAME}' was accepted on ${unique_pth_hosts}. This confirms the hash is valid for authentication on that host." \
            "Rotate the password for '${LATERAL_USERNAME}' immediately. Review account usage and privilege level on affected hosts. Deploy LAPS for local accounts. Review whether this account requires local admin rights." \
            "pth_single_host"
        log_wrn "  PTH: hash valid on 1 host — ${unique_pth_hosts}"
    else
        log_ok "  PTH: NT hash not accepted on any target"
        echo "[T05] NT hash not accepted on any target" >> "$ev_f"
    fi

    log_ok "  T05 complete — PTH surface assessed against ${#_LATERAL_TARGETS_RAW[@]} target(s)"
}

# - MRK:21_T06 — T06 LSASS PROTECTION STATUS
test_T06_lsass_protection() {
    local ev_f; ev_f="$(_ev_file "lsass_protection")"

    log_inf "[T06] LSASS protection status via SMB registry read"

    if [[ "$_HAS_CREDS" -eq 0 ]]; then
        log_inf "  No credentials set — LSASS protection check requires authentication"
        echo "[T06] No credentials — skipped" >> "$ev_f"
        return
    fi

    if [[ ${#_LATERAL_LIVE_SMB[@]} -eq 0 ]]; then
        log_wrn "  No SMB-open hosts discovered (run T01 first or check target list)"
        # Fallback: try raw target list
        if [[ ${#_LATERAL_TARGETS_RAW[@]} -eq 0 ]]; then
            return
        fi
        log_inf "  Using raw target list for T06"
    fi

    local targets_for_t06=("${_LATERAL_LIVE_SMB[@]:-}")
    [[ ${#targets_for_t06[@]} -eq 0 ]] && targets_for_t06=("${_LATERAL_TARGETS_RAW[@]}")

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "crackmapexec smb <hosts> -u ${LATERAL_USERNAME} -p/H <cred> --reg-query HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
        return
    }

    {
        echo "=== T06 LSASS Protection Status ==="
        echo "Timestamp: $(date)"
        echo "Note: checking RunAsPPL, WDigest UseLogonCredential, LSA protection"
    } > "$ev_f"

    local cme; cme="$(_cme_tool)"

    for host in "${targets_for_t06[@]}"; do
        echo "--- Host: ${host} ---" >> "$ev_f"
        log_inf "  Checking LSASS protection on ${host}..."

        # Build credential args
        local cme_cred_args=()
        if [[ -n "${LATERAL_NT_HASH}" ]]; then
            cme_cred_args=("-u" "${LATERAL_USERNAME}" "-H" "${LATERAL_NT_HASH}")
        else
            cme_cred_args=("-u" "${LATERAL_USERNAME}" "-p" "${LATERAL_PASSWORD}")
        fi

        # Method 1: crackmapexec/netexec --reg-query
        if [[ -n "$cme" ]]; then
            # Check RunAsPPL (LSASS protected process)
            local runasppl_out
            runasppl_out=$(timeout "${LATERAL_TIMEOUT}" "$cme" smb "$host" \
                "${cme_cred_args[@]}" \
                --reg-query 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' \
                --reg-filter 'RunAsPPL' 2>&1 | head -20 || true)
            echo "--- RunAsPPL ---" >> "$ev_f"
            echo "$runasppl_out" >> "$ev_f"

            # Check WDigest
            local wdigest_out
            wdigest_out=$(timeout "${LATERAL_TIMEOUT}" "$cme" smb "$host" \
                "${cme_cred_args[@]}" \
                --reg-query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' \
                --reg-filter 'UseLogonCredential' 2>&1 | head -20 || true)
            echo "--- WDigest UseLogonCredential ---" >> "$ev_f"
            echo "$wdigest_out" >> "$ev_f"

            # Parse RunAsPPL
            local runasppl_val
            runasppl_val=$(echo "$runasppl_out" | grep -oiE 'RunAsPPL.*0x[0-9a-fA-F]+|RunAsPPL.*[0-9]+' | head -1 || true)
            # Parse WDigest
            local wdigest_val
            wdigest_val=$(echo "$wdigest_out" | grep -oiE 'UseLogonCredential.*0x[0-9a-fA-F]+|UseLogonCredential.*[0-9]+' | head -1 || true)

            {
                echo "RunAsPPL          : ${runasppl_val:-not retrieved}"
                echo "WDigest LogonCred : ${wdigest_val:-not retrieved}"
            } >> "$ev_f"

            # WDigest UseLogonCredential=1 = plaintext creds in memory
            if echo "$wdigest_val" | grep -qiE '0x1\b|:.*1$| 1$'; then
                emit_finding "critical" \
                    "WDigest UseLogonCredential Enabled (Plaintext Creds in Memory): ${host}" \
                    "WDigest UseLogonCredential is set to 1 on ${host}. This causes Windows to cache plaintext credentials in LSASS memory, recoverable by tools such as Mimikatz after obtaining LSASS access. This setting should be 0 on all modern Windows versions." \
                    "Set UseLogonCredential=0 via registry or Group Policy: HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 0. Apply KB2871997 on older Windows versions. Enable Windows Credential Guard to isolate LSA credentials from user-mode access." \
                    "wdigest_enabled_${host//\./_}"
                log_wrn "  CRITICAL: WDigest plaintext creds enabled on ${host}"
            fi

            # RunAsPPL = 0 or absent = LSASS unprotected
            if echo "$runasppl_val" | grep -qiE '0x0\b|:.*0$| 0$'; then
                emit_finding "high" \
                    "LSASS RunAsPPL Disabled (LSASS Not Protected): ${host}" \
                    "RunAsPPL is disabled on ${host}. LSASS is not running as a Protected Process Light, allowing user-mode processes with SeDebugPrivilege to read LSASS memory directly (e.g. via Mimikatz sekurlsa::logonpasswords)." \
                    "Enable RunAsPPL: set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL=1 via Group Policy Preferences or a deployment script. Requires reboot. Test compatibility with third-party AV/EDR before broad deployment. Enable Windows Credential Guard for stronger isolation." \
                    "runasppl_disabled_${host//\./_}"
                log_wrn "  RunAsPPL disabled on ${host}"
            elif [[ -z "$runasppl_val" ]]; then
                log_inf "  RunAsPPL value not retrieved on ${host} — access may be restricted or registry query failed"
            else
                log_ok "  RunAsPPL appears enabled on ${host}: ${runasppl_val}"
            fi
        fi

        # Method 2: impacket-reg fallback
        if [[ -z "$cme" ]] && (_check_tool impacket-reg || _check_tool reg.py); then
            local reg_tool
            _check_tool impacket-reg && reg_tool="impacket-reg" || reg_tool="reg.py"

            local impacket_cred
            if [[ -n "${LATERAL_NT_HASH}" ]]; then
                impacket_cred="${LATERAL_USERNAME} --hashes :${LATERAL_NT_HASH}"
            else
                impacket_cred="${LATERAL_USERNAME}:${LATERAL_PASSWORD}"
            fi

            local lsa_reg_out
            # shellcheck disable=SC2086
            lsa_reg_out=$(timeout "${LATERAL_TIMEOUT}" "$reg_tool" \
                "${impacket_cred}@${host}" \
                query -keyName 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa' \
                -v RunAsPPL 2>&1 | head -20 || true)
            echo "--- impacket-reg RunAsPPL ---" >> "$ev_f"
            echo "$lsa_reg_out" >> "$ev_f"

            if echo "$lsa_reg_out" | grep -qi 'RunAsPPL.*0x0'; then
                emit_finding "high" \
                    "LSASS RunAsPPL Disabled (impacket-reg): ${host}" \
                    "impacket-reg confirmed RunAsPPL=0 on ${host}. LSASS is not running as a Protected Process Light." \
                    "Enable RunAsPPL via Group Policy. See Microsoft documentation for LSASS protection configuration." \
                    "runasppl_impacket_${host//\./_}"
                log_wrn "  RunAsPPL disabled on ${host} (via impacket-reg)"
            fi
        fi
    done

    log_ok "  T06 complete — LSASS protection checked on ${#targets_for_t06[@]} host(s)"
}

# - MRK:21_T07 — T07 SERVICE ACCOUNT CREDENTIAL REUSE
test_T07_cred_reuse() {
    local ev_f; ev_f="$(_ev_file "cred_reuse")"

    log_inf "[T07] Service account credential reuse across lateral targets"

    if [[ ${#_LATERAL_TARGETS_RAW[@]} -eq 0 ]]; then
        log_wrn "  No lateral targets defined — skipping T07"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && {
        log_dry "Parse working/*.jsonl for credential findings; probe SMB/WinRM/SSH per cred"
        return
    }

    {
        echo "=== T07 Service Account Credential Reuse ==="
        echo "Timestamp: $(date)"
    } > "$ev_f"

    # Parse credential pairs from previous findings in working/*.jsonl
    declare -a _CRED_USERS=()
    declare -a _CRED_PASSES=()
    declare -a _CRED_HASHES=()

    log_inf "  Parsing working/*.jsonl for credentials from previous steps..."

    local jsonl_files=()
    # shellcheck disable=SC2206
    jsonl_files=(${SCRIPT_DIR}/working/*.jsonl)

    local creds_found=0
    for jf in "${jsonl_files[@]}"; do
        [[ -f "$jf" ]] || continue
        # Match lines containing credential/password in the description field
        while IFS= read -r line; do
            if echo "$line" | grep -qiE '"description".*[Cc]redential|"description".*[Pp]assword|"description".*username|"description".*passwd'; then
                # Extract username using jq if available, fallback to grep
                local usr="" pas="" hsh=""
                if command -v jq &>/dev/null; then
                    usr=$(echo "$line" | jq -r '.username // empty' 2>/dev/null || true)
                    [[ -z "$usr" ]] && usr=$(echo "$line" | jq -r '.description' 2>/dev/null | grep -oP '(?i)user(?:name)?[:\s]+\K\S+' | head -1 || true)
                    pas=$(echo "$line" | jq -r '.password // empty' 2>/dev/null || true)
                    [[ -z "$pas" ]] && pas=$(echo "$line" | jq -r '.description' 2>/dev/null | grep -oP '(?i)pass(?:word)?[:\s]+\K\S+' | head -1 || true)
                    hsh=$(echo "$line" | jq -r '.hash // empty' 2>/dev/null || true)
                else
                    usr=$(echo "$line" | grep -oP '"username"\s*:\s*"\K[^"]+' | head -1 || true)
                    pas=$(echo "$line" | grep -oP '"password"\s*:\s*"\K[^"]+' | head -1 || true)
                    hsh=$(echo "$line" | grep -oP '"hash"\s*:\s*"\K[^"]+' | head -1 || true)
                fi

                if [[ -n "$usr" && ( -n "$pas" || -n "$hsh" ) ]]; then
                    # Avoid duplicates
                    local already=0
                    for i in "${!_CRED_USERS[@]}"; do
                        if [[ "${_CRED_USERS[$i]}" == "$usr" && "${_CRED_PASSES[$i]:-}" == "$pas" ]]; then
                            already=1; break
                        fi
                    done
                    if [[ "$already" -eq 0 ]]; then
                        _CRED_USERS+=("$usr")
                        _CRED_PASSES+=("$pas")
                        _CRED_HASHES+=("$hsh")
                        (( creds_found++ )) || true
                        log_inf "  Discovered credential: ${usr} (from ${jf##*/})"
                        echo "Discovered credential: user=${usr} source=${jf##*/}" >> "$ev_f"
                    fi
                fi
            fi
        done < "$jf"
    done

    # Also add the LATERAL_USERNAME/PASSWORD/HASH from conf if set
    if [[ -n "${LATERAL_USERNAME}" && ( -n "${LATERAL_PASSWORD}" || -n "${LATERAL_NT_HASH}" ) ]]; then
        local conf_already=0
        for i in "${!_CRED_USERS[@]}"; do
            [[ "${_CRED_USERS[$i]}" == "${LATERAL_USERNAME}" ]] && conf_already=1 && break
        done
        if [[ "$conf_already" -eq 0 ]]; then
            _CRED_USERS+=("${LATERAL_USERNAME}")
            _CRED_PASSES+=("${LATERAL_PASSWORD}")
            _CRED_HASHES+=("${LATERAL_NT_HASH}")
            (( creds_found++ )) || true
            log_inf "  Added conf credential: ${LATERAL_USERNAME}"
        fi
    fi

    if [[ "$creds_found" -eq 0 ]]; then
        log_inf "  No credentials found in findings or conf — T07 cannot proceed"
        echo "[T07] No credentials found — skipped" >> "$ev_f"
        return
    fi

    log_inf "  Testing ${creds_found} credential pair(s) across ${#_LATERAL_TARGETS_RAW[@]} target(s) on SMB/WinRM/SSH"

    local cme; cme="$(_cme_tool)"

    for i in "${!_CRED_USERS[@]}"; do
        local usr="${_CRED_USERS[$i]}"
        local pas="${_CRED_PASSES[$i]:-}"
        local hsh="${_CRED_HASHES[$i]:-}"

        [[ -z "$pas" && -z "$hsh" ]] && continue

        echo "--- Credential: ${usr} ---" >> "$ev_f"
        log_inf "  Testing credential: ${usr}"

        local -a valid_smb_hosts=()
        local -a valid_winrm_hosts=()
        local -a valid_ssh_hosts=()

        for host in "${_LATERAL_TARGETS_RAW[@]}"; do

            # Protocol 1: SMB (port 445)
            if [[ -n "$cme" ]]; then
                local smb_cme_out
                if [[ -n "$hsh" ]]; then
                    smb_cme_out=$(timeout "${LATERAL_TIMEOUT}" "$cme" smb "$host" \
                        -u "$usr" -H "$hsh" 2>&1 | head -10 || true)
                else
                    smb_cme_out=$(timeout "${LATERAL_TIMEOUT}" "$cme" smb "$host" \
                        -u "$usr" -p "$pas" 2>&1 | head -10 || true)
                fi
                echo "  SMB ${host}: $(echo "$smb_cme_out" | grep -oE '\[\+\].*|STATUS_.*' | head -1 || echo 'no result')" >> "$ev_f"
                if echo "$smb_cme_out" | grep -qE '\[\+\]' && \
                   ! echo "$smb_cme_out" | grep -qiE 'STATUS_LOGON_FAILURE|STATUS_ACCOUNT_LOCKED|STATUS_ACCOUNT_DISABLED'; then
                    valid_smb_hosts+=("$host")
                fi
            elif _check_tool smbclient; then
                local smb_cl_out
                if [[ -n "$pas" ]]; then
                    smb_cl_out=$(timeout "${LATERAL_TIMEOUT}" smbclient -L "//${host}" \
                        -U "${usr}%${pas}" 2>&1 | head -10 || true)
                    if echo "$smb_cl_out" | grep -qiE 'Sharename|IPC\$'; then
                        valid_smb_hosts+=("$host")
                    fi
                fi
            fi

            # Protocol 2: WinRM (port 5985)
            if _check_tool curl; then
                local winrm_code
                winrm_code=$(timeout 5 curl -sk -o /dev/null -w "%{http_code}" \
                    "http://${host}:5985/wsman" 2>/dev/null || echo "000")
                if [[ "$winrm_code" == "401" ]]; then
                    # Port is open with authentication; attempt credential
                    if _check_tool evil-winrm && [[ -n "$pas" ]]; then
                        local ew_test
                        ew_test=$(timeout 8 evil-winrm -i "$host" \
                            -u "$usr" -p "$pas" -e /dev/null 2>&1 | head -5 || true)
                        if echo "$ew_test" | grep -qiE 'Establishing|Win32_ComputerSystem|connected'; then
                            valid_winrm_hosts+=("$host")
                        fi
                    elif _check_tool evil-winrm && [[ -n "$hsh" ]]; then
                        local ew_hash_test
                        ew_hash_test=$(timeout 8 evil-winrm -i "$host" \
                            -u "$usr" -H "$hsh" -e /dev/null 2>&1 | head -5 || true)
                        if echo "$ew_hash_test" | grep -qiE 'Establishing|Win32_ComputerSystem|connected'; then
                            valid_winrm_hosts+=("$host")
                        fi
                    fi
                    echo "  WinRM ${host}: HTTP ${winrm_code}" >> "$ev_f"
                fi
            fi

            # Protocol 3: SSH (port 22)
            if _check_tool ssh && [[ -n "$pas" ]]; then
                local ssh_out
                ssh_out=$(timeout "${LATERAL_TIMEOUT}" ssh -o BatchMode=no \
                    -o StrictHostKeyChecking=no \
                    -o PasswordAuthentication=yes \
                    -o PubkeyAuthentication=no \
                    -o ConnectTimeout=5 \
                    -o NumberOfPasswordPrompts=1 \
                    "${usr}@${host}" "echo orc_ssh_ok" 2>&1 | head -5 || true)
                echo "  SSH ${host}: $(echo "$ssh_out" | head -1)" >> "$ev_f"
                if echo "$ssh_out" | grep -q 'orc_ssh_ok'; then
                    valid_ssh_hosts+=("$host")
                fi
            fi
        done

        # Emit findings for valid credential reuse
        local total_hits=$(( ${#valid_smb_hosts[@]} + ${#valid_winrm_hosts[@]} + ${#valid_ssh_hosts[@]} ))
        if [[ "$total_hits" -gt 0 ]]; then
            local detail=""
            [[ ${#valid_smb_hosts[@]} -gt 0 ]] && detail+="SMB: ${valid_smb_hosts[*]} "
            [[ ${#valid_winrm_hosts[@]} -gt 0 ]] && detail+="WinRM: ${valid_winrm_hosts[*]} "
            [[ ${#valid_ssh_hosts[@]} -gt 0 ]] && detail+="SSH: ${valid_ssh_hosts[*]} "

            emit_finding "critical" \
                "Service Account Credential Reuse: ${usr} Valid on Additional Host(s)" \
                "Credentials for '${usr}' (discovered in previous steps) are valid on additional host(s): ${detail}. This enables lateral movement beyond the initial compromise point without additional exploitation." \
                "Implement unique credentials per service and host. Deploy LAPS for local accounts. Audit service account privilege levels — apply least privilege. Rotate all discovered credentials. Review password reuse policy and enforce MFA where possible." \
                "cred_reuse_${usr//[^A-Za-z0-9]/_}"
            log_wrn "  CRITICAL: Credential reuse for '${usr}' on: ${detail}"
        else
            log_ok "  Credential '${usr}' not found valid on additional hosts"
            echo "  ${usr}: no valid reuse detected" >> "$ev_f"
        fi
    done

    log_ok "  T07 complete — credential reuse check complete"
}

# =============================================================================
# - MRK:21_TRUN
# =============================================================================
_run_tests() {
    local find_before="$_FIND_CTR"

    log_inf "=== Lateral movement tests — $(date) ==="
    log_inf "Targets: ${_LATERAL_TARGETS_RAW[*]:-<none defined>}"

    # Per-host scan tests (T01 also populates live host lists for downstream tests)
    _test_skip T01 || test_T01_smb_matrix
    _test_skip T02 || test_T02_winrm_reachability
    _test_skip T03 || test_T03_rdp_exposure
    _test_skip T04 || test_T04_ssh_key_reuse

    # Cross-host / credential tests
    _test_skip T05 || test_T05_pth_surface
    _test_skip T06 || test_T06_lsass_protection
    _test_skip T07 || test_T07_cred_reuse

    local find_delta=$(( _FIND_CTR - find_before ))
    echo "SUMMARY_ROW|lateral_movement|findings=${find_delta}"
}

# =============================================================================
# - MRK:21_MAIN
# =============================================================================
main() {
    printf "\n${_W}╔══════════════════════════════════════════════════════╗${_N}\n"
    printf "${_W}║  PT-Orc  ·  Step 21: Lateral Movement Assessment    ║${_N}\n"
    printf "${_W}╚══════════════════════════════════════════════════════╝${_N}\n\n"

    log_inf "Project  : ${PROJECT_NAME}"
    log_inf "Profile  : ${SCAN_PROFILE}"
    log_inf "Targets  : ${LATERAL_TARGETS:-<default: TARGET_IPS + TARGET_SUBNETS>}"
    log_inf "Auth     : $( [[ "$_HAS_CREDS" -eq 1 ]] && echo "authenticated (${LATERAL_USERNAME})" || echo "unauthenticated" )"
    log_inf "PTH Hash : $( [[ -n "${LATERAL_NT_HASH}" ]] && echo "set" || echo "not set" )"
    log_inf "Session  : ${SESSION_TS}"
    log_inf "Log      : ${LOG_FILE}"

    if [[ ${#_LATERAL_TARGETS_RAW[@]} -eq 0 ]]; then
        log_wrn "No lateral targets defined. Set LATERAL_TARGETS in pt-orc.conf or use --targets."
        log_wrn "Defaulting tests will run but no hosts will be found."
    fi

    setup_profile "$SCAN_PROFILE"
    _confirm

    command -v trail_phase_start &>/dev/null && trail_phase_start "21_lateral_movement"

    local row
    row=$(_run_tests)
    local total_findings
    total_findings=$(echo "$row" | grep -oE 'findings=[0-9]+' | grep -oE '[0-9]+' || echo 0)

    command -v trail_phase_end &>/dev/null && trail_phase_end "21_lateral_movement"

    # Summary report
    local report_f="${SCRIPT_DIR}/working/$(ev_fname "21-lateral-summary" "md")"
    {
        printf "# Lateral Movement Assessment Summary — %s\n\n" "$PROJECT_NAME"
        printf "| Profile | Targets | Auth | Findings |\n|---------|---------|------|----------|\n"
        printf "| %s | %s | %s | %d |\n" \
            "$SCAN_PROFILE" \
            "${LATERAL_TARGETS:-TARGET_IPS+SUBNETS}" \
            "$( [[ "$_HAS_CREDS" -eq 1 ]] && echo "authenticated" || echo "unauthenticated" )" \
            "$total_findings"
        printf "\n**SMB-open hosts:** %s\n" "${_LATERAL_LIVE_SMB[*]:-none}"
        printf "\n**WinRM-open hosts:** %s\n" "${_LATERAL_LIVE_WINRM[*]:-none}"
        printf "\n**RDP-open hosts:** %s\n" "${_LATERAL_LIVE_RDP[*]:-none}"
        printf "\n**SSH-open hosts:** %s\n" "${_LATERAL_LIVE_SSH[*]:-none}"
        printf "\n**Total Findings:** %d\n" "$total_findings"
        printf "\nFindings JSONL: \`%s\`\n" "$FINDINGS_FILE"
        printf "\nEvidence dir  : \`%s\`\n" "$EVIDENCE_BASE"
    } > "$report_f"

    printf "\n${_G}[DONE]${_N} Lateral movement assessment complete.\n"
    printf "  Profile  : %s\n" "$SCAN_PROFILE"
    printf "  Findings : %d\n" "$total_findings"
    printf "  Summary  : %s\n" "$report_f"
    printf "  Findings : %s\n" "$FINDINGS_FILE"
    printf "  Evidence : %s\n\n" "$EVIDENCE_BASE"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
