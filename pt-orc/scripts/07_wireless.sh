#!/usr/bin/env bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:07_NAV_TOC — Section index | nav,toc,index | L5-20
# - MRK:07_T01 — T01 WIRELESS INTERFACE SETUP | t01,wireless,interface,monitor | L21-21
# - MRK:07_T02 — T02 BEACON AND PROBE SCAN (PASSIVE) | t02,beacon,probe,passive,scan | L22-22
# - MRK:07_T03 — T03 WPA/WPA2 HANDSHAKE CAPTURE | t03,wpa,handshake,capture,deauth | L23-23
# - MRK:07_T04 — T04 PMKID ATTACK SURFACE | t04,pmkid,hcxdumptool,attack | L24-24
# - MRK:07_T05 — T05 ROGUE AP AND EVIL TWIN DETECTION | t05,rogue,ap,evil,twin | L25-25
# - MRK:07_T06 — T06 EAP/PEAP CERTIFICATE VALIDATION | t06,eap,peap,certificate,wps | L26-26
# - MRK:07_T07 — T07 WPS ENUMERATION | t07,wps,pixie,reaver,enumeration | L27-27
# NAV-LEN: 7 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-06-25

# =============================================================================
# 22_wireless.sh — Wireless Security Assessment
# TechGuard Labs | PT-Orc Suite v0.8
# =============================================================================
# NAV: MRK:07_TOC (this block) | MRK:07_ROOT | MRK:07_CONF | MRK:07_LOG
#      MRK:07_ARGS | MRK:07_CONFIRM
#      MRK:07_FIND | MRK:07_UTILS | MRK:07_PROF
#      MRK:07_T01 — T01 WIRELESS INTERFACE SETUP | t01,wireless,interface,monitor | L21-21
#      MRK:07_T02 — T02 BEACON AND PROBE SCAN (PASSIVE) | t02,beacon,probe,passive,scan | L22-22
#      MRK:07_T03 — T03 WPA/WPA2 HANDSHAKE CAPTURE | t03,wpa,handshake,capture,deauth | L23-23
#      MRK:07_T04 — T04 PMKID ATTACK SURFACE | t04,pmkid,hcxdumptool,attack | L24-24
#      MRK:07_T05 — T05 ROGUE AP AND EVIL TWIN DETECTION | t05,rogue,ap,evil,twin | L25-25
#      MRK:07_T06 — T06 EAP/PEAP CERTIFICATE VALIDATION | t06,eap,peap,certificate,wps | L26-26
#      MRK:07_T07 — T07 WPS ENUMERATION | t07,wps,pixie,reaver,enumeration | L27-27
#      MRK:07_TRUN | MRK:07_MAIN
# =============================================================================

# - MRK:07_ROOT
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# - MRK:07_CONF
CONF_FILE="${SCRIPT_DIR}/pt-orc.conf"
[[ -f "$CONF_FILE" ]] || { echo "[FATAL] pt-orc.conf not found at ${CONF_FILE}"; exit 1; }
# shellcheck source=pt-orc.conf
source "$CONF_FILE"

LIB_FILE="${SCRIPT_DIR}/orc-common-lib.sh"
[[ -f "$LIB_FILE" ]] && source "$LIB_FILE"

# Root check — required for airmon-ng, airodump-ng, raw socket operations
[[ "$EUID" -ne 0 ]] && { echo "[FATAL] 07_wireless.sh must be run as root (EUID=${EUID})"; exit 1; }

PROJ_SLUG="${PROJECT_NAME//[^A-Za-z0-9._-]/_}"
EVIDENCE_BASE="${SCRIPT_DIR}/evidence/${PROJ_SLUG}"
DRY_RUN=0
SCAN_PROFILE="${SCAN_PROFILE:-standard}"

# Wireless conf defaults (overrideable via pt-orc.conf or CLI)
WIRELESS_IFACE="${WIRELESS_IFACE:-}"
WIRELESS_MON_IFACE="${WIRELESS_MON_IFACE:-}"
WIRELESS_EXPECTED_SSIDS="${WIRELESS_EXPECTED_SSIDS:-}"
WIRELESS_SCAN_TIME="${WIRELESS_SCAN_TIME:-60}"
WIRELESS_DEAUTH_ENABLED="${WIRELESS_DEAUTH_ENABLED:-0}"
WIRELESS_PMKID_ENABLED="${WIRELESS_PMKID_ENABLED:-0}"
WIRELESS_CHANNEL="${WIRELESS_CHANNEL:-}"

# Internal state flag — set to 1 by T01 if no wireless interface is available
_NO_WIRELESS=0

# - MRK:07_LOG
_R='\033[0;31m'; _G='\033[0;32m'; _Y='\033[1;33m'; _B='\033[0;34m'; _C='\033[0;36m'; _W='\033[1;37m'; _N='\033[0m'
SESSION_TS="$(date +%Y%m%d_%H%M%S)"
EV_TS="$(date +'%Y-%m-%d-%H-%M-%S')"
LOG_FILE="${SCRIPT_DIR}/working/${PROJ_SLUG}_07_wireless_${SESSION_TS}.log"
mkdir -p "${SCRIPT_DIR}/working" "${EVIDENCE_BASE}"

_log()    { local ts; ts="$(date +%H:%M:%S)"; printf "[%s] %s\n" "$ts" "$*" | tee -a "$LOG_FILE"; }
log_ok()  { printf "${_G}[+]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_inf() { printf "${_B}[*]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_wrn() { printf "${_Y}[!]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_err() { printf "${_R}[-]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_dry() { printf "${_C}[DRY]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }

# - MRK:07_ARGS
_SKIP_CONFIRM=0
_ONLY_TESTS=()
_SKIP_TESTS=()

_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Wireless Security Assessment (step 22)
Tests passive beacon scan, WPA handshake capture, PMKID, rogue AP detection,
EAP/PEAP cert validation, and WPS enumeration.

Options:
  --iface <IFACE>            Wireless interface (overrides WIRELESS_IFACE from conf)
  --expected-ssids <LIST>    Space-separated expected SSIDs (overrides WIRELESS_EXPECTED_SSIDS)
  --scan-time <seconds>      Passive scan duration (overrides WIRELESS_SCAN_TIME; default: 60)
  --deauth                   Enable WPA handshake capture via deauth (sets WIRELESS_DEAUTH_ENABLED=1)
  --pmkid                    Enable PMKID capture (sets WIRELESS_PMKID_ENABLED=1)
  --channel <CH>             Restrict to a single channel (overrides WIRELESS_CHANNEL)
  -p, --profile <name>       Scan profile: quick|standard|deep  [default: standard]
  --only <T01,T05,...>       Run only specified tests
  --skip <T02,T06,...>       Skip specified tests
  -y, --yes                  Skip confirmation prompt
  --dry-run                  Print actions without executing
  -h, --help                 Show this help

Profiles:
  quick    — T01, T02, T05, T07
  standard — T01, T02, T05, T06, T07
  deep     — T01–T07 (T03 gated by WIRELESS_DEAUTH_ENABLED; T04 gated by WIRELESS_PMKID_ENABLED)

WARNING: T03 (deauth) sends disassociation frames. Enable only within authorised scope.
         T04 (PMKID) requires hcxdumptool. Both require --profile deep AND explicit opt-in.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iface)            WIRELESS_IFACE="$2"; shift 2 ;;
        --expected-ssids)   WIRELESS_EXPECTED_SSIDS="$2"; shift 2 ;;
        --scan-time)        WIRELESS_SCAN_TIME="$2"; shift 2 ;;
        --deauth)           WIRELESS_DEAUTH_ENABLED=1; shift ;;
        --pmkid)            WIRELESS_PMKID_ENABLED=1; shift ;;
        --channel)          WIRELESS_CHANNEL="$2"; shift 2 ;;
        -p|--profile)       SCAN_PROFILE="$2"; shift 2 ;;
        --only)             IFS=',' read -ra _ONLY_TESTS <<< "$2"; shift 2 ;;
        --skip)             IFS=',' read -ra _SKIP_TESTS <<< "$2"; shift 2 ;;
        -y|--yes)           _SKIP_CONFIRM=1; shift ;;
        --dry-run)          DRY_RUN=1; shift ;;
        -h|--help)          _usage; exit 0 ;;
        *)                  log_err "Unknown option: $1"; _usage; exit 1 ;;
    esac
done

# - MRK:07_CONFIRM
_confirm() {
    [[ "$_SKIP_CONFIRM" -eq 1 ]] && return 0
    printf "\n${_Y}[CONFIRM]${_N} Wireless security assessment. Profile: ${_W}%s${_N}\n" "$SCAN_PROFILE"
    printf "  Project       : %s\n" "$PROJECT_NAME"
    printf "  Interface     : %s\n" "${WIRELESS_IFACE:-<auto-detect>}"
    printf "  Scan time     : %s seconds\n" "$WIRELESS_SCAN_TIME"
    printf "  Deauth (T03)  : %s\n" "$( [[ "$WIRELESS_DEAUTH_ENABLED" -eq 1 ]] && echo "ENABLED" || echo "disabled" )"
    printf "  PMKID (T04)   : %s\n" "$( [[ "$WIRELESS_PMKID_ENABLED" -eq 1 ]] && echo "ENABLED" || echo "disabled" )"
    printf "\n  ${_R}WARNING:${_N} This script requires monitor mode and may disrupt nearby wireless clients.\n"
    printf "  Only run within authorised scope and agreed engagement window.\n"
    printf "\n  Continue? [y/N] "
    read -r _ans
    [[ "${_ans,,}" == "y" ]] || { log_err "Aborted by user."; exit 0; }
}

# - MRK:07_FIND
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "22-wireless-findings" "jsonl")"
_FIND_CTR=0
: > "$FINDINGS_FILE"

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="${5:-}"
    (( _FIND_CTR++ )) || true
    local fid
    fid="f-22-wlan-$(printf '%04d' "$_FIND_CTR")"
    local ev_id="${ev_tag:-${fid}-ev}"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"07_wireless","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
        "$fid" \
        "$(echo "$title" | sed 's/"/\\"/g')" \
        "$sev" \
        "$ev_id" \
        "$(echo "$desc" | sed 's/"/\\"/g')" \
        "$(echo "$rec"  | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_wrn "FINDING [${sev^^}] ${title}"
}

# - MRK:07_UTILS
_check_tool() {
    local tool="$1"
    command -v "$tool" &>/dev/null
}

_ev_file() {
    local tag="$1"
    echo "${EVIDENCE_BASE}/$(ev_fname "wlan-${tag}" "txt")"
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

# - MRK:07_PROF
setup_profile() {
    local prof="${1:-standard}"
    for n in T01 T02 T03 T04 T05 T06 T07; do
        _T_ENABLED[$n]=1
    done
    case "$prof" in
        quick)
            # Quick: interface setup, passive beacon scan, rogue AP, WPS
            for n in T03 T04 T06; do _T_ENABLED[$n]=0; done ;;
        standard)
            # Standard: everything except opt-in active attacks
            for n in T03 T04; do _T_ENABLED[$n]=0; done ;;
        deep)
            # All enabled — T03/T04 still gated by WIRELESS_DEAUTH_ENABLED / WIRELESS_PMKID_ENABLED
            : ;;
        *)
            log_wrn "Unknown profile '${prof}' — defaulting to standard"
            for n in T03 T04; do _T_ENABLED[$n]=0; done ;;
    esac
    _apply_cli_filters
}

# =============================================================================
# TESTS
# =============================================================================

# - MRK:07_T01 — T01 WIRELESS INTERFACE SETUP
test_T01_interface_setup() {
    local ev_f; ev_f="$(_ev_file "t01-iface-setup")"
    log_inf "[T01] Wireless interface setup"

    {
        echo "=== T01 Wireless Interface Setup ==="
        echo "Requested WIRELESS_IFACE: ${WIRELESS_IFACE:-<auto-detect>}"
    } > "$ev_f"

    # List all wireless interfaces
    local iw_out
    iw_out=$(iw dev 2>/dev/null || true)
    echo "--- iw dev output ---" >> "$ev_f"
    echo "$iw_out" >> "$ev_f"

    # Auto-detect if not configured
    if [[ -z "$WIRELESS_IFACE" ]]; then
        WIRELESS_IFACE=$(iw dev 2>/dev/null | awk '/Interface/{print $2}' | head -1 || true)
        if [[ -z "$WIRELESS_IFACE" ]]; then
            log_wrn "  [T01] No wireless interface found — skipping wireless tests"
            emit_finding "info" \
                "No Wireless Interface Available" \
                "No wireless interface was detected on this system. Wireless security tests (T02–T07) cannot be performed. If wireless testing is required, attach a compatible USB wireless adapter and re-run." \
                "Attach a wireless adapter supporting monitor mode (e.g. Alfa AWUS036ACH). Verify with 'iw dev' and set WIRELESS_IFACE in pt-orc.conf." \
                "wlan_no_iface"
            _NO_WIRELESS=1
            return
        fi
        log_inf "  [T01] Auto-detected wireless interface: ${WIRELESS_IFACE}"
    fi

    echo "Selected interface: ${WIRELESS_IFACE}" >> "$ev_f"

    # Enable monitor mode
    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_dry "airmon-ng check kill"
        log_dry "airmon-ng start ${WIRELESS_IFACE}"
        WIRELESS_MON_IFACE="${WIRELESS_IFACE}mon"
        log_dry "iw dev ${WIRELESS_MON_IFACE} info"
        log_ok "  [T01] DRY_RUN: monitor interface would be ${WIRELESS_MON_IFACE}"
        echo "DRY_RUN: monitor interface = ${WIRELESS_MON_IFACE}" >> "$ev_f"
        return
    fi

    log_inf "  [T01] Killing interfering processes (airmon-ng check kill)..."
    airmon-ng check kill >> "$ev_f" 2>&1 || true

    log_inf "  [T01] Starting monitor mode on ${WIRELESS_IFACE}..."
    local airmon_out
    airmon_out=$(airmon-ng start "$WIRELESS_IFACE" 2>&1 || true)
    echo "$airmon_out" >> "$ev_f"

    # Determine monitor interface name (typically <iface>mon, but airmon-ng may differ)
    if [[ -z "$WIRELESS_MON_IFACE" ]]; then
        # First try standard naming
        WIRELESS_MON_IFACE="${WIRELESS_IFACE}mon"
        # Verify it exists; if not, search iw dev for a monitor-mode interface
        if ! iw dev "$WIRELESS_MON_IFACE" info &>/dev/null 2>&1; then
            local detected_mon
            detected_mon=$(iw dev 2>/dev/null | awk '/Interface/{iface=$2} /type monitor/{print iface}' | head -1 || true)
            if [[ -n "$detected_mon" ]]; then
                WIRELESS_MON_IFACE="$detected_mon"
            fi
        fi
    fi

    # Validate monitor mode
    local iface_info
    iface_info=$(iw dev "$WIRELESS_MON_IFACE" info 2>&1 || true)
    echo "--- Monitor interface info ---" >> "$ev_f"
    echo "$iface_info" >> "$ev_f"

    if echo "$iface_info" | grep -q "type monitor"; then
        log_ok "  [T01] Monitor mode active on ${WIRELESS_MON_IFACE}"
        echo "Monitor interface: ${WIRELESS_MON_IFACE} (verified)" >> "$ev_f"
    else
        log_wrn "  [T01] Monitor mode verification failed for ${WIRELESS_MON_IFACE} — tests may fail"
        emit_finding "info" \
            "Wireless Monitor Mode Could Not Be Verified" \
            "airmon-ng ran but 'iw dev ${WIRELESS_MON_IFACE} info' did not confirm monitor type. Subsequent tests may produce incomplete results." \
            "Manually verify with 'iw dev' and ensure the adapter supports monitor mode. Some adapters require firmware patches." \
            "wlan_monitor_unverified"
    fi
}

# - MRK:07_T02 — T02 BEACON AND PROBE SCAN (PASSIVE)
test_T02_beacon_scan() {
    local ev_f; ev_f="$(_ev_file "t02-beacon-scan")"
    log_inf "[T02] Beacon and probe scan (passive) — ${WIRELESS_SCAN_TIME}s"

    if [[ "$_NO_WIRELESS" -eq 1 ]]; then
        log_wrn "  [T02] No wireless interface available — skipping"
        return
    fi

    {
        echo "=== T02 Beacon and Probe Scan (Passive) ==="
        echo "Monitor interface: ${WIRELESS_MON_IFACE}"
        echo "Scan time: ${WIRELESS_SCAN_TIME}s"
        echo "Channel filter: ${WIRELESS_CHANNEL:-all}"
    } > "$ev_f"

    if ! _check_tool airodump-ng; then
        log_wrn "  [T02] airodump-ng not found — install aircrack-ng suite"
        return
    fi

    local csv_base="${EVIDENCE_BASE}/$(ev_fname "wlan-t02-airodump" "csv" | sed 's/\.csv$//')"
    local csv_file="${csv_base}-01.csv"

    # Build airodump-ng args
    local -a dump_args=("--output-format" "csv" "--write" "$csv_base" "--band" "abg")
    [[ -n "$WIRELESS_CHANNEL" ]] && dump_args+=("--channel" "$WIRELESS_CHANNEL")
    dump_args+=("$WIRELESS_MON_IFACE")

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_dry "airodump-ng ${dump_args[*]} (${WIRELESS_SCAN_TIME}s)"
        return
    fi

    log_inf "  [T02] Running airodump-ng for ${WIRELESS_SCAN_TIME}s..."
    timeout "$WIRELESS_SCAN_TIME" airodump-ng "${dump_args[@]}" >> "$ev_f" 2>&1 || true

    if [[ ! -f "$csv_file" ]]; then
        log_wrn "  [T02] airodump-ng CSV not found — scan may have produced no output"
        echo "[T02] No CSV output captured" >> "$ev_f"
        return
    fi

    echo "--- airodump-ng CSV: ${csv_file} ---" >> "$ev_f"

    # Parse AP section (before first blank line)
    # CSV header: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
    local ap_section
    ap_section=$(awk 'BEGIN{p=1} /^[[:space:]]*$/{p=0} p && NR>1{print}' "$csv_file" 2>/dev/null || true)

    # Parse client section (after blank line)
    local client_section
    client_section=$(awk 'BEGIN{p=0} /^[[:space:]]*$/{p=1; next} p && NR>2{print}' "$csv_file" 2>/dev/null || true)

    local ssid_count bssid_count client_count
    ssid_count=$(echo "$ap_section" | grep -v '^$\|^BSSID' | grep -c ',' || echo 0)
    bssid_count=$ssid_count
    client_count=$(echo "$client_section" | grep -v '^$\|^Station' | grep -c ',' || echo 0)

    log_ok "  [T02] Scan complete: ${ssid_count} AP(s), ${client_count} client(s)"
    {
        echo ""
        echo "--- Parse summary ---"
        echo "APs    : ${ssid_count}"
        echo "Clients: ${client_count}"
    } >> "$ev_f"

    # Analyse each AP line
    local open_count=0 wep_count=0 wpa_count=0 hidden_count=0
    while IFS=',' read -r bssid _first _last channel _speed privacy _cipher _auth _power _beacons _iv _lan _idlen essid _key; do
        # Trim whitespace
        bssid="${bssid// /}"
        privacy="${privacy// /}"
        essid="${essid// /}"
        [[ -z "$bssid" || "$bssid" == "BSSID" ]] && continue

        # Hidden network: ESSID is empty or length 0
        if [[ -z "$essid" || "$essid" == "" ]]; then
            (( hidden_count++ )) || true
            emit_finding "low" \
                "Hidden SSID Broadcasting — BSSID ${bssid}" \
                "A wireless AP (BSSID ${bssid}) is broadcasting with a hidden SSID. Hidden SSIDs provide minimal security as the SSID is revealed in probe responses when a client connects." \
                "Hidden SSIDs do not improve security. Consider using WPA3 or strong WPA2 with a non-guessable SSID. Rely on strong encryption rather than obscurity." \
                "wlan_hidden_${bssid//:/}"
        fi

        # Open network detection (Privacy = OPN or empty)
        if echo "$privacy" | grep -qiE '^OPN$|^$'; then
            (( open_count++ )) || true
            emit_finding "high" \
                "Open (Unencrypted) Wireless Network: ${essid:-<hidden>} (${bssid})" \
                "Wireless network '${essid:-<hidden>}' (BSSID ${bssid}, channel ${channel// /}) has no encryption. All traffic is transmitted in plaintext and is trivially interceptable." \
                "Enable WPA3-Personal or WPA2-Personal with AES/CCMP encryption. Disable open authentication. If a guest network is required, isolate it and use a captive portal." \
                "wlan_open_${bssid//:/}"

        # WEP network detection
        elif echo "$privacy" | grep -qiE 'WEP'; then
            (( wep_count++ )) || true
            emit_finding "critical" \
                "WEP Encrypted Network (Broken): ${essid:-<hidden>} (${bssid})" \
                "Wireless network '${essid:-<hidden>}' (BSSID ${bssid}) uses WEP encryption which was broken in 2001. WEP keys can be recovered in minutes using aircrack-ng IV capture." \
                "Immediately replace WEP with WPA3-Personal or WPA2-Personal (AES/CCMP). WEP offers no effective security against modern attacks." \
                "wlan_wep_${bssid//:/}"

        # WPA/WPA2 network
        elif echo "$privacy" | grep -qiE 'WPA'; then
            (( wpa_count++ )) || true
        fi

        # Unexpected SSID check
        if [[ -n "$WIRELESS_EXPECTED_SSIDS" && -n "$essid" ]]; then
            local found_expected=0
            for exp_ssid in $WIRELESS_EXPECTED_SSIDS; do
                [[ "$essid" == "$exp_ssid" ]] && found_expected=1 && break
            done
            if [[ "$found_expected" -eq 0 ]]; then
                emit_finding "medium" \
                    "Unexpected SSID Detected: ${essid} (${bssid})" \
                    "SSID '${essid}' (BSSID ${bssid}) is not in the expected SSID list (${WIRELESS_EXPECTED_SSIDS}). This may indicate an unauthorised access point, shadow IT, or a misconfigured device." \
                    "Investigate the source of unexpected SSIDs. Validate against authorised AP inventory. Remove or remediate unauthorised access points." \
                    "wlan_unexpected_ssid_${bssid//:/}"
            fi
        fi
    done < <(echo "$ap_section")

    {
        echo "Open networks : ${open_count}"
        echo "WEP networks  : ${wep_count}"
        echo "WPA networks  : ${wpa_count}"
        echo "Hidden SSIDs  : ${hidden_count}"
    } >> "$ev_f"

    log_ok "  [T02] Open: ${open_count}, WEP: ${wep_count}, WPA/WPA2: ${wpa_count}, Hidden: ${hidden_count}"
}

# - MRK:07_T03 — T03 WPA/WPA2 HANDSHAKE CAPTURE (OPT-IN)
test_T03_handshake_capture() {
    local ev_f; ev_f="$(_ev_file "t03-handshake-capture")"
    log_inf "[T03] WPA/WPA2 handshake capture (opt-in)"

    if [[ "$_NO_WIRELESS" -eq 1 ]]; then
        log_wrn "  [T03] No wireless interface available — skipping"
        return
    fi

    # Double gate: deep profile AND explicit opt-in
    if [[ "${SCAN_PROFILE}" != "deep" ]]; then
        log_inf "  [T03] Handshake capture requires --profile deep — skipping (current: ${SCAN_PROFILE})"
        return
    fi
    if [[ "${WIRELESS_DEAUTH_ENABLED:-0}" -ne 1 ]]; then
        log_inf "  [T03] WIRELESS_DEAUTH_ENABLED=0 — deauth/handshake capture disabled (use --deauth to enable)"
        return
    fi

    if ! _check_tool airodump-ng || ! _check_tool aireplay-ng; then
        log_wrn "  [T03] airodump-ng or aireplay-ng not found — install aircrack-ng suite"
        return
    fi

    {
        echo "=== T03 WPA/WPA2 Handshake Capture ==="
        echo "Monitor interface: ${WIRELESS_MON_IFACE}"
        echo "WIRELESS_DEAUTH_ENABLED: 1"
    } > "$ev_f"

    # Read AP list from T02 CSV
    local csv_base="${EVIDENCE_BASE}/$(ev_fname "wlan-t02-airodump" "csv" | sed 's/\.csv$//')"
    local csv_file="${csv_base}-01.csv"

    if [[ ! -f "$csv_file" ]]; then
        log_wrn "  [T03] T02 CSV not found — run T02 first or re-run with T02 enabled"
        echo "[T03] No T02 CSV available — skipping AP iteration" >> "$ev_f"
        return
    fi

    # Extract WPA APs from T02 output
    local ap_section
    ap_section=$(awk 'BEGIN{p=1} /^[[:space:]]*$/{p=0} p && NR>1{print}' "$csv_file" 2>/dev/null || true)

    local handshake_count=0

    while IFS=',' read -r bssid _first _last channel _speed privacy _cipher _auth _power _beacons _iv _lan _idlen essid _key; do
        bssid="${bssid// /}"
        privacy="${privacy// /}"
        essid="${essid// /}"
        channel="${channel// /}"
        [[ -z "$bssid" || "$bssid" == "BSSID" ]] && continue
        echo "$privacy" | grep -qiE 'WPA' || continue

        log_inf "  [T03] Targeting WPA AP: ${essid:-<hidden>} (${bssid}) ch${channel}"

        local cap_base="${EVIDENCE_BASE}/$(ev_fname "wlan-t03-cap-${bssid//:/}" "cap" | sed 's/\.cap$//')"
        local cap_file="${cap_base}-01.cap"

        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_dry "airodump-ng --bssid ${bssid} --channel ${channel} --write ${cap_base} ${WIRELESS_MON_IFACE} (30s)"
            log_dry "aireplay-ng --deauth 2 -a ${bssid} ${WIRELESS_MON_IFACE}"
            log_dry "aircrack-ng -a2 -w /dev/null ${cap_file} (handshake check only)"
            continue
        fi

        # Capture in background for 30s while sending deauth
        log_inf "  [T03] Capturing on BSSID ${bssid} ch${channel} for 30s..."
        timeout 32 airodump-ng --bssid "$bssid" --channel "$channel" \
            --write "$cap_base" "$WIRELESS_MON_IFACE" >> "$ev_f" 2>&1 &
        local dump_pid=$!

        # Brief delay then send 2 deauth frames
        sleep 5
        log_inf "  [T03] Sending 2 deauth frames to BSSID ${bssid}..."
        aireplay-ng --deauth 2 -a "$bssid" "$WIRELESS_MON_IFACE" >> "$ev_f" 2>&1 || true

        emit_finding "info" \
            "Deauth Frames Sent to AP: ${essid:-<hidden>} (${bssid})" \
            "2 deauthentication frames were sent to AP '${essid:-<hidden>}' (${bssid}) to trigger client reconnection for WPA handshake capture. This is an active action." \
            "Informational — part of WPA handshake capture test. Authorised within engagement scope only." \
            "wlan_deauth_${bssid//:/}"

        # Wait for capture to finish
        wait "$dump_pid" 2>/dev/null || true

        # Check for handshake in cap file
        if [[ -f "$cap_file" ]]; then
            local hs_check
            hs_check=$(aircrack-ng -a2 -w /dev/null "$cap_file" 2>&1 | head -20 || true)
            echo "--- Handshake check for ${bssid} ---" >> "$ev_f"
            echo "$hs_check" >> "$ev_f"

            if echo "$hs_check" | grep -qiE '1 handshake|handshake found|Passphrase not in dictionary'; then
                (( handshake_count++ )) || true
                emit_finding "high" \
                    "WPA Handshake Captured: ${essid:-<hidden>} (${bssid})" \
                    "A 4-way WPA handshake was captured for network '${essid:-<hidden>}' (${bssid}). The handshake can be cracked offline using wordlists or GPU-accelerated tools (hashcat mode 22000) without requiring further network access." \
                    "Use a strong WPA2/WPA3 passphrase (20+ random characters). Enable WPA3-SAE to prevent offline cracking. Consider enterprise 802.1X authentication for production networks." \
                    "wlan_handshake_${bssid//:/}"
                log_wrn "  [T03] Handshake captured for ${essid:-<hidden>} (${bssid}) → ${cap_file}"
            else
                log_ok "  [T03] No handshake captured for ${bssid} in 30s window"
            fi
        fi
    done < <(echo "$ap_section")

    log_ok "  [T03] Handshake capture complete — ${handshake_count} handshake(s) captured"
}

# - MRK:07_T04 — T04 PMKID ATTACK SURFACE (OPT-IN)
test_T04_pmkid_capture() {
    local ev_f; ev_f="$(_ev_file "t04-pmkid")"
    log_inf "[T04] PMKID attack surface (opt-in)"

    if [[ "$_NO_WIRELESS" -eq 1 ]]; then
        log_wrn "  [T04] No wireless interface available — skipping"
        return
    fi

    # Double gate: deep profile AND explicit opt-in
    if [[ "${SCAN_PROFILE}" != "deep" ]]; then
        log_inf "  [T04] PMKID capture requires --profile deep — skipping (current: ${SCAN_PROFILE})"
        return
    fi
    if [[ "${WIRELESS_PMKID_ENABLED:-0}" -ne 1 ]]; then
        log_inf "  [T04] WIRELESS_PMKID_ENABLED=0 — PMKID capture disabled (use --pmkid to enable)"
        return
    fi

    if ! _check_tool hcxdumptool; then
        log_wrn "  [T04] hcxdumptool not found — install hcxtools (apt install hcxtools)"
        return
    fi

    {
        echo "=== T04 PMKID Attack Surface ==="
        echo "Monitor interface: ${WIRELESS_MON_IFACE}"
        echo "WIRELESS_PMKID_ENABLED: 1"
    } > "$ev_f"

    local pcapng_file="${EVIDENCE_BASE}/$(ev_fname "wlan-t04-pmkid" "pcapng")"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_dry "hcxdumptool -i ${WIRELESS_MON_IFACE} -o ${pcapng_file} --enable_status=1 (30s)"
        log_dry "hcxpcapngtool -o /dev/null --pmkid ${pcapng_file}"
        return
    fi

    log_inf "  [T04] Running hcxdumptool for 30s to capture PMKID frames..."
    timeout 30 hcxdumptool -i "$WIRELESS_MON_IFACE" \
        -o "$pcapng_file" \
        --enable_status=1 >> "$ev_f" 2>&1 || true

    if [[ ! -f "$pcapng_file" ]]; then
        log_wrn "  [T04] No pcapng file produced by hcxdumptool"
        echo "[T04] No pcapng output captured" >> "$ev_f"
        return
    fi

    # Check for PMKID frames
    if _check_tool hcxpcapngtool; then
        local pmkid_out
        pmkid_out=$(hcxpcapngtool --pmkid=/dev/stdout "$pcapng_file" 2>&1 | head -50 || true)
        echo "--- PMKID extraction ---" >> "$ev_f"
        echo "$pmkid_out" >> "$ev_f"

        local pmkid_count
        pmkid_count=$(echo "$pmkid_out" | grep -cE '^[0-9a-f]{32}\*' || echo 0)

        if [[ "$pmkid_count" -gt 0 ]]; then
            emit_finding "high" \
                "PMKID Captured: ${pmkid_count} Hash(es) — Offline Crack Possible" \
                "${pmkid_count} PMKID hash(es) captured from WPA/WPA2 access points. PMKID attacks do not require a client to be connected and allow offline passphrase cracking (hashcat mode 22000)." \
                "Use a strong WPA2/WPA3 passphrase (20+ random characters). Enable WPA3-SAE which is immune to PMKID attacks. Audit all access points for WPA2 usage." \
                "wlan_pmkid_captured"
            log_wrn "  [T04] ${pmkid_count} PMKID hash(es) captured → ${pcapng_file}"
        else
            log_ok "  [T04] No PMKID frames captured in 30s window"
        fi
    else
        log_wrn "  [T04] hcxpcapngtool not found — cannot parse pcapng for PMKID. Install hcxtools."
        log_inf "  [T04] Raw pcapng saved to ${pcapng_file} — analyse manually"
        emit_finding "info" \
            "PMKID Capture Raw File Saved — Manual Analysis Required" \
            "hcxdumptool captured data to ${pcapng_file} but hcxpcapngtool is not available for automated PMKID extraction. Manual analysis with hcxpcapngtool or hashcat is required." \
            "Install hcxtools (apt install hcxtools). Run: hcxpcapngtool --pmkid=pmkid.hash <pcapng>" \
            "wlan_pmkid_manual"
    fi
}

# - MRK:07_T05 — T05 ROGUE AP AND EVIL TWIN DETECTION
test_T05_rogue_ap_detection() {
    local ev_f; ev_f="$(_ev_file "t05-rogue-ap")"
    log_inf "[T05] Rogue AP and evil twin detection"

    if [[ "$_NO_WIRELESS" -eq 1 ]]; then
        log_wrn "  [T05] No wireless interface available — skipping"
        return
    fi

    {
        echo "=== T05 Rogue AP and Evil Twin Detection ==="
        echo "Expected SSIDs: ${WIRELESS_EXPECTED_SSIDS:-<none configured>}"
    } > "$ev_f"

    # Require T02 CSV
    local csv_base="${EVIDENCE_BASE}/$(ev_fname "wlan-t02-airodump" "csv" | sed 's/\.csv$//')"
    local csv_file="${csv_base}-01.csv"

    if [[ ! -f "$csv_file" ]]; then
        log_wrn "  [T05] T02 CSV not found — run T02 first. Skipping rogue AP analysis."
        echo "[T05] No T02 CSV available" >> "$ev_f"
        return
    fi

    local ap_section
    ap_section=$(awk 'BEGIN{p=1} /^[[:space:]]*$/{p=0} p && NR>1{print}' "$csv_file" 2>/dev/null || true)

    # Build associative map: SSID -> list of BSSID:OUI entries
    declare -A ssid_bssids

    while IFS=',' read -r bssid _first _last _ch _speed _priv _cipher _auth _power _beacons _iv _lan _idlen essid _key; do
        bssid="${bssid// /}"
        essid="${essid// /}"
        [[ -z "$bssid" || "$bssid" == "BSSID" ]] && continue
        [[ -z "$essid" ]] && continue

        if [[ -v "ssid_bssids[$essid]" ]]; then
            ssid_bssids["$essid"]+=" ${bssid}"
        else
            ssid_bssids["$essid"]="${bssid}"
        fi
    done < <(echo "$ap_section")

    echo "--- SSID to BSSID mapping ---" >> "$ev_f"
    for ssid in "${!ssid_bssids[@]}"; do
        echo "  ${ssid}: ${ssid_bssids[$ssid]}" >> "$ev_f"
    done

    # Check each SSID for multiple BSSIDs with different OUI prefixes (different vendors)
    for ssid in "${!ssid_bssids[@]}"; do
        local bssid_list="${ssid_bssids[$ssid]}"
        local -a bssids=()
        read -ra bssids <<< "$bssid_list"
        local bssid_count=${#bssids[@]}

        if [[ "$bssid_count" -gt 1 ]]; then
            # Extract OUI prefixes (first 3 octets)
            declare -A oui_map
            for b in "${bssids[@]}"; do
                local oui
                oui=$(echo "$b" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
                oui_map["$oui"]=1
            done
            local unique_ouis=${#oui_map[@]}
            unset oui_map

            if [[ "$unique_ouis" -gt 1 ]]; then
                # Different vendor OUIs = likely different hardware = potential evil twin
                emit_finding "high" \
                    "Duplicate SSID with Different Vendors — Potential Evil Twin: ${ssid}" \
                    "SSID '${ssid}' is being broadcast by ${bssid_count} APs (${bssid_list}) with ${unique_ouis} different vendor OUI prefixes. APs from different manufacturers broadcasting the same SSID strongly suggests an evil twin or rogue AP." \
                    "Investigate all APs broadcasting '${ssid}'. Verify MAC addresses against authorised AP inventory. Isolate and remove any unauthorised AP. Implement 802.11w Management Frame Protection to harden against rogue APs." \
                    "wlan_evil_twin_${ssid//[^A-Za-z0-9]/_}"
                log_wrn "  [T05] Potential evil twin: '${ssid}' seen from ${bssid_count} BSSIDs with ${unique_ouis} different OUIs"
            else
                log_inf "  [T05] SSID '${ssid}' has ${bssid_count} BSSIDs (same vendor OUI — likely legitimate multi-AP deployment)"
            fi
        fi
    done

    # Check expected SSIDs appearing with unexpected BSSIDs
    if [[ -n "$WIRELESS_EXPECTED_SSIDS" ]]; then
        echo "--- Expected SSID vendor mismatch check ---" >> "$ev_f"
        for exp_ssid in $WIRELESS_EXPECTED_SSIDS; do
            if [[ -v "ssid_bssids[$exp_ssid]" ]]; then
                local detected_bssids="${ssid_bssids[$exp_ssid]}"
                echo "  Expected '${exp_ssid}' found at: ${detected_bssids}" >> "$ev_f"
                log_inf "  [T05] Expected SSID '${exp_ssid}' present (BSSID(s): ${detected_bssids})"
                # Flag if multiple BSSIDs exist for an expected SSID (could be legitimate or rogue)
                local -a exp_bssid_arr=()
                read -ra exp_bssid_arr <<< "$detected_bssids"
                if [[ "${#exp_bssid_arr[@]}" -gt 1 ]]; then
                    emit_finding "critical" \
                        "Expected SSID with Multiple BSSIDs — Verify for Rogue AP: ${exp_ssid}" \
                        "Expected SSID '${exp_ssid}' is broadcasting from ${#exp_bssid_arr[@]} BSSIDs: ${detected_bssids}. If only one AP is authorised for this SSID, an additional BSSID indicates a rogue or evil twin AP impersonating a legitimate network." \
                        "Verify all BSSIDs against the authorised AP inventory. Investigate any unauthorised BSSID. Implement wireless IDS (WIDS) to detect rogue APs. Enable 802.11w Management Frame Protection." \
                        "wlan_expected_rogue_${exp_ssid//[^A-Za-z0-9]/_}"
                    log_wrn "  [T05] Expected SSID '${exp_ssid}' has multiple BSSIDs — verify for rogue AP"
                fi
            else
                log_inf "  [T05] Expected SSID '${exp_ssid}' not observed in scan"
                echo "  Expected '${exp_ssid}': NOT SEEN in scan window" >> "$ev_f"
            fi
        done
    fi

    log_ok "  [T05] Rogue AP / evil twin detection complete"
}

# - MRK:07_T06 — T06 EAP/PEAP CERTIFICATE VALIDATION
test_T06_eap_cert_validation() {
    local ev_f; ev_f="$(_ev_file "t06-eap-cert")"
    log_inf "[T06] EAP/PEAP certificate validation and WPS discovery"

    if [[ "$_NO_WIRELESS" -eq 1 ]]; then
        log_wrn "  [T06] No wireless interface available — skipping"
        return
    fi

    {
        echo "=== T06 EAP/PEAP Certificate Validation ==="
        echo "Monitor interface: ${WIRELESS_MON_IFACE}"
    } > "$ev_f"

    # Require T02 CSV to identify WPA-Enterprise networks
    local csv_base="${EVIDENCE_BASE}/$(ev_fname "wlan-t02-airodump" "csv" | sed 's/\.csv$//')"
    local csv_file="${csv_base}-01.csv"

    # --- WPS detection via wash ---
    if _check_tool wash; then
        log_inf "  [T06] Running wash for WPS-enabled AP discovery (30s)..."
        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_dry "wash -i ${WIRELESS_MON_IFACE} --scan (30s)"
        else
            local wash_out
            wash_out=$(timeout 30 wash -i "$WIRELESS_MON_IFACE" --scan 2>&1 | head -80 || true)
            echo "--- wash WPS scan ---" >> "$ev_f"
            echo "$wash_out" >> "$ev_f"

            # Parse wash output: columns are BSSID, Ch, dBm, WPS, Lck, Vendor, ESSID
            while IFS= read -r wline; do
                [[ "$wline" =~ ^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2} ]] || continue
                local w_bssid w_ch w_dbm w_wps w_lck w_vendor w_essid
                read -r w_bssid w_ch w_dbm w_wps w_lck w_vendor w_essid <<< "$wline"
                log_inf "  [T06] WPS found: ${w_essid:-<hidden>} (${w_bssid}) WPS ver:${w_wps} Locked:${w_lck}"

                if [[ "${w_lck,,}" == "yes" ]]; then
                    emit_finding "info" \
                        "WPS Locked on AP: ${w_essid:-<hidden>} (${w_bssid})" \
                        "WPS is enabled but locked on AP '${w_essid:-<hidden>}' (${w_bssid}). WPS lockout prevents Pixie Dust and Reaver brute-force attacks but WPS should still be disabled." \
                        "Disable WPS entirely on all access points regardless of lock status. WPS provides no benefit when strong passphrases are used." \
                        "wlan_wps_locked_${w_bssid//:/}"
                elif echo "$w_wps" | grep -qE '^1\.0|^1$'; then
                    emit_finding "high" \
                        "WPS 1.0 Enabled and Unlocked — Pixie Dust / Reaver Vulnerable: ${w_essid:-<hidden>} (${w_bssid})" \
                        "AP '${w_essid:-<hidden>}' (${w_bssid}) has WPS version 1.0 enabled and unlocked. WPS 1.0 is vulnerable to Pixie Dust attack (offline nonce brute-force) and Reaver PIN brute-force, potentially recovering the WPA passphrase without deauthentication." \
                        "Disable WPS on all access points. WPS PIN mode is inherently insecure. If push-button WPS is required, upgrade to WPS 2.0 with lockout and consider disabling after initial setup." \
                        "wlan_wps10_${w_bssid//:/}"
                else
                    emit_finding "medium" \
                        "WPS Enabled on AP: ${w_essid:-<hidden>} (${w_bssid})" \
                        "WPS is enabled on AP '${w_essid:-<hidden>}' (${w_bssid}). WPS introduces PIN brute-force risk and design flaws that may allow passphrase recovery." \
                        "Disable WPS on all access points. Use manual WPA passphrase configuration instead. If WPS is required, use push-button mode only with lockout enabled." \
                        "wlan_wps_${w_bssid//:/}"
                fi
            done < <(echo "$wash_out")
        fi

    elif _check_tool nmap; then
        log_inf "  [T06] wash not found — using nmap broadcast-wps-discover fallback..."
        if [[ "$DRY_RUN" -eq 1 ]]; then
            log_dry "nmap --script broadcast-wps-discover"
        else
            local nmap_wps
            nmap_wps=$(timeout 30 nmap --script broadcast-wps-discover 2>&1 | head -60 || true)
            echo "--- nmap WPS discover ---" >> "$ev_f"
            echo "$nmap_wps" >> "$ev_f"
            if echo "$nmap_wps" | grep -qi 'WPS'; then
                emit_finding "medium" \
                    "WPS Enabled APs Detected via Nmap Broadcast Probe" \
                    "nmap broadcast-wps-discover identified WPS-enabled access points. See evidence file for details. WPS introduces PIN brute-force attack surface." \
                    "Disable WPS on all access points. Use nmap or wash output to identify specific devices requiring remediation." \
                    "wlan_wps_nmap"
                log_wrn "  [T06] WPS-enabled APs detected via nmap — see ${ev_f}"
            else
                log_ok "  [T06] No WPS-enabled APs detected via nmap broadcast probe"
            fi
        fi
    else
        log_wrn "  [T06] wash and nmap not found — WPS detection skipped. Install wash (apt install wash) or nmap."
    fi

    # --- EAP/PEAP enterprise network detection ---
    if [[ -f "$csv_file" ]]; then
        local ap_section
        ap_section=$(awk 'BEGIN{p=1} /^[[:space:]]*$/{p=0} p && NR>1{print}' "$csv_file" 2>/dev/null || true)
        local eap_count=0

        while IFS=',' read -r bssid _first _last _ch _speed privacy _cipher auth _power _beacons _iv _lan _idlen essid _key; do
            bssid="${bssid// /}"
            privacy="${privacy// /}"
            auth="${auth// /}"
            essid="${essid// /}"
            [[ -z "$bssid" || "$bssid" == "BSSID" ]] && continue

            # WPA-Enterprise networks show MGT in authentication field
            if echo "$auth" | grep -qiE 'MGT|EAP|Enterprise'; then
                (( eap_count++ )) || true
                log_inf "  [T06] WPA-Enterprise network: ${essid:-<hidden>} (${bssid}) auth=${auth}"
                echo "WPA-Enterprise AP: ${essid:-<hidden>} ${bssid} auth=${auth}" >> "$ev_f"

                if [[ "$DRY_RUN" -eq 1 ]]; then
                    log_dry "EAP probe: wpa_supplicant/eaphammer cert-verify for ${bssid}"
                    continue
                fi

                # Probe EAP server certificate validation using eaphammer if available
                if _check_tool eaphammer; then
                    local eap_probe_out
                    eap_probe_out=$(timeout 30 eaphammer --cert-verify \
                        --interface "$WIRELESS_MON_IFACE" \
                        --essid "${essid:-hidden}" \
                        --bssid "$bssid" 2>&1 | head -40 || true)
                    echo "--- eaphammer cert-verify: ${bssid} ---" >> "$ev_f"
                    echo "$eap_probe_out" >> "$ev_f"

                    if echo "$eap_probe_out" | grep -qiE 'no.*cert|cert.*not.*validated|cert.*ignored|certificate.*bypass'; then
                        emit_finding "high" \
                            "EAP/PEAP No Certificate Validation: ${essid:-<hidden>} (${bssid})" \
                            "WPA-Enterprise network '${essid:-<hidden>}' (${bssid}) does not validate the RADIUS server certificate. Clients connecting to a rogue AP with a fake RADIUS server will submit credentials without warning." \
                            "Configure EAP supplicants to validate the server certificate. Pin the trusted CA certificate in wireless profile configuration. Inform users not to accept certificate warnings. Deploy Network Access Control (NAC)." \
                            "wlan_eap_no_cert_${bssid//:/}"
                        log_wrn "  [T06] EAP no cert validation: ${essid:-<hidden>} (${bssid})"
                    else
                        log_ok "  [T06] EAP cert validation probe inconclusive or cert verified: ${bssid}"
                    fi
                else
                    # Informational finding — manual testing required
                    emit_finding "info" \
                        "WPA-Enterprise Network Detected — EAP Certificate Validation Not Automatically Tested: ${essid:-<hidden>} (${bssid})" \
                        "WPA-Enterprise (EAP/PEAP) network '${essid:-<hidden>}' (${bssid}) detected. Automated certificate validation testing requires eaphammer. Manual testing is recommended to verify that clients enforce server certificate validation." \
                        "Install eaphammer for automated EAP cert testing. Manually verify that wireless profiles enforce server certificate validation. Conduct a rogue AP simulation within authorised scope." \
                        "wlan_eap_manual_${bssid//:/}"
                    log_inf "  [T06] WPA-Enterprise '${essid:-<hidden>}' — install eaphammer for cert validation test"
                fi
            fi
        done < <(echo "$ap_section")

        if [[ "$eap_count" -eq 0 ]]; then
            log_inf "  [T06] No WPA-Enterprise (EAP/MGT) networks found in T02 scan data"
            echo "[T06] No WPA-Enterprise networks detected" >> "$ev_f"
        fi
    else
        log_inf "  [T06] T02 CSV not available — EAP network detection skipped"
        echo "[T06] T02 CSV not available for EAP detection" >> "$ev_f"
    fi

    log_ok "  [T06] EAP/PEAP and WPS assessment complete"
}

# - MRK:07_T07 — T07 WPS ENUMERATION
test_T07_wps_enum() {
    local ev_f; ev_f="$(_ev_file "t07-wps-enum")"
    log_inf "[T07] WPS enumeration"

    if [[ "$_NO_WIRELESS" -eq 1 ]]; then
        log_wrn "  [T07] No wireless interface available — skipping"
        return
    fi

    {
        echo "=== T07 WPS Enumeration ==="
        echo "Monitor interface: ${WIRELESS_MON_IFACE}"
        echo "NOTE: WPS PIN brute-force (Reaver/Pixie Dust) is NOT performed — detection only."
    } > "$ev_f"

    if ! _check_tool wash; then
        log_wrn "  [T07] wash not found — install wash (apt install wash) for WPS enumeration"
        log_inf "  [T07] Attempting fallback: parsing T02 airodump CSV for WPS indicators..."

        local csv_base="${EVIDENCE_BASE}/$(ev_fname "wlan-t02-airodump" "csv" | sed 's/\.csv$//')"
        local csv_file="${csv_base}-01.csv"
        if [[ -f "$csv_file" ]]; then
            echo "[T07] wash not available — T02 CSV does not contain WPS fields" >> "$ev_f"
            log_inf "  [T07] WPS detail not available in airodump CSV — install wash for full enumeration"
        else
            echo "[T07] wash not available and no T02 CSV" >> "$ev_f"
        fi
        return
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_dry "wash -i ${WIRELESS_MON_IFACE} (30s)"
        return
    fi

    log_inf "  [T07] Running wash for 30s to enumerate WPS-enabled APs..."
    local wash_out
    wash_out=$(timeout 30 wash -i "$WIRELESS_MON_IFACE" 2>&1 | head -100 || true)
    echo "$wash_out" >> "$ev_f"

    local wps_ap_count=0
    local wps10_count=0
    local wps_locked_count=0

    while IFS= read -r wline; do
        [[ "$wline" =~ ^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2} ]] || continue
        local w_bssid w_ch w_dbm w_wps w_lck w_vendor w_essid
        read -r w_bssid w_ch w_dbm w_wps w_lck w_vendor w_essid <<< "$wline"
        (( wps_ap_count++ )) || true

        echo "AP: BSSID=${w_bssid} Ch=${w_ch} WPS=${w_wps} Locked=${w_lck} ESSID=${w_essid}" >> "$ev_f"
        log_inf "  [T07] WPS AP: ${w_essid:-<hidden>} (${w_bssid}) ver=${w_wps} locked=${w_lck} vendor=${w_vendor}"

        if [[ "${w_lck,,}" == "yes" ]]; then
            (( wps_locked_count++ )) || true
            emit_finding "info" \
                "WPS Locked — Brute-force Resistant: ${w_essid:-<hidden>} (${w_bssid})" \
                "WPS is enabled and locked on AP '${w_essid:-<hidden>}' (${w_bssid}). The lockout mechanism is active, reducing Reaver brute-force risk. WPS should still be disabled as lockout can be bypassed on some firmwares." \
                "Disable WPS entirely on all access points. Even a locked WPS implementation represents unnecessary attack surface." \
                "wlan_t07_wps_locked_${w_bssid//:/}"

        elif echo "$w_wps" | grep -qE '^1\.0|^1$'; then
            (( wps10_count++ )) || true
            emit_finding "high" \
                "WPS 1.0 Enabled and Unlocked — Pixie Dust Attack Possible: ${w_essid:-<hidden>} (${w_bssid})" \
                "AP '${w_essid:-<hidden>}' (${w_bssid}, vendor: ${w_vendor:-unknown}) has WPS version 1.0 enabled and is not locked. WPS 1.0 is vulnerable to: (1) Pixie Dust — offline nonce brute-force recovering the PIN; (2) Reaver — online PIN brute-force. Either attack can recover the WPA passphrase. NOTE: WPS PIN attempts are NOT performed in this test." \
                "Disable WPS on all access points. If WPS must be used temporarily, upgrade to WPS 2.0 with rate limiting, enable lockout after 3 failed attempts, and disable WPS after initial setup. Consider replacing the AP if firmware updates are unavailable." \
                "wlan_t07_wps10_${w_bssid//:/}"
            log_wrn "  [T07] WPS 1.0 unlocked — Pixie Dust vulnerable: ${w_essid:-<hidden>} (${w_bssid})"

        else
            emit_finding "medium" \
                "WPS Enabled on AP: ${w_essid:-<hidden>} (${w_bssid})" \
                "WPS is enabled on AP '${w_essid:-<hidden>}' (${w_bssid}, WPS ver: ${w_wps}, vendor: ${w_vendor:-unknown}). WPS PIN exchange is susceptible to brute-force in some configurations and should be disabled." \
                "Disable WPS on all access points. Review AP firmware for WPS vulnerability advisories. If WPS must remain enabled, ensure lockout is active and the AP is patched." \
                "wlan_t07_wps_${w_bssid//:/}"
        fi
    done < <(echo "$wash_out")

    {
        echo ""
        echo "--- WPS Summary ---"
        echo "Total WPS APs  : ${wps_ap_count}"
        echo "WPS 1.0 unlocked: ${wps10_count}"
        echo "WPS locked     : ${wps_locked_count}"
    } >> "$ev_f"

    log_ok "  [T07] WPS enumeration complete — ${wps_ap_count} WPS AP(s) found (${wps10_count} WPS 1.0 unlocked)"
}

# =============================================================================
# - MRK:07_TRUN
# =============================================================================
_run_tests() {
    local find_before="$_FIND_CTR"

    log_inf "=== Running wireless assessment (profile: ${SCAN_PROFILE}) ==="

    _test_skip T01 || test_T01_interface_setup
    _test_skip T02 || test_T02_beacon_scan
    _test_skip T03 || test_T03_handshake_capture
    _test_skip T04 || test_T04_pmkid_capture
    _test_skip T05 || test_T05_rogue_ap_detection
    _test_skip T06 || test_T06_eap_cert_validation
    _test_skip T07 || test_T07_wps_enum

    local find_delta=$(( _FIND_CTR - find_before ))
    echo "SUMMARY_ROW|wireless|${WIRELESS_MON_IFACE:-none}|findings=${find_delta}"
}

# =============================================================================
# - MRK:07_MAIN
# =============================================================================
main() {
    printf "\n${_W}╔══════════════════════════════════════════════════════╗${_N}\n"
    printf "${_W}║  PT-Orc  ·  Step 7: Wireless Security Assessment   ║${_N}\n"
    printf "${_W}╚══════════════════════════════════════════════════════╝${_N}\n\n"

    log_inf "Project      : ${PROJECT_NAME}"
    log_inf "Profile      : ${SCAN_PROFILE}"
    log_inf "Interface    : ${WIRELESS_IFACE:-<auto-detect>}"
    log_inf "Scan time    : ${WIRELESS_SCAN_TIME}s"
    log_inf "Deauth (T03) : $( [[ "$WIRELESS_DEAUTH_ENABLED" -eq 1 ]] && echo "ENABLED" || echo "disabled" )"
    log_inf "PMKID  (T04) : $( [[ "$WIRELESS_PMKID_ENABLED" -eq 1 ]] && echo "ENABLED" || echo "disabled" )"
    log_inf "Session      : ${SESSION_TS}"
    log_inf "Log          : ${LOG_FILE}"

    setup_profile "$SCAN_PROFILE"
    _confirm

    command -v trail_phase_start &>/dev/null && trail_phase_start "07_wireless_testing"

    local row
    row=$(_run_tests)
    local total_findings
    total_findings=$(echo "$row" | grep -oE 'findings=[0-9]+' | grep -oE '[0-9]+' || echo 0)

    command -v trail_phase_end &>/dev/null && trail_phase_end "07_wireless_testing"

    # Summary report
    local report_f="${SCRIPT_DIR}/working/$(ev_fname "22-wireless-summary" "md")"
    {
        printf "# Wireless Security Assessment Summary — %s\n\n" "$PROJECT_NAME"
        printf "| Interface | Monitor | Findings |\n|-----------|---------|----------|\n"
        local iface_col mon_col finds_col
        iface_col=$(echo "$row" | cut -d'|' -f2)
        mon_col=$(echo "$row" | cut -d'|' -f3)
        finds_col=$(echo "$row" | grep -oE 'findings=[0-9]+')
        printf "| %s | %s | %s |\n" "$iface_col" "$mon_col" "$finds_col"
        printf "\n**Total Findings:** %d\n" "$total_findings"
        printf "\nFindings JSONL: \`%s\`\n" "$FINDINGS_FILE"
        printf "\nEvidence dir  : \`%s\`\n" "$EVIDENCE_BASE"
    } > "$report_f"

    printf "\n${_G}[DONE]${_N} Wireless security assessment complete.\n"
    printf "  Interface  : %s (monitor: %s)\n" "${WIRELESS_IFACE:-<none>}" "${WIRELESS_MON_IFACE:-<none>}"
    printf "  Findings   : %d\n" "$total_findings"
    printf "  Summary    : %s\n" "$report_f"
    printf "  Evidence   : %s\n\n" "$EVIDENCE_BASE"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
