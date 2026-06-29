#!/usr/bin/env bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:17_NAV_TOC — Section index | nav,toc,index | L5-20
# - MRK:17_T01 — T01 SNMP COMMUNITY STRING SWEEP | t01,snmp,community,sweep,onesixtyone | L21-21
# - MRK:17_T02 — T02 NETWORK DEVICE DEFAULT CREDENTIALS SPRAY | t02,default,creds,spray,hydra,ssh,telnet | L22-22
# - MRK:17_T03 — T03 VLAN HOPPING PROBE (DTP / 802.1Q) | t03,vlan,hopping,dtp,8021q,yersinia | L23-23
# - MRK:17_T04 — T04 PRINTER ENUMERATION (PJL/IPP/SNMP) | t04,printer,pjl,ipp,lpd,snmp | L24-24
# - MRK:17_T05 — T05 NETWORK SEGMENTATION VALIDATION | t05,segmentation,reachability,isolation | L25-25
# NAV-LEN: 5 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-06-25

# =============================================================================
# 17_network_infra.sh — Network Infrastructure Security Testing
# TechGuard Labs | PT-Orc Suite v0.8
# =============================================================================
# NAV: MRK:17_TOC (this block) | MRK:17_ROOT | MRK:17_CONF | MRK:17_LOG
#      MRK:17_ARGS | MRK:17_CONFIRM | MRK:17_TARGETS
#      MRK:17_FIND | MRK:17_UTILS | MRK:17_PROF
#      MRK:17_T01 — T01 SNMP COMMUNITY STRING SWEEP | t01,snmp,community,sweep | L21-21
#      MRK:17_T02 — T02 NETWORK DEVICE DEFAULT CREDENTIALS SPRAY | t02,default,creds | L22-22
#      MRK:17_T03 — T03 VLAN HOPPING PROBE | t03,vlan,dtp | L23-23
#      MRK:17_T04 — T04 PRINTER ENUMERATION | t04,printer,pjl | L24-24
#      MRK:17_T05 — T05 NETWORK SEGMENTATION VALIDATION | t05,segmentation | L25-25
#      MRK:17_TRUN | MRK:17_MAIN
# =============================================================================

# - MRK:17_ROOT
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# - MRK:17_CONF
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
_NI_TIMEOUT=30

# Conf vars with defaults
NETINFRA_TARGETS="${NETINFRA_TARGETS:-}"
NETINFRA_SNMP_COMMUNITIES="${NETINFRA_SNMP_COMMUNITIES:-public private cisco community manager monitor admin network}"
NETINFRA_SPRAY_ENABLED="${NETINFRA_SPRAY_ENABLED:-0}"
NETINFRA_VLAN_IFACE="${NETINFRA_VLAN_IFACE:-}"
NETINFRA_SEGMENT_PROBES="${NETINFRA_SEGMENT_PROBES:-}"

# - MRK:17_LOG
_R='\033[0;31m'; _G='\033[0;32m'; _Y='\033[1;33m'; _B='\033[0;34m'; _C='\033[0;36m'; _W='\033[1;37m'; _N='\033[0m'
SESSION_TS="$(date +%Y%m%d_%H%M%S)"
EV_TS="$(date +'%Y-%m-%d-%H-%M-%S')"
LOG_FILE="${SCRIPT_DIR}/working/${PROJ_SLUG}_17_netinfra_${SESSION_TS}.log"
mkdir -p "${SCRIPT_DIR}/working" "${EVIDENCE_BASE}"

_log()    { local ts; ts="$(date +%H:%M:%S)"; printf "[%s] %s\n" "$ts" "$*" | tee -a "$LOG_FILE"; }
log_ok()  { printf "${_G}[+]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_inf() { printf "${_B}[*]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_wrn() { printf "${_Y}[!]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_err() { printf "${_R}[-]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_dry() { printf "${_C}[DRY]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }

# - MRK:17_ARGS
_SKIP_CONFIRM=0
_ONLY_TESTS=()
_SKIP_TESTS=()

_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Network Infrastructure Security Testing (step 17)

Scans NETINFRA_TARGETS (from pt-orc.conf) for SNMP, default credentials,
VLAN hopping, printer exposure, and segmentation failures.

Options:
  --targets <IPs/CIDRs>       Space-separated target IPs/CIDRs (overrides NETINFRA_TARGETS)
  --communities <list>         Space-separated SNMP community strings (overrides NETINFRA_SNMP_COMMUNITIES)
  --iface <interface>          Network interface for VLAN probing (overrides NETINFRA_VLAN_IFACE)
  -p, --profile <name>         Scan profile: quick|standard|deep  [default: standard]
  --only <T01,T04,...>         Run only specified tests
  --skip <T02,T03,...>         Skip specified tests
  -y, --yes                    Skip confirmation prompt
  --dry-run                    Print actions without executing
  -h, --help                   Show this help

Profiles:
  quick    : T01, T04, T05
  standard : T01, T03, T04, T05  (default)
  deep     : T01, T02, T03, T04, T05  (T02 also requires NETINFRA_SPRAY_ENABLED=1)

WARNING: Default credential spray (T02) is disabled by default.
         Enable with NETINFRA_SPRAY_ENABLED=1 in pt-orc.conf AND --profile deep.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --targets)      NETINFRA_TARGETS="$2"; shift 2 ;;
        --communities)  NETINFRA_SNMP_COMMUNITIES="$2"; shift 2 ;;
        --iface)        NETINFRA_VLAN_IFACE="$2"; shift 2 ;;
        -p|--profile)   SCAN_PROFILE="$2"; shift 2 ;;
        --only)         IFS=',' read -ra _ONLY_TESTS <<< "$2"; shift 2 ;;
        --skip)         IFS=',' read -ra _SKIP_TESTS <<< "$2"; shift 2 ;;
        -y|--yes)       _SKIP_CONFIRM=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -h|--help)      _usage; exit 0 ;;
        *)              log_err "Unknown option: $1"; _usage; exit 1 ;;
    esac
done

# - MRK:17_CONFIRM
_confirm() {
    [[ "$_SKIP_CONFIRM" -eq 1 ]] && return 0
    printf "\n${_Y}[CONFIRM]${_N} Network infrastructure testing. Profile: ${_W}%s${_N}\n" "$SCAN_PROFILE"
    printf "  Project  : %s\n" "$PROJECT_NAME"
    printf "  Targets  : %s\n" "${NETINFRA_TARGETS:-<derived from TARGET_SUBNETS / TARGET_IPS>}"
    printf "  Spray    : %s\n" "$( [[ "${NETINFRA_SPRAY_ENABLED}" -eq 1 && "${SCAN_PROFILE}" == "deep" ]] && echo "ENABLED (deep + NETINFRA_SPRAY_ENABLED=1)" || echo "disabled" )"
    printf "\n  ${_R}WARNING:${_N} This script sends active packets to network infrastructure.\n"
    printf "  Only run within authorised scope and agreed engagement window.\n"
    printf "\n  Continue? [y/N] "
    read -r _ans
    [[ "${_ans,,}" == "y" ]] || { log_err "Aborted by user."; exit 0; }
}

# - MRK:17_TARGETS
_resolve_targets() {
    # Priority: NETINFRA_TARGETS → TARGET_SUBNETS → TARGET_IPS
    local raw=""
    if [[ -n "${NETINFRA_TARGETS:-}" ]]; then
        raw="$NETINFRA_TARGETS"
    elif [[ -n "${TARGET_SUBNETS:-}" ]]; then
        raw="$TARGET_SUBNETS"
    elif [[ -n "${TARGET_IPS:-}" ]]; then
        raw="$TARGET_IPS"
    fi
    echo "$raw"
}

_expand_targets() {
    # Expand a space-separated list of IPs/CIDRs to individual IPs using nmap list scan.
    local raw="$1"
    [[ -z "$raw" ]] && return
    if command -v nmap &>/dev/null; then
        # shellcheck disable=SC2086
        nmap -sL -n $raw 2>/dev/null | awk '/Nmap scan report/{print $NF}' | sort -u
    else
        # Fallback: emit as-is (CIDRs won't expand but single IPs will work)
        for item in $raw; do echo "$item"; done
    fi
}

_validate_config() {
    local raw; raw="$(_resolve_targets)"
    if [[ -z "$raw" ]]; then
        log_err "No targets defined. Set NETINFRA_TARGETS, TARGET_SUBNETS, or TARGET_IPS in pt-orc.conf."
        return 1
    fi
    return 0
}

# - MRK:17_FIND
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "17-netinfra-findings" "jsonl")"
_FIND_CTR=0
: > "$FINDINGS_FILE"

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="${5:-}"
    (( _FIND_CTR++ )) || true
    local fid
    fid="f-17-net-$(printf '%04d' "$_FIND_CTR")"
    local ev_id="${ev_tag:-${fid}-ev}"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"17_network_infra","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
        "$fid" \
        "$(echo "$title" | sed 's/"/\\"/g')" \
        "$sev" \
        "$ev_id" \
        "$(echo "$desc" | sed 's/"/\\"/g')" \
        "$(echo "$rec"  | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_wrn "FINDING [${sev^^}] ${title}"
}

# - MRK:17_UTILS
_check_tool() {
    local tool="$1"
    command -v "$tool" &>/dev/null
}

_ev_file() {
    local tag="$1"
    echo "${EVIDENCE_BASE}/$(ev_fname "net-${tag}" "txt")"
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

# - MRK:17_PROF
setup_profile() {
    local prof="${1:-standard}"
    for n in T01 T02 T03 T04 T05; do
        _T_ENABLED[$n]=1
    done
    case "$prof" in
        quick)
            # Quick: SNMP sweep, printer enum, segmentation check
            for n in T02 T03; do _T_ENABLED[$n]=0; done ;;
        standard)
            # Standard: everything except default credential spray
            _T_ENABLED[T02]=0 ;;
        deep)
            # All enabled — but T02 still gated by NETINFRA_SPRAY_ENABLED conf var
            : ;;
        *)
            log_wrn "Unknown profile '${prof}' — defaulting to standard"
            _T_ENABLED[T02]=0 ;;
    esac
    _apply_cli_filters
}

# =============================================================================
# TESTS
# =============================================================================

# - MRK:17_T01 — T01 SNMP COMMUNITY STRING SWEEP
test_T01_snmp_sweep() {
    local ev_f; ev_f="$(_ev_file "snmp_sweep")"
    local raw_targets; raw_targets="$(_resolve_targets)"

    log_inf "[T01] SNMP community string sweep"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "onesixtyone / snmpwalk against ${raw_targets} with communities: ${NETINFRA_SNMP_COMMUNITIES}"; return; }

    {
        echo "=== T01 SNMP Community String Sweep ==="
        echo "Targets  : ${raw_targets}"
        echo "Community list: ${NETINFRA_SNMP_COMMUNITIES}"
        echo ""
    } > "$ev_f"

    local -a targets_arr
    mapfile -t targets_arr < <(_expand_targets "$raw_targets")

    if [[ ${#targets_arr[@]} -eq 0 ]]; then
        log_wrn "  [T01] No targets resolved — skipping"
        return
    fi

    # Build community list file for onesixtyone
    local comm_file; comm_file="$(mktemp)"
    local target_file; target_file="$(mktemp)"
    for comm in ${NETINFRA_SNMP_COMMUNITIES}; do echo "$comm"; done > "$comm_file"
    printf '%s\n' "${targets_arr[@]}" > "$target_file"

    local -a found_community_hosts=()

    if _check_tool onesixtyone; then
        log_inf "  [T01] Running onesixtyone sweep (UDP 161)..."
        local o161_out
        o161_out=$(timeout 120 onesixtyone -c "$comm_file" -i "$target_file" 2>/dev/null || true)
        echo "--- onesixtyone output ---" >> "$ev_f"
        echo "$o161_out" >> "$ev_f"

        # Parse: lines like "10.0.0.1 [public] Software: ..."
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local host comm_found
            host=$(echo "$line" | awk '{print $1}')
            comm_found=$(echo "$line" | grep -oP '(?<=\[)[^\]]+(?=\])' | head -1 || true)
            [[ -z "$host" || -z "$comm_found" ]] && continue
            found_community_hosts+=("${host}:${comm_found}")
            log_wrn "  [T01] SNMP community '${comm_found}' accepted on ${host}"

            # Determine severity: v1/v2c with guessable community = High
            emit_finding "high" \
                "SNMP v1/v2c Guessable Community String: '${comm_found}' on ${host}" \
                "SNMP community string '${comm_found}' is accepted on ${host}. SNMPv1/v2c transmits community strings in cleartext and this string is a well-known default. An attacker can use this to enumerate the full device configuration, routing tables, ARP tables, and interfaces." \
                "Upgrade to SNMPv3 with authentication and encryption (authPriv mode). Disable SNMPv1 and v2c. Change all default/guessable community strings. Restrict SNMP access to authorised management stations via ACLs." \
                "snmp_community_${host//\./_}"
        done <<< "$o161_out"
    else
        log_wrn "  [T01] onesixtyone not found — falling back to nmap SNMP NSE"
        for host in "${targets_arr[@]}"; do
            local nmap_snmp
            nmap_snmp=$(timeout 60 nmap -sU -p 161 --script snmp-info,snmp-brute \
                --script-args "snmp-brute.communitiesdb=${comm_file}" \
                -oN - "$host" 2>/dev/null || true)
            echo "--- nmap SNMP ${host} ---" >> "$ev_f"
            echo "$nmap_snmp" >> "$ev_f"

            if echo "$nmap_snmp" | grep -qiE 'open.*snmp|snmp-brute.*found'; then
                local comm_found
                comm_found=$(echo "$nmap_snmp" | grep -iE 'snmp-brute.*found|community.*string' | grep -oE "'[^']+'" | tr -d "'" | head -1 || echo "unknown")
                found_community_hosts+=("${host}:${comm_found}")
                log_wrn "  [T01] SNMP open on ${host} — community: ${comm_found}"
                emit_finding "high" \
                    "SNMP v1/v2c Guessable Community String on ${host}" \
                    "nmap detected SNMP service open on ${host} with an accessible community string ('${comm_found}'). Unauthenticated enumeration of device information is possible." \
                    "Upgrade to SNMPv3 authPriv. Disable SNMPv1/v2c. Apply SNMP ACLs. Change all default community strings." \
                    "snmp_nmap_${host//\./_}"
            fi
        done
    fi

    rm -f "$comm_file" "$target_file"

    # For each host where a community was found, do a full snmpwalk for sysDescr, interfaces, routing
    if [[ ${#found_community_hosts[@]} -gt 0 ]] && _check_tool snmpwalk; then
        log_inf "  [T01] Running snmpwalk for info disclosure on ${#found_community_hosts[@]} host(s)..."
        for entry in "${found_community_hosts[@]}"; do
            local walk_host="${entry%%:*}"
            local walk_comm="${entry##*:}"
            local walk_ev; walk_ev="$(_ev_file "snmp_walk_${walk_host//\./_}")"

            {
                echo "=== snmpwalk ${walk_host} community=${walk_comm} ==="
                echo ""
            } > "$walk_ev"

            # sysDescr — system description
            local sys_descr
            sys_descr=$(timeout $_NI_TIMEOUT snmpwalk -c "$walk_comm" -v2c "$walk_host" sysDescr 2>/dev/null || true)
            echo "--- sysDescr ---" >> "$walk_ev"
            echo "$sys_descr" >> "$walk_ev"

            # Interfaces — ifDescr, ifAdminStatus
            local ifaces
            ifaces=$(timeout $_NI_TIMEOUT snmpwalk -c "$walk_comm" -v2c "$walk_host" ifDescr 2>/dev/null || true)
            echo "--- interfaces (ifDescr) ---" >> "$walk_ev"
            echo "$ifaces" >> "$walk_ev"

            # Routing table — ipRouteTable (OID 1.3.6.1.2.1.4.21)
            local routes
            routes=$(timeout $_NI_TIMEOUT snmpwalk -c "$walk_comm" -v2c "$walk_host" ipRouteTable 2>/dev/null || true)
            echo "--- routing table (ipRouteTable) ---" >> "$walk_ev"
            echo "$routes" >> "$walk_ev"

            # ARP table — ipNetToMediaTable
            local arp_table
            arp_table=$(timeout $_NI_TIMEOUT snmpwalk -c "$walk_comm" -v2c "$walk_host" ipNetToMediaTable 2>/dev/null || true)
            echo "--- ARP table (ipNetToMediaTable) ---" >> "$walk_ev"
            echo "$arp_table" >> "$walk_ev"

            local disclosed_items=()
            [[ -n "$sys_descr" ]]  && disclosed_items+=("sysDescr")
            [[ -n "$ifaces" ]]     && disclosed_items+=("interfaces")
            [[ -n "$routes" ]]     && disclosed_items+=("routing-table")
            [[ -n "$arp_table" ]]  && disclosed_items+=("arp-table")

            if [[ ${#disclosed_items[@]} -gt 0 ]]; then
                emit_finding "medium" \
                    "SNMP Information Disclosure via snmpwalk on ${walk_host}" \
                    "Full snmpwalk on ${walk_host} (community '${walk_comm}') disclosed: ${disclosed_items[*]}. This reveals device type, software version, network topology, active interfaces, and connected hosts — enabling targeted attack planning." \
                    "Upgrade to SNMPv3 authPriv. Remove all world-readable MIB subtrees if SNMPv2c must remain. Apply SNMP view restrictions (SNMP views / vacmViewTreeFamily). Restrict SNMP to management VLAN only." \
                    "snmp_walk_disclosure_${walk_host//\./_}"
                log_inf "  [T01] snmpwalk disclosed [${disclosed_items[*]}] from ${walk_host} — see ${walk_ev}"
            fi
        done
    elif [[ ${#found_community_hosts[@]} -gt 0 ]] && ! _check_tool snmpwalk; then
        log_wrn "  [T01] snmpwalk not found — install snmp package for full MIB walk (apt install snmp)"
    fi

    if [[ ${#found_community_hosts[@]} -eq 0 ]]; then
        log_ok "  [T01] No guessable SNMP community strings found"
    fi
    log_ok "  [T01] SNMP sweep complete — see ${ev_f}"
}

# - MRK:17_T02 — T02 NETWORK DEVICE DEFAULT CREDENTIALS SPRAY
test_T02_default_creds() {
    local ev_f; ev_f="$(_ev_file "default_creds")"
    local raw_targets; raw_targets="$(_resolve_targets)"

    log_inf "[T02] Network device default credentials spray"

    # Dual gate: deep profile + NETINFRA_SPRAY_ENABLED conf var
    if [[ "${SCAN_PROFILE}" != "deep" ]]; then
        log_inf "  [T02] Default credential spray requires deep profile — skipping (current: ${SCAN_PROFILE})"
        return
    fi
    if [[ "${NETINFRA_SPRAY_ENABLED:-0}" -ne 1 ]]; then
        log_inf "  [T02] NETINFRA_SPRAY_ENABLED=0 — default credential spray disabled in conf (intentional default)"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "hydra SSH/Telnet default creds against ${raw_targets} (admin/admin, admin/cisco, cisco/cisco, admin/<blank>, root/root)"; return; }

    {
        echo "=== T02 Network Device Default Credentials Spray ==="
        echo "Targets  : ${raw_targets}"
        echo "Credentials: admin/admin, admin/cisco, cisco/cisco, admin/<blank>, root/root"
        echo ""
    } > "$ev_f"

    local -a targets_arr
    mapfile -t targets_arr < <(_expand_targets "$raw_targets")

    if [[ ${#targets_arr[@]} -eq 0 ]]; then
        log_wrn "  [T02] No targets resolved — skipping"
        return
    fi

    # Build tiny wordlists for hydra
    local user_file; user_file="$(mktemp)"
    local pass_file; pass_file="$(mktemp)"
    printf 'admin\nadmin\ncisco\nadmin\nroot\n' > "$user_file"
    printf 'admin\ncisco\ncisco\n\nroot\n'      > "$pass_file"

    printf "\n${_R}  [SPRAY WARNING]${_N} Sending default credential attempts to SSH (22) and Telnet (23).\n"
    printf "  Only 5 credential pairs — minimal lockout risk for network devices.\n\n"

    local found_any=0

    for host in "${targets_arr[@]}"; do
        # Determine which ports are open
        local ssh_open=0 telnet_open=0
        if _check_tool nmap; then
            local port_scan
            port_scan=$(timeout 15 nmap -sT -p 22,23 --open -oN - "$host" 2>/dev/null || true)
            echo "$port_scan" | grep -q '22/tcp.*open'  && ssh_open=1
            echo "$port_scan" | grep -q '23/tcp.*open'  && telnet_open=1
        else
            timeout 3 bash -c "echo > /dev/tcp/${host}/22"  2>/dev/null && ssh_open=1    || true
            timeout 3 bash -c "echo > /dev/tcp/${host}/23"  2>/dev/null && telnet_open=1 || true
        fi

        [[ "$ssh_open" -eq 0 && "$telnet_open" -eq 0 ]] && continue

        log_inf "  [T02] Testing ${host} — SSH open: ${ssh_open}, Telnet open: ${telnet_open}"

        if _check_tool hydra; then
            # SSH spray
            if [[ "$ssh_open" -eq 1 ]]; then
                local hydra_ssh
                hydra_ssh=$(timeout 60 hydra -C <(paste "$user_file" "$pass_file" | sed 's/\t/:/' | tr -d ' ') \
                    -t 1 -w 5 ssh://"$host" 2>&1 | grep -E 'login:|ERROR|host:' | head -20 || true)
                echo "--- hydra SSH ${host} ---" >> "$ev_f"
                echo "$hydra_ssh" >> "$ev_f"
                if echo "$hydra_ssh" | grep -qi 'login:.*password:'; then
                    local found_cred
                    found_cred=$(echo "$hydra_ssh" | grep -i 'login:' | head -1)
                    emit_finding "critical" \
                        "Default Credentials Accepted on SSH: ${host}" \
                        "hydra confirmed valid default credentials on ${host} SSH (port 22): ${found_cred}. An attacker can gain shell access to the network device and reconfigure routing, ACLs, or pivot to connected segments." \
                        "Change all default credentials immediately. Disable password authentication on SSH — use key-based authentication only. Enable TACACS+/RADIUS centralised authentication. Disable Telnet and use SSH only." \
                        "default_creds_ssh_${host//\./_}"
                    found_any=1
                fi
            fi

            # Telnet spray
            if [[ "$telnet_open" -eq 1 ]]; then
                local hydra_telnet
                hydra_telnet=$(timeout 60 hydra -C <(paste "$user_file" "$pass_file" | sed 's/\t/:/' | tr -d ' ') \
                    -t 1 -w 5 telnet://"$host" 2>&1 | grep -E 'login:|ERROR|host:' | head -20 || true)
                echo "--- hydra Telnet ${host} ---" >> "$ev_f"
                echo "$hydra_telnet" >> "$ev_f"
                if echo "$hydra_telnet" | grep -qi 'login:.*password:'; then
                    local found_cred_t
                    found_cred_t=$(echo "$hydra_telnet" | grep -i 'login:' | head -1)
                    emit_finding "critical" \
                        "Default Credentials Accepted on Telnet: ${host}" \
                        "hydra confirmed valid default credentials on ${host} Telnet (port 23): ${found_cred_t}. Telnet transmits credentials in cleartext. Full device compromise is possible from the network segment." \
                        "Disable Telnet entirely — replace with SSH (version 2). Change all default credentials. Enforce centralised authentication (TACACS+/RADIUS). Apply management VLAN restrictions." \
                        "default_creds_telnet_${host//\./_}"
                    found_any=1
                fi

                # Telnet open is itself a finding even if creds fail
                emit_finding "medium" \
                    "Telnet Service Enabled on Network Device: ${host}" \
                    "Telnet (port 23) is open on ${host}. Telnet transmits all data including credentials in cleartext, making it susceptible to passive interception on the management network." \
                    "Disable Telnet. Enable SSH v2 for all remote management. Apply management ACLs to restrict access to the management VLAN." \
                    "telnet_open_${host//\./_}"
            fi
        else
            log_wrn "  [T02] hydra not found — using nmap ssh-default-creds NSE fallback"
            # nmap NSE fallback for SSH
            if [[ "$ssh_open" -eq 1 ]]; then
                local nmap_creds
                nmap_creds=$(timeout 60 nmap -p 22 --script ssh-default-creds,telnet-brute \
                    --script-args "brute.mode=user,brute.firstonly=true,userdb=${user_file},passdb=${pass_file}" \
                    -oN - "$host" 2>/dev/null || true)
                echo "--- nmap ssh-default-creds ${host} ---" >> "$ev_f"
                echo "$nmap_creds" >> "$ev_f"
                if echo "$nmap_creds" | grep -qi 'Valid credentials\|Login correct'; then
                    local found_nmap
                    found_nmap=$(echo "$nmap_creds" | grep -iE 'Valid credentials|Login correct' | head -1)
                    emit_finding "critical" \
                        "Default Credentials Accepted on SSH: ${host}" \
                        "nmap NSE confirmed valid default credentials on ${host} SSH: ${found_nmap}. Device takeover is possible." \
                        "Change all default credentials. Use SSH key-based authentication. Deploy centralised AAA (TACACS+/RADIUS)." \
                        "default_creds_nse_${host//\./_}"
                    found_any=1
                fi
            fi
            if [[ "$telnet_open" -eq 1 ]]; then
                emit_finding "medium" \
                    "Telnet Service Enabled on Network Device: ${host}" \
                    "Telnet (port 23) is open on ${host}. Telnet transmits all data including credentials in cleartext." \
                    "Disable Telnet. Enable SSH v2. Apply management ACLs." \
                    "telnet_open_${host//\./_}"
            fi
        fi
    done

    rm -f "$user_file" "$pass_file"

    if [[ "$found_any" -eq 0 ]]; then
        log_ok "  [T02] No default credentials accepted on tested hosts"
    fi
    log_ok "  [T02] Default credential spray complete — see ${ev_f}"
}

# - MRK:17_T03 — T03 VLAN HOPPING PROBE (DTP / 802.1Q)
test_T03_vlan_hopping() {
    local ev_f; ev_f="$(_ev_file "vlan_hopping")"
    local raw_targets; raw_targets="$(_resolve_targets)"

    log_inf "[T03] VLAN hopping probe (DTP / 802.1Q)"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "yersinia dtp / nmap CDP probe; active DTP on iface ${NETINFRA_VLAN_IFACE:-<not set>}"; return; }

    {
        echo "=== T03 VLAN Hopping Probe (DTP / 802.1Q Double-Tagging) ==="
        echo "Targets    : ${raw_targets}"
        echo "VLAN iface : ${NETINFRA_VLAN_IFACE:-<not configured>}"
        echo ""
    } > "$ev_f"

    local -a targets_arr
    mapfile -t targets_arr < <(_expand_targets "$raw_targets")

    # --- Passive: CDP / LLDP detection via nmap NSE ---
    log_inf "  [T03] Passive CDP/LLDP discovery via nmap NSE..."
    if _check_tool nmap; then
        for host in "${targets_arr[@]}"; do
            local cdp_out
            cdp_out=$(timeout 30 nmap -sU -p 5353 --script broadcast-eigrp-discovery,cdp \
                -oN - "$host" 2>/dev/null || true)
            # Also run general discovery on the local broadcast domain
            echo "--- nmap CDP/LLDP ${host} ---" >> "$ev_f"
            echo "$cdp_out" >> "$ev_f"
            if echo "$cdp_out" | grep -qiE 'cdp|lldp|Device ID|Platform'; then
                log_wrn "  [T03] CDP/LLDP information visible from ${host}"
                emit_finding "medium" \
                    "CDP/LLDP Network Device Discovery Enabled: ${host}" \
                    "Cisco Discovery Protocol (CDP) or LLDP is visible from ${host}. Device type, platform, IOS version, and native VLAN information is exposed, enabling targeted VLAN hopping attack preparation." \
                    "Disable CDP globally on access ports (no cdp enable on interfaces). Disable LLDP on untrusted ports. Enable only on uplinks between managed infrastructure. CDP info aids VLAN hopping reconnaissance." \
                    "cdp_lldp_${host//\./_}"
            fi
        done

        # Run broadcast CDP capture (local segment only)
        local cdp_broad
        cdp_broad=$(timeout 30 nmap --script broadcast-cdp-discover 2>/dev/null | head -60 || true)
        if [[ -n "$cdp_broad" ]]; then
            echo "--- broadcast CDP discover ---" >> "$ev_f"
            echo "$cdp_broad" >> "$ev_f"
            if echo "$cdp_broad" | grep -qi 'Device ID\|Platform\|Version'; then
                emit_finding "medium" \
                    "CDP Broadcast Reveals Network Infrastructure Details" \
                    "broadcast-cdp-discover captured CDP announcements: device identifiers, IOS version, native VLAN, and management IP are exposed on the local broadcast domain." \
                    "Disable CDP on all access-layer switchports. Limit CDP to trunk ports between network devices only." \
                    "cdp_broadcast_discovery"
            fi
        fi
    else
        log_wrn "  [T03] nmap not found — CDP/LLDP passive detection skipped"
    fi

    # --- DTP passive detection via nmap broadcast script ---
    if _check_tool nmap; then
        log_inf "  [T03] Checking for DTP trunking negotiation (broadcast probe)..."
        local dtp_broad
        dtp_broad=$(timeout 15 nmap --script broadcast-eigrp-discovery 2>/dev/null | head -30 || true)
        echo "--- broadcast EIGRP/DTP probe ---" >> "$ev_f"
        echo "$dtp_broad" >> "$ev_f"
    fi

    # --- Active yersinia DTP probe if NETINFRA_VLAN_IFACE is configured ---
    if [[ -n "${NETINFRA_VLAN_IFACE:-}" ]]; then
        log_inf "  [T03] Active DTP/802.1Q probe on interface ${NETINFRA_VLAN_IFACE}..."
        printf "  ${_Y}[WARNING]${_N} Sending DTP negotiation frames on ${NETINFRA_VLAN_IFACE}\n"

        if _check_tool yersinia; then
            # yersinia attack 1 = enable trunking (DTP)
            local yers_out
            yers_out=$(timeout 20 yersinia dtp -attack 1 -interface "$NETINFRA_VLAN_IFACE" 2>&1 | head -30 || true)
            echo "--- yersinia DTP attack 1 on ${NETINFRA_VLAN_IFACE} ---" >> "$ev_f"
            echo "$yers_out" >> "$ev_f"

            if echo "$yers_out" | grep -qiE 'Trunk|Trunk mode|DTP|SUCCESS|enable'; then
                emit_finding "high" \
                    "VLAN Hopping: DTP Trunk Negotiation Succeeded on ${NETINFRA_VLAN_IFACE}" \
                    "yersinia successfully negotiated a trunk (DTP attack 1) on interface ${NETINFRA_VLAN_IFACE}. The connected switch port is in dynamic auto/desirable mode and accepted trunking. An attacker can access all VLANs on the trunk, enabling double-tagging to cross VLAN boundaries." \
                    "Disable DTP on all access ports: 'switchport mode access' + 'switchport nonegotiate'. Set explicit VLAN assignments. Disable unused ports. Change the native VLAN from VLAN 1 to an unused VLAN ID." \
                    "vlan_hopping_dtp_active"
            else
                # Still check for DTP frames via tshark even if yersinia did not confirm trunk
                if _check_tool tshark; then
                    local dtp_sniff
                    dtp_sniff=$(timeout 15 tshark -i "$NETINFRA_VLAN_IFACE" \
                        -Y 'dtp or vlan' -a duration:10 2>/dev/null | head -30 || true)
                    echo "--- tshark DTP/VLAN sniff ---" >> "$ev_f"
                    echo "$dtp_sniff" >> "$ev_f"
                    if [[ -n "$dtp_sniff" ]]; then
                        emit_finding "high" \
                            "DTP / VLAN Trunking Frames Observed on ${NETINFRA_VLAN_IFACE}" \
                            "DTP or 802.1Q VLAN tagging frames were captured on interface ${NETINFRA_VLAN_IFACE}, indicating trunk negotiation is active on the switch port. VLAN hopping via double-tagging may be feasible." \
                            "Configure access ports with 'switchport mode access; switchport nonegotiate'. Disable DTP. Set native VLAN to an unused VLAN. Apply BPDU guard on access ports." \
                            "vlan_dtp_frames_tshark"
                    else
                        log_ok "  [T03] No DTP frames captured — switch port appears to be in access mode"
                    fi
                fi
            fi
        else
            log_wrn "  [T03] yersinia not found — using tshark for passive DTP frame detection"
            if _check_tool tshark; then
                log_inf "  [T03] Passive DTP/VLAN frame capture on ${NETINFRA_VLAN_IFACE} (15s)..."
                local dtp_passive
                dtp_passive=$(timeout 20 tshark -i "$NETINFRA_VLAN_IFACE" \
                    -Y 'dtp or vlan' -a duration:15 2>/dev/null | head -40 || true)
                echo "--- tshark DTP/VLAN passive ${NETINFRA_VLAN_IFACE} ---" >> "$ev_f"
                echo "$dtp_passive" >> "$ev_f"
                if [[ -n "$dtp_passive" ]]; then
                    emit_finding "high" \
                        "DTP / VLAN Trunking Frames Observed on ${NETINFRA_VLAN_IFACE}" \
                        "DTP or 802.1Q VLAN tagging frames were captured passively on ${NETINFRA_VLAN_IFACE}. VLAN hopping attack may be feasible. Install yersinia for active DTP negotiation testing." \
                        "Configure 'switchport mode access; switchport nonegotiate' on all access ports. Set native VLAN to an unused ID. Apply BPDU guard." \
                        "vlan_dtp_passive_tshark"
                else
                    log_ok "  [T03] No DTP/VLAN frames captured passively — access mode appears enforced"
                fi
            else
                log_wrn "  [T03] Neither yersinia nor tshark available — active VLAN probe skipped"
                echo "[T03] MANUAL CHECK: Install yersinia or tshark for active DTP probe on ${NETINFRA_VLAN_IFACE}" >> "$ev_f"
            fi
        fi
    else
        log_inf "  [T03] NETINFRA_VLAN_IFACE not set — skipping active DTP/802.1Q probe"
        log_inf "  [T03] Set NETINFRA_VLAN_IFACE=<eth0> in pt-orc.conf or use --iface for active testing"
        echo "[T03] NETINFRA_VLAN_IFACE not configured — active probe skipped" >> "$ev_f"
    fi

    log_ok "  [T03] VLAN hopping probe complete — see ${ev_f}"
}

# - MRK:17_T04 — T04 PRINTER ENUMERATION
test_T04_printer_enum() {
    local ev_f; ev_f="$(_ev_file "printer_enum")"
    local raw_targets; raw_targets="$(_resolve_targets)"

    log_inf "[T04] Printer enumeration (PJL/LPD/IPP/SNMP)"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "nmap -p 9100,515,631,80,443 + PJL banner grab + SNMP printer MIB on ${raw_targets}"; return; }

    {
        echo "=== T04 Printer Enumeration (PJL/IPP/LPD/SNMP) ==="
        echo "Targets  : ${raw_targets}"
        echo "Ports    : 9100 (PJL), 515 (LPD), 631 (IPP), 80 (HTTP), 443 (HTTPS)"
        echo ""
    } > "$ev_f"

    local -a targets_arr
    mapfile -t targets_arr < <(_expand_targets "$raw_targets")

    if [[ ${#targets_arr[@]} -eq 0 ]]; then
        log_wrn "  [T04] No targets resolved — skipping"
        return
    fi

    local printer_count=0

    for host in "${targets_arr[@]}"; do
        local host_has_printer=0

        # Port scan: 9100, 515, 631, 80, 443
        local open_ports=""
        if _check_tool nmap; then
            local port_scan
            port_scan=$(timeout 60 nmap -sT -p 9100,515,631,80,443 --open -oN - "$host" 2>/dev/null || true)
            echo "--- port scan ${host} ---" >> "$ev_f"
            echo "$port_scan" >> "$ev_f"
            open_ports=$(echo "$port_scan" | grep '/tcp.*open' | awk '{print $1}' | tr '\n' ' ')
        else
            for port in 9100 515 631 80 443; do
                if timeout 3 bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; then
                    open_ports+="${port}/tcp "
                fi
            done
        fi

        [[ -z "$open_ports" ]] && continue

        log_inf "  [T04] ${host} — open ports: ${open_ports}"
        echo "Host: ${host}  Open: ${open_ports}" >> "$ev_f"

        # PJL banner grab (port 9100)
        if echo "$open_ports" | grep -q '9100'; then
            host_has_printer=1
            log_inf "  [T04] PJL port 9100 open on ${host} — grabbing banner"
            local pjl_banner
            pjl_banner=$(printf '@PJL INFO ID\r\n' | timeout 5 nc -w3 "$host" 9100 2>/dev/null | head -10 || true)
            echo "--- PJL banner ${host}:9100 ---" >> "$ev_f"
            echo "${pjl_banner:-<no response>}" >> "$ev_f"

            if [[ -n "$pjl_banner" ]]; then
                log_wrn "  [T04] PJL accepted on ${host} — ${pjl_banner:0:80}"
                emit_finding "medium" \
                    "PJL Port 9100 Accepts Commands: ${host}" \
                    "Port 9100 (PJL — Printer Job Language) on ${host} accepted a PJL INFO ID query and returned: '${pjl_banner:0:120}'. PJL access allows reading the printer filesystem, extracting stored print jobs (potentially containing sensitive documents), changing device settings, and denial of service." \
                    "Block port 9100 at the network perimeter and on host-based firewalls. Disable PJL remote administration if not required. Restrict printer access to authorised VLAN/subnets. Enable authentication on the printer web UI." \
                    "pjl_open_${host//\./_}"
            else
                # Port open but no PJL response — still flag as printer surface
                emit_finding "low" \
                    "PJL Port 9100 Open (No Response): ${host}" \
                    "Port 9100 is open on ${host} but did not respond to PJL INFO ID. The port may still accept raw print jobs or other PJL commands that could enable data leakage or DoS." \
                    "Block port 9100 from untrusted networks. Restrict raw print access to authorised hosts. Verify printer firmware is up to date." \
                    "pjl_noresp_${host//\./_}"
            fi

            # Additional PJL enumeration
            local pjl_env
            pjl_env=$(printf '@PJL INFO STATUS\r\n@PJL INFO VARIABLES\r\n' \
                | timeout 5 nc -w3 "$host" 9100 2>/dev/null | head -30 || true)
            if [[ -n "$pjl_env" ]]; then
                echo "--- PJL STATUS/VARIABLES ---" >> "$ev_f"
                echo "$pjl_env" >> "$ev_f"
            fi
        fi

        # LPD (port 515)
        if echo "$open_ports" | grep -q '515'; then
            host_has_printer=1
            log_inf "  [T04] LPD port 515 open on ${host}"
            echo "--- LPD 515 open on ${host} ---" >> "$ev_f"
            # Queue listing: send RFC 1179 short-queue request
            local lpd_banner
            lpd_banner=$(printf '\x01\n' | timeout 5 nc -w3 "$host" 515 2>/dev/null | strings | head -5 || true)
            echo "${lpd_banner:-<no LPD response>}" >> "$ev_f"
        fi

        # IPP (port 631)
        if echo "$open_ports" | grep -q '631'; then
            host_has_printer=1
            log_inf "  [T04] IPP port 631 open on ${host}"
            # Query IPP with a Get-Printer-Attributes request
            if _check_tool curl; then
                local ipp_attrs
                # IPP Get-Printer-Attributes request (minimal binary encoded payload)
                ipp_attrs=$(timeout 10 curl -s -m 8 \
                    -H 'Content-Type: application/ipp' \
                    --data-binary $'\x01\x01\x00\x0b\x00\x00\x00\x01\x01G\x00\x12attributes-charset\x00\x05utf-8H\x00\x1battributes-natural-language\x00\x05en-us\x03' \
                    "http://${host}:631/ipp/print" 2>/dev/null | strings | head -10 || true)
                echo "--- IPP attrs ${host}:631 ---" >> "$ev_f"
                echo "${ipp_attrs:-<no IPP response>}" >> "$ev_f"
                if [[ -n "$ipp_attrs" ]]; then
                    log_wrn "  [T04] IPP responding on ${host}:631 — printer attributes accessible"
                fi
            fi
        fi

        # HTTP/HTTPS admin web UI (ports 80, 443)
        for web_port in 80 443; do
            local proto="http"; [[ "$web_port" -eq 443 ]] && proto="https"
            if echo "$open_ports" | grep -q "${web_port}/tcp"; then
                host_has_printer=1
                if _check_tool curl; then
                    local web_banner
                    web_banner=$(timeout 10 curl -sk -m 8 \
                        -o /dev/null -w '%{http_code} %{content_type}' \
                        "${proto}://${host}:${web_port}/" 2>/dev/null || echo "000 error")
                    local http_code; http_code=$(echo "$web_banner" | awk '{print $1}')
                    echo "--- HTTP ${proto}://${host}:${web_port}/ → ${web_banner} ---" >> "$ev_f"

                    if [[ "$http_code" =~ ^[23] ]]; then
                        # Check if it looks like a printer admin page
                        local page_title
                        page_title=$(timeout 10 curl -sk -m 8 "${proto}://${host}:${web_port}/" \
                            2>/dev/null | grep -ioP '(?<=<title>)[^<]+' | head -1 || true)
                        echo "  Title: ${page_title:-unknown}" >> "$ev_f"

                        if echo "${page_title}" | grep -qiE 'HP|Lexmark|Canon|Epson|Brother|Xerox|Ricoh|Konica|printer|LaserJet|MFP|print server|Embedded Web'; then
                            emit_finding "medium" \
                                "Printer Admin Web UI Accessible: ${proto}://${host}:${web_port} (${page_title:-unknown})" \
                                "A printer/MFP web administration interface is accessible at ${proto}://${host}:${web_port}/. Device title: '${page_title:-unknown}'. Default or weak credentials may allow configuration changes, firmware updates, access to stored print jobs, or network settings modification." \
                                "Require authentication on the printer web UI. Change default credentials. Restrict access to management VLAN. Disable unused remote management services. Keep printer firmware updated." \
                                "printer_webui_${host//\./_}_${web_port}"
                        fi
                    fi
                fi
            fi
        done

        # SNMP printer MIB (OID 1.3.6.1.2.1.43 — Printer-MIB)
        if _check_tool snmpwalk; then
            for comm in ${NETINFRA_SNMP_COMMUNITIES}; do
                local printer_mib
                printer_mib=$(timeout 15 snmpwalk -c "$comm" -v2c "$host" \
                    1.3.6.1.2.1.43 2>/dev/null | head -20 || true)
                if [[ -n "$printer_mib" ]]; then
                    host_has_printer=1
                    echo "--- SNMP Printer MIB ${host} (community=${comm}) ---" >> "$ev_f"
                    echo "$printer_mib" >> "$ev_f"
                    emit_finding "low" \
                        "SNMP Printer MIB Accessible: ${host} (community '${comm}')" \
                        "SNMP Printer-MIB (OID 1.3.6.1.2.1.43) is accessible on ${host} with community '${comm}'. Printer model, toner levels, page counts, and error logs are exposed. This confirms SNMP v1/v2c with a guessable community on a printer device." \
                        "Upgrade to SNMPv3. Disable SNMPv1/v2c. Change community strings to unpredictable values. Apply SNMP ACLs to restrict to management hosts." \
                        "printer_snmp_mib_${host//\./_}"
                    break
                fi
            done
        fi

        [[ "$host_has_printer" -eq 1 ]] && (( printer_count++ )) || true
    done

    if [[ "$printer_count" -eq 0 ]]; then
        log_ok "  [T04] No printer services found on scanned targets"
    else
        log_wrn "  [T04] Printer services found on ${printer_count} host(s)"
    fi
    log_ok "  [T04] Printer enumeration complete — see ${ev_f}"
}

# - MRK:17_T05 — T05 NETWORK SEGMENTATION VALIDATION
test_T05_segmentation() {
    local ev_f; ev_f="$(_ev_file "segmentation")"

    log_inf "[T05] Network segmentation validation"

    if [[ -z "${NETINFRA_SEGMENT_PROBES:-}" ]]; then
        log_inf "  [T05] NETINFRA_SEGMENT_PROBES not set — skipping"
        log_inf "  [T05] Set NETINFRA_SEGMENT_PROBES='10.10.20.0/24 192.168.99.0/24' in pt-orc.conf to test"
        echo "[T05] NETINFRA_SEGMENT_PROBES not configured — skipping" > "$ev_f"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "nmap ping+TCP probe on NETINFRA_SEGMENT_PROBES: ${NETINFRA_SEGMENT_PROBES}"; return; }

    {
        echo "=== T05 Network Segmentation Validation ==="
        echo "Segment probes: ${NETINFRA_SEGMENT_PROBES}"
        echo "Key ports     : 22, 80, 443, 445, 3389"
        echo ""
    } > "$ev_f"

    local -a seg_targets=()
    for seg in ${NETINFRA_SEGMENT_PROBES}; do
        mapfile -t _seg_ips < <(_expand_targets "$seg")
        seg_targets+=("${_seg_ips[@]}")
    done

    if [[ ${#seg_targets[@]} -eq 0 ]]; then
        log_wrn "  [T05] No segment probe targets resolved"
        echo "[T05] No targets resolved from NETINFRA_SEGMENT_PROBES" >> "$ev_f"
        return
    fi

    log_inf "  [T05] Probing ${#seg_targets[@]} host(s) across segment(s): ${NETINFRA_SEGMENT_PROBES}"

    local -a reachable_hosts=()

    if _check_tool nmap; then
        # Single nmap sweep across all segment probes — ping + key ports
        local seg_scan
        # shellcheck disable=SC2046
        seg_scan=$(timeout 120 nmap -sT -Pn --open \
            -p 22,80,443,445,3389 \
            --max-retries 1 --host-timeout 10s \
            -oN - ${NETINFRA_SEGMENT_PROBES} 2>/dev/null || true)
        echo "$seg_scan" >> "$ev_f"

        # Parse responding hosts
        while IFS= read -r line; do
            if echo "$line" | grep -q 'Nmap scan report'; then
                local scan_host
                scan_host=$(echo "$line" | awk '{print $NF}')
                # Check if next lines show open ports
                local open_check
                open_check=$(echo "$seg_scan" | \
                    awk "/scan report.*${scan_host}/,/Nmap scan report/" | \
                    grep 'open' | head -3 || true)
                if [[ -n "$open_check" ]]; then
                    reachable_hosts+=("$scan_host")
                fi
            fi
        done <<< "$seg_scan"
    else
        # Fallback: ping + nc port check
        for host in "${seg_targets[@]}"; do
            local is_reachable=0
            if ping -c 1 -W 2 "$host" &>/dev/null 2>&1; then
                is_reachable=1
            else
                for port in 22 80 443 445 3389; do
                    if timeout 3 bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; then
                        is_reachable=1
                        break
                    fi
                done
            fi
            if [[ "$is_reachable" -eq 1 ]]; then
                reachable_hosts+=("$host")
            fi
        done
    fi

    if [[ ${#reachable_hosts[@]} -gt 0 ]]; then
        log_wrn "  [T05] ${#reachable_hosts[@]} host(s) reachable from restricted segment(s): ${reachable_hosts[*]}"
        {
            echo ""
            echo "=== REACHABLE HOSTS (should be unreachable) ==="
            printf '%s\n' "${reachable_hosts[@]}"
        } >> "$ev_f"

        local reachable_str; reachable_str=$(printf '%s ' "${reachable_hosts[@]}")
        emit_finding "high" \
            "Network Segmentation Failure: ${#reachable_hosts[@]} Host(s) Reachable from Restricted Segment" \
            "The following host(s) responded to probes from the test host, but belong to network segment(s) expected to be unreachable: ${reachable_str}. Tested ports: 22,80,443,445,3389. Segment probe config: ${NETINFRA_SEGMENT_PROBES}. This indicates firewall rules, ACLs, or VLAN boundaries are not enforcing the intended segmentation policy." \
            "Review and tighten firewall/ACL rules between network segments. Verify VLAN trunk policies and inter-VLAN routing ACLs. Use a zero-trust network model — deny by default, allow by exception. Confirm the intended isolation policy for each probed segment and align firewall rules accordingly." \
            "segmentation_failure"
    else
        log_ok "  [T05] No hosts responded from probed restricted segment(s) — segmentation appears effective"
        echo "[T05] RESULT: All probed segment hosts were unreachable — segmentation effective." >> "$ev_f"
    fi

    log_ok "  [T05] Segmentation validation complete — see ${ev_f}"
}

# =============================================================================
# - MRK:17_TRUN
# =============================================================================
_run_tests() {
    local find_before="$_FIND_CTR"

    log_inf "=== Running Network Infrastructure Tests ==="

    _test_skip T01 || test_T01_snmp_sweep
    _test_skip T02 || test_T02_default_creds
    _test_skip T03 || test_T03_vlan_hopping
    _test_skip T04 || test_T04_printer_enum
    _test_skip T05 || test_T05_segmentation

    local find_delta=$(( _FIND_CTR - find_before ))
    echo "$find_delta"
}

# =============================================================================
# - MRK:17_MAIN
# =============================================================================
main() {
    printf "\n${_W}╔══════════════════════════════════════════════════════╗${_N}\n"
    printf "${_W}║  PT-Orc  ·  Step 17: Network Infrastructure Testing  ║${_N}\n"
    printf "${_W}╚══════════════════════════════════════════════════════╝${_N}\n\n"

    log_inf "Project  : ${PROJECT_NAME}"
    log_inf "Profile  : ${SCAN_PROFILE}"
    log_inf "Targets  : ${NETINFRA_TARGETS:-<from TARGET_SUBNETS / TARGET_IPS>}"
    log_inf "Spray    : ${NETINFRA_SPRAY_ENABLED}"
    log_inf "VLAN if  : ${NETINFRA_VLAN_IFACE:-<not set>}"
    log_inf "Session  : ${SESSION_TS}"
    log_inf "Log      : ${LOG_FILE}"

    _validate_config || exit 1
    setup_profile "$SCAN_PROFILE"
    _confirm

    command -v trail_phase_start &>/dev/null && trail_phase_start "17_network_infra"

    local total_findings
    total_findings=$(_run_tests)

    command -v trail_phase_end &>/dev/null && trail_phase_end "17_network_infra"

    # Summary report
    local report_f="${SCRIPT_DIR}/working/$(ev_fname "17-netinfra-summary" "md")"
    {
        printf "# Network Infrastructure Testing Summary — %s\n\n" "$PROJECT_NAME"
        printf "| Profile | Targets | Findings |\n|---------|---------|----------|\n"
        printf "| %s | %s | %d |\n" \
            "$SCAN_PROFILE" \
            "${NETINFRA_TARGETS:-TARGET_SUBNETS/TARGET_IPS}" \
            "$total_findings"
        printf "\n**Total Findings:** %d\n" "$total_findings"
        printf "\nFindings JSONL: \`%s\`\n" "$FINDINGS_FILE"
        printf "\nEvidence dir  : \`%s\`\n" "$EVIDENCE_BASE"
    } > "$report_f"

    printf "\n${_G}[DONE]${_N} Network infrastructure testing complete.\n"
    printf "  Profile  : %s\n" "$SCAN_PROFILE"
    printf "  Findings : %d\n" "$total_findings"
    printf "  Summary  : %s\n" "$report_f"
    printf "  Evidence : %s\n\n" "$EVIDENCE_BASE"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
