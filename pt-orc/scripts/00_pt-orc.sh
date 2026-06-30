#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:00_NAV_TOC — Section index | nav,toc,index | L5-60
# - MRK:00_ROOT — ROOT CHECK | root,check | L61-66 | ⚠ no-insert-before
# - MRK:00_CONF — ENGAGEMENT CONFIG | conf,engagement,config,edit,pt | L67-74 | ⚠ no-insert-before; propose-before-edit
# - MRK:00_LOG — COLOURS AND LOGGING + STEP BANNER | log,colours,logging,step,banner | L75-104 | ⚠ no-insert-before
# - MRK:00_DEFAULTS — DEFAULTS + STEP STATUS ACCUMULATORS | defaults,step,status,accumulators | L105-140 | ⚠ no-insert-before
# - MRK:00_USAGE — USAGE BANNER | usage,banner | L141-243 | ⚠ no-insert-before; read-toc-first
# - MRK:00_ARGS — ARGUMENT PARSING | args,argument,parsing | L244-278 | ⚠ no-insert-before
# - MRK:00_DISCOVER — SCRIPT DISCOVERY | discover,script,discovery,find,subscript | L279-310 | ⚠ no-insert-before
# - MRK:00_CONTROL — STEP CONTROL | control,step,should,run,skip | L311-330 | ⚠ no-insert-before
# - MRK:00_RUNNER — STEP RUNNER | runner,step,invoke,subscript,capture | L331-373 | ⚠ no-insert-before; read-toc-first
# - MRK:00_SUMMARY — SUMMARY TABLE | summary,table,final,status,overview | L374-440 | ⚠ no-insert-before; read-toc-first
# - MRK:00_MAIN — MAIN | main,banner,run,loop,summary | L441-603 | ⚠ no-insert-before; read-toc-first
# NAV-LEN: 11 entries | Integrity-hash: 71368cc4f325b40a | Last-indexed: 2026-06-09T07:17:36Z

# =============================================================================
# 00_pt-orc.sh — PT-Orc Suite Orchestrator — runs steps 1–9 and 12 sequentially.
# TechGuard.
# =============================================================================
# Coordinates the full PT-Orc 10-script suite. Runs all steps sequentially,
# forwards flags to each subscript, and suppresses interactive prompts when
# --yes is passed.
#
# USAGE:
#   sudo ./00_pt-orc.sh [OPTIONS]
#
# OPTIONS:
#   --yes               Bypass all interactive scope prompts (required for
#                       unattended / automated runs)
#   --mode <pti|pte>    Engagement mode (default: from pt-orc.conf)
#   --tier <t>          ghost|normal|loud|evasion (default: from pt-orc.conf)
#   --from <N>          Start from step N (1-7); default 1
#   --only <N>          Run only step N; skip all others
#   --skip <N>          Skip step N; repeatable (--skip 1 --skip 2)
#   --dry-run           No packets sent; prints what would run
#   --skip-active       01: skip AXFR and DNS brute-force
#   --phase <name>      03: tcp|udp|enum|report|all (forwarded to 03 only)
#   --masscan-only      03: stop after Pass 1 fast scan (forwarded to 03 only)
#   --fast              04+05: headers/tech detection only; skip gobuster+nikto
#   --skip-gobuster     05: skip directory brute-force
#   --skip-nikto        05: skip Nikto scan
#   --no-wp-detect      06: skip WP detection sweep (use existing wp_targets.txt)
#   --continue-on-error Continue to next step even if a step fails
#   -h|--help           Show this help and exit
#
# EXAMPLES:
#   sudo ./00_pt-orc.sh --yes
#   sudo ./00_pt-orc.sh --yes --from 3 --tier ghost
#   sudo ./00_pt-orc.sh --yes --only 4
#   sudo ./00_pt-orc.sh --yes --skip 1 --skip 2
#   sudo ./00_pt-orc.sh --yes --mode pti --tier normal
#   sudo ./00_pt-orc.sh --dry-run --yes
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# MRK:00_ROOT — ROOT CHECK | root,check | L61-66
# NAV-RULE: no-insert-before
# Root check runs inside main() so --help / --list-profiles work without sudo.
# =============================================================================

# =============================================================================
# MRK:00_CONF — ENGAGEMENT CONFIG | conf,engagement,config,edit,pt | L67-74
# NAV-RULE: no-insert-before; propose-before-edit
# =============================================================================
# shellcheck source=pt-orc.conf
[[ -f "${SCRIPT_DIR}/pt-orc.conf" ]] && source "${SCRIPT_DIR}/pt-orc.conf" \
    || echo "[WARN] pt-orc.conf not found in ${SCRIPT_DIR} — script defaults in effect"

# =============================================================================
# MRK:00_LOG — COLOURS AND LOGGING + STEP BANNER | log,colours,logging,step,banner | L75-104
# NAV-RULE: no-insert-before
# =============================================================================
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

_now() { date +'%Y-%m-%d %H:%M:%S'; }
_ts()  { date +'%Y%m%d_%H%M%S'; }
SESSION_TS="$(_ts)"

mkdir -p working
LOG_FILE="working/pt-orc_${SESSION_TS}.log"

log()      { local m="[$(_now)] $1";     echo -e "${BLUE}${m}${NC}";           echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()   { local m="[$(_now)] ✓ $1";  echo -e "${GREEN}${m}${NC}";           echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn() { local m="[$(_now)] ⚠ $1";  echo -e "${YELLOW}${m}${NC}";          echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err()  { local m="[$(_now)] ✗ $1";  echo -e "${RED}${m}${NC}" >&2;         echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_step() {
    local n="$1" name="$2" script="$3"
    local line; line="$(printf '━%.0s' {1..52})"
    echo ""
    echo -e "${BOLD}${BLUE}${line}${NC}"
    echo -e "${BOLD}${BLUE}  STEP ${n} — ${name}${NC}"
    echo -e "${BOLD}${BLUE}  $(basename "${script:-?}")${NC}"
    echo -e "${BOLD}${BLUE}${line}${NC}"
    echo ""
    echo "[$(_now)] START step ${n} — ${name} — $(basename "${script:-?}")" >> "$LOG_FILE" 2>/dev/null || true
}

# =============================================================================
# MRK:00_DEFAULTS — DEFAULTS + STEP STATUS ACCUMULATORS | defaults,step,status,accumulators | L105-140
# NAV-RULE: no-insert-before
# =============================================================================
AUTO_YES=0
DRY_RUN=0
MODE="${MODE:-pte}"
GLOBAL_TIER="${GLOBAL_TIER:-normal}"
FROM_STEP=1
ONLY_STEP=0
SKIP_STEPS=()
PROFILE_OVERRIDE=""
OPT_SKIP_ACTIVE=0
OPT_SKIP_GOBUSTER=0
OPT_SKIP_NIKTO=0
OPT_FAST=0
OPT_NO_WP_DETECT=0
OPT_REUSE_WORKSPACE=0
OPT_PHASE_CONTINUE=0
CONTINUE_ON_ERROR=0
OPT_AGGRESSIVE=0
OPT_NUCLEI=0
OPT_RETEST=0
OPT_API_KEY=""
OPT_PROJECT_ID=""
OPT_BURP_KEY=""
DO_RECOMMEND=0

# Steps that continue after failure regardless of --continue-on-error.
# These are opportunistic scans only relevant when a specific condition is met
# (e.g., WPScan only matters if WordPress is present on a target).
SOFT_STEPS=(7)

# Result tracking (steps 1-25)
declare -A STEP_STATUS
declare -A STEP_DURATION
declare -A STEP_SCRIPT
for _n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
    STEP_STATUS[$_n]="—"
    STEP_DURATION[$_n]="—"
    STEP_SCRIPT[$_n]="—"
done

# =============================================================================
# MRK:00_USAGE — USAGE BANNER | usage,banner | L141-243
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================
usage() {
    cat <<EOF
Usage: sudo ./00_pt-orc.sh [OPTIONS]

Profile selection (auto-selects which steps to run):
  --profile <name>      Run the named profile's step set (overrides pt-orc.conf
                        ENGAGEMENT_PROFILE). Profiles: external internal web api
                        ai_llm cloud ad hybrid retest
  --list-profiles       Print all profiles with their step lists and exit

Step control (override profile selection):
  --from <N>            Start from step N (1–25)
  --only <N>            Run only step N
  --skip <N>            Skip step N; repeatable: --skip 1 --skip 2

General:
  --yes                 Bypass all interactive scope prompts (required for
                        unattended runs)
  --mode <pti|pte>      Engagement mode (default: from pt-orc.conf)
  --tier <t>            ghost|normal|loud|evasion (default: from pt-orc.conf)
  --dry-run             No packets sent; prints what would run
  --continue-on-error   Continue to next step if a step fails
  --recommend           AI step recommendation: reads working/ for discovered
                        services and findings, then suggests which steps to run
                        next (requires orc-ai-lib.sh + an AI backend)
  -h|--help             Show this help and exit

Per-step flags:
  --skip-active         01: skip AXFR and DNS brute-force
  --phase <name>        04: tcp|udp|enum|report|all
  --continue            04: continue subsequent phases after --phase
  --masscan-only        04: stop after Pass 1 fast scan
  --reuse-workspace     04: reuse existing MSF workspace
  --fast                05+08: headers/tech detection only; skip gobuster+nikto
  --skip-gobuster       08: skip directory brute-force
  --skip-nikto          08: skip Nikto scan
  --no-wp-detect        09: skip WP detection sweep
  --aggressive          13: aggressive probe mode (more CVE checks)
  --nuclei              13: run nuclei templates after service probes
  --api-key <key>       16: bearer/API key for authenticated LLM testing
  --burp-key <key>      11: override BURP_API_KEY from pt-orc.conf
  --project-id <uuid>   25: override ORCHESTRATOR_PROJECT_ID from pt-orc.conf
  --retest              25: set retest_status=pending in report_bundle

Steps:
  Recon:    1  DNS Recon       2  OSINT Recon    3  IP Analysis
  Network:  4  Comp Scan       5  TLS Scan       6  Network Infra   7  Wireless
  Web:      8  Web Enum        9  WPScan        10  Auth/SSO       11  Active Fuzz  12  Content Sec
  App/API: 13  Svc Verify     14  App/API       15  API Deep       16  AI/LLM
  Cloud:   17  Cloud Testing  18  CI/CD DevOps  19  Secrets Scan
  AD/Infra:20  AD Testing     21  Lateral Move  22  DB Audit
  Analysis:23  Vuln Corpus    24  Attack Chain
  Report:  25  Report Pack    ← exports to TG Audit Orchestrator

Examples:
  sudo ./00_pt-orc.sh --profile web --yes
  sudo ./00_pt-orc.sh --profile external --tier ghost --yes
  sudo ./00_pt-orc.sh --profile api --yes --dry-run
  sudo ./00_pt-orc.sh --yes --from 3 --tier ghost
  sudo ./00_pt-orc.sh --yes --only 4
  sudo ./00_pt-orc.sh --list-profiles
EOF
}

list_profiles() {
    # Resolve step list for a profile variable name
    _profile_steps() {
        local var="PROFILE_STEPS_${1}"
        echo "${!var:-[not configured]}"
    }
    cat <<EOF

  PT-Orc Profile Reference
  ─────────────────────────────────────────────────────────
  Profile     Description                  Steps
  ─────────────────────────────────────────────────────────
  external    Full external (black-box) PT  $(_profile_steps external)
  internal    Full internal (white-box) PT  $(_profile_steps internal)
  web         Web application only          $(_profile_steps web)
  api         API-only (no comp scan/WP)    $(_profile_steps api)
  ai_llm      AI / LLM endpoint review      $(_profile_steps ai_llm)
  cloud       Cloud infrastructure          $(_profile_steps cloud)
  ad          Active Directory              $(_profile_steps ad)
  hybrid      Hybrid (all steps)            $(_profile_steps hybrid)
  retest      Re-test / verification only   $(_profile_steps retest)
  ─────────────────────────────────────────────────────────

  Step reference:
    Recon:   1 DNS Recon    2 OSINT       3 IP Analysis
    Network: 4 Comp Scan    5 TLS Scan    6 Net Infra   7 Wireless
    Web:     8 Web Enum     9 WPScan     10 Auth/SSO   11 Active Fuzz  12 Content Sec
    App:    13 Svc Verify  14 App/API    15 API Deep   16 AI/LLM
    Cloud:  17 Cloud       18 CI/CD      19 Secrets
    AD:     20 AD Testing  21 Lateral    22 DB Audit
    Finish: 23 Vuln Corpus 24 Atk Chain  25 Report Pack

  Usage:
    sudo ./00_pt-orc.sh --profile web --yes
    sudo ./00_pt-orc.sh --profile external --tier ghost --yes
    sudo ./00_pt-orc.sh --profile retest --yes --from 5

  Or set ENGAGEMENT_PROFILE in pt-orc.conf for the default profile.

EOF
}

# =============================================================================
# MRK:00_ARGS — ARGUMENT PARSING | args,argument,parsing | L244-278
# NAV-RULE: no-insert-before
# =============================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)           PROFILE_OVERRIDE="$2"; shift 2 ;;
        --list-profiles)     list_profiles; exit 0 ;;
        --yes)               AUTO_YES=1; shift ;;
        --dry-run)           DRY_RUN=1; shift ;;
        --mode)              MODE="$2"; shift 2 ;;
        --tier)              GLOBAL_TIER="$2"; shift 2 ;;
        --from)              FROM_STEP="$2"; shift 2 ;;
        --only)              ONLY_STEP="$2"; shift 2 ;;
        --skip)              SKIP_STEPS+=("$2"); shift 2 ;;
        --skip-active)       OPT_SKIP_ACTIVE=1; shift ;;
        --phase)             OPT_PHASE="$2"; shift 2 ;;
        --masscan-only)      OPT_MASSCAN_ONLY=1; shift ;;
        --reuse-workspace)   OPT_REUSE_WORKSPACE=1; shift ;;
        --continue)          OPT_PHASE_CONTINUE=1; shift ;;
        --skip-gobuster)     OPT_SKIP_GOBUSTER=1; shift ;;
        --skip-nikto)        OPT_SKIP_NIKTO=1; shift ;;
        --fast)              OPT_FAST=1; shift ;;
        --no-wp-detect)      OPT_NO_WP_DETECT=1; shift ;;
        --continue-on-error) CONTINUE_ON_ERROR=1; shift ;;
        --recommend)         DO_RECOMMEND=1; shift ;;
        --aggressive)        OPT_AGGRESSIVE=1; shift ;;
        --nuclei)            OPT_NUCLEI=1; shift ;;
        --api-key)           OPT_API_KEY="$2"; shift 2 ;;
        --burp-key)          OPT_BURP_KEY="$2"; shift 2 ;;
        --project-id)        OPT_PROJECT_ID="$2"; shift 2 ;;
        --retest)            OPT_RETEST=1; shift ;;
        -h|--help)           usage; exit 0 ;;
        *) log_err "Unknown argument: $1"; usage; exit 1 ;;
    esac
done

# =============================================================================
# MRK:00_DISCOVER — SCRIPT DISCOVERY | discover,script,discovery,find,subscript | L279-310
# NAV-RULE: no-insert-before
# =============================================================================
# Finds the subscript for step N. Prefers unversioned 0N_*.sh (normalised form);
# falls back to highest-versioned 0N_*_v[0-9]*.sh if no unversioned variant exists.
# Excludes ACTUAL_RUN subdirectory.
# NOTE: versioned scripts must use _v<digit> suffix (e.g. 08_web_enum_v2.sh) to avoid
# false matches on script names containing _v (e.g. service_verify, vuln_corpus).
find_script() {
    local n="$1"
    local prefix
    prefix="${SCRIPT_DIR}/$(printf '%02d' "$n")_"
    local unversioned=()
    local matches=()
    local f
    for f in "${prefix}"*_v[0-9]*.sh; do
        [[ -f "$f" ]] || continue
        [[ "$f" == */ACTUAL_RUN/* ]] && continue
        matches+=("$f")
    done
    for f in "${prefix}"*.sh; do
        [[ -f "$f" ]] || continue
        [[ "$f" == */ACTUAL_RUN/* ]] && continue
        [[ "${f##*/}" == *_v[0-9]*.sh ]] && continue
        unversioned+=("$f")
    done
    if [[ "${#unversioned[@]}" -gt 0 ]]; then
        printf '%s\n' "${unversioned[@]}" | sort | head -1
        return 0
    fi
    [[ "${#matches[@]}" -gt 0 ]] && printf '%s\n' "${matches[@]}" | sort | tail -1 || true
}

# =============================================================================
# MRK:00_CONTROL — STEP CONTROL | control,step,should,run,skip | L311-330
# NAV-RULE: no-insert-before
# =============================================================================
is_soft_step() {
    local n="$1" s
    for s in "${SOFT_STEPS[@]+"${SOFT_STEPS[@]}"}"; do
        [[ "$n" -eq "$s" ]] && return 0
    done
    return 1
}

should_run() {
    local n="$1"
    # --only: run only that step
    if [[ "$ONLY_STEP" -ne 0 ]]; then
        [[ "$n" -eq "$ONLY_STEP" ]] && return 0 || return 1
    fi
    # --skip: explicitly skipped steps (evaluated before --from so explicit skip always wins)
    local s
    for s in "${SKIP_STEPS[@]+"${SKIP_STEPS[@]}"}"; do
        [[ "$n" -eq "$s" ]] && return 1
    done
    # Step 25 (Report Pack) is intentionally last in the run loop regardless of its number.
    # Never filter it by --from; only an explicit --skip 25 can suppress it.
    [[ "$n" -eq 25 ]] && return 0
    # --from: skip steps whose number is below the start point
    [[ "$n" -lt "$FROM_STEP" ]] && return 1
    return 0
}

# =============================================================================
# MRK:00_RUNNER — STEP RUNNER | runner,step,invoke,subscript,capture | L331-373
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================
# Usage: run_step <n> <name> [flags_to_pass...]
run_step() {
    local n="$1" name="$2"; shift 2

    local script
    script="$(find_script "$n")"

    if [[ -z "$script" ]]; then
        log_err "Step ${n} (${name}): script not found — ${SCRIPT_DIR}/0${n}_*.sh"
        STEP_STATUS[$n]="NOT FOUND"
        STEP_DURATION[$n]="—"
        return 1
    fi

    STEP_SCRIPT[$n]="$(basename "$script")"
    log_step "$n" "$name" "$script"
    log "Flags: $*"

    local t_start; t_start=$(date +%s)

    # Run subscript — CWD is SCRIPT_DIR (set in main); subscripts use relative paths
    bash "$script" "$@"
    local rc=$?

    local elapsed=$(( $(date +%s) - t_start ))
    local mm=$(( elapsed / 60 ))
    local ss=$(( elapsed % 60 ))
    STEP_DURATION[$n]="${mm}m${ss}s"

    if [[ $rc -eq 0 ]]; then
        STEP_STATUS[$n]="OK"
        log_ok "Step ${n} (${name}) completed — ${mm}m${ss}s"
    else
        STEP_STATUS[$n]="FAIL(rc=${rc})"
        log_err "Step ${n} (${name}) failed — rc=${rc}, elapsed=${mm}m${ss}s"
        return $rc
    fi
}

# =============================================================================
# MRK:00_SUMMARY — SUMMARY TABLE | summary,table,final,status,overview | L374-440
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================
print_summary() {
    local total="${1:-}"
    local -A names=(
        [1]="DNS Recon"
        [2]="OSINT Recon"
        [3]="IP Analysis"
        [4]="Comprehensive Scan"
        [5]="TLS Scan"
        [6]="Network Infra"
        [7]="Wireless"
        [8]="Web Enumeration"
        [9]="WPScan"
        [10]="Auth / SSO"
        [11]="Active Fuzz"
        [12]="Content Sec"
        [13]="Service Verify"
        [14]="App / API Review"
        [15]="API Deep"
        [16]="AI / LLM Review"
        [17]="Cloud Testing"
        [18]="CI/CD DevOps"
        [19]="Secrets Scan"
        [20]="AD Testing"
        [21]="Lateral Movement"
        [22]="Database Audit"
        [23]="Vuln Corpus"
        [24]="Attack Chain AI"
        [25]="Report Pack"
    )
    local line; line="$(printf '━%.0s' {1..60})"

    echo ""
    echo -e "${BOLD}${GREEN}${line}${NC}"
    echo -e "${BOLD}${GREEN}  PT-Orc Suite Summary — ${PROJECT_NAME:-[project]}${NC}"
    echo -e "${BOLD}${GREEN}  Profile: ${ENGAGEMENT_PROFILE:-unset}${NC}"
    [[ -n "$total" ]] && echo -e "${BOLD}${GREEN}  Total elapsed: ${total}${NC}"
    echo -e "${BOLD}${GREEN}${line}${NC}"
    printf "${BOLD}  %-4s  %-22s  %-26s  %-14s  %s${NC}\n" \
        "Step" "Name" "Script" "Status" "Duration"
    echo -e "  $(printf '─%.0s' {1..68})"

    local all_ok=1
    local n
    for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
        local status="${STEP_STATUS[$n]:-—}"
        local dur="${STEP_DURATION[$n]:-—}"
        local scr="${STEP_SCRIPT[$n]:-—}"
        local color
        case "$status" in
            OK)             color="$GREEN"  ;;
            SKIP|"—")       color="$CYAN"   ;;
            "NOT FOUND")    color="$YELLOW" ;;
            FAIL*)          color="$RED"; all_ok=0 ;;
            *)              color="$NC"     ;;
        esac
        printf "  ${color}%-4s  %-22s  %-26s  %-14s  %s${NC}\n" \
            "$n" "${names[$n]}" "${scr:0:26}" "$status" "$dur"
    done

    echo -e "  ${BOLD}${GREEN}${line}${NC}"
    echo -e "  Log:  ${LOG_FILE}"
    echo ""

    # Write summary to log
    {
        echo ""
        echo "=== PT-Orc Suite Summary ==="
        echo "Project: ${PROJECT_NAME:-[project]}"
        [[ -n "$total" ]] && echo "Total elapsed: ${total}"
        for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
            printf "  Step %-2s  %-22s  %-14s  %s\n" \
                "$n" "${names[$n]}" "${STEP_STATUS[$n]:-—}" "${STEP_DURATION[$n]:-—}"
        done
    } >> "$LOG_FILE" 2>/dev/null || true

    return $(( all_ok == 1 ? 0 : 1 ))
}

# =============================================================================
# MRK:00_RECOMMEND — AI STEP RECOMMENDER | recommend,ai,steps,suggest | L459-510
# NAV-RULE: no-insert-before
# =============================================================================
# recommend_steps — sources orc-ai-lib.sh and calls recommend_steps_ai().
# Called when --recommend is passed. Does not require root.
recommend_steps() {
    local ai_lib="${SCRIPT_DIR}/orc-ai-lib.sh"
    if [[ ! -f "$ai_lib" ]]; then
        log_err "--recommend: orc-ai-lib.sh not found at ${ai_lib}"
        return 1
    fi

    # shellcheck source=orc-ai-lib.sh
    source "$ai_lib" || { log_err "--recommend: failed to source orc-ai-lib.sh"; return 1; }

    local line; line="$(printf '═%.0s' {1..52})"
    echo -e "${CYAN}${line}${NC}"
    echo -e "${CYAN}  PT-Orc — AI Step Recommendation${NC}"
    echo -e "${CYAN}  Profile: ${ENGAGEMENT_PROFILE:-external} | Working dir: ${SCRIPT_DIR}/working${NC}"
    echo -e "${CYAN}${line}${NC}"
    echo ""

    local result
    result=$(recommend_steps_ai "${SCRIPT_DIR}/working" "${ENGAGEMENT_PROFILE:-external}") || true

    if [[ -z "$result" ]]; then
        log_warn "--recommend: AI recommendation unavailable (no data in working/ or no AI backend configured)"
        log_warn "  Ensure at least one step has run (step 4 recommended) and an AI backend is active."
        log_warn "  Set ANTHROPIC_API_KEY in pt-orc.conf or start ollama to enable recommendations."
        return 1
    fi

    echo -e "$result"
    echo ""

    # Optionally save to working/
    local out_file="${SCRIPT_DIR}/working/step_recommendation_${SESSION_TS}.md"
    echo "$result" > "$out_file" 2>/dev/null && \
        log_ok "Recommendation saved: ${out_file}"
}

# =============================================================================
# MRK:00_MAIN — MAIN | main,banner,run,loop,summary | L511-674
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================
main() {
    # ─── Root check (here so --help / --list-profiles work without sudo) ──────
    if [[ "$EUID" -ne 0 ]]; then
        echo "[ERROR] This script must be run as root."
        echo "        Run: sudo $0 $*"
        exit 1
    fi

    # Work from SCRIPT_DIR — all subscripts use relative paths for working/ scripts/ evidence/
    cd "${SCRIPT_DIR}"

    # ─── Apply --profile CLI override before anything else ───────────────────
    [[ -n "$PROFILE_OVERRIDE" ]] && ENGAGEMENT_PROFILE="$PROFILE_OVERRIDE"

    # Resolve active profile steps for banner display
    local _active_pvar="PROFILE_STEPS_${ENGAGEMENT_PROFILE:-}"
    local _active_steps="${!_active_pvar:-all}"

    # ─── Banner ───────────────────────────────────────────────────────────────
    local line; line="$(printf '═%.0s' {1..52})"
    echo -e "${GREEN}"
    echo "${line}"
    echo "  PT-Orc Suite Orchestrator"
    echo "  TechGuard."
    printf "  %-22s %s\n" "Project:"   "${PROJECT_NAME:-[see pt-orc.conf]}"
    printf "  %-22s %s\n" "Mode:"      "${MODE}"
    printf "  %-22s %s\n" "Profile:"   "${ENGAGEMENT_PROFILE:-unset}${PROFILE_OVERRIDE:+ (CLI override)}"
    printf "  %-22s %s\n" "Steps:"     "${_active_steps}"
    printf "  %-22s %s\n" "Tier:"      "${GLOBAL_TIER}"
    printf "  %-22s %s\n" "Auto-yes:"  "$([ "$AUTO_YES" -eq 1 ] && echo 'YES — no prompts' || echo 'NO — prompts active')"
    printf "  %-22s %s\n" "Dry-run:"   "$([ "$DRY_RUN"  -eq 1 ] && echo 'YES' || echo 'no')"
    [[ "$FROM_STEP"  -gt 1 ]] && printf "  %-22s %s\n" "Starting from:" "step ${FROM_STEP}"
    [[ "$ONLY_STEP"  -ne 0 ]] && printf "  %-22s %s\n" "Only step:"    "${ONLY_STEP}"
    [[ "${#SKIP_STEPS[@]}" -gt 0 ]] && printf "  %-22s %s\n" "Skipping steps:" "${SKIP_STEPS[*]}"
    echo "${line}"
    echo -e "${NC}"

    [[ "$AUTO_YES" -ne 1 ]] && log_warn "No --yes flag — scripts will pause for scope confirmation prompts"

    # ─── AI step recommendation (--recommend exits after printing) ────────────
    if [[ "$DO_RECOMMEND" -eq 1 ]]; then
        recommend_steps
        exit $?
    fi

    {
        echo "=== PT-Orc Suite Start ==="
        echo "Project:   ${PROJECT_NAME:-[project]}"
        echo "Mode:      ${MODE}"
        echo "Profile:   ${ENGAGEMENT_PROFILE:-unset}"
        echo "Steps:     ${_active_steps}"
        echo "Tier:      ${GLOBAL_TIER}"
        echo "Session:   ${SESSION_TS}"
        echo "Auto-yes:  ${AUTO_YES}"
        echo "Dry-run:   ${DRY_RUN}"
    } >> "$LOG_FILE" 2>/dev/null || true

    # ─── Common flags forwarded to every subscript ────────────────────────────
    local common=()
    [[ "$AUTO_YES" -eq 1 ]] && common+=("--yes")
    [[ "$DRY_RUN"  -eq 1 ]] && common+=("--dry-run")

    # ─── Profile preset — auto-skip steps not in ENGAGEMENT_PROFILE ──────────
    # Only applies when no manual step control (--only/--from/--skip) is active.
    if [[ "$ONLY_STEP" -eq 0 && "$FROM_STEP" -eq 1 && "${#SKIP_STEPS[@]}" -eq 0 ]]; then
        local _pvar="PROFILE_STEPS_${ENGAGEMENT_PROFILE:-}"
        local _psteps="${!_pvar:-}"
        if [[ -n "$_psteps" ]]; then
            log "Profile '${ENGAGEMENT_PROFILE}' active — running steps: ${_psteps}"
            local _s
            for _s in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
                [[ " ${_psteps} " == *" ${_s} "* ]] || SKIP_STEPS+=("$_s")
            done
            [[ "${#SKIP_STEPS[@]}" -gt 0 ]] && log "  Auto-skipping: ${SKIP_STEPS[*]}"
        else
            log_warn "No PROFILE_STEPS_${ENGAGEMENT_PROFILE} preset found — running all steps"
        fi
    fi

    # ─── Run loop ─────────────────────────────────────────────────────────────
    local suite_start; suite_start=$(date +%s)
    local n

    for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25; do
        if ! should_run "$n"; then
            STEP_STATUS[$n]="SKIP"
            STEP_DURATION[$n]="—"
            STEP_SCRIPT[$n]="—"
            log "  Step ${n}: skipped"
            continue
        fi

        # Build per-step flags on top of common
        local flags=("${common[@]+"${common[@]}"}")

        case "$n" in
            1)
                [[ "$OPT_SKIP_ACTIVE" -eq 1 ]] && flags+=("--skip-active")
                ;;
            2)
                # OSINT Recon (02_osint.sh)
                flags+=("--profile" "$TESTING_DEPTH" "--tier" "$GLOBAL_TIER")
                [[ -n "${OSINT_GITHUB_TOKEN:-}" ]] && flags+=("--github-token" "$OSINT_GITHUB_TOKEN")
                [[ -n "${HIBP_API_KEY:-}" ]]        && flags+=("--hibp-key" "$HIBP_API_KEY")
                ;;
            3)
                # IP Analysis (03_ip_analysis.sh)
                flags+=("--mode" "$MODE")
                ;;
            4)
                # Comprehensive Scan (04_comp_scan.sh)
                flags+=("--mode" "$MODE" "--tier" "$GLOBAL_TIER")
                [[ -n "${OPT_PHASE:-}"       ]] && flags+=("--phase" "$OPT_PHASE")
                [[ "${OPT_MASSCAN_ONLY:-0}" -eq 1 ]] && flags+=("--masscan-only")
                [[ "${OPT_REUSE_WORKSPACE:-0}" -eq 1 ]] && flags+=("--reuse-workspace")
                [[ "${OPT_PHASE_CONTINUE:-0}"  -eq 1 ]] && flags+=("--continue")
                ;;
            5)
                # TLS Scan (05_tls_scan.sh)
                [[ "$OPT_FAST" -eq 1 ]] && flags+=("--fast")
                ;;
            6)
                # Network Infra (06_network_infra.sh)
                flags+=("--profile" "$TESTING_DEPTH")
                [[ -n "${NETINFRA_TARGETS:-}"    ]] && flags+=("--targets" "$NETINFRA_TARGETS")
                [[ -n "${NETINFRA_VLAN_IFACE:-}" ]] && flags+=("--iface"   "$NETINFRA_VLAN_IFACE")
                ;;
            7)
                # Wireless (07_wireless.sh)
                flags+=("--profile" "$TESTING_DEPTH")
                [[ -n "${WIRELESS_IFACE:-}"          ]] && flags+=("--iface"          "$WIRELESS_IFACE")
                [[ -n "${WIRELESS_EXPECTED_SSIDS:-}" ]] && flags+=("--expected-ssids" "$WIRELESS_EXPECTED_SSIDS")
                [[ -n "${WIRELESS_SCAN_TIME:-}"      ]] && flags+=("--scan-time"      "$WIRELESS_SCAN_TIME")
                [[ -n "${WIRELESS_CHANNEL:-}"        ]] && flags+=("--channel"        "$WIRELESS_CHANNEL")
                [[ "${WIRELESS_DEAUTH_ENABLED:-0}" -eq 1 ]] && flags+=("--deauth")
                [[ "${WIRELESS_PMKID_ENABLED:-0}"  -eq 1 ]] && flags+=("--pmkid")
                ;;
            8)
                # Web Enumeration (08_web_enum.sh)
                flags+=("--tier" "$GLOBAL_TIER")
                [[ "$OPT_SKIP_GOBUSTER" -eq 1 ]] && flags+=("--skip-gobuster")
                [[ "$OPT_SKIP_NIKTO"    -eq 1 ]] && flags+=("--skip-nikto")
                [[ "$OPT_FAST"          -eq 1 ]] && flags+=("--fast")
                ;;
            9)
                # WPScan (09_wpscan.sh)
                flags+=("--mode" "$MODE" "--tier" "$GLOBAL_TIER")
                [[ "$OPT_NO_WP_DETECT" -eq 0 ]] && flags+=("--detect")
                ;;
            10)
                # Auth / SSO (10_auth_sso.sh)
                flags+=("--profile" "$TESTING_DEPTH" "--tier" "$GLOBAL_TIER")
                [[ -n "${OAUTH_CLIENT_ID:-}"     ]] && flags+=("--oauth-client-id"     "$OAUTH_CLIENT_ID")
                [[ -n "${OAUTH_CLIENT_SECRET:-}" ]] && flags+=("--oauth-client-secret" "$OAUTH_CLIENT_SECRET")
                [[ -n "${OAUTH_AUTHORIZE_URL:-}" ]] && flags+=("--oauth-authorize-url" "$OAUTH_AUTHORIZE_URL")
                [[ -n "${SAML_SSO_URL:-}"        ]] && flags+=("--saml-sso-url"        "$SAML_SSO_URL")
                [[ -n "${OIDC_DISCOVERY_URL:-}"  ]] && flags+=("--oidc-discovery-url"  "$OIDC_DISCOVERY_URL")
                [[ -n "${SSO_REDIRECT_URI:-}"    ]] && flags+=("--redirect-uri"         "$SSO_REDIRECT_URI")
                [[ -n "${SSO_BEARER_TOKEN:-}"    ]] && flags+=("--token"                "$SSO_BEARER_TOKEN")
                ;;
            11)
                # Active Fuzz (11_active_fuzz.sh)
                flags+=("--profile" "$TESTING_DEPTH" "--tier" "$GLOBAL_TIER")
                [[ -n "$OPT_BURP_KEY" ]] && flags+=("--burp-key" "$OPT_BURP_KEY")
                ;;
            12)
                # Content Security (12_content_sec.sh)
                flags+=("--profile" "$TESTING_DEPTH" "--tier" "$GLOBAL_TIER")
                [[ -n "${BEARER_TOKEN:-}"  ]] && flags+=("--token"  "$BEARER_TOKEN")
                [[ -n "${COOKIE_HEADER:-}" ]] && flags+=("--cookie" "$COOKIE_HEADER")
                ;;
            13)
                # Service Verify (13_service_verify.sh)
                flags+=("--mode" "$MODE")
                [[ "$OPT_AGGRESSIVE" -eq 1 ]] && flags+=("--aggressive")
                [[ "$OPT_NUCLEI"     -eq 1 ]] && flags+=("--nuclei")
                ;;
            14)
                # App / API Review (14_app_api_review.sh)
                flags+=("--tier" "$GLOBAL_TIER")
                [[ "$OPT_FAST" -eq 1 ]] && flags+=("--fast")
                ;;
            15)
                # API Deep (15_api_deep.sh)
                flags+=("--profile" "$TESTING_DEPTH" "--tier" "$GLOBAL_TIER")
                [[ -n "${BEARER_TOKEN:-}"         ]] && flags+=("--token"             "$BEARER_TOKEN")
                [[ -n "${API_KEY:-}"              ]] && flags+=("--api-key"           "$API_KEY")
                [[ -n "${API_BASE:-}"             ]] && flags+=("--api-base"          "$API_BASE")
                [[ -n "${API_VERSION:-}"          ]] && flags+=("--api-version"       "$API_VERSION")
                [[ -n "${GRAPHQL_URL:-}"          ]] && flags+=("--graphql-url"       "$GRAPHQL_URL")
                [[ -n "${API_DEEP_BUSINESS_EP:-}" ]] && flags+=("--business-endpoint" "$API_DEEP_BUSINESS_EP")
                [[ -n "${API_DEEP_ENUM_START:-}"  ]] && flags+=("--enum-start"        "$API_DEEP_ENUM_START")
                [[ -n "${API_DEEP_ENUM_COUNT:-}"  ]] && flags+=("--enum-count"        "$API_DEEP_ENUM_COUNT")
                for _p in ${API_DEEP_NOSQL_PARAMS:-}; do
                    flags+=("--nosql-param" "$_p")
                done
                ;;
            16)
                # AI / LLM Review (16_ai_llm_review.sh)
                flags+=("--tier" "$GLOBAL_TIER")
                [[ -n "$OPT_API_KEY" ]] && flags+=("--api-key" "$OPT_API_KEY")
                ;;
            17)
                # Cloud Testing (17_cloud_testing.sh)
                flags+=("--profile" "$TESTING_DEPTH")
                [[ -n "${CLOUD_PROVIDER:-}"      ]] && flags+=("--provider"      "$CLOUD_PROVIDER")
                [[ -n "${CLOUD_BUCKET_PREFIX:-}" ]] && flags+=("--bucket-prefix" "$CLOUD_BUCKET_PREFIX")
                ;;
            18)
                # CI/CD DevOps (18_cicd_devops.sh)
                flags+=("--profile" "$TESTING_DEPTH")
                [[ -n "${CICD_JENKINS_URL:-}" ]] && flags+=("--jenkins-url" "$CICD_JENKINS_URL")
                [[ -n "${CICD_GITLAB_URL:-}"  ]] && flags+=("--gitlab-url"  "$CICD_GITLAB_URL")
                [[ -n "${CICD_ARGOCD_URL:-}"  ]] && flags+=("--argocd-url"  "$CICD_ARGOCD_URL")
                [[ -n "${CICD_K8S_API_URL:-}" ]] && flags+=("--k8s-url"     "$CICD_K8S_API_URL")
                ;;
            19)
                # Secrets Scan (19_secrets_scan.sh)
                flags+=("--profile" "$TESTING_DEPTH")
                [[ -n "${SECRETS_SMB_TARGETS:-}" ]] && flags+=("--targets"  "$SECRETS_SMB_TARGETS")
                [[ -n "${SECRETS_SMB_USER:-}"    ]] && flags+=("--smb-user" "$SECRETS_SMB_USER")
                [[ -n "${SECRETS_SMB_PASS:-}"    ]] && flags+=("--smb-pass" "$SECRETS_SMB_PASS")
                ;;
            20)
                # Active Directory Testing (20_active_directory.sh)
                flags+=("--profile" "$TESTING_DEPTH")
                [[ -n "${AD_DOMAIN:-}"   ]] && flags+=("--domain" "$AD_DOMAIN")
                [[ -n "${AD_DC_IP:-}"    ]] && flags+=("--dc"     "$AD_DC_IP")
                [[ -n "${AD_USERNAME:-}" ]] && flags+=("--user"   "$AD_USERNAME")
                [[ -n "${AD_PASSWORD:-}" ]] && flags+=("--pass"   "$AD_PASSWORD")
                [[ -n "${AD_NT_HASH:-}"  ]] && flags+=("--hash"   "$AD_NT_HASH")
                ;;
            21)
                # Lateral Movement (21_lateral_movement.sh)
                flags+=("--profile" "$TESTING_DEPTH")
                [[ -n "${LATERAL_TARGETS:-}"  ]] && flags+=("--targets" "$LATERAL_TARGETS")
                [[ -n "${LATERAL_USERNAME:-}" ]] && flags+=("--user"    "$LATERAL_USERNAME")
                [[ -n "${LATERAL_PASSWORD:-}" ]] && flags+=("--pass"    "$LATERAL_PASSWORD")
                [[ -n "${LATERAL_NT_HASH:-}"  ]] && flags+=("--hash"    "$LATERAL_NT_HASH")
                ;;
            22)
                # Database Audit (22_database_audit.sh)
                flags+=("--profile" "$TESTING_DEPTH")
                [[ -n "${DB_TARGETS:-}"               ]] && flags+=("--targets" "$DB_TARGETS")
                [[ "${DB_CRED_SPRAY_ENABLED:-0}" -eq 1 ]] && flags+=("--spray")
                ;;
            23)
                # Vuln Corpus (23_vuln_corpus.sh)
                flags+=("--profile" "$TESTING_DEPTH" "--tier" "$GLOBAL_TIER")
                ;;
            24)
                # Attack Chain AI (24_attack_chain.sh)
                ;;
            25)
                # Report Pack (25_report_pack.sh)
                [[ -n "$OPT_PROJECT_ID" ]] && flags+=("--project-id" "$OPT_PROJECT_ID")
                [[ "$OPT_RETEST" -eq 1  ]] && flags+=("--retest")
                ;;
        esac

        local step_names=([1]="DNS Recon" [2]="OSINT Recon" [3]="IP Analysis" [4]="Comprehensive Scan" [5]="TLS Scan" [6]="Network Infra" [7]="Wireless" [8]="Web Enumeration" [9]="WPScan" [10]="Auth / SSO" [11]="Active Fuzz" [12]="Content Sec" [13]="Service Verify" [14]="App / API Review" [15]="API Deep" [16]="AI / LLM Review" [17]="Cloud Testing" [18]="CI/CD DevOps" [19]="Secrets Scan" [20]="AD Testing" [21]="Lateral Movement" [22]="Database Audit" [23]="Vuln Corpus" [24]="Attack Chain AI" [25]="Report Pack")

        if ! run_step "$n" "${step_names[$n]}" "${flags[@]+"${flags[@]}"}"; then
            if is_soft_step "$n"; then
                log_warn "Step ${n} failed — continuing (optional step, non-blocking)"
            elif [[ "$CONTINUE_ON_ERROR" -eq 1 ]]; then
                log_warn "Step ${n} failed — continuing (--continue-on-error)"
            else
                log_err "Suite aborted at step ${n}. Use --continue-on-error to proceed past failures."
                local suite_elapsed=$(( $(date +%s) - suite_start ))
                local mm=$(( suite_elapsed / 60 )); local ss=$(( suite_elapsed % 60 ))
                print_summary "${mm}m${ss}s"
                exit 1
            fi
        fi
    done

    local suite_elapsed=$(( $(date +%s) - suite_start ))
    local mm=$(( suite_elapsed / 60 ))
    local ss=$(( suite_elapsed % 60 ))
    print_summary "${mm}m${ss}s"
}

main

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
