#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:02_NAV_TOC — Section index | nav,toc,index | L5-30
# - MRK:02_CONF — ENGAGEMENT CONFIGURATION | conf,engagement | L31-80
# - MRK:02_LOG — COLOURS AND LOGGING | log,colours | L81-110
# - MRK:02_ARGS — ARGUMENT PARSING | args | L111-155
# - MRK:02_FIND — FINDING WRITER | find,finding,jsonl | L156-185
# - MRK:02_UTILS — SHARED UTILITIES | utils,shared,tier,sleep | L186-210
# - MRK:02_PROF — PROFILE SETUP | prof,profile,setup | L211-240
# - MRK:02_T01 — T01 SOURCE CODE LEAK SCAN | t01,github,gitlab,trufflehog,gitleaks | LXXXX-XXXX
# - MRK:02_T02 — T02 EMPLOYEE & EMAIL EXPOSURE | t02,harvester,linkedin,email | LXXXX-XXXX
# - MRK:02_T03 — T03 BREACH & PASTE DATA | t03,hibp,haveibeenpwned,dehashed | LXXXX-XXXX
# - MRK:02_T04 — T04 DOCUMENT METADATA EXTRACTION | t04,exiftool,pdf,docx,metadata | LXXXX-XXXX
# - MRK:02_TRUN — PER-DOMAIN DISPATCHER | trun,domain,dispatcher | LXXXX-XXXX
# - MRK:02_MAIN — MAIN ENTRY POINT | main,entry,summary | LXXXX-XXXX
# NAV-LEN: 13 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-06-24

# =============================================================================
# 02_osint.sh — TechGuard. [VAPT-Advanced v1.0 — 2026-06-24]
# Open Source Intelligence (OSINT) Recon — pre/post-engagement passive collection
# Coverage: source code leaks (GitHub/GitLab), employee exposure (theHarvester),
#   breach/paste data (HaveIBeenPwned, Dehashed), document metadata (exiftool)
# Profiles: quick | standard (default) | deep
# Does NOT require root — all checks are passive / API-based
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# MRK:02_CONF — ENGAGEMENT CONFIGURATION | conf,engagement | L31-80
# NAV-RULE: no-insert-before; propose-before-edit; read-toc-first
# =============================================================================

[[ -f "${SCRIPT_DIR}/pt-orc.conf" ]] && source "${SCRIPT_DIR}/pt-orc.conf" \
    || echo "[WARN] pt-orc.conf not found in ${SCRIPT_DIR}"

[[ -f "${SCRIPT_DIR}/orc-common-lib.sh" ]] && source "${SCRIPT_DIR}/orc-common-lib.sh" \
    || echo "[WARN] orc-common-lib.sh not found — trail/notes writes disabled"

PROJ_SLUG="${PROJECT_NAME//[^A-Za-z0-9._-]/_}"
EVIDENCE_BASE="${SCAN_EVIDENCE_DIR:-${SCRIPT_DIR}/evidence}/${PROJ_SLUG}"

PROFILE="standard"
TIER="${GLOBAL_TIER:-normal}"
AUTO_YES=0
DRY_RUN=0

# Test flags (set by setup_profile)
declare -A _T_ENABLED
for _k in T01 T02 T03 T04; do _T_ENABLED[$_k]=1; done

# Domain targets
declare -a DOMAINS=()
TARGETS_FILE=""

# API keys (sourced from conf; can be overridden via env)
HIBP_API_KEY="${HIBP_API_KEY:-}"
OSINT_GITHUB_TOKEN="${OSINT_GITHUB_TOKEN:-}"
DEHASHED_API_EMAIL="${DEHASHED_API_EMAIL:-}"
DEHASHED_API_KEY="${DEHASHED_API_KEY:-}"
OSINT_HARVESTER_SOURCES="${OSINT_HARVESTER_SOURCES:-google,bing,duckduckgo,github}"
OSINT_MAX_DOCS="${OSINT_MAX_DOCS:-20}"

# =============================================================================
# MRK:02_LOG — COLOURS AND LOGGING | log,colours | L81-110
# NAV-RULE: no-insert-before
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

_ts()  { date +'%Y%m%d_%H%M%S'; }
_now() { date +'%Y-%m-%d %H:%M:%S'; }

SESSION_TS="$(_ts)"
EV_TS="$(_ev_ts 2>/dev/null || date +'%Y%m%d_%H%M%S')"
[[ "$EVIDENCE_BASE" != /* ]] && EVIDENCE_BASE="$(pwd)/${EVIDENCE_BASE}"
mkdir -p "${EVIDENCE_BASE}/_sweep" "${SCRIPT_DIR}/working"
LOG_FILE="${EVIDENCE_BASE}/_sweep/osint_${SESSION_TS}.log"
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "02-osint-findings" "jsonl" 2>/dev/null || echo "02-osint-findings_${EV_TS}.jsonl")"
: > "$FINDINGS_FILE"

log()     { local m="[$(_now)] $1";   echo -e "${BLUE}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()  { local m="[$(_now)] ✓ $1"; echo -e "${GREEN}${m}${NC}" >&2;   echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn(){ local m="[$(_now)] ⚠ $1"; echo -e "${YELLOW}${m}${NC}" >&2;  echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err() { local m="[$(_now)] ✗ $1"; echo -e "${RED}${m}${NC}" >&2;     echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_info(){ local m="[$(_now)]   $1"; echo -e "${CYAN}${m}${NC}" >&2;    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_hi()  { local m="[$(_now)] ! $1"; echo -e "${MAGENTA}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }

# =============================================================================
# MRK:02_ARGS — ARGUMENT PARSING | args | L111-155
# NAV-RULE: no-insert-before
# =============================================================================

_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

OSINT Recon — passive external intelligence collection per domain.

Options:
  --domain <domain>       Target domain (can repeat; overrides TARGET_DOMAINS)
  --targets-file <file>   File with one domain per line
  -p, --profile <name>    Scan profile: quick|standard|deep  [default: standard]
  --tier <tier>           Rate tier: ghost|evasion|normal|loud
  --github-token <tok>    GitHub API token (overrides OSINT_GITHUB_TOKEN)
  --hibp-key <key>        HIBP API key (overrides HIBP_API_KEY)
  --skip-test <T01,...>   Skip named test(s)
  --only-test <T01,...>   Run only named test(s)
  -y, --yes               Skip confirmation prompt
  --dry-run               Print actions without executing
  -h, --help              Show this help
EOF
}

declare -a _ONLY_TESTS=()
declare -a _SKIP_TESTS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --domain)         DOMAINS+=("$2");           shift 2 ;;
        --targets-file)   TARGETS_FILE="$2";         shift 2 ;;
        -p|--profile)     PROFILE="$2";              shift 2 ;;
        --tier)           TIER="$2";                 shift 2 ;;
        --github-token)   OSINT_GITHUB_TOKEN="$2";   shift 2 ;;
        --hibp-key)       HIBP_API_KEY="$2";         shift 2 ;;
        --skip-test)      _SKIP_TESTS+=("$2");       shift 2 ;;
        --only-test)      _ONLY_TESTS+=("$2");       shift 2 ;;
        -y|--yes)         AUTO_YES=1;                shift   ;;
        --dry-run)        DRY_RUN=1;                 shift   ;;
        -h|--help)        _usage; exit 0             ;;
        *)                log_err "Unknown option: $1"; _usage; exit 1 ;;
    esac
done

# Populate domains from conf if not provided via CLI
if [[ "${#DOMAINS[@]}" -eq 0 ]]; then
    if [[ -n "$TARGETS_FILE" && -f "$TARGETS_FILE" ]]; then
        mapfile -t DOMAINS < "$TARGETS_FILE"
    else
        read -ra _conf_domains <<< "${TARGET_DOMAINS:-}"
        DOMAINS=("${_conf_domains[@]}")
    fi
fi

if [[ "${#DOMAINS[@]}" -eq 0 ]]; then
    log_err "No target domains found. Set TARGET_DOMAINS in pt-orc.conf or use --domain."
    exit 1
fi

# =============================================================================
# MRK:02_FIND — FINDING WRITER | find,finding,jsonl | L156-185
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

_FIND_CTR=0
_CURRENT_DOMAIN=""

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="$5"
    (( _FIND_CTR++ )) || true
    local dom_slug="${_CURRENT_DOMAIN//[^A-Za-z0-9._-]/_}"
    local fid="f-02-${dom_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local ev_id="ev-02-${dom_slug}-$(printf '%03d' "${_FIND_CTR}")"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"02_osint","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
        "$fid" \
        "$(echo "$title" | sed 's/"/\\"/g')" \
        "$sev" \
        "${ev_tag:-$ev_id}" \
        "$(echo "$desc" | sed 's/"/\\"/g')" \
        "$(echo "$rec"  | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_hi "FINDING [${sev^^}]: ${title}"
}

# =============================================================================
# MRK:02_UTILS — SHARED UTILITIES | utils,shared,tier,sleep | L186-210
# NAV-RULE: no-insert-before
# =============================================================================

_tier_sleep() {
    case "$TIER" in
        ghost)   sleep 3 ;;
        evasion) sleep 2 ;;
        *)       : ;;
    esac
}

_test_skip() {
    local n="$1"
    if [[ "${#_ONLY_TESTS[@]}" -gt 0 ]]; then
        local found=0
        for o in "${_ONLY_TESTS[@]}"; do [[ "${o^^}" == "${n^^}" ]] && found=1; done
        [[ "$found" -eq 0 ]] && return 0
    fi
    for s in "${_SKIP_TESTS[@]+"${_SKIP_TESTS[@]}"}"; do
        [[ "${s^^}" == "${n^^}" ]] && return 0
    done
    local enabled="${_T_ENABLED[$n]:-1}"
    [[ "$enabled" -eq 0 ]] && return 0
    return 1
}

# Derive org/company name from domain for GitHub searches
_domain_to_org() {
    local domain="$1"
    # Strip leading www. and take the second-level domain label
    domain="${domain#www.}"
    echo "${domain%%.*}"
}

# Evidence file path for this domain + tag
_ev_file() {
    local domain="$1" tag="$2"
    local dom_slug="${domain//[^A-Za-z0-9._-]/_}"
    local ev_dir="${EVIDENCE_BASE}/${dom_slug}"
    mkdir -p "$ev_dir"
    echo "${ev_dir}/$(ev_fname "osint-${tag}" "txt" 2>/dev/null || echo "osint-${tag}_${EV_TS}.txt")"
}

# =============================================================================
# MRK:02_PROF — PROFILE SETUP | prof,profile,setup | L211-240
# NAV-RULE: no-insert-before
# =============================================================================

setup_profile() {
    log_info "OSINT Profile: ${PROFILE}"
    case "$PROFILE" in
        quick)
            # Quick: source code leaks + employee exposure only
            _T_ENABLED[T03]=0
            _T_ENABLED[T04]=0
            ;;
        standard)
            # All tests — default
            ;;
        deep)
            # All tests — same as standard; controls depth within each test
            ;;
        *)
            log_warn "Unknown profile '${PROFILE}' — using standard"
            ;;
    esac
    for t in "${_SKIP_TESTS[@]+"${_SKIP_TESTS[@]}"}"; do _T_ENABLED["${t^^}"]=0; done
    if [[ "${#_ONLY_TESTS[@]}" -gt 0 ]]; then
        for k in "${!_T_ENABLED[@]}"; do _T_ENABLED[$k]=0; done
        for t in "${_ONLY_TESTS[@]}"; do _T_ENABLED["${t^^}"]=1; done
    fi
}

# =============================================================================
# MRK:02_T01 — T01 SOURCE CODE LEAK SCAN | t01,github,gitlab,trufflehog,gitleaks
# =============================================================================

test_T01_source_code_leaks() {
    local domain="$1"
    local ev_f; ev_f=$(_ev_file "$domain" "t01-source-leaks")
    log "T01: Source Code Leak Scan — ${domain}"

    local org_name; org_name=$(_domain_to_org "$domain")
    echo "=== T01: Source Code Leak Scan for ${domain} (org hint: ${org_name}) ===" >> "$ev_f"

    # --- GitHub Search API: look for exposed domain/org references ---
    local gh_auth_header="Accept: application/vnd.github+json"
    [[ -n "$OSINT_GITHUB_TOKEN" ]] && gh_auth_header="Authorization: Bearer ${OSINT_GITHUB_TOKEN}"

    log_info "T01: GitHub code search for '${domain}'..."
    if [[ "$DRY_RUN" -eq 0 ]]; then
        local gh_search_resp
        gh_search_resp=$(curl -sk \
            -H "$gh_auth_header" \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "https://api.github.com/search/code?q=${domain}+in:file&per_page=10" \
            2>/dev/null | head -c 4096 || true)
        echo "=== GitHub code search ===" >> "$ev_f"
        echo "$gh_search_resp" >> "$ev_f"

        local gh_total
        gh_total=$(echo "$gh_search_resp" | grep -oP '"total_count":\s*\K[0-9]+' | head -1 || echo 0)

        if [[ "${gh_total:-0}" -gt 0 ]]; then
            local gh_repos
            gh_repos=$(echo "$gh_search_resp" \
                | grep -oP '"html_url":\s*"\K[^"]+' | grep -v '/blob/' | head -5 | tr '\n' ' ' || true)
            emit_finding "high" \
                "GitHub Code Exposure — ${gh_total} Result(s) for ${domain}" \
                "GitHub code search found ${gh_total} file(s) referencing '${domain}'. This may include configuration files, API keys, connection strings, or internal URLs committed to public repositories. Sample URLs: ${gh_repos:-see evidence file}." \
                "Audit all public repositories mentioning the domain. Rotate any exposed credentials immediately. Use git-secrets or pre-commit hooks to prevent future leaks. Consider GitHub secret scanning alerts." \
                "ev-02-${domain//[^A-Za-z0-9]/}_t01-github-code"
        else
            log_info "T01: GitHub code search — no results for ${domain}"
        fi
    fi
    _tier_sleep

    # --- GitHub Search: look for repo names matching the org ---
    if [[ -n "$OSINT_GITHUB_TOKEN" && "$DRY_RUN" -eq 0 ]]; then
        log_info "T01: GitHub org repo listing for '${org_name}'..."
        local org_resp
        org_resp=$(curl -sk \
            -H "Authorization: Bearer ${OSINT_GITHUB_TOKEN}" \
            -H "Accept: application/vnd.github+json" \
            "https://api.github.com/orgs/${org_name}/repos?type=public&per_page=10" \
            2>/dev/null | head -c 4096 || true)
        echo "=== GitHub org repos ===" >> "$ev_f"
        echo "$org_resp" >> "$ev_f"

        if echo "$org_resp" | grep -q '"full_name"'; then
            local repo_names
            repo_names=$(echo "$org_resp" | grep -oP '"full_name":\s*"\K[^"]+' | head -5 | tr '\n' ', ' || true)
            emit_finding "info" \
                "GitHub Organisation Found — ${org_name} (Public Repos Enumerated)" \
                "GitHub organisation '${org_name}' has public repositories. Repos: ${repo_names:-see evidence}. Review these for exposed secrets, internal API endpoints, infrastructure details, or credential leaks." \
                "Run trufflehog/gitleaks against all public repositories. Audit commit history for secrets. Enable GitHub secret scanning and push protection on all org repos." \
                "ev-02-${domain//[^A-Za-z0-9]/}_t01-github-org"
        fi
        _tier_sleep
    fi

    # --- trufflehog: scan GitHub org if available ---
    if command -v trufflehog &>/dev/null; then
        log_info "T01: trufflehog GitHub scan for org '${org_name}'..."
        if [[ "$DRY_RUN" -eq 0 ]]; then
            local th_args=("github" "--org=${org_name}" "--only-verified" "--no-update")
            [[ -n "$OSINT_GITHUB_TOKEN" ]] && th_args+=("--token=${OSINT_GITHUB_TOKEN}")
            local th_out
            th_out=$(timeout 120 trufflehog "${th_args[@]}" 2>&1 | head -100 || true)
            echo "=== trufflehog output ===" >> "$ev_f"
            echo "$th_out" >> "$ev_f"

            local th_verified
            th_verified=$(echo "$th_out" | grep -c "Verified: true" || true)
            local th_unverified
            th_unverified=$(echo "$th_out" | grep -c "Verified: false" || true)

            if [[ "${th_verified:-0}" -gt 0 ]]; then
                emit_finding "critical" \
                    "Verified Secrets Leaked on GitHub — ${th_verified} Finding(s) for ${org_name}" \
                    "trufflehog found ${th_verified} VERIFIED secret(s) in GitHub repositories under org '${org_name}'. Verified secrets are confirmed active credentials. Immediate revocation is required." \
                    "Rotate all exposed credentials immediately. Remove secrets from git history (git filter-repo). Enable GitHub secret scanning + push protection. Audit IAM permissions for affected secrets." \
                    "ev-02-${domain//[^A-Za-z0-9]/}_t01-trufflehog-verified"
            elif [[ "${th_unverified:-0}" -gt 0 ]]; then
                emit_finding "medium" \
                    "Unverified Secrets Pattern Matched on GitHub — ${th_unverified} Finding(s) for ${org_name}" \
                    "trufflehog found ${th_unverified} unverified secret pattern(s) in GitHub repositories under org '${org_name}'. These may be inactive or test credentials but require manual review." \
                    "Manually review each matched secret. Rotate if any are active. Scrub git history. Enable GitHub secret scanning." \
                    "ev-02-${domain//[^A-Za-z0-9]/}_t01-trufflehog-unverified"
            else
                log_ok "T01: trufflehog — no secrets found for org ${org_name}"
            fi
        fi
        _tier_sleep
    elif command -v gitleaks &>/dev/null; then
        # gitleaks fallback — requires a local clone; use GitHub API-based detect if supported
        log_info "T01: gitleaks available but requires local clone — GitHub API search used above"
        echo "[T01] gitleaks installed; run: gitleaks detect --source=<cloned-repo-path> for full repo scan" >> "$ev_f"
    else
        log_info "T01: trufflehog and gitleaks not installed — GitHub API search only"
        echo "[T01] Install trufflehog (brew install trufflehog) for automated secret scanning" >> "$ev_f"
    fi

    log_ok "T01: Source code leak scan complete for ${domain}"
}

# =============================================================================
# MRK:02_T02 — T02 EMPLOYEE & EMAIL EXPOSURE | t02,harvester,linkedin,email
# =============================================================================

test_T02_employee_exposure() {
    local domain="$1"
    local ev_f; ev_f=$(_ev_file "$domain" "t02-employee-exposure")
    log "T02: Employee & Email Exposure — ${domain}"

    echo "=== T02: Employee & Email Exposure for ${domain} ===" >> "$ev_f"

    if ! command -v theHarvester &>/dev/null && ! command -v theharvester &>/dev/null; then
        log_warn "T02: theHarvester not installed — skipping (pip install theHarvester)"
        echo "[T02] theHarvester not found. Install: pip install theHarvester" >> "$ev_f"
        emit_finding "info" \
            "OSINT Tool Missing — theHarvester Not Installed (${domain})" \
            "theHarvester is required for employee/email enumeration but is not installed. Email exposure, LinkedIn employee enumeration, and DNS hostname discovery via OSINT sources were not performed." \
            "Install theHarvester: pip install theHarvester. Rerun step 16 after installation." \
            "ev-02-${domain//[^A-Za-z0-9]/}_t02-no-tool"
        return
    fi

    local harvester_bin="theHarvester"
    command -v theHarvester &>/dev/null || harvester_bin="theharvester"

    local limit=200
    [[ "$PROFILE" == "deep" ]] && limit=500

    log_info "T02: theHarvester scan for ${domain} (sources: ${OSINT_HARVESTER_SOURCES})..."
    local harvester_out_base="${ev_f%.txt}_harvester"
    if [[ "$DRY_RUN" -eq 0 ]]; then
        timeout 180 "$harvester_bin" \
            -d "$domain" \
            -b "${OSINT_HARVESTER_SOURCES}" \
            -l "$limit" \
            -f "${harvester_out_base}" \
            >> "$ev_f" 2>&1 || true

        # Parse results
        local email_count=0 host_count=0
        if [[ -f "${harvester_out_base}.json" ]]; then
            email_count=$(grep -c '"emails"' "${harvester_out_base}.json" 2>/dev/null || true)
            host_count=$(grep -c '"hosts"' "${harvester_out_base}.json" 2>/dev/null || true)
        fi

        # Also check the text output
        local emails_found
        emails_found=$(grep -oE '[a-zA-Z0-9._%+-]+@'"${domain//./\\.}" "$ev_f" 2>/dev/null | sort -u | head -20 || true)
        local email_list_count
        email_list_count=$(echo "$emails_found" | grep -c '@' || true)

        if [[ "${email_list_count:-0}" -gt 0 ]]; then
            emit_finding "medium" \
                "Employee Email Addresses Exposed via OSINT — ${email_list_count} Address(es) for ${domain}" \
                "theHarvester discovered ${email_list_count} employee email address(es) for ${domain} via public OSINT sources (${OSINT_HARVESTER_SOURCES}). Exposed emails enable targeted phishing, password spray, and credential stuffing attacks. Sample addresses: $(echo "$emails_found" | head -5 | tr '\n' ' ')." \
                "Implement email gateway filtering (SPF, DKIM, DMARC). Conduct security awareness training to reduce phishing susceptibility. Consider monitoring exposed emails in breach databases (HIBP). Limit email address publication on public websites." \
                "ev-02-${domain//[^A-Za-z0-9]/}_t02-emails"
        fi

        local linkedin_hits
        linkedin_hits=$(grep -ci "linkedin\|employee\|staff\|people" "$ev_f" 2>/dev/null | head -1 || true)
        if [[ "${linkedin_hits:-0}" -gt 0 ]]; then
            emit_finding "info" \
                "LinkedIn/Employee Data Found via OSINT — ${domain}" \
                "theHarvester found LinkedIn employee references for ${domain}. Employee names and job titles enable targeted social engineering and spear-phishing campaigns. Review evidence file for details." \
                "Conduct phishing simulation training. Restrict employee LinkedIn profiles where company policy allows. Monitor for social engineering attempts." \
                "ev-02-${domain//[^A-Za-z0-9]/}_t02-linkedin"
        fi

        if [[ "${email_list_count:-0}" -eq 0 && "${linkedin_hits:-0}" -eq 0 ]]; then
            log_info "T02: No employee emails or LinkedIn hits found via theHarvester"
            echo "[T02] No email/employee data found" >> "$ev_f"
        fi
    fi

    log_ok "T02: Employee exposure scan complete for ${domain}"
}

# =============================================================================
# MRK:02_T03 — T03 BREACH & PASTE DATA | t03,hibp,haveibeenpwned,dehashed
# =============================================================================

test_T03_breach_data() {
    local domain="$1"
    local ev_f; ev_f=$(_ev_file "$domain" "t03-breach-data")
    log "T03: Breach & Paste Data — ${domain}"

    echo "=== T03: Breach & Paste Data for ${domain} ===" >> "$ev_f"

    # --- HaveIBeenPwned: domain breach lookup ---
    if [[ -n "$HIBP_API_KEY" ]]; then
        log_info "T03: HIBP domain breach check for ${domain}..."
        if [[ "$DRY_RUN" -eq 0 ]]; then
            local hibp_resp
            hibp_resp=$(curl -sk \
                -H "Hibp-Api-Key: ${HIBP_API_KEY}" \
                -H "User-Agent: PT-Orc-VAPT/1.0" \
                "https://haveibeenpwned.com/api/v3/breacheddomain/${domain}" \
                2>/dev/null || true)
            echo "=== HIBP domain response ===" >> "$ev_f"
            echo "$hibp_resp" >> "$ev_f"

            if echo "$hibp_resp" | grep -q '"Name"'; then
                local breach_count
                breach_count=$(echo "$hibp_resp" | grep -c '"Name"' || echo 1)
                local breach_names
                breach_names=$(echo "$hibp_resp" | grep -oP '"Name":\s*"\K[^"]+' | head -5 | tr '\n' ', ' | sed 's/,$//' || true)
                emit_finding "high" \
                    "Domain Breached — ${breach_count} Breach(es) Found for ${domain} (HIBP)" \
                    "HaveIBeenPwned reports ${breach_count} data breach(es) involving @${domain} email addresses: ${breach_names:-see evidence}. Breached employees are at elevated risk of credential stuffing and account takeover." \
                    "Enforce password resets for affected accounts. Enable MFA on all accounts. Monitor for credential stuffing (unusual auth failures). Brief affected users on phishing/social engineering risk. Consider breach monitoring services." \
                    "ev-02-${domain//[^A-Za-z0-9]/}_t03-hibp-breach"
            elif echo "$hibp_resp" | grep -q '"statusCode":401\|Unauthorized\|unauthorised'; then
                log_warn "T03: HIBP API — Unauthorized (domain breach search requires paid API tier)"
                echo "[T03] HIBP 401 — domain breach search requires paid API key" >> "$ev_f"
            elif echo "$hibp_resp" | grep -q '"statusCode":404\|"message":"The account could not be found"'; then
                log_ok "T03: HIBP — no breaches found for domain ${domain}"
                echo "[T03] HIBP: domain ${domain} not found in any breach" >> "$ev_f"
            else
                log_info "T03: HIBP response: ${hibp_resp:0:80}"
                echo "[T03] HIBP: unexpected response — check evidence file" >> "$ev_f"
            fi
        fi
        _tier_sleep
    else
        log_info "T03: HIBP_API_KEY not set — skipping domain breach check (set in pt-orc.conf)"
        echo "[T03] HIBP_API_KEY not configured — skipping" >> "$ev_f"
    fi

    # --- Dehashed: domain credential leak search ---
    if [[ -n "$DEHASHED_API_KEY" && -n "$DEHASHED_API_EMAIL" ]]; then
        log_info "T03: Dehashed search for @${domain}..."
        if [[ "$DRY_RUN" -eq 0 ]]; then
            local dehashed_resp
            dehashed_resp=$(curl -sk \
                -u "${DEHASHED_API_EMAIL}:${DEHASHED_API_KEY}" \
                -H "Accept: application/json" \
                "https://api.dehashed.com/search?query=email%3A%40${domain}&size=10" \
                2>/dev/null | head -c 4096 || true)
            echo "=== Dehashed response ===" >> "$ev_f"
            echo "$dehashed_resp" >> "$ev_f"

            local dehashed_total
            dehashed_total=$(echo "$dehashed_resp" | grep -oP '"total":\s*\K[0-9]+' | head -1 || echo 0)
            if [[ "${dehashed_total:-0}" -gt 0 ]]; then
                emit_finding "high" \
                    "Dehashed — ${dehashed_total} Credential Leak(s) for @${domain}" \
                    "Dehashed reports ${dehashed_total} leaked credential record(s) associated with @${domain} email addresses. These may include plaintext or hashed passwords from historical breaches, enabling credential stuffing attacks against corporate services." \
                    "Enforce password resets for affected users. Enable MFA on all corporate accounts. Monitor authentication logs for credential stuffing (high volume failed logins). Consider continuous breach credential monitoring." \
                    "ev-02-${domain//[^A-Za-z0-9]/}_t03-dehashed"
            elif [[ "${dehashed_total:-0}" -eq 0 ]]; then
                log_ok "T03: Dehashed — no credential leaks found for @${domain}"
                echo "[T03] Dehashed: no results for @${domain}" >> "$ev_f"
            fi
        fi
        _tier_sleep
    else
        log_info "T03: DEHASHED_API_KEY/EMAIL not set — skipping (set in pt-orc.conf)"
        echo "[T03] Dehashed credentials not configured — skipping" >> "$ev_f"
    fi

    log_ok "T03: Breach data check complete for ${domain}"
}

# =============================================================================
# MRK:02_T04 — T04 DOCUMENT METADATA EXTRACTION | t04,exiftool,pdf,docx,metadata
# =============================================================================

test_T04_document_metadata() {
    local domain="$1"
    local ev_f; ev_f=$(_ev_file "$domain" "t04-doc-metadata")
    log "T04: Document Metadata Extraction — ${domain}"

    echo "=== T04: Document Metadata for ${domain} ===" >> "$ev_f"

    if ! command -v exiftool &>/dev/null; then
        log_warn "T04: exiftool not installed — skipping (apt install libimage-exiftool-perl)"
        echo "[T04] exiftool not found. Install: apt install libimage-exiftool-perl" >> "$ev_f"
        return
    fi

    local doc_dir="${EVIDENCE_BASE}/${domain//[^A-Za-z0-9._-]/_}/t04-docs"
    mkdir -p "$doc_dir"

    # Crawl for document links on the target site
    local scheme="https"
    local doc_extensions="pdf docx xlsx pptx doc xls ppt odt ods"
    local doc_pattern
    doc_pattern=$(echo "$doc_extensions" | tr ' ' '|')

    log_info "T04: Crawling ${scheme}://${domain} for documents..."
    local doc_urls=()
    if command -v wget &>/dev/null && [[ "$DRY_RUN" -eq 0 ]]; then
        local crawl_out
        crawl_out=$(wget -q --spider --recursive --level=2 \
            --no-directories --no-parent \
            --accept="${doc_extensions// /,}" \
            --timeout=10 --tries=1 \
            "https://${domain}/" 2>&1 || true)
        # Also try http
        crawl_out+=$(wget -q --spider --recursive --level=2 \
            --no-directories --no-parent \
            --accept="${doc_extensions// /,}" \
            --timeout=10 --tries=1 \
            "http://${domain}/" 2>&1 || true)

        while IFS= read -r url; do
            doc_urls+=("$url")
        done < <(echo "$crawl_out" | grep -oE "https?://[^ ]+\.($doc_pattern)" | sort -u | head "$OSINT_MAX_DOCS" || true)
    fi

    # Fallback: try Google-indexed documents if no direct crawl results
    if [[ "${#doc_urls[@]}" -eq 0 ]]; then
        log_info "T04: No documents found via crawl — trying site:${domain} filetype query..."
        if command -v curl &>/dev/null && [[ "$DRY_RUN" -eq 0 ]]; then
            local g_resp
            g_resp=$(curl -sk \
                -H "User-Agent: Mozilla/5.0 (compatible; PT-Orc-OSINT/1.0)" \
                "https://www.google.com/search?q=site:${domain}+filetype:pdf+OR+filetype:docx&num=10" \
                2>/dev/null | head -c 8192 || true)
            while IFS= read -r url; do
                doc_urls+=("$url")
            done < <(echo "$g_resp" | grep -oE "https?://${domain}[^ \"<>]*\.(pdf|docx|xlsx|pptx)" | sort -u | head "$OSINT_MAX_DOCS" || true)
        fi
    fi

    echo "[T04] Document URLs found: ${#doc_urls[@]}" >> "$ev_f"

    if [[ "${#doc_urls[@]}" -eq 0 ]]; then
        log_info "T04: No documents discovered for ${domain}"
        echo "[T04] No documents found" >> "$ev_f"
        return
    fi

    log_info "T04: Downloading ${#doc_urls[@]} document(s) for metadata extraction..."
    local downloaded=0
    for url in "${doc_urls[@]}"; do
        local fname
        fname=$(basename "${url%%\?*}" | tr -dc 'A-Za-z0-9._-')
        [[ -z "$fname" ]] && fname="doc_${downloaded}.pdf"
        local out_path="${doc_dir}/${fname}"
        echo "[T04] Downloading: ${url}" >> "$ev_f"
        if [[ "$DRY_RUN" -eq 0 ]]; then
            curl -sk -L -o "$out_path" --max-filesize 10485760 \
                --connect-timeout 5 --max-time 15 "$url" 2>/dev/null || true
            [[ -f "$out_path" && -s "$out_path" ]] && (( downloaded++ )) || true
        fi
        _tier_sleep
    done

    log_info "T04: Running exiftool on ${downloaded} downloaded document(s)..."
    if [[ "$downloaded" -gt 0 && "$DRY_RUN" -eq 0 ]]; then
        local meta_out
        meta_out=$(exiftool -csv -Author -Creator -LastModifiedBy -Company -Software \
            -CreateDate -ModifyDate -Producer -EmailAddress \
            "${doc_dir}"/ 2>/dev/null || true)
        echo "=== exiftool CSV output ===" >> "$ev_f"
        echo "$meta_out" >> "$ev_f"

        # Check for interesting metadata
        local authors
        authors=$(echo "$meta_out" | awk -F',' 'NR>1 && $2!="" {print $2}' | sort -u | head -10 | tr '\n' ', ' | sed 's/,$//' || true)
        local companies
        companies=$(echo "$meta_out" | awk -F',' 'NR>1 && $4!="" {print $4}' | sort -u | head -5 | tr '\n' ', ' | sed 's/,$//' || true)
        local software_list
        software_list=$(echo "$meta_out" | awk -F',' 'NR>1 && $5!="" {print $5}' | sort -u | head -10 | tr '\n' ', ' | sed 's/,$//' || true)
        local emails_found
        emails_found=$(echo "$meta_out" | awk -F',' 'NR>1 && $9!="" {print $9}' | sort -u | head -5 | tr '\n' ', ' | sed 's/,$//' || true)

        local has_findings=0
        if [[ -n "$authors" || -n "$companies" ]]; then
            emit_finding "low" \
                "Document Metadata Exposes Internal User/Company Data — ${downloaded} Document(s) (${domain})" \
                "exiftool extracted internal metadata from ${downloaded} document(s) published on ${domain}. Author names: ${authors:-none}. Company: ${companies:-none}. Software: ${software_list:-none}. This data aids targeted spear-phishing, username enumeration, and software fingerprinting." \
                "Strip document metadata before publication using tools like MAT2 (Metadata Anonymisation Toolkit) or PDF optimization tools. Establish a document publishing policy requiring metadata removal. Consider DLP controls for outbound document sharing." \
                "ev-02-${domain//[^A-Za-z0-9]/}_t04-doc-metadata"
            has_findings=1
        fi
        if [[ -n "$emails_found" ]]; then
            emit_finding "medium" \
                "Email Addresses Embedded in Document Metadata — ${domain}" \
                "Internal email addresses found in document metadata: ${emails_found}. These enable direct targeting for phishing campaigns and bypass public-facing email obfuscation." \
                "Strip metadata from all publicly accessible documents. Use MAT2 or pdfopt before publication. Review document management workflow for metadata removal requirements." \
                "ev-02-${domain//[^A-Za-z0-9]/}_t04-doc-emails"
            has_findings=1
        fi
        if [[ "$has_findings" -eq 0 ]]; then
            log_ok "T04: No sensitive metadata found in ${downloaded} document(s)"
            echo "[T04] No sensitive metadata found" >> "$ev_f"
        fi
    fi

    log_ok "T04: Document metadata extraction complete for ${domain} (${downloaded} docs processed)"
}

# =============================================================================
# MRK:02_TRUN — PER-DOMAIN DISPATCHER | trun,domain,dispatcher
# =============================================================================

run_domain() {
    local domain="$1"
    _CURRENT_DOMAIN="$domain"
    local find_before="$_FIND_CTR"

    log "========================================================"
    log "OSINT DOMAIN: ${domain} | Profile: ${PROFILE}"
    log "========================================================"

    local dom_ev_dir="${EVIDENCE_BASE}/${domain//[^A-Za-z0-9._-]/_}"
    mkdir -p "$dom_ev_dir"

    _test_skip T01 || test_T01_source_code_leaks  "$domain"
    _test_skip T02 || test_T02_employee_exposure   "$domain"
    _test_skip T03 || test_T03_breach_data         "$domain"
    _test_skip T04 || test_T04_document_metadata   "$domain"

    local domain_finds=$(( _FIND_CTR - find_before ))
    log_ok "Domain ${domain} complete — ${domain_finds} finding(s)"
    echo "SUMMARY_ROW|${domain}|${domain_finds}"
}

# =============================================================================
# MRK:02_MAIN — MAIN ENTRY POINT | main,entry,summary
# =============================================================================

main() {
    log "PT-Orc 02_osint.sh v1.0 — OSINT Recon"
    log "Session: ${SESSION_TS} | Profile: ${PROFILE} | Domains: ${DOMAINS[*]}"

    setup_profile

    # Confirmation
    if [[ "$AUTO_YES" -ne 1 ]]; then
        printf "\n${YELLOW}[CONFIRM]${NC} OSINT Recon. Profile: ${BOLD}%s${NC}\n" "$PROFILE"
        printf "  Project : %s\n" "${PROJECT_NAME:-unknown}"
        printf "  Domains : %s\n" "${DOMAINS[*]}"
        printf "\n  NOTE: All checks are passive (API-based / public sources only).\n"
        printf "  Confirm scope before proceeding on client engagements.\n"
        printf "\n  Continue? [y/N] "
        read -r _ans
        [[ "${_ans,,}" == "y" ]] || { log_err "Aborted by user."; exit 0; }
    fi

    command -v trail_phase_start &>/dev/null && trail_phase_start "02_osint"

    local -a summary_rows=()
    for domain in "${DOMAINS[@]}"; do
        [[ -z "$domain" ]] && continue
        local row
        row=$(run_domain "$domain")
        # run_domain echoes the SUMMARY_ROW line; capture last line
        local srow
        srow=$(echo "$row" | grep "^SUMMARY_ROW|" | tail -1 || true)
        [[ -n "$srow" ]] && summary_rows+=("$srow")
    done

    command -v trail_phase_end &>/dev/null && trail_phase_end "02_osint" "${_FIND_CTR} findings"

    # Markdown summary
    local summary_md="${SCRIPT_DIR}/working/$(ev_fname "02-osint-summary" "md" 2>/dev/null || echo "02-osint-summary_${EV_TS}.md")"
    {
        echo "# OSINT Recon Summary — ${PROJECT_NAME:-unknown}"
        echo ""
        echo "**Date:** $(date +'%Y-%m-%d %H:%M:%S')"
        echo "**Profile:** ${PROFILE} | **Tests:** T01-T04"
        echo "**Domains:** ${#DOMAINS[@]}"
        echo ""
        echo "## Coverage"
        echo ""
        echo "| # | Test | Status |"
        echo "|---|------|--------|"
        echo "| T01 | Source Code Leak Scan (GitHub/GitLab) | $([ "${_T_ENABLED[T01]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T02 | Employee & Email Exposure (theHarvester) | $([ "${_T_ENABLED[T02]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T03 | Breach & Paste Data (HIBP / Dehashed) | $([ "${_T_ENABLED[T03]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo "| T04 | Document Metadata Extraction (exiftool) | $([ "${_T_ENABLED[T04]:-1}" -eq 1 ] && echo "✓ Run" || echo "— Skipped") |"
        echo ""
        echo "## Per-Domain Results"
        echo ""
        echo "| Domain | Findings |"
        echo "|--------|----------|"
        for row in "${summary_rows[@]+"${summary_rows[@]}"}"; do
            IFS='|' read -r _ rdom rfinds <<< "$row"
            echo "| ${rdom} | ${rfinds} |"
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
        echo "*Generated by PT-Orc 02_osint.sh v1.0 — TechGuard Labs*"
        echo "*Profile: ${PROFILE} | GitHub leaks / employee exposure / breach data / document metadata*"
    } > "$summary_md"

    log_ok "Summary: ${summary_md}"
    log_ok "Findings: ${FINDINGS_FILE} (${_FIND_CTR} total)"
    log_ok "Evidence: ${EVIDENCE_BASE}"

    cat "$summary_md"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
