#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:12_NAV_TOC — Section index | nav,toc,index | L5-44
# - MRK:12_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration,edit,pt | L45-88 | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:12_LOG — COLOURS AND LOGGING | log,colours,logging | L89-111 | ⚠ no-insert-before
# - MRK:12_ARGS — ARGUMENT PARSING | args,argument,parsing | L112-145 | ⚠ no-insert-before
# - MRK:12_VALIDATE — VALIDATION | validate,validation,project,id,required | L146-174 | ⚠ no-insert-before
# - MRK:12_SCOPE — BUILD SCOPE JSON | scope,build,json,targets,window | L175-255 | ⚠ no-insert-before; read-toc-first
# - MRK:12_EVIDENCE — BUILD EVIDENCE MANIFEST | evidence,build,manifest,walk,sha256 | L256-354 | ⚠ no-insert-before; read-toc-first
# - MRK:12_FINDINGS — COLLECT FINDINGS | findings,collect,pattern,detect,jsonl | L355-620 | ⚠ no-insert-before; read-toc-first
# - MRK:12_BUNDLE — BUILD REPORT BUNDLE | bundle,build,report,residual,risk | L621-679 | ⚠ no-insert-before; read-toc-first
# - MRK:12_WRITE — WRITE OUTPUT FILES | write,output,export,dir | L680-744 | ⚠ no-insert-before; read-toc-first
# - MRK:12_AI_REPORT — AI REPORT HTML/PDF/JSON | ai,report,html,pdf,json | L745-1703 | ⚠ no-insert-before; read-toc-first
# - MRK:12_MAIN — MAIN entry point | main,entry,point | L1704-1779 | ⚠ no-insert-before; read-toc-first
# NAV-LEN: 11 entries | Integrity-hash: 8a1b9c0b90a405f7 | Last-indexed: 2026-06-16T15:34:52Z

# =============================================================================
# 12_report_pack.sh — TechGuard. [VAPT-Enhanced v1.0 — 2026-06-06]
# Report Pack — reads all scan evidence and produces 4 files for TG Audit Orchestrator
#
# Output files (strict Pydantic validation on import):
#   scope.json            — engagement scope, targets, window, RoE
#   evidence_manifest.jsonl — one evidence record per file (sha256, phase, summary)
#   findings.jsonl        — deduplicated, severity-ranked findings
#   report_bundle.json    — counts, residual risk, metadata
# =============================================================================
# USAGE:
#   ./12_report_pack.sh [OPTIONS]
#
# OPTIONS:
#   --project-id <uuid>   Override ORCHESTRATOR_PROJECT_ID from conf (required if not in conf)
#   --profile <profile>   Override ENGAGEMENT_PROFILE (external|internal|web|api|ai_llm|cloud|ad|hybrid|retest)
#   --output-dir <dir>    Directory to create run/ output under (default: ${SCRIPT_DIR}/run)
#   --retest              Set retest_status to "pending" in report_bundle (for retest runs)
#   --dry-run             Compute everything but do not write output files
#
# REQUIRES: jq, sha256sum
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# =============================================================================
# MRK:12_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration,edit,pt | L45-88
# NAV-RULE: no-insert-before; propose-before-edit; read-toc-first
# =============================================================================

# Load shared engagement config
# shellcheck source=pt-orc.conf
[[ -f "${SCRIPT_DIR}/pt-orc.conf" ]] && source "${SCRIPT_DIR}/pt-orc.conf" \
    || echo "[WARN] pt-orc.conf not found in ${SCRIPT_DIR} — defaults used"

# Shared helpers (logging, trail/notes writer)
# shellcheck source=orc-common-lib.sh
[[ -f "${SCRIPT_DIR}/orc-common-lib.sh" ]] && source "${SCRIPT_DIR}/orc-common-lib.sh" \
    || echo "[WARN] orc-common-lib.sh not found — trail writes disabled"

# Load .env from audit-orc-vapt/ project root (two levels up from pt-orc/scripts/)
_ENV_FILE="$(cd "${SCRIPT_DIR}/../.." 2>/dev/null && pwd)/.env"
if [[ -f "$_ENV_FILE" ]]; then
    set -a; source "$_ENV_FILE"; set +a
fi

PROJ_SLUG="${PROJECT_NAME//[^A-Za-z0-9._-]/_}"
EVIDENCE_BASE="${EVIDENCE_BASE:-${SCRIPT_DIR}/evidence}/${PROJ_SLUG}"
[[ "$EVIDENCE_BASE" != /* ]] && EVIDENCE_BASE="${SCRIPT_DIR}/evidence"

# ---------------------------------------------------------------------------
# Orchestrator integration variables — read from conf, override via args
# ---------------------------------------------------------------------------
ORCHESTRATOR_PROJECT_ID="${ORCHESTRATOR_PROJECT_ID:-}"
ENGAGEMENT_PROFILE="${ENGAGEMENT_PROFILE:-external}"
TESTING_DEPTH="${TESTING_DEPTH:-standard}"
AUTH_LEVEL="${AUTH_LEVEL:-none}"
RULES_OF_ENGAGEMENT="${RULES_OF_ENGAGEMENT:-No DoS. Testing window business hours only.}"
WINDOW_START="${WINDOW_START:-}"
WINDOW_END="${WINDOW_END:-}"

OUTPUT_DIR="${SCRIPT_DIR}/run"
DRY_RUN=0
RETEST=0
AI_REPORT=1             # 0 = skip AI report; disable with --no-ai-report
AI_NO_PDF=0             # 1 = skip PDF (HTML + JSON only); enable with --no-pdf
AI_MODEL="claude-haiku-4-5-20251001"
BASELINE_RUN_DIR=""     # set via --baseline <prior_run_dir>; enables retest diff
RUN_DIR_ACTUAL=""       # set by write_output; consumed by generate_ai_report

# =============================================================================
# MRK:12_LOG — COLOURS AND LOGGING | log,colours,logging | L89-111
# NAV-RULE: no-insert-before
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

_ts()  { date +'%Y%m%d_%H%M%S'; }
_now() { date +'%Y-%m-%d %H:%M:%S'; }

SESSION_TS="$(_ts)"

WORKING_DIR="${SCAN_WORKING_DIR:-${SCRIPT_DIR}/working}"; mkdir -p "$WORKING_DIR"
LOG_FILE="${WORKING_DIR}/report_pack_${SESSION_TS}.log"

log()      { local m="[$(_now)] $1";            echo -e "${BLUE}${m}${NC}" >&2;       echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()   { local m="[$(_now)] [OK] $1";       echo -e "${GREEN}${m}${NC}" >&2;      echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn() { local m="[$(_now)] [WARN] $1";     echo -e "${YELLOW}${m}${NC}" >&2;     echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err()  { local m="[$(_now)] [ERR] $1";      echo -e "${RED}${m}${NC}" >&2;        echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_info() { local m="[$(_now)]   $1";          echo -e "${CYAN}${m}${NC}" >&2;       echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_find() { local m="[$(_now)] FINDING: $1";   echo -e "${BOLD}${RED}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }

# =============================================================================
# MRK:12_ARGS — ARGUMENT PARSING | args,argument,parsing | L112-145
# NAV-RULE: no-insert-before
# =============================================================================

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project-id)
            [[ -z "${2:-}" ]] && { echo "[ERR] --project-id requires a value"; exit 1; }
            ORCHESTRATOR_PROJECT_ID="$2"; shift 2 ;;
        --profile)
            [[ -z "${2:-}" ]] && { echo "[ERR] --profile requires a value"; exit 1; }
            ENGAGEMENT_PROFILE="$2"; shift 2 ;;
        --output-dir)
            [[ -z "${2:-}" ]] && { echo "[ERR] --output-dir requires a value"; exit 1; }
            OUTPUT_DIR="$2"; shift 2 ;;
        --retest)
            RETEST=1; shift ;;
        --baseline)
            [[ -z "${2:-}" ]] && { echo "[ERR] --baseline requires a path to a prior run directory"; exit 1; }
            BASELINE_RUN_DIR="$2"; RETEST=1; shift 2 ;;
        --dry-run)
            DRY_RUN=1; shift ;;
        --no-ai-report)
            AI_REPORT=0; shift ;;
        --no-pdf)
            AI_NO_PDF=1; shift ;;
        --ai-model)
            [[ -z "${2:-}" ]] && { echo "[ERR] --ai-model requires a value"; exit 1; }
            AI_MODEL="$2"; shift 2 ;;
        --yes)
            shift ;;  # forwarded by 00_pt-orc.sh common flags; step 12 is non-interactive
        *)
            log_err "Unknown argument: $1"; exit 1 ;;
    esac
done

# =============================================================================
# MRK:12_VALIDATE — VALIDATION | validate,validation,project,id,required | L146-174
# NAV-RULE: no-insert-before
# =============================================================================

if [[ -z "$ORCHESTRATOR_PROJECT_ID" ]]; then
    echo ""
    echo -e "${RED}${BOLD}[ERROR] ORCHESTRATOR_PROJECT_ID is not set.${NC}"
    echo ""
    echo "  Set it one of two ways:"
    echo "    1. Add to pt-orc.conf:   ORCHESTRATOR_PROJECT_ID=\"<uuid-from-orchestrator>\""
    echo "    2. Pass as argument:      --project-id <uuid>"
    echo ""
    echo "  The UUID is assigned when you create the project in the TG Audit Orchestrator."
    echo "  Example: ./12_report_pack.sh --project-id a1b2c3d4-1234-5678-abcd-ef0123456789"
    echo ""
    exit 1
fi

if ! command -v jq &>/dev/null; then
    log_err "jq is required but not found. Install: apt-get install -y jq"
    exit 1
fi

log "12_report_pack.sh — TechGuard. | Project: ${ORCHESTRATOR_PROJECT_ID}"
log "Evidence base: ${EVIDENCE_BASE}"
log "Output dir:    ${OUTPUT_DIR}"
[[ "$DRY_RUN" -eq 1 ]] && log_warn "DRY-RUN mode — no output files will be written"

# =============================================================================
# MRK:12_SCOPE — BUILD SCOPE JSON | scope,build,json,targets,window | L175-255
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

build_scope_json() {
    log "Building scope.json ..."

    # Assemble raw target list from all three sources then deduplicate + sort
    local -a raw_targets=()

    # Source 1: targets.txt (IPs produced by 01_dns_recon)
    local tgt_file="${SCRIPT_DIR}/targets.txt"
    if [[ -f "$tgt_file" ]]; then
        while IFS= read -r line; do
            # Strip comments and blank lines
            line="${line%%#*}"; line="${line// /}"
            [[ -n "$line" ]] && raw_targets+=("$line")
        done < "$tgt_file"
        log_info "  targets.txt: ${#raw_targets[@]} entries"
    else
        log_warn "  targets.txt not found — skipping (run 01_dns_recon first)"
    fi

    # Source 2: TARGET_DOMAINS from conf
    for d in ${TARGET_DOMAINS:-}; do
        [[ -n "$d" ]] && raw_targets+=("$d")
    done

    # Source 3: TARGET_IPS from conf
    for ip in ${TARGET_IPS:-}; do
        [[ -n "$ip" ]] && raw_targets+=("$ip")
    done

    # Deduplicate + sort into a clean newline-separated list
    local targets_sorted
    targets_sorted=$(printf '%s\n' "${raw_targets[@]}" | sort -u | grep -v '^$' || true)
    local target_count
    target_count=$(echo "$targets_sorted" | grep -c '.' 2>/dev/null || echo 0)
    log_ok "  Targets consolidated: ${target_count} unique entries"

    # Window: use conf values; fall back to today ± 14 days
    local today; today=$(date +'%Y-%m-%d')
    local ws="${WINDOW_START:-}"
    local we="${WINDOW_END:-}"
    if [[ -z "$ws" ]]; then
        ws=$(date -d "today - 14 days" +'%Y-%m-%d' 2>/dev/null || date -v-14d +'%Y-%m-%d' 2>/dev/null || echo "$today")
        log_warn "  WINDOW_START not set — using ${ws} (today-14d)"
    fi
    if [[ -z "$we" ]]; then
        we=$(date -d "today + 14 days" +'%Y-%m-%d' 2>/dev/null || date -v+14d +'%Y-%m-%d' 2>/dev/null || echo "$today")
        log_warn "  WINDOW_END not set — using ${we} (today+14d)"
    fi

    # Build JSON array of targets using jq
    local targets_json
    targets_json=$(echo "$targets_sorted" | jq -R . | jq -s .)

    SCOPE_JSON=$(jq -n \
        --arg project_ref    "$ORCHESTRATOR_PROJECT_ID" \
        --arg eng_profile    "$ENGAGEMENT_PROFILE" \
        --arg testing_depth  "$TESTING_DEPTH" \
        --arg auth_level     "$AUTH_LEVEL" \
        --argjson targets    "$targets_json" \
        --arg roe            "$RULES_OF_ENGAGEMENT" \
        --arg ws             "$ws" \
        --arg we             "$we" \
        '{
            project_ref:        $project_ref,
            engagement_profile: $eng_profile,
            testing_depth:      $testing_depth,
            auth_level:         $auth_level,
            targets:            $targets,
            rules_of_engagement: $roe,
            window: { start: $ws, end: $we }
        }')

    SCOPE_TARGET_COUNT="$target_count"
    log_ok "scope.json built — ${target_count} targets, window ${ws} → ${we}"
}

# =============================================================================
# MRK:12_EVIDENCE — BUILD EVIDENCE MANIFEST | evidence,build,manifest,walk,sha256 | L256-354
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

# Global maps used by MRK:12_FINDINGS to link files to ev-NNN ids
declare -A EV_ID_BY_PATH    # absolute_path -> ev-NNN
declare -A EV_ID_BY_BASE    # basename -> ev-NNN (last writer wins; sufficient for matching)

build_evidence_manifest() {
    log "Building evidence_manifest.jsonl ..."

    EVIDENCE_LINES=()   # array of JSONL lines
    local ev_count=0

    # Walk evidence base recursively; process regular files only
    while IFS= read -r -d '' fpath; do
        local fname; fname="$(basename "$fpath")"
        local fdir;  fdir="$(dirname "$fpath")"

        # Skip: log files
        [[ "$fname" == *.log ]] && continue
        # Skip: MSF resource files
        [[ "$fname" == *.rc  ]] && continue
        # Skip: files inside _msf/ directory
        [[ "$fdir" == */_msf* || "$fdir" == */_msf ]] && continue
        # Skip: summary markdown in working/
        [[ "$fdir" == */working && "$fname" == *.md ]] && continue
        # Skip: zero-size files
        [[ ! -s "$fpath" ]] && continue

        # Phase detection from path components
        local phase="05_web"   # catchall default
        if [[ "$fdir" == *_dns* || "$fname" == *_dns_* ]]; then
            phase="01_dns"
        elif [[ "$fname" == ip_analysis* ]]; then
            phase="02_ip"
        elif [[ "$fname" == nmap_* || ( "$fdir" == *_sweep* && "$fname" == *comp_scan* ) ]]; then
            phase="03_network"
        elif [[ "$fname" == tls_* || "$fname" == testssl_* || "$fname" == cert_* ]]; then
            phase="04_tls"
        elif [[ "$fname" == headers_* || "$fname" == sec_headers_* || \
                "$fname" == gobuster_* || "$fname" == nikto_* || \
                "$fname" == whatweb_* || "$fname" == sensitive_* || \
                "$fname" == cors_*    || "$fname" == graphql_* || \
                "$fname" == api_endpoints_* ]]; then
            phase="05_web"
        elif [[ "$fname" == wp_* ]]; then
            phase="06_wordpress"
        elif [[ "$fname" == service_* ]]; then
            phase="07_service"
        elif [[ "$fname" == app_* ]]; then
            phase="08_app_api"
        elif [[ "$fname" == llm_* || "$fname" == ai_* ]]; then
            phase="09_ai_llm"
        fi

        # Compute sha256
        local sha256
        sha256=$(sha256sum "$fpath" 2>/dev/null | awk '{print $1}') || { log_warn "  sha256 failed: $fpath"; continue; }

        # Increment counter and build ID
        (( ev_count++ )) || true
        local ev_id; ev_id="ev-$(printf '%03d' "$ev_count")"

        # Generate a human-readable summary from filename
        # Strip leading timestamp-like suffixes (YYYYMMDD_HHMMSS) and underscores
        local summary; summary="$fname"
        # Remove extension
        summary="${summary%.*}"
        # Strip trailing timestamp _YYYYMMDD_HHMMSS
        summary=$(echo "$summary" | sed 's/_[0-9]\{8\}_[0-9]\{6\}$//')
        # Replace underscores with spaces
        summary="${summary//_/ }"

        # Build JSONL record
        local ev_line
        ev_line=$(jq -n \
            --arg id      "$ev_id" \
            --arg phase   "$phase" \
            --arg srcfile "$fname" \
            --arg sha256  "$sha256" \
            --arg summary "$summary" \
            '{"id":$id,"phase":$phase,"source_file":$srcfile,"sha256":$sha256,"summary":$summary}')

        EVIDENCE_LINES+=("$ev_line")

        # Register in maps for findings linkage
        EV_ID_BY_PATH["$fpath"]="$ev_id"
        EV_ID_BY_BASE["$fname"]="$ev_id"

        log_info "  ${ev_id}  [${phase}]  ${fname}"

    done < <(find "$EVIDENCE_BASE" -type f -print0 2>/dev/null | sort -z)

    EVIDENCE_COUNT="${#EVIDENCE_LINES[@]}"
    log_ok "Evidence manifest built — ${EVIDENCE_COUNT} items"
}

# =============================================================================
# MRK:12_FINDINGS — COLLECT FINDINGS | findings,collect,pattern,detect,jsonl | L355-620
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

# Global arrays populated by this section
FINDINGS_LINES=()
FINDING_SEVERITIES=()   # parallel array — severity string per finding for residual calc

_make_finding() {
    # _make_finding <id> <title> <severity> <phase> <ev_ids_json> <description> <recommendation> [retest_status] [residual_risk]
    local fid="$1" title="$2" sev="$3" phase="$4" ev_ids="$5" desc="$6" rec="$7"
    local retest="${8:-n/a}" residual="${9:-}"
    jq -n \
        --arg id          "$fid" \
        --arg title       "$title" \
        --arg severity    "$sev" \
        --arg phase       "$phase" \
        --argjson evidence_ids "$ev_ids" \
        --arg description "$desc" \
        --arg recommendation "$rec" \
        --arg retest_status  "$retest" \
        --arg residual_risk  "$residual" \
        '{"id":$id,"title":$title,"severity":$severity,"phase":$phase,"evidence_ids":$evidence_ids,"description":$description,"recommendation":$recommendation,"retest_status":$retest_status,"residual_risk":$residual_risk}'
}

_ev_ids_for_file() {
    # Returns a JSON array of ev-NNN IDs for a given absolute path (or empty array)
    local fpath="$1"
    local fname; fname="$(basename "$fpath")"
    local ev_id="${EV_ID_BY_PATH[$fpath]:-${EV_ID_BY_BASE[$fname]:-}}"
    if [[ -n "$ev_id" ]]; then
        echo "[\"${ev_id}\"]"
    else
        echo "[]"
    fi
}

collect_findings() {
    log "Collecting findings ..."
    local f_count=0

    # -------------------------------------------------------------------------
    # Step 1: Read pre-generated findings from phase scripts (05, 07, 08, 09, 10, 11)
    # -------------------------------------------------------------------------
    log "  Step 1: pre-generated findings from phase scripts ..."

    local -a pregen_files=()
    while IFS= read -r -d '' f; do
        pregen_files+=("$f")
    done < <(find "${WORKING_DIR}" -maxdepth 1 \
        \( -name "*01_dns_findings_*.jsonl" \
        -o -name "*02_ip_analysis_findings_*.jsonl" \
        -o -name "*03_comp_scan_findings_*.jsonl" \
        -o -name "*04_tls_scan_findings_*.jsonl" \
        -o -name "*05_web_enum_findings_*.jsonl" \
        -o -name "*06_wpscan_findings_*.jsonl" \
        -o -name "*07_service_verify_findings_*.jsonl" \
        -o -name "*08_app_api_findings_*.jsonl" \
        -o -name "*09_ai_llm_findings_*.jsonl" \
        -o -name "*10_cloud_findings_*.jsonl" \
        -o -name "*11_ad_findings_*.jsonl" \
        -o -name "*13_fuzz_findings_*.jsonl" \
        -o -name "*14_corpus_findings_*.jsonl" \
        -o -name "*15_attack_chain_findings_*.jsonl" \) \
        -type f -print0 2>/dev/null | sort -z)

    for pf in "${pregen_files[@]:-}"; do
        [[ -z "$pf" || ! -f "$pf" ]] && continue
        log_info "  Loading pre-generated findings: $(basename "$pf")"
        while IFS= read -r fline; do
            [[ -z "$fline" ]] && continue
            (( f_count++ )) || true
            local new_id; new_id="f-$(printf '%03d' "$f_count")"
            local sev; sev=$(echo "$fline" | jq -r '.severity // "info"')

            # Remap evidence_ids: replace any source_file-based references with ev-NNN
            # Strategy: for each source_file name in the finding's evidence_ids field,
            # look up our manifest map; fall back to the original id if not found.
            local remapped_ev
            remapped_ev=$(echo "$fline" | jq -r '.evidence_ids // [] | @json')
            # Try to rebuild from source_file field if present
            local src_file; src_file=$(echo "$fline" | jq -r '.source_file // empty')
            if [[ -n "$src_file" ]]; then
                local mapped="${EV_ID_BY_BASE[$src_file]:-}"
                if [[ -n "$mapped" ]]; then
                    remapped_ev="[\"${mapped}\"]"
                fi
            fi

            local relined
            relined=$(echo "$fline" | jq \
                --arg new_id "$new_id" \
                --argjson ev_ids "$remapped_ev" \
                '.id = $new_id | .evidence_ids = $ev_ids')
            FINDINGS_LINES+=("$relined")
            FINDING_SEVERITIES+=("$sev")
            log_find "Pre-generated [${sev}] $(echo "$fline" | jq -r '.title // "unknown"')"
        done < "$pf"
    done
    log_info "  Pre-generated findings loaded: ${f_count}"

    # -------------------------------------------------------------------------
    # Step 2: Pattern-based finding detection from evidence files
    # -------------------------------------------------------------------------
    log "  Step 2: pattern-based detection across evidence files ..."

    while IFS= read -r -d '' fpath; do
        local fname; fname="$(basename "$fpath")"
        local fdir;  fdir="$(dirname "$fpath")"

        # Skip files that were excluded from the manifest (same rules)
        [[ "$fname" == *.log ]] && continue
        [[ "$fname" == *.rc  ]] && continue
        [[ "$fdir"  == */_msf* ]] && continue
        [[ "$fdir"  == */working && "$fname" == *.md ]] && continue
        [[ ! -s "$fpath" ]] && continue

        local ev_ids; ev_ids="$(_ev_ids_for_file "$fpath")"

        # ---- 04_tls: TLS 1.0/1.1 legacy files ----
        if [[ "$fname" == tls_legacy_* ]]; then
            if grep -qiE "TLSv1 |TLSv1\.1" "$fpath" 2>/dev/null && \
               grep -qiE "ENABLED|YES|Offered|supported" "$fpath" 2>/dev/null; then
                (( f_count++ )) || true
                local fid; fid="f-$(printf '%03d' "$f_count")"
                local rec="Disable TLS 1.0 and TLS 1.1; enforce TLS 1.2+."
                local desc="Legacy TLS protocol versions (TLSv1.0 and/or TLSv1.1) are active on the target. These versions are deprecated and vulnerable to known attacks (POODLE, BEAST). Evidence: ${fname}"
                FINDINGS_LINES+=("$(_make_finding "$fid" "TLS 1.0/1.1 still active" "medium" "04_tls" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("medium")
                log_find "medium [04_tls] TLS 1.0/1.1 still active — ${fname}"
            fi
        fi

        # ---- 04_tls: testssl JSON HIGH/CRITICAL findings ----
        if [[ "$fname" == testssl_*.json ]]; then
            local testssl_results
            testssl_results=$(jq -r '.scanResult[]?.findings[]? | select(.severity == "HIGH" or .severity == "CRITICAL") | .severity + "|||" + .id + ": " + .finding' "$fpath" 2>/dev/null || true)
            if [[ -n "$testssl_results" ]]; then
                while IFS= read -r tline; do
                    [[ -z "$tline" ]] && continue
                    local tsev="${tline%%|||*}"
                    local ttext="${tline#*|||}"
                    local normalized_sev="high"
                    [[ "$tsev" == "CRITICAL" ]] && normalized_sev="critical"
                    (( f_count++ )) || true
                    local fid; fid="f-$(printf '%03d' "$f_count")"
                    local desc="testssl.sh reported a ${tsev} severity finding: ${ttext}"
                    local rec="Remediate per testssl recommendation."
                    FINDINGS_LINES+=("$(_make_finding "$fid" "testssl: ${ttext:0:80}" "$normalized_sev" "04_tls" "$ev_ids" "$desc" "$rec")")
                    FINDING_SEVERITIES+=("$normalized_sev")
                    log_find "${normalized_sev} [04_tls] testssl: ${ttext:0:60}"
                done <<< "$testssl_results"
            fi
        fi

        # ---- 05_web: security headers missing ----
        if [[ "$fname" == sec_headers_* || "$fname" == headers_* ]]; then
            local missing_count
            missing_count=$(grep -ciE "MISSING|NOT PRESENT|not set|absent" "$fpath" 2>/dev/null | head -1 | tr -dc '0-9')
            [[ -z "$missing_count" ]] && missing_count=0
            if [[ "$missing_count" -ge 3 ]]; then
                (( f_count++ )) || true
                local fid; fid="f-$(printf '%03d' "$f_count")"
                local desc="Security header analysis identified ${missing_count} missing HTTP security headers on the target. Missing headers increase exposure to clickjacking, MIME sniffing, and XSS attacks. Evidence: ${fname}"
                local rec="Add X-Content-Type-Options, X-Frame-Options, CSP, HSTS, X-XSS-Protection headers."
                FINDINGS_LINES+=("$(_make_finding "$fid" "Multiple security headers missing" "medium" "05_web" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("medium")
                log_find "medium [05_web] Multiple security headers missing (${missing_count}) — ${fname}"
            fi
        fi

        # ---- 05_web: sensitive files / directories exposed ----
        if [[ "$fname" == sensitive_files_* || "$fname" == sensitive_* ]]; then
            if grep -qE "HTTP/1\.[01] 200|HTTP/2 200" "$fpath" 2>/dev/null; then
                (( f_count++ )) || true
                local fid; fid="f-$(printf '%03d' "$f_count")"
                local hits; hits=$(grep -cE "HTTP/1\.[01] 200|HTTP/2 200" "$fpath" 2>/dev/null || echo 1)
                local desc="Sensitive file or directory probing returned HTTP 200 responses (${hits} hit(s)). Exposed backup files, configuration, or version control metadata can disclose credentials and source code. Evidence: ${fname}"
                local rec="Block access to backup files, .git, .env, and config directories in webserver config."
                FINDINGS_LINES+=("$(_make_finding "$fid" "Sensitive file or directory exposed" "high" "05_web" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("high")
                log_find "high [05_web] Sensitive file or directory exposed — ${fname}"
            fi
        fi

        # ---- 01_dns: subdomain takeover candidates ----
        if [[ "$fname" == takeover_candidates_* ]]; then
            local line_count; line_count=$(wc -l < "$fpath" 2>/dev/null | tr -d ' ' || echo 0)
            if [[ "$line_count" -gt 0 ]]; then
                (( f_count++ )) || true
                local fid; fid="f-$(printf '%03d' "$f_count")"
                local context; context=$(head -5 "$fpath" 2>/dev/null | tr '\n' '; ')
                local desc="One or more subdomains appear to be candidates for subdomain takeover. These subdomains resolve to external services that are no longer claimed by the organisation. Context (first 5): ${context}"
                local rec="Remove dangling DNS records or reclaim the third-party service."
                FINDINGS_LINES+=("$(_make_finding "$fid" "Subdomain takeover candidate detected" "high" "01_dns" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("high")
                log_find "high [01_dns] Subdomain takeover candidate (${line_count} entries) — ${fname}"
            fi
        fi

        # ---- 05_web / 06_wordpress: nikto findings ----
        if [[ "$fname" == nikto_*.txt ]]; then
            # Extract meaningful nikto output lines
            local nikto_hits
            nikto_hits=$(grep -E "^\+ (OSVDB|/|Server)" "$fpath" 2>/dev/null | head -10 || true)
            if [[ -n "$nikto_hits" ]]; then
                (( f_count++ )) || true
                local fid; fid="f-$(printf '%03d' "$f_count")"
                # Derive host:port from filename (nikto_<host>_<port>_*.txt)
                local hostport; hostport=$(echo "$fname" | sed 's/^nikto_//' | sed 's/_[0-9]\{8\}_[0-9]\{6\}\.txt$//' | tr '_' ':')
                local desc_body; desc_body=$(echo "$nikto_hits" | tr '\n' '|')
                local desc="Nikto scanner identified configuration weaknesses on ${hostport}. Findings (top 10): ${desc_body}"
                local rec="Review individual Nikto findings and remediate configuration weaknesses."
                local nikto_phase="05_web"
                [[ "$fdir" == *wp* || "$fname" == *wp_* ]] && nikto_phase="06_wordpress"
                FINDINGS_LINES+=("$(_make_finding "$fid" "Nikto scanner findings on ${hostport}" "low" "$nikto_phase" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("low")
                log_find "low [${nikto_phase}] Nikto scanner findings — ${fname}"
            fi
        fi

        # ---- 08_app_api: auth bypass candidates ----
        if [[ "$fname" == app_auth_* ]]; then
            local bypass_count; bypass_count=$(grep -c "AUTH_BYPASS_CANDIDATE" "$fpath" 2>/dev/null || echo 0)
            if [[ "$bypass_count" -gt 0 ]]; then
                (( f_count++ )) || true
                local fid; fid="f-$(printf '%03d' "$f_count")"
                local desc="API authentication bypass candidates detected (${bypass_count} endpoint(s)). These endpoints appear to return successful responses without valid authentication tokens. Evidence: ${fname}"
                local rec="Enforce authentication on all API endpoints. Implement consistent authorization checks server-side. Review access control design."
                FINDINGS_LINES+=("$(_make_finding "$fid" "API endpoint accessible without authentication" "high" "08_app_api" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("high")
                log_find "high [08_app_api] API auth bypass candidates (${bypass_count}) — ${fname}"
            fi
        fi

        # ---- 08_app_api: missing rate limiting ----
        if [[ "$fname" == app_rate_limit_* ]]; then
            if grep -q "RATE_LIMIT: MISSING" "$fpath" 2>/dev/null; then
                local rl_count; rl_count=$(grep -c "RATE_LIMIT: MISSING" "$fpath" 2>/dev/null || echo 1)
                (( f_count++ )) || true
                local fid; fid="f-$(printf '%03d' "$f_count")"
                local desc="Rate limiting is absent on ${rl_count} API endpoint(s). Without rate limiting, endpoints are vulnerable to credential stuffing, enumeration, and denial-of-service via request flooding. Evidence: ${fname}"
                local rec="Implement rate limiting on all API endpoints. Consider token-bucket or sliding-window algorithms. Return HTTP 429 with Retry-After header."
                FINDINGS_LINES+=("$(_make_finding "$fid" "No rate limiting on API endpoints" "medium" "08_app_api" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("medium")
                log_find "medium [08_app_api] No rate limiting on API endpoints — ${fname}"
            fi
        fi

        # ---- 09_ai_llm: prompt injection ----
        if [[ "$fname" == llm_injection_* || "$fname" == ai_injection_* ]]; then
            if grep -qE "INJECTION_SUCCESS|INJECTION: SUCCESS" "$fpath" 2>/dev/null; then
                (( f_count++ )) || true
                local fid; fid="f-$(printf '%03d' "$f_count")"
                local desc="Prompt injection was confirmed against the AI/LLM endpoint. The model accepted injected instructions that overrode its system prompt or changed its output behaviour. This can lead to data exfiltration, safety bypass, and indirect command execution. Evidence: ${fname}"
                local rec="Implement robust input sanitisation and output validation for all LLM integrations. Use a separate instruction channel from user data. Apply content filtering and monitoring."
                FINDINGS_LINES+=("$(_make_finding "$fid" "Prompt injection vulnerability confirmed" "high" "09_ai_llm" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("high")
                log_find "high [09_ai_llm] Prompt injection confirmed — ${fname}"
            fi
        fi

    done < <(find "$EVIDENCE_BASE" -type f -print0 2>/dev/null | sort -z)

    FINDINGS_COUNT="${#FINDINGS_LINES[@]}"
    log_ok "Findings collected — ${FINDINGS_COUNT} total"
}

# =============================================================================
# MRK:12_BUNDLE — BUILD REPORT BUNDLE | bundle,build,report,residual,risk | L621-679
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

build_report_bundle() {
    log "Building report_bundle.json ..."

    # Compute residual risk from highest finding severity present
    local has_critical=0 has_high=0 has_medium=0 has_low=0 has_info=0
    local cnt_critical=0 cnt_high=0 cnt_medium=0 cnt_low=0 cnt_info=0

    for sev in "${FINDING_SEVERITIES[@]:-}"; do
        case "$sev" in
            critical) (( has_critical++ )) || true; (( cnt_critical++ )) || true ;;
            high)     (( has_high++     )) || true; (( cnt_high++     )) || true ;;
            medium)   (( has_medium++   )) || true; (( cnt_medium++   )) || true ;;
            low)      (( has_low++      )) || true; (( cnt_low++      )) || true ;;
            info)     (( has_info++     )) || true; (( cnt_info++     )) || true ;;
        esac
    done

    local residual="None identified"
    if [[ "$has_critical" -gt 0 ]]; then
        residual="Critical — immediate remediation required"
    elif [[ "$has_high" -gt 0 ]]; then
        residual="High — remediation required before closure"
    elif [[ "$has_medium" -gt 0 ]]; then
        residual="Medium — remediation recommended"
    elif [[ "$has_low" -gt 0 || "$has_info" -gt 0 ]]; then
        residual="Low — advisory items only"
    fi

    local retest_val="n/a"
    [[ "$RETEST" -eq 1 ]] && retest_val="pending"

    REPORT_BUNDLE=$(jq -n \
        --arg project_ref    "$ORCHESTRATOR_PROJECT_ID" \
        --arg profile        "$ENGAGEMENT_PROFILE" \
        --arg retest_status  "$retest_val" \
        --arg residual_risk  "$residual" \
        --argjson findings   "$FINDINGS_COUNT" \
        --argjson evidence   "$EVIDENCE_COUNT" \
        '{
            project_ref:    $project_ref,
            profile:        $profile,
            retest_status:  $retest_status,
            residual_risk:  $residual_risk,
            counts: {
                findings: $findings,
                evidence: $evidence
            }
        }')

    RESIDUAL_RISK="$residual"
    SEVERITY_COUNTS="C:${cnt_critical} H:${cnt_high} M:${cnt_medium} L:${cnt_low} I:${cnt_info}"
    log_ok "report_bundle.json built — residual: ${residual}"
}

# =============================================================================
# MRK:12_WRITE — WRITE OUTPUT FILES | write,output,export,dir | L680-744
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

write_output() {
    local run_dir="${OUTPUT_DIR}/${ORCHESTRATOR_PROJECT_ID}_${SESSION_TS}"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log_warn "DRY-RUN: would write to ${run_dir}/"
        log_warn "DRY-RUN: scope.json — ${SCOPE_TARGET_COUNT} targets"
        log_warn "DRY-RUN: evidence_manifest.jsonl — ${EVIDENCE_COUNT} items"
        log_warn "DRY-RUN: findings.jsonl — ${FINDINGS_COUNT} findings"
        log_warn "DRY-RUN: report_bundle.json — residual: ${RESIDUAL_RISK}"
        RUN_DIR_DISPLAY="${run_dir}/"
        return 0
    fi

    mkdir -p "$run_dir"
    RUN_DIR_ACTUAL="$run_dir"
    log "Writing output to ${run_dir}/ ..."

    # scope.json
    echo "$SCOPE_JSON" > "${run_dir}/scope.json"
    log_ok "  scope.json written"

    # evidence_manifest.jsonl
    : > "${run_dir}/evidence_manifest.jsonl"
    for line in "${EVIDENCE_LINES[@]:-}"; do
        echo "$line" >> "${run_dir}/evidence_manifest.jsonl"
    done
    log_ok "  evidence_manifest.jsonl written (${EVIDENCE_COUNT} items)"

    # findings.jsonl
    : > "${run_dir}/findings.jsonl"
    for line in "${FINDINGS_LINES[@]:-}"; do
        echo "$line" >> "${run_dir}/findings.jsonl"
    done
    log_ok "  findings.jsonl written (${FINDINGS_COUNT} findings)"

    # report_bundle.json
    echo "$REPORT_BUNDLE" > "${run_dir}/report_bundle.json"
    log_ok "  report_bundle.json written"

    RUN_DIR_DISPLAY="${run_dir}/"

    # Compute phases represented in evidence for summary
    local phases_present
    phases_present=$(for l in "${EVIDENCE_LINES[@]:-}"; do echo "$l" | jq -r '.phase'; done \
        | sort -u | tr '\n' ',' | sed 's/,$//')

    {
        echo "# Session End — 12_report_pack.sh"
        echo "# Time:        $(_now)"
        echo "# Project:     ${ORCHESTRATOR_PROJECT_ID}"
        echo "# Run dir:     ${run_dir}"
        echo "# Evidence:    ${EVIDENCE_COUNT}"
        echo "# Findings:    ${FINDINGS_COUNT} (${SEVERITY_COUNTS})"
        echo "# Residual:    ${RESIDUAL_RISK}"
    } >> "$LOG_FILE"

    PHASES_DISPLAY="${phases_present:-none}"
    EVIDENCE_COUNT_DISPLAY="${EVIDENCE_COUNT}"
}

# =============================================================================
# MRK:12_AI_REPORT — AI REPORT HTML/PDF/JSON | ai,report,html,pdf,json | L745-1703
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

generate_ai_report() {
    [[ "$AI_REPORT" -eq 0 ]] && { log "AI report skipped (--no-ai-report)"; return 0; }
    [[ -z "$RUN_DIR_ACTUAL"  ]] && { log_err "No run dir — cannot generate AI report"; return 1; }

    local api_key="${ANTHROPIC_API_KEY:-}"
    local gemini_key="${GEMINI_API_KEY:-}"
    local ollama_host="${OLLAMA_HOST:-}"
    local ollama_model="${OLLAMA_MODEL:-mistral}"
    local ollama_ok=0

    if [[ -n "$ollama_host" ]]; then
        if curl -sf --max-time 3 "${ollama_host}/api/tags" >/dev/null 2>&1; then
            ollama_ok=1
        else
            log_warn "Ollama configured at ${ollama_host} but not reachable — skipping local backend"
            ollama_host=""
        fi
    fi

    if [[ -z "$api_key" && -z "$gemini_key" && "$ollama_ok" -eq 0 ]]; then
        log_err "No AI backend — set ANTHROPIC_API_KEY, GEMINI_API_KEY, or configure OLLAMA_HOST in pt-orc.conf"
        log_warn "AI report skipped."
        return 1
    fi

    # Resolve Python interpreter — prefer user's ~/venv when packages live there
    # (packages installed with `pip` inside a venv are NOT visible to system python3)
    local _as_user="" _py_exe="python3"
    if [[ "$EUID" -eq 0 && -n "${SUDO_USER:-}" ]]; then
        _as_user="${SUDO_USER}"
        local _uhome; _uhome=$(getent passwd "${SUDO_USER}" | cut -d: -f6)
        [[ -x "${_uhome}/venv/bin/python3" ]] && _py_exe="${_uhome}/venv/bin/python3"
    elif [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python3" ]]; then
        _py_exe="${VIRTUAL_ENV}/bin/python3"
    fi

    if ! command -v "${_py_exe%% *}" &>/dev/null && ! [[ -x "$_py_exe" ]]; then
        log_err "python3 not found — AI report skipped"
        return 1
    fi

    # py_check: run import tests as the target user with the resolved interpreter
    local py_check="${_py_exe}"
    [[ -n "$_as_user" ]] && py_check="sudo -u ${_as_user} ${_py_exe}"
    log "  Python: ${_py_exe}${_as_user:+ (as ${_as_user})}"

    # jinja2 is always required; AI libs checked per key
    if ! $py_check -c "import jinja2" 2>/dev/null; then
        log_err "jinja2 not installed — run: pip install jinja2"
        return 1
    fi
    if [[ -n "$api_key" ]] && ! $py_check -c "import anthropic" 2>/dev/null; then
        log_warn "anthropic not installed (pip install anthropic) — Claude unavailable; falling back to Gemini"
        api_key=""
    fi
    if [[ -n "$gemini_key" ]] && ! $py_check -c "import warnings; warnings.filterwarnings('ignore'); import google.generativeai" 2>/dev/null; then
        log_warn "google-generativeai not installed (pip install google-generativeai) — Gemini unavailable"
        gemini_key=""
    fi
    if [[ -z "$api_key" && -z "$gemini_key" && "$ollama_ok" -eq 0 ]]; then
        log_err "No usable AI backend after dependency check — install required packages or configure Ollama"
        return 1
    fi

    if [[ "$ollama_ok" -eq 1 && -z "$api_key" && -z "$gemini_key" ]]; then
        log "AI backend:  Ollama only (${ollama_host} model=${ollama_model})"
    elif [[ "$ollama_ok" -eq 1 && -n "$api_key" && -n "$gemini_key" ]]; then
        log "AI backends: Ollama primary → Claude → Gemini fallback"
    elif [[ "$ollama_ok" -eq 1 && -n "$api_key" ]]; then
        log "AI backends: Ollama primary → Claude fallback"
    elif [[ "$ollama_ok" -eq 1 && -n "$gemini_key" ]]; then
        log "AI backends: Ollama primary → Gemini fallback"
    elif [[ -n "$api_key" && -n "$gemini_key" ]]; then
        log "AI backends: Claude primary, Gemini fallback"
    elif [[ -n "$api_key" ]]; then
        log "AI backend:  Claude only"
    else
        log "AI backend:  Gemini only"
    fi
    log "Generating AI report (model: ${AI_MODEL}) ..."

    local tmp_py; tmp_py=$(mktemp /tmp/tg_ai_report_XXXXXX.py)
    [[ -n "$_as_user" ]] && chmod 644 "$tmp_py"

    cat > "$tmp_py" << 'PYTHON_EOF'
#!/usr/bin/env python3
"""AI-Powered VAPT Report — embedded engine for 12_report_pack.sh"""
import json, os, re, sys
from datetime import datetime
from pathlib import Path

try:
    import anthropic
    _ANTHROPIC_AVAILABLE = True
except ImportError:
    _ANTHROPIC_AVAILABLE = False
try:
    import urllib.request as _urllib_req
except ImportError:
    _urllib_req = None
try:
    from jinja2 import Template
except ImportError:
    sys.exit("[ERROR] jinja2 not installed: pip install jinja2")
try:
    from weasyprint import HTML as WeasyprintHTML
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

RUN_DIR     = Path(os.environ.get("TG_RUN_DIR", ""))
_conf_env   = os.environ.get("TG_CONF", "")
CONF_FILE   = Path(_conf_env) if _conf_env else None
_out_env    = os.environ.get("TG_OUTPUT_DIR", "")
OUTPUT_DIR  = Path(_out_env) if _out_env else RUN_DIR
API_KEY      = os.environ.get("TG_API_KEY", "")
GEMINI_KEY   = os.environ.get("TG_GEMINI_API_KEY", "")
MODEL        = os.environ.get("TG_MODEL", "claude-haiku-4-5-20251001")
OLLAMA_HOST  = os.environ.get("TG_OLLAMA_HOST", "")
OLLAMA_MODEL = os.environ.get("TG_OLLAMA_MODEL", "mistral")
GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
NO_PDF       = os.environ.get("TG_NO_PDF", "0") == "1"
DRY_RUN      = os.environ.get("TG_DRY_RUN", "0") == "1"
SCRIPT_DIR   = Path(os.environ.get("TG_SCRIPT_DIR", ""))
WORKING_DIR  = SCRIPT_DIR / "working"
_bl_env      = os.environ.get("TG_BASELINE_DIR", "")
BASELINE_DIR = Path(_bl_env) if _bl_env else None

MAX_EVIDENCE_LINES = 120
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
OWASP_MAP = {
    "A01": ("Broken Access Control",                     "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    "A02": ("Cryptographic Failures",                    "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    "A03": ("Injection",                                 "https://owasp.org/Top10/A03_2021-Injection/"),
    "A04": ("Insecure Design",                           "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
    "A05": ("Security Misconfiguration",                 "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    "A06": ("Vulnerable and Outdated Components",        "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    "A07": ("Identification and Authentication Failures","https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    "A08": ("Software and Data Integrity Failures",      "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
    "A09": ("Security Logging and Monitoring Failures",  "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
    "A10": ("Server-Side Request Forgery",               "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery/"),
}

def load_config(conf_path):
    config = {}
    try:
        with open(conf_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                m = re.match(r'^([A-Z_][A-Z0-9_]*)=["\']?(.*?)["\']?\s*(?:#.*)?$', line)
                if m:
                    config[m.group(1)] = m.group(2).strip("\"'")
    except FileNotFoundError:
        pass
    return config

def get_proj_slug(config):
    name = config.get("PROJECT_NAME", "")
    return re.sub(r'[^A-Za-z0-9._-]', '_', name) if name else ""

def get_evidence_dir(config):
    slug = get_proj_slug(config)
    scoped = SCRIPT_DIR / "evidence" / slug
    if slug and scoped.exists():
        return scoped
    return SCRIPT_DIR / "evidence"

def load_and_deduplicate_findings(run_dir):
    fpath = run_dir / "findings.jsonl"
    if not fpath.exists():
        return []
    raw = []
    content = fpath.read_text(errors="replace").strip()
    decoder = json.JSONDecoder()
    pos = 0
    while pos < len(content):
        while pos < len(content) and content[pos] in " \t\n\r":
            pos += 1
        if pos >= len(content):
            break
        try:
            obj, end = decoder.raw_decode(content, pos)
            raw.append(obj)
            pos = end
        except json.JSONDecodeError:
            nxt = content.find('{', pos + 1)
            if nxt == -1:
                break
            pos = nxt
    groups = {}
    for f in raw:
        title_key = re.sub(r'\s+on\s+(port\s+)?\d+$', '', f.get("title",""), flags=re.IGNORECASE).strip()
        sev = f.get("severity","low").lower()
        key = (title_key, sev)
        if key not in groups:
            groups[key] = {**f, "title": title_key, "_descs": [f.get("description","")]}
        else:
            groups[key]["_descs"].append(f.get("description",""))
            groups[key]["evidence_ids"] = list(dict.fromkeys(
                groups[key].get("evidence_ids",[]) + f.get("evidence_ids",[])))
    result = []
    for item in groups.values():
        descs = item.pop("_descs", [])
        item["description"] = max(descs, key=len) if descs else item.get("description","")
        result.append(item)
    result.sort(key=lambda f: SEV_ORDER.get(f.get("severity","low").lower(), 5))
    return result

def _read_truncated(path, max_lines):
    try:
        lines = path.read_text(errors="replace").splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + f"\n...[{len(lines)-max_lines} more lines truncated]"
        return "\n".join(lines)
    except Exception as e:
        return f"[ERROR reading {path.name}: {e}]"

def _finding_key(f):
    title = re.sub(r'\s+on\s+(port\s+)?\d+$', '', f.get("title", ""), flags=re.IGNORECASE).strip().lower()
    return (title, f.get("severity", "low").lower())

def load_and_diff_baseline(baseline_dir, current_findings):
    fpath = baseline_dir / "findings.jsonl"
    if not fpath.exists():
        print(f"[WARN] Baseline findings.jsonl not found at {fpath} — retest diff skipped")
        return None
    baseline = load_and_deduplicate_findings(baseline_dir)
    if not baseline:
        print("[WARN] Baseline findings.jsonl is empty — retest diff skipped")
        return None

    SEV_ORDER_LOCAL = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

    baseline_map  = {_finding_key(f): f for f in baseline}
    current_map   = {_finding_key(f): f for f in current_findings}

    fixed      = []
    persists   = []
    regressed  = []
    new        = []

    for key, bf in baseline_map.items():
        if key not in current_map:
            fixed.append({"title": bf.get("title"), "severity": bf.get("severity","Low").capitalize()})
        else:
            cf = current_map[key]
            b_sev = SEV_ORDER_LOCAL.get(bf.get("severity","low").lower(), 5)
            c_sev = SEV_ORDER_LOCAL.get(cf.get("severity","low").lower(), 5)
            if c_sev < b_sev:
                regressed.append({
                    "title":    cf.get("title"),
                    "severity": cf.get("severity","Low").capitalize(),
                    "was":      bf.get("severity","Low").capitalize(),
                })
            else:
                persists.append({"title": cf.get("title"), "severity": cf.get("severity","Low").capitalize()})

    for key, cf in current_map.items():
        if key not in baseline_map:
            new.append({"title": cf.get("title"), "severity": cf.get("severity","Low").capitalize()})

    return {
        "baseline_run":    str(baseline_dir),
        "baseline_count":  len(baseline),
        "current_count":   len(current_findings),
        "fixed":           fixed,
        "persists":        persists,
        "regressed":       regressed,
        "new":             new,
        "counts": {
            "fixed":     len(fixed),
            "persists":  len(persists),
            "regressed": len(regressed),
            "new":       len(new),
        },
    }

def collect_evidence_summaries(config):
    blocks = []
    slug = get_proj_slug(config)
    evidence_dir = get_evidence_dir(config)
    summary_prefixes = [
        ("tls_summary",      "TLS Assessment"),
        ("web_enum_summary", "Web Enumeration"),
        ("web_summary",      "Web Enumeration (alt)"),
        ("dns_summary",      "DNS Recon"),
        ("ip_range_report",  "IP Range Analysis"),
        ("manual_followup",  "Manual Follow-up"),
        ("app_api_summary",  "App API Summary"),
        ("ai_llm_summary",   "AI/LLM Endpoint Analysis"),
        ("scan_summary",     "Network Scan"),
        ("verify_summary",   "Service Verification"),
        ("wpscan_report",    "WordPress Scan"),
    ]
    seen_labels = set()
    if WORKING_DIR.exists():
        for prefix, label in summary_prefixes:
            if label in seen_labels:
                continue
            patterns = ([f"{slug}_{prefix}_*.md"] if slug else []) + [f"{prefix}_*.md"]
            candidates = []
            for pat in patterns:
                candidates = sorted(
                    [f for f in WORKING_DIR.glob(pat) if f.stat().st_size > 10],
                    key=lambda f: f.stat().st_mtime, reverse=True)
                if candidates:
                    break
            if candidates:
                seen_labels.add(label)
                blocks.append(f"=== {label} ({candidates[0].name}) ===\n{_read_truncated(candidates[0], MAX_EVIDENCE_LINES)}")
        jsonl_seen = set()
        patterns = ([f"{slug}_0*_*findings_*.jsonl"] if slug else []) + ["0*_*findings_*.jsonl"]
        for pat in patterns:
            for jf in sorted(WORKING_DIR.glob(pat), reverse=True)[:3]:
                stem_key = re.sub(r'^.*?_?(\d{2}_\w+_findings)_.*', r'\1', jf.name)
                if stem_key in jsonl_seen:
                    continue
                jsonl_seen.add(stem_key)
                try:
                    lines = jf.read_text().strip().splitlines()[:25]
                    blocks.append(f"=== Pre-generated Findings: {jf.name} ===\n" + "\n".join(lines))
                except Exception:
                    pass
    if evidence_dir.exists():
        seen = set()
        for host_dir in sorted(evidence_dir.iterdir()):
            if not host_dir.is_dir() or host_dir.name.startswith("_"):
                continue
            host_label = host_dir.name.replace("_",":")
            for ev_file in sorted(host_dir.glob("t0*.txt")):
                type_key = re.sub(r'_\d{14}', '', ev_file.stem)
                dk = f"{host_label}:{type_key}"
                if dk in seen:
                    continue
                seen.add(dk)
                blocks.append(f"=== Evidence [{host_label}] {ev_file.name} ===\n{_read_truncated(ev_file, 60)}")
        ip_dir = evidence_dir / "_ip_analysis"
        if ip_dir.exists():
            for ip_subdir in ip_dir.iterdir():
                if ip_subdir.is_dir():
                    for sf in ip_subdir.glob("summary_*.md"):
                        blocks.append(f"=== IP Analysis: {ip_subdir.name} ===\n{_read_truncated(sf, 50)}")
    return "\n\n".join(blocks)

PROMPT_TEMPLATE = """\
You are a senior penetration tester writing a formal VAPT report for a client.

## Engagement Configuration
{config_block}

## Deduplicated Raw Findings (from automated scans — {finding_count} findings)
{findings_json}

## Supporting Evidence & Summaries
{evidence_block}

## Instructions

Return a SINGLE JSON object (no markdown fences, no extra text) with this exact structure.

Rules:
1. Consolidate findings with the same root vulnerability into one entry.
2. Assign accurate CVSS 3.1 scores and vectors from evidence.
3. Map each finding to OWASP Top 10 2021 (A01–A10).
4. Assign accurate CWE IDs. Only include CVE IDs if directly applicable.
5. Write business_impact in plain language for non-technical executives.
6. Remediation steps must be specific and actionable.
7. Include informational findings (WAF present, CORS correctly configured) as "Informational" severity.
8. Sort findings: Critical → High → Medium → Low → Informational.
9. Identify 2–5 multi-step attack chains where chaining two or more findings reaches a higher-impact outcome than any single finding alone. Each path must reference finding IDs from the findings array above.

Required JSON schema:
{{
  "engagement_summary": {{
    "project": "<project name>",
    "targets": ["<ip:port>", "..."],
    "assessment_type": "External Web Application Penetration Test",
    "testing_period": "<e.g. June 2026>",
    "overall_risk_rating": "Critical|High|Medium|Low",
    "executive_summary": "<3-4 sentences for non-technical executives>",
    "risk_justification": "<1-2 sentences explaining the rating>",
    "severity_counts": {{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}},
    "tools_used": ["nmap", "nikto", "testssl", "wafw00f", "gobuster", "wpscan"]
  }},
  "findings": [
    {{
      "id": "F-001",
      "title": "<concise title>",
      "severity": "Critical|High|Medium|Low|Informational",
      "cvss_score": 7.5,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
      "owasp_id": "A05",
      "owasp_name": "Security Misconfiguration",
      "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
      "cwe_id": "CWE-16",
      "cwe_name": "Configuration",
      "cwe_url": "https://cwe.mitre.org/data/definitions/16.html",
      "cve_ids": [],
      "chain_steps": [],
      "affected_hosts": ["172.16.12.1:443"],
      "description": "<clear technical description>",
      "technical_detail": "<observed evidence>",
      "business_impact": "<plain-language executive risk>",
      "remediation": "<one-sentence fix>",
      "remediation_steps": ["Step 1...", "Step 2..."],
      "references": ["<url>"],
      "evidence_refs": ["<filename>"],
      "confidence": "Confirmed|High Confidence|Possible",
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low",
      "effort": "Low|Medium|High",
      "priority": 1,
      "timeframe": "Immediate (0-7 days)|Short-term (1-4 weeks)|Medium-term (1-3 months)|Long-term (3+ months)"
    }}
  ],
  "attack_paths": [
    {{
      "id": "AP-001",
      "title": "<chain name>",
      "combined_severity": "Critical|High|Medium|Low",
      "combined_cvss_score": 9.0,
      "entry_point": "<initial access vector, e.g. unauthenticated HTTP request>",
      "finding_ids": ["F-001", "F-003"],
      "steps": [
        {{"step": 1, "finding_id": "F-001", "action": "<what attacker does>", "outcome": "<what they gain>"}},
        {{"step": 2, "finding_id": "F-003", "action": "<what attacker does next>", "outcome": "<escalated access>"}}
      ],
      "narrative": "<2-3 sentence kill-chain story explaining how the chain works end-to-end>",
      "final_impact": "<worst-case business impact if the full chain is exploited>"
    }}
  ],
  "methodology_notes": "<brief testing methodology>",
  "disclaimer": "<standard pentest disclaimer>"
}}"""

def _parse_ai_json(raw, provider):
    raw = re.sub(r'^```(?:json)?\s*', '', raw.strip())
    raw = re.sub(r'\s*```$', '', raw).strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
        raise RuntimeError(f"{provider} returned non-JSON. First 400 chars:\n{raw[:400]}")

def analyze_with_claude(api_key, model, config, findings, evidence_block):
    if not _ANTHROPIC_AVAILABLE:
        raise RuntimeError("anthropic package not installed: pip install anthropic")
    config_block = "\n".join(f"{k}: {v}" for k, v in config.items() if v)
    prompt = PROMPT_TEMPLATE.format(
        config_block=config_block,
        finding_count=len(findings),
        findings_json=json.dumps(findings, indent=2)[:28000],
        evidence_block=evidence_block[:48000],
    )
    client = anthropic.Anthropic(api_key=api_key)
    print(f"[INFO] Calling Claude ({model}) — {len(prompt):,} chars prompt...")
    message = client.messages.create(
        model=model,
        max_tokens=16000,
        messages=[{"role": "user", "content": prompt}],
    )
    return _parse_ai_json(message.content[0].text, "Claude")

def analyze_with_gemini(gemini_key, gemini_models, config, findings, evidence_block):
    import warnings
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            import google.generativeai as genai
    except ImportError:
        raise RuntimeError("google-generativeai not installed: pip install google-generativeai")
    config_block = "\n".join(f"{k}: {v}" for k, v in config.items() if v)
    prompt = PROMPT_TEMPLATE.format(
        config_block=config_block,
        finding_count=len(findings),
        findings_json=json.dumps(findings, indent=2)[:28000],
        evidence_block=evidence_block[:48000],
    )
    genai.configure(api_key=gemini_key)
    if isinstance(gemini_models, str):
        gemini_models = [gemini_models]
    last_err = None
    for model_name in gemini_models:
        try:
            print(f"[INFO] Calling Gemini ({model_name}) — {len(prompt):,} chars prompt...")
            model = genai.GenerativeModel(model_name)
            response = model.generate_content(prompt)
            return _parse_ai_json(response.text, "Gemini")
        except Exception as e:
            err_str = str(e)
            if any(kw in err_str for kw in ("RESOURCE_EXHAUSTED", "429", "quota", "rate")):
                print(f"[WARN] Gemini {model_name} quota/rate-limit — trying next model...")
                last_err = e
                continue
            if any(kw in err_str for kw in ("NOT_FOUND", "404", "not found", "not supported")):
                print(f"[WARN] Gemini {model_name} not available in this API version — trying next model...")
                last_err = e
                continue
            raise
    raise RuntimeError(f"All Gemini models failed (quota or unavailable): {last_err}") from last_err

def analyze_with_ollama(ollama_host, ollama_model, config, findings, evidence_block):
    """Call local Ollama instance — no API key, no cost. Prompt is truncated for local context limits."""
    if _urllib_req is None:
        raise RuntimeError("urllib.request unavailable")
    config_block = "\n".join(f"{k}: {v}" for k, v in config.items() if v)
    prompt = PROMPT_TEMPLATE.format(
        config_block=config_block,
        finding_count=len(findings),
        findings_json=json.dumps(findings, indent=2)[:12000],
        evidence_block=evidence_block[:16000],
    )
    payload = json.dumps({
        "model": ollama_model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }).encode()
    req = _urllib_req.Request(
        f"{ollama_host}/api/chat",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    print(f"[INFO] Calling Ollama ({ollama_model} @ {ollama_host}) — {len(prompt):,} chars prompt...")
    with _urllib_req.urlopen(req, timeout=600) as resp:
        data = json.loads(resp.read())
    text = data.get("message", {}).get("content", "")
    if not text:
        raise RuntimeError(f"Ollama returned empty content: {str(data)[:200]}")
    return _parse_ai_json(text, "Ollama")

def analyze_with_ai(api_key, gemini_key, claude_model, ollama_host, ollama_model, config, findings, evidence_block):
    """Try Ollama first (local/free), then Claude, then Gemini."""
    if ollama_host:
        try:
            return analyze_with_ollama(ollama_host, ollama_model, config, findings, evidence_block)
        except Exception as e:
            print(f"[WARN] Ollama failed: {str(e)[:200]}")
            if api_key or gemini_key:
                print("[INFO] Falling back to cloud AI...")
            else:
                raise RuntimeError(f"Ollama failed and no cloud API key configured: {e}") from e
    if api_key:
        try:
            return analyze_with_claude(api_key, claude_model, config, findings, evidence_block)
        except Exception as e:
            err_str = str(e)
            print(f"[WARN] Claude failed: {err_str[:200]}")
            if gemini_key:
                print("[INFO] Falling back to Gemini...")
            else:
                raise RuntimeError(f"Claude failed and no Gemini key configured: {err_str}") from e
    if gemini_key:
        return analyze_with_gemini(gemini_key, GEMINI_MODELS, config, findings, evidence_block)
    raise RuntimeError("No AI backend available")

def build_dry_run_analysis(findings, config):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    for f in findings:
        sev = f.get("severity", "low").lower()
        if sev in counts:
            counts[sev] += 1
    enriched = []
    for i, f in enumerate(findings):
        enriched.append({
            "id": f"F-{str(i+1).zfill(3)}",
            "title":           f.get("title", "Untitled"),
            "severity":        f.get("severity", "Low").capitalize(),
            "cvss_score":      0.0,
            "cvss_vector":     "",
            "owasp_id":        "A05",
            "owasp_name":      "Security Misconfiguration",
            "owasp_url":       "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
            "cwe_id":          "CWE-16",
            "cwe_name":        "Configuration",
            "cwe_url":         "https://cwe.mitre.org/data/definitions/16.html",
            "cve_ids":         [],
            "chain_steps":     [],
            "affected_hosts":  [],
            "description":     f.get("description", ""),
            "technical_detail":"[Dry run — AI analysis not performed]",
            "business_impact": "[Dry run — AI analysis not performed]",
            "remediation":     f.get("recommendation", "Review and remediate."),
            "remediation_steps": [],
            "references":      [],
            "evidence_refs":   f.get("evidence_ids", []),
            "confidence":      "High Confidence",
            "likelihood":      "Medium",
            "impact":          "Medium",
            "effort":          "Medium",
            "priority":        i + 1,
            "timeframe":       "Medium-term (1-3 months)",
        })
    project = config.get("PROJECT_NAME", "VAPT Assessment")
    targets = [t.strip() for t in config.get("TARGET_IPS", "").split(",") if t.strip()]
    return {
        "engagement_summary": {
            "project":            project,
            "targets":            targets or ["See pt-orc.conf"],
            "assessment_type":    "External Web Application Penetration Test",
            "testing_period":     datetime.now().strftime("%B %Y"),
            "overall_risk_rating":"Medium",
            "executive_summary":  "[Dry run — add ANTHROPIC_API_KEY to .env to generate AI analysis.]",
            "risk_justification": "Risk rating requires AI analysis.",
            "severity_counts":    counts,
            "tools_used":         ["nmap", "nikto", "testssl", "wafw00f", "gobuster"],
        },
        "findings": enriched,
        "methodology_notes": "Dry run mode — AI analysis skipped.",
        "disclaimer": (
            "This report was produced for authorized penetration testing purposes only. "
            "All testing was conducted with written authorization from the asset owner. "
            "TechGuard Labs assumes no liability for actions taken based on this report. "
            "Re-testing is recommended after remediation of all findings."
        ),
    }

HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>{{ report_title }}</title>
<style>
@page { margin: 20mm 18mm 20mm 18mm; size: A4; }
@page :first { margin: 0; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', Arial, Helvetica, sans-serif; font-size: 10pt; color: #1a1a2e; background: #ffffff; line-height: 1.5; }
.cover { background: #0f1940; color: #fff; min-height: 297mm; padding: 60px 70px; page-break-after: always; }
.cover-logo { font-size: 13pt; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; color: #90caf9; margin-bottom: 6px; }
.cover-logo-sub { font-size: 9pt; color: #7986cb; letter-spacing: 1px; }
.cover-spacer { height: 80px; }
.cover-classif { display: inline-block; background: #e53935; color: #fff; font-size: 9pt; font-weight: 700; letter-spacing: 3px; text-transform: uppercase; padding: 5px 18px; border-radius: 2px; margin-bottom: 30px; }
.cover-title { font-size: 28pt; font-weight: 700; line-height: 1.2; margin-bottom: 12px; }
.cover-subtitle { font-size: 14pt; color: #90caf9; margin-bottom: 44px; }
.cover-meta { border-top: 1px solid rgba(255,255,255,0.2); border-bottom: 1px solid rgba(255,255,255,0.2); padding: 20px 0; display: table; }
.cover-row { display: table-row; }
.cover-lbl { display: table-cell; color: #7986cb; font-size: 9pt; text-transform: uppercase; letter-spacing: 1px; padding: 4px 24px 4px 0; font-weight: 600; }
.cover-val { display: table-cell; color: #e8eaf6; font-size: 10pt; padding: 4px 0; }
.cover-footer { margin-top: 60px; color: rgba(255,255,255,0.4); font-size: 8pt; text-align: center; }
h2.sec-hdr { background: #1a237e; color: #fff; padding: 10px 18px; font-size: 13pt; font-weight: 700; margin-bottom: 20px; border-radius: 3px; page-break-before: always; }
h2.sec-hdr .n { color: #7986cb; margin-right: 8px; }
.page-section { padding-top: 4px; }
.risk-banner { border-radius: 6px; padding: 12px 18px; margin-bottom: 18px; }
.risk-banner.high     { background: #fff3e0; border-left: 6px solid #e64a19; }
.risk-banner.medium   { background: #fffde7; border-left: 6px solid #f57f17; }
.risk-banner.low      { background: #e8f5e9; border-left: 6px solid #2e7d32; }
.risk-banner.critical { background: #ffebee; border-left: 6px solid #c62828; }
.risk-banner-lbl { font-size: 9pt; color: #546e7a; margin-right: 12px; }
.risk-banner-val { font-size: 14pt; font-weight: 800; }
.risk-banner.critical .risk-banner-val { color: #c62828; }
.risk-banner.high     .risk-banner-val { color: #e64a19; }
.risk-banner.medium   .risk-banner-val { color: #f57f17; }
.risk-banner.low      .risk-banner-val { color: #2e7d32; }
.risk-banner-just { font-size: 9pt; color: #546e7a; margin-left: 14px; }
.exec-text { background: #f8f9ff; border-left: 4px solid #3f51b5; padding: 14px 18px; margin-bottom: 20px; font-size: 10.5pt; line-height: 1.65; color: #1a1a2e; border-radius: 0 4px 4px 0; }
.sev-cards { display: table; width: 100%; border-collapse: separate; border-spacing: 8px; margin-bottom: 24px; }
.sev-row   { display: table-row; }
.sev-card  { display: table-cell; text-align: center; padding: 16px 8px; border-radius: 8px; width: 20%; }
.sev-card.critical      { background: #ffebee; }
.sev-card.high          { background: #fff3e0; }
.sev-card.medium        { background: #fffde7; }
.sev-card.low           { background: #e3f2fd; }
.sev-card.informational { background: #eceff1; }
.sev-count { font-size: 28pt; font-weight: 800; line-height: 1; margin-bottom: 4px; }
.sev-card.critical      .sev-count { color: #c62828; }
.sev-card.high          .sev-count { color: #e64a19; }
.sev-card.medium        .sev-count { color: #f57f17; }
.sev-card.low           .sev-count { color: #1565c0; }
.sev-card.informational .sev-count { color: #546e7a; }
.sev-label { font-size: 8pt; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; color: #546e7a; }
table.dt { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 9.5pt; }
table.dt th { background: #283593; color: #fff; padding: 8px 12px; text-align: left; font-weight: 600; font-size: 9pt; }
table.dt td { padding: 8px 12px; border-bottom: 1px solid #e8eaf6; vertical-align: top; }
table.dt tr:nth-child(even) td { background: #f5f5ff; }
table.dt tr:last-child td { border-bottom: none; }
.rm-wrap { margin-bottom: 24px; }
.rm-wrap h3 { font-size: 10pt; color: #546e7a; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; font-weight: 600; }
table.rm { border-collapse: collapse; width: 100%; font-size: 9pt; }
table.rm td, table.rm th { border: 2px solid #fff; padding: 10px 8px; text-align: center; vertical-align: middle; }
table.rm th { background: #37474f; color: #fff; font-weight: 600; }
table.rm .rh { background: #37474f; color: #fff; font-weight: 600; width: 90px; font-size: 8.5pt; }
.rm-crit   { background: #ffcdd2; color: #b71c1c; font-weight: 700; }
.rm-high   { background: #ffe0b2; color: #bf360c; font-weight: 600; }
.rm-medium { background: #fff9c4; color: #7c5b00; }
.rm-low    { background: #e3f2fd; color: #1565c0; }
.rm-info   { background: #eceff1; color: #546e7a; }
.rm-lbl { font-size: 8pt; font-weight: 700; text-transform: uppercase; }
.rm-ids { font-size: 7.5pt; margin-top: 4px; color: #455a64; }
table.owasp { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 9pt; }
table.owasp th { background: #1a237e; color: #fff; padding: 8px 12px; text-align: left; font-weight: 600; }
table.owasp td { padding: 7px 12px; border-bottom: 1px solid #e8eaf6; }
table.owasp tr:nth-child(even) td { background: #f5f5ff; }
.bar-wrap { background: #e8eaf6; border-radius: 10px; height: 8px; width: 120px; display: inline-block; vertical-align: middle; overflow: hidden; }
.bar-fill { height: 100%; background: #3f51b5; border-radius: 10px; }
.cnt { display: inline-block; background: #3f51b5; color: #fff; font-size: 8pt; font-weight: 700; padding: 2px 8px; border-radius: 10px; min-width: 24px; text-align: center; }
.cnt.zero { background: #cfd8dc; color: #546e7a; }
.fc { border: 1px solid #e0e0e0; border-radius: 6px; margin-bottom: 28px; overflow: hidden; page-break-inside: avoid; }
.fc-hdr { padding: 12px 16px; display: table; width: 100%; }
.fc-hdr.critical      { background: #ffebee; border-left: 5px solid #c62828; }
.fc-hdr.high          { background: #fff3e0; border-left: 5px solid #e64a19; }
.fc-hdr.medium        { background: #fffde7; border-left: 5px solid #f9a825; }
.fc-hdr.low           { background: #e3f2fd; border-left: 5px solid #1565c0; }
.fc-hdr.informational { background: #eceff1; border-left: 5px solid #546e7a; }
.fc-hdr-inner { display: table-row; }
.fc-id    { display: table-cell; font-size: 9pt; font-weight: 700; color: #546e7a; vertical-align: middle; width: 52px; }
.fc-title { display: table-cell; font-size: 11pt; font-weight: 700; vertical-align: middle; padding-right: 12px; }
.fc-hdr.critical      .fc-title { color: #c62828; }
.fc-hdr.high          .fc-title { color: #bf360c; }
.fc-hdr.medium        .fc-title { color: #6d4c00; }
.fc-hdr.low           .fc-title { color: #1565c0; }
.fc-hdr.informational .fc-title { color: #37474f; }
.fc-badge-cell { display: table-cell; vertical-align: middle; width: 90px; text-align: right; }
.sev-badge { display: inline-block; font-size: 8pt; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; padding: 3px 12px; border-radius: 12px; color: #fff; }
.sev-badge.critical      { background: #c62828; }
.sev-badge.high          { background: #e64a19; }
.sev-badge.medium        { background: #f9a825; color: #3e2000; }
.sev-badge.low           { background: #1565c0; }
.sev-badge.informational { background: #546e7a; }
.fc-meta { display: table; width: 100%; background: #fafafa; border-top: 1px solid #e0e0e0; border-bottom: 1px solid #e0e0e0; padding: 10px 16px; }
.fc-meta-row  { display: table-row; }
.fc-meta-cell { display: table-cell; padding: 3px 20px 3px 0; font-size: 8.5pt; }
.fc-meta-cell .lbl { color: #78909c; font-weight: 600; text-transform: uppercase; font-size: 7.5pt; letter-spacing: 0.5px; display: block; }
.fc-meta-cell .val { color: #1a1a2e; font-weight: 500; }
.cvss-score { font-size: 14pt; font-weight: 800; }
.cvss-score.critical      { color: #c62828; }
.cvss-score.high          { color: #e64a19; }
.cvss-score.medium        { color: #f9a825; }
.cvss-score.low           { color: #1565c0; }
.cvss-score.informational { color: #546e7a; }
.fc-body { padding: 16px; }
.fc-sec { margin-bottom: 14px; }
.fc-sec-title { font-size: 8.5pt; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #455a64; margin-bottom: 5px; padding-bottom: 3px; border-bottom: 1px solid #eceff1; }
.fc-sec p { font-size: 9.5pt; line-height: 1.55; color: #263238; }
.tag { display: inline-block; font-size: 7.5pt; font-weight: 600; padding: 2px 8px; border-radius: 10px; margin: 2px 2px 2px 0; }
.tag.cve  { background: #fce4ec; color: #880e4f; }
.tag.host { background: #e8f5e9; color: #1b5e20; }
.tag.ref  { background: #e8eaf6; color: #3949ab; }
ol.steps { margin: 6px 0 0 18px; font-size: 9.5pt; line-height: 1.6; }
ol.steps li { margin-bottom: 3px; }
.ref-link { color: #1565c0; font-size: 8.5pt; display: block; margin-bottom: 2px; }
table.roadmap { width: 100%; border-collapse: collapse; font-size: 9pt; margin-bottom: 20px; }
table.roadmap th { background: #1a237e; color: #fff; padding: 8px 12px; text-align: left; font-weight: 600; }
table.roadmap td { padding: 8px 12px; border-bottom: 1px solid #e8eaf6; vertical-align: top; }
table.roadmap tr:nth-child(even) td { background: #f5f5ff; }
.effort-Low    { color: #2e7d32; font-weight: 600; }
.effort-Medium { color: #f57f17; font-weight: 600; }
.effort-High   { color: #c62828; font-weight: 600; }
.disc { background: #fff8e1; border: 1px solid #ffe082; border-radius: 6px; padding: 16px 20px; font-size: 9pt; color: #4e3400; line-height: 1.6; }
.disc h3 { color: #f57f17; font-size: 10pt; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
.footer { margin-top: 40px; border-top: 2px solid #1a237e; padding-top: 12px; text-align: center; font-size: 8pt; color: #78909c; }
.scope-h3 { font-size: 9.5pt; font-weight: 700; color: #283593; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
.scope-block { margin-bottom: 20px; }
</style>
</head>
<body>
<div class="cover">
  <div>
    <div class="cover-logo">TechGuard Labs</div>
    <div class="cover-logo-sub">Security Intelligence &amp; Penetration Testing</div>
  </div>
  <div class="cover-spacer"></div>
  <div>
    <div class="cover-classif">CONFIDENTIAL</div>
    <div class="cover-title">Security Assessment<br/>Report</div>
    <div class="cover-subtitle">Web Application Penetration Test</div>
    <div class="cover-meta">
      <div class="cover-row"><div class="cover-lbl">Project</div><div class="cover-val">{{ summary.project }}</div></div>
      <div class="cover-row"><div class="cover-lbl">Target(s)</div><div class="cover-val">{{ summary.targets | join(", ") }}</div></div>
      <div class="cover-row"><div class="cover-lbl">Assessment Type</div><div class="cover-val">{{ summary.assessment_type }}</div></div>
      <div class="cover-row"><div class="cover-lbl">Testing Period</div><div class="cover-val">{{ summary.testing_period }}</div></div>
      <div class="cover-row"><div class="cover-lbl">Report Date</div><div class="cover-val">{{ report_date }}</div></div>
      <div class="cover-row"><div class="cover-lbl">Overall Risk</div><div class="cover-val"><strong>{{ summary.overall_risk_rating }}</strong></div></div>
    </div>
  </div>
  <div class="cover-footer">
    <p>This report contains confidential information. Distribution is restricted to authorized personnel only.</p>
    <p>TechGuard Labs &bull; hari@techguardlabs.com</p>
  </div>
</div>
<div class="page-section">
<h2 class="sec-hdr"><span class="n">01</span>Executive Summary</h2>
<div class="risk-banner {{ summary.overall_risk_rating | lower }}">
  <span class="risk-banner-lbl">Overall Risk Rating</span>
  <span class="risk-banner-val">{{ summary.overall_risk_rating | upper }}</span>
  <span class="risk-banner-just">{{ summary.risk_justification }}</span>
</div>
<div class="exec-text">{{ summary.executive_summary }}</div>
<div class="sev-cards">
  <div class="sev-row">
    <div class="sev-card critical"><div class="sev-count">{{ summary.severity_counts.critical }}</div><div class="sev-label">Critical</div></div>
    <div class="sev-card high"><div class="sev-count">{{ summary.severity_counts.high }}</div><div class="sev-label">High</div></div>
    <div class="sev-card medium"><div class="sev-count">{{ summary.severity_counts.medium }}</div><div class="sev-label">Medium</div></div>
    <div class="sev-card low"><div class="sev-count">{{ summary.severity_counts.low }}</div><div class="sev-label">Low</div></div>
    <div class="sev-card informational"><div class="sev-count">{{ summary.severity_counts.informational }}</div><div class="sev-label">Info</div></div>
  </div>
</div>
</div>
<div class="page-section">
<h2 class="sec-hdr"><span class="n">02</span>Scope &amp; Methodology</h2>
<div class="scope-block">
<div class="scope-h3">Target Scope</div>
<table class="dt">
  <tr><th>Host / IP</th><th>Port(s)</th><th>Protocol</th><th>Application</th></tr>
  {% for t in scope_targets %}
  <tr><td>{{ t.host }}</td><td>{{ t.ports }}</td><td>{{ t.protocol }}</td><td>{{ t.application }}</td></tr>
  {% endfor %}
</table>
</div>
<div class="scope-block">
<div class="scope-h3">Testing Phases</div>
<table class="dt">
  <tr><th>Phase</th><th>Activity</th><th>Tools</th></tr>
  <tr><td>01 DNS Recon</td><td>Domain enumeration, subdomain discovery</td><td>dig, subfinder, dnsx</td></tr>
  <tr><td>02 IP Analysis</td><td>ASN, geolocation, cloud provider, WHOIS</td><td>whois, ipinfo</td></tr>
  <tr><td>03 Network Scan</td><td>Port scanning, service fingerprinting</td><td>nmap</td></tr>
  <tr><td>04 TLS Assessment</td><td>Certificate analysis, cipher enumeration</td><td>testssl.sh</td></tr>
  <tr><td>05 Web Enumeration</td><td>Header analysis, WAF detection, content discovery</td><td>curl, wafw00f, gobuster, nikto</td></tr>
  <tr><td>06 WordPress Scan</td><td>Plugin/theme enumeration, CVE checks</td><td>wpscan</td></tr>
  <tr><td>07 Service Verification</td><td>Manual probing of open services</td><td>Manual</td></tr>
  <tr><td>08 Application API</td><td>Rate limiting, auth bypass, API enumeration</td><td>curl, python-requests</td></tr>
  <tr><td>09 AI/LLM Endpoints</td><td>Prompt injection, data exfiltration probes</td><td>PT-Orc AI Skill</td></tr>
</table>
</div>
{% if summary.tools_used %}
<div class="scope-block">
<div class="scope-h3">Tools &amp; Frameworks</div>
<p style="font-size:9.5pt;line-height:1.8;">{% for t in summary.tools_used %}<span class="tag ref">{{ t }}</span>{% endfor %}</p>
</div>
{% endif %}
</div>
<div class="page-section">
<h2 class="sec-hdr"><span class="n">03</span>Risk Analysis</h2>
<div class="rm-wrap">
<h3>Risk Matrix — Likelihood × Impact</h3>
<table class="rm">
  <tr><th class="rh"></th><th>LOW IMPACT</th><th>MEDIUM IMPACT</th><th>HIGH IMPACT</th></tr>
  <tr>
    <th class="rh">HIGH<br/>LIKELIHOOD</th>
    <td class="rm-medium"><div class="rm-lbl">Medium</div><div class="rm-ids">{{ rm.high_low | join(", ") }}</div></td>
    <td class="rm-high"><div class="rm-lbl">High</div><div class="rm-ids">{{ rm.high_medium | join(", ") }}</div></td>
    <td class="rm-crit"><div class="rm-lbl">Critical</div><div class="rm-ids">{{ rm.high_high | join(", ") }}</div></td>
  </tr>
  <tr>
    <th class="rh">MEDIUM<br/>LIKELIHOOD</th>
    <td class="rm-low"><div class="rm-lbl">Low</div><div class="rm-ids">{{ rm.medium_low | join(", ") }}</div></td>
    <td class="rm-medium"><div class="rm-lbl">Medium</div><div class="rm-ids">{{ rm.medium_medium | join(", ") }}</div></td>
    <td class="rm-high"><div class="rm-lbl">High</div><div class="rm-ids">{{ rm.medium_high | join(", ") }}</div></td>
  </tr>
  <tr>
    <th class="rh">LOW<br/>LIKELIHOOD</th>
    <td class="rm-info"><div class="rm-lbl">Info</div><div class="rm-ids">{{ rm.low_low | join(", ") }}</div></td>
    <td class="rm-low"><div class="rm-lbl">Low</div><div class="rm-ids">{{ rm.low_medium | join(", ") }}</div></td>
    <td class="rm-medium"><div class="rm-lbl">Medium</div><div class="rm-ids">{{ rm.low_high | join(", ") }}</div></td>
  </tr>
</table>
</div>
<div class="scope-block">
<div class="scope-h3">OWASP Top 10 2021 — Coverage Map</div>
<table class="owasp">
  <tr><th style="width:60px;">Code</th><th>Category</th><th style="width:160px;">Coverage</th><th style="width:60px;">Count</th></tr>
  {% for item in owasp_coverage %}
  <tr>
    <td><strong>{{ item.id }}</strong></td>
    <td>{{ item.name }}</td>
    <td><div class="bar-wrap"><div class="bar-fill" style="width:{{ item.pct }}%;"></div></div></td>
    <td><span class="cnt {% if item.count == 0 %}zero{% endif %}">{{ item.count }}</span></td>
  </tr>
  {% endfor %}
</table>
</div>
</div>
<div class="page-section">
<h2 class="sec-hdr"><span class="n">04</span>Detailed Findings</h2>
{% for f in findings %}
<div class="fc">
  <div class="fc-hdr {{ f.severity | lower }}">
    <div class="fc-hdr-inner">
      <div class="fc-id">{{ f.id }}</div>
      <div class="fc-title">{{ f.title }}</div>
      <div class="fc-badge-cell"><span class="sev-badge {{ f.severity | lower }}">{{ f.severity }}</span></div>
    </div>
  </div>
  <div class="fc-meta">
    <div class="fc-meta-row">
      <div class="fc-meta-cell"><span class="lbl">CVSS 3.1</span><span class="val cvss-score {{ f.severity | lower }}">{{ f.cvss_score }}</span></div>
      <div class="fc-meta-cell"><span class="lbl">OWASP 2021</span><span class="val">{{ f.owasp_id }} — {{ f.owasp_name }}</span></div>
      <div class="fc-meta-cell"><span class="lbl">CWE</span><span class="val">{{ f.cwe_id }} — {{ f.cwe_name }}</span></div>
      <div class="fc-meta-cell"><span class="lbl">Confidence</span><span class="val">{{ f.confidence }}</span></div>
    </div>
  </div>
  <div class="fc-body">
    {% if f.cve_ids %}<div class="fc-sec"><div class="fc-sec-title">CVE References</div>{% for cve in f.cve_ids %}<span class="tag cve">{{ cve }}</span>{% endfor %}</div>{% endif %}
    {% if f.chain_steps %}<div class="fc-sec"><div class="fc-sec-title">Attack Chain Steps</div><ol class="steps">{% for step in f.chain_steps %}<li>{{ step }}</li>{% endfor %}</ol></div>{% endif %}
    <div class="fc-sec"><div class="fc-sec-title">Affected Hosts</div>{% for h in f.affected_hosts %}<span class="tag host">{{ h }}</span>{% endfor %}{% if not f.affected_hosts %}<span class="tag host">See description</span>{% endif %}</div>
    <div class="fc-sec"><div class="fc-sec-title">Description</div><p>{{ f.description }}</p></div>
    <div class="fc-sec"><div class="fc-sec-title">Technical Detail</div><p>{{ f.technical_detail }}</p></div>
    <div class="fc-sec"><div class="fc-sec-title">Business Impact</div><p>{{ f.business_impact }}</p></div>
    <div class="fc-sec">
      <div class="fc-sec-title">Remediation</div>
      <p><strong>{{ f.remediation }}</strong></p>
      {% if f.remediation_steps %}<ol class="steps">{% for step in f.remediation_steps %}<li>{{ step }}</li>{% endfor %}</ol>{% endif %}
    </div>
    {% if f.references %}<div class="fc-sec"><div class="fc-sec-title">References</div>{% for ref in f.references %}<a class="ref-link" href="{{ ref }}">{{ ref }}</a>{% endfor %}</div>{% endif %}
  </div>
</div>
{% endfor %}
</div>
<div class="page-section">
<h2 class="sec-hdr"><span class="n">05</span>Attack Path Analysis</h2>
{% if attack_paths %}
{% for ap in attack_paths %}
<div class="finding-card sev-{{ ap.combined_severity | lower }}" style="margin-bottom:18px;">
  <div class="finding-hdr">
    <span class="finding-id">{{ ap.id }}</span>
    <span class="finding-title">{{ ap.title }}</span>
    <span class="sev-badge {{ ap.combined_severity | lower }}" style="margin-left:auto;">{{ ap.combined_severity }}</span>
    <span style="margin-left:12px;font-size:8.5pt;color:#546e7a;">Combined CVSS {{ ap.combined_cvss_score }}</span>
  </div>
  <div class="finding-body">
    <div class="finding-row"><span class="finding-lbl">Entry Point</span><span>{{ ap.entry_point }}</span></div>
    <div class="finding-row"><span class="finding-lbl">Finding IDs</span><span>{{ ap.finding_ids | join(', ') }}</span></div>
    <div class="finding-row"><span class="finding-lbl">Kill Chain</span>
      <ol style="margin:4px 0 0 16px;padding:0;font-size:9pt;line-height:1.7;">
        {% for s in ap.steps %}
        <li><strong>{{ s.finding_id }}</strong> — {{ s.action }} → <em>{{ s.outcome }}</em></li>
        {% endfor %}
      </ol>
    </div>
    <div class="finding-row"><span class="finding-lbl">Narrative</span><span>{{ ap.narrative }}</span></div>
    <div class="finding-row"><span class="finding-lbl">Final Impact</span><span>{{ ap.final_impact }}</span></div>
  </div>
</div>
{% endfor %}
{% else %}
<p style="font-size:9.5pt;color:#546e7a;">No multi-step attack chains identified in this assessment.</p>
{% endif %}
</div>
<div class="page-section">
{% if retest_diff %}
<div class="page-section">
<h2 class="sec-hdr"><span class="n">06</span>Retest Comparison</h2>
{% set c = retest_diff.counts %}
<div class="risk-banner {{ 'high' if c.regressed > 0 else ('medium' if c.new > 0 else 'low') }}" style="margin-bottom:16px;">
  <span class="risk-banner-lbl">Baseline:</span> {{ retest_diff.baseline_count }} findings &nbsp;|&nbsp;
  <span class="risk-banner-lbl">Current:</span> {{ retest_diff.current_count }} findings &nbsp;&nbsp;
  <strong style="color:#2e7d32;">&#10003; Fixed: {{ c.fixed }}</strong> &nbsp;&nbsp;
  <strong style="color:#546e7a;">&#8635; Persists: {{ c.persists }}</strong> &nbsp;&nbsp;
  {% if c.new > 0 %}<strong style="color:#e64a19;">&#43; New: {{ c.new }}</strong> &nbsp;&nbsp;{% endif %}
  {% if c.regressed > 0 %}<strong style="color:#c62828;">&#8593; Regressed: {{ c.regressed }}</strong>{% endif %}
</div>
<table class="roadmap">
  <tr><th>Status</th><th>Finding</th><th style="width:90px;">Severity</th><th style="width:70px;">Was</th></tr>
  {% for f in retest_diff.fixed %}
  <tr><td style="color:#2e7d32;font-weight:700;">Fixed</td><td>{{ f.title }}</td><td><span class="sev-badge {{ f.severity | lower }}" style="font-size:7.5pt;">{{ f.severity }}</span></td><td>—</td></tr>
  {% endfor %}
  {% for f in retest_diff.persists %}
  <tr><td style="color:#546e7a;">Persists</td><td>{{ f.title }}</td><td><span class="sev-badge {{ f.severity | lower }}" style="font-size:7.5pt;">{{ f.severity }}</span></td><td>—</td></tr>
  {% endfor %}
  {% for f in retest_diff.regressed %}
  <tr><td style="color:#c62828;font-weight:700;">Regressed</td><td>{{ f.title }}</td><td><span class="sev-badge {{ f.severity | lower }}" style="font-size:7.5pt;">{{ f.severity }}</span></td><td>{{ f.was }}</td></tr>
  {% endfor %}
  {% for f in retest_diff.new %}
  <tr><td style="color:#e64a19;font-weight:700;">New</td><td>{{ f.title }}</td><td><span class="sev-badge {{ f.severity | lower }}" style="font-size:7.5pt;">{{ f.severity }}</span></td><td>—</td></tr>
  {% endfor %}
</table>
</div>
{% endif %}
<div class="page-section">
<h2 class="sec-hdr"><span class="n">{{ '07' if retest_diff else '06' }}</span>Remediation Roadmap</h2>
<table class="roadmap">
  <tr><th style="width:60px;">ID</th><th>Finding</th><th style="width:90px;">Severity</th><th style="width:80px;">Effort</th><th style="width:170px;">Timeframe</th></tr>
  {% for f in findings | sort(attribute='priority') %}
  {% if f.severity | lower != 'informational' %}
  <tr>
    <td>{{ f.id }}</td><td>{{ f.title }}</td>
    <td><span class="sev-badge {{ f.severity | lower }}" style="font-size:7.5pt;">{{ f.severity }}</span></td>
    <td><span class="effort-{{ f.effort }}">{{ f.effort }}</span></td>
    <td>{{ f.timeframe }}</td>
  </tr>
  {% endif %}
  {% endfor %}
</table>
</div>
<div class="page-section">
<h2 class="sec-hdr"><span class="n">{{ '08' if retest_diff else '07' }}</span>Disclaimer &amp; Legal</h2>
<div class="disc"><h3>Important Notice</h3><p>{{ disclaimer }}</p></div>
{% if methodology_notes %}
<div style="margin-top:20px;">
  <div class="scope-h3" style="margin-bottom:8px;">Methodology Notes</div>
  <p style="font-size:9.5pt;line-height:1.6;">{{ methodology_notes }}</p>
</div>
{% endif %}
<div class="footer">
  <strong>TechGuard Labs</strong> &bull; hari@techguardlabs.com &bull;
  Report generated {{ report_date }} &bull; PT-Orc Suite v1.0
</div>
</div>
</body>
</html>"""

def build_risk_matrix(findings):
    matrix = {k: [] for k in ("high_high","high_medium","high_low","medium_high","medium_medium","medium_low","low_high","low_medium","low_low")}
    for f in findings:
        if f.get("severity","").lower() == "informational":
            continue
        lk = (f.get("likelihood") or "Medium").lower()
        im = (f.get("impact") or "Medium").lower()
        lk = lk if lk in ("high","medium","low") else "medium"
        im = im if im in ("high","medium","low") else "medium"
        key = f"{lk}_{im}"
        if key in matrix:
            matrix[key].append(f.get("id","?"))
    return matrix

def build_owasp_coverage(findings):
    counts = {k: 0 for k in OWASP_MAP}
    for f in findings:
        oid = f.get("owasp_id","")
        if oid in counts:
            counts[oid] += 1
    max_c = max(counts.values(), default=1)
    return [{"id": oid, "name": OWASP_MAP[oid][0], "count": counts[oid],
             "pct": int(counts[oid] / max(max_c,1) * 100)} for oid in OWASP_MAP]

def build_scope_targets(config):
    targets = []
    for ip in (config.get("TARGET_IPS","") or "").split(","):
        ip = ip.strip()
        if ip:
            targets.append({"host": ip, "ports": "443, 4443, 8443", "protocol": "HTTPS", "application": "Web Application"})
    for domain in (config.get("TARGET_DOMAINS","") or "").split(","):
        domain = domain.strip()
        if domain:
            targets.append({"host": domain, "ports": "443", "protocol": "HTTPS", "application": "Web Application"})
    if not targets:
        targets.append({"host": "See pt-orc.conf", "ports": "—", "protocol": "—", "application": "—"})
    return targets

def generate_html(analysis, config, retest_diff=None):
    summary  = analysis.get("engagement_summary", {})
    findings = analysis.get("findings", [])
    for f in findings:
        sev = f.get("severity","Low")
        f["severity"] = sev.capitalize() if sev else "Low"
        f.setdefault("priority", 99)
        f.setdefault("effort", "Medium")
        f.setdefault("timeframe", "Medium-term (1-3 months)")
        f.setdefault("remediation_steps", [])
        f.setdefault("affected_hosts", [])
        f.setdefault("cve_ids", [])
        f.setdefault("chain_steps", [])
        f.setdefault("references", [])
    tpl = Template(HTML_TEMPLATE)
    return tpl.render(
        report_title=f"Security Assessment Report — {summary.get('project','VAPT')}",
        report_date=datetime.now().strftime("%d %B %Y"),
        summary=summary,
        findings=findings,
        rm=build_risk_matrix(findings),
        owasp_coverage=build_owasp_coverage(findings),
        scope_targets=build_scope_targets(config),
        attack_paths=analysis.get("attack_paths", []),
        retest_diff=retest_diff,
        disclaimer=analysis.get("disclaimer","This report was produced for authorized penetration testing purposes only."),
        methodology_notes=analysis.get("methodology_notes",""),
    )

def generate_pdf(html_content, output_path):
    if not WEASYPRINT_AVAILABLE:
        print("[WARN] WeasyPrint not available — PDF skipped. Install: pip install weasyprint")
        return False
    try:
        print("[INFO] Generating PDF via WeasyPrint...")
        WeasyprintHTML(string=html_content, base_url=str(SCRIPT_DIR)).write_pdf(str(output_path))
        return True
    except Exception as e:
        print(f"[WARN] PDF generation failed: {e}")
        return False

def main():
    if not RUN_DIR or not RUN_DIR.exists():
        sys.exit(f"[ERROR] TG_RUN_DIR not found: {RUN_DIR}")
    if not OUTPUT_DIR:
        sys.exit("[ERROR] TG_OUTPUT_DIR not set")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    config = load_config(CONF_FILE) if CONF_FILE and CONF_FILE.exists() else {}
    project_name = config.get("PROJECT_NAME", "VAPT-Assessment")
    print(f"[INFO] Project   : {project_name}")
    print(f"[INFO] Run dir   : {RUN_DIR.name}")

    findings = load_and_deduplicate_findings(RUN_DIR)
    print(f"[INFO] Findings  : {len(findings)} deduplicated")

    retest_diff = None
    if BASELINE_DIR:
        print(f"[INFO] Baseline  : {BASELINE_DIR}")
        retest_diff = load_and_diff_baseline(BASELINE_DIR, findings)
        if retest_diff:
            diff_out = OUTPUT_DIR / "retest_diff.json"
            diff_out.write_text(json.dumps(retest_diff, indent=2))
            c = retest_diff["counts"]
            print(f"[OK]   retest_diff.json — fixed:{c['fixed']} persists:{c['persists']} regressed:{c['regressed']} new:{c['new']}")

    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = re.sub(r'[^A-Za-z0-9_-]', '_', project_name)
    html_out = OUTPUT_DIR / f"ai_report_{safe}_{ts}.html"
    pdf_out  = OUTPUT_DIR / f"ai_report_{safe}_{ts}.pdf"
    json_out = OUTPUT_DIR / f"ai_report_{safe}_{ts}_analysis.json"

    if DRY_RUN:
        print("[INFO] Dry run — skipping AI API call")
        analysis = build_dry_run_analysis(findings, config)
    else:
        if not API_KEY and not GEMINI_KEY and not OLLAMA_HOST:
            sys.exit("[ERROR] No AI backend — set TG_API_KEY, TG_GEMINI_API_KEY, or TG_OLLAMA_HOST")
        if OLLAMA_HOST and not API_KEY and not GEMINI_KEY:
            backend = f"Ollama ({OLLAMA_MODEL} @ {OLLAMA_HOST})"
        elif OLLAMA_HOST and API_KEY and GEMINI_KEY:
            backend = f"Ollama primary ({OLLAMA_MODEL}), Claude + Gemini fallback"
        elif OLLAMA_HOST and API_KEY:
            backend = f"Ollama primary ({OLLAMA_MODEL}), Claude fallback"
        elif OLLAMA_HOST and GEMINI_KEY:
            backend = f"Ollama primary ({OLLAMA_MODEL}), Gemini fallback"
        elif API_KEY and GEMINI_KEY:
            backend = "Claude (Gemini fallback ready)"
        elif API_KEY:
            backend = "Claude"
        else:
            backend = "Gemini"
        print(f"[INFO] AI backend: {backend}")
        print("[INFO] Collecting evidence summaries...")
        evidence_block = collect_evidence_summaries(config)
        if retest_diff:
            c = retest_diff["counts"]
            evidence_block += (
                f"\n\n## Retest Comparison vs Baseline\n"
                f"Baseline findings: {retest_diff['baseline_count']} | Current: {retest_diff['current_count']}\n"
                f"Fixed: {c['fixed']} | Persists: {c['persists']} | Regressed: {c['regressed']} | New: {c['new']}\n"
                f"Regressed items: {[r['title'] for r in retest_diff['regressed']] or 'none'}\n"
                f"New items: {[n['title'] for n in retest_diff['new']] or 'none'}\n"
            )
        print(f"[INFO] Evidence  : {len(evidence_block):,} chars")
        analysis = analyze_with_ai(API_KEY, GEMINI_KEY, MODEL, OLLAMA_HOST, OLLAMA_MODEL, config, findings, evidence_block)
        f_count = len(analysis.get("findings",[]))
        print(f"[INFO] Analysis complete — {f_count} findings in report")

    json_out.write_text(json.dumps(analysis, indent=2))
    print(f"[OK]   JSON      : {json_out.name}")

    print("[INFO] Rendering HTML report...")
    html_content = generate_html(analysis, config, retest_diff)
    html_out.write_text(html_content, encoding="utf-8")
    print(f"[OK]   HTML      : {html_out}")

    if not NO_PDF:
        if generate_pdf(html_content, pdf_out):
            print(f"[OK]   PDF       : {pdf_out}")
    else:
        print("[INFO] PDF skipped (TG_NO_PDF=1)")

if __name__ == "__main__":
    main()
PYTHON_EOF

    local _py_env=(
        "TG_RUN_DIR=${RUN_DIR_ACTUAL}"
        "TG_CONF=${SCRIPT_DIR}/pt-orc.conf"
        "TG_OUTPUT_DIR=${RUN_DIR_ACTUAL}"
        "TG_API_KEY=${api_key}"
        "TG_GEMINI_API_KEY=${gemini_key}"
        "TG_MODEL=${AI_MODEL}"
        "TG_OLLAMA_HOST=${ollama_host}"
        "TG_OLLAMA_MODEL=${ollama_model}"
        "TG_NO_PDF=${AI_NO_PDF}"
        "TG_DRY_RUN=${DRY_RUN}"
        "TG_SCRIPT_DIR=${SCRIPT_DIR}"
        "TG_BASELINE_DIR=${BASELINE_RUN_DIR}"
    )
    if [[ -n "$_as_user" ]]; then
        sudo -u "$_as_user" env "${_py_env[@]}" "$_py_exe" "$tmp_py"
    else
        env "${_py_env[@]}" "$_py_exe" "$tmp_py"
    fi
    local rc=$?

    rm -f "$tmp_py"

    if [[ $rc -eq 0 ]]; then
        log_ok "AI report written to ${RUN_DIR_ACTUAL}/"
        AI_REPORT_FILES=$(ls "${RUN_DIR_ACTUAL}"/ai_report_* 2>/dev/null | tr '\n' ' ')
    else
        log_err "AI report generation failed (exit ${rc})"
    fi
    return $rc
}

# =============================================================================
# MRK:12_MAIN — MAIN entry point | main,entry,point | L1704-1779
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

main() {
    AI_REPORT_FILES=""

    echo -e "${GREEN}"
    echo "════════════════════════════════════════════════════════════"
    echo "  12_report_pack.sh"
    echo "  TechGuard."
    echo "  Project:  ${ORCHESTRATOR_PROJECT_ID}"
    echo "  Profile:  ${ENGAGEMENT_PROFILE}"
    echo "  Evidence: ${EVIDENCE_BASE}"
    [[ "$DRY_RUN"   -eq 1 ]] && echo "  Mode:     DRY-RUN"
    [[ "$RETEST"    -eq 1 ]] && echo "  Retest:   YES (retest_status=pending)"
    [[ -n "$BASELINE_RUN_DIR" ]] && echo "  Baseline: ${BASELINE_RUN_DIR}"
    [[ "$AI_REPORT" -eq 0 ]] && echo "  AI Report: DISABLED (--no-ai-report)"
    [[ "$AI_NO_PDF" -eq 1 ]] && echo "  PDF:       DISABLED (--no-pdf)"
    echo "════════════════════════════════════════════════════════════"
    echo -e "${NC}"

    {
        echo "# Session Start — 12_report_pack.sh"
        echo "# Time:        $(_now)"
        echo "# Project:     ${ORCHESTRATOR_PROJECT_ID}"
        echo "# Profile:     ${ENGAGEMENT_PROFILE}"
        echo "# Dry run:     ${DRY_RUN}"
        echo "# Retest:      ${RETEST}"
        echo "# AI Report:   ${AI_REPORT}"
        echo "# AI Model:    ${AI_MODEL}"
        echo "# Evidence:    ${EVIDENCE_BASE}"
    } >> "$LOG_FILE"

    # Check for jq before doing any real work (belt-and-suspenders; also caught in validate)
    command -v jq &>/dev/null || { log_err "jq required"; exit 1; }
    command -v sha256sum &>/dev/null || { log_err "sha256sum required"; exit 1; }

    # Run each section
    build_scope_json
    build_evidence_manifest
    collect_findings
    build_report_bundle
    write_output
    generate_ai_report || true   # non-fatal: missing API key or deps just warns

    # Compute phases from evidence lines for display
    local phases_str="${PHASES_DISPLAY:-unknown}"

    echo ""
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  12_report_pack.sh — Export complete${NC}"
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    printf "  %-14s %s\n" "Run dir:"     "${RUN_DIR_DISPLAY:-<dry-run>}"
    printf "  %-14s %s\n" "scope.json:"  "${SCOPE_TARGET_COUNT} targets"
    printf "  %-14s %s\n" "evidence:"    "${EVIDENCE_COUNT} items across ${phases_str} phases"
    printf "  %-14s %s\n" "findings:"    "${FINDINGS_COUNT} findings (${SEVERITY_COUNTS})"
    printf "  %-14s %s\n" "residual:"    "${RESIDUAL_RISK}"
    if [[ -n "$AI_REPORT_FILES" ]]; then
        echo ""
        echo -e "${BOLD}${GREEN}  AI Report files (in run dir):${NC}"
        for f in $AI_REPORT_FILES; do
            printf "    %s\n" "$(basename "$f")"
        done
    fi
    echo ""
    if [[ "$DRY_RUN" -ne 0 ]]; then
        echo -e "${YELLOW}  DRY-RUN complete — no files written.${NC}"
    fi
    echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo ""
}

main

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
