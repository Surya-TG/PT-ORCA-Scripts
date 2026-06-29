#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:25_NAV_TOC — Section index | nav,toc,index | L5-44
# - MRK:25_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration,edit,pt | L45-88 | ⚠ no-insert-before; propose-before-edit; read-toc-first
# - MRK:25_LOG — COLOURS AND LOGGING | log,colours,logging | L89-111 | ⚠ no-insert-before
# - MRK:25_ARGS — ARGUMENT PARSING | args,argument,parsing | L112-145 | ⚠ no-insert-before
# - MRK:25_VALIDATE — VALIDATION | validate,validation,project,id,required | L146-174 | ⚠ no-insert-before
# - MRK:25_SCOPE — BUILD SCOPE JSON | scope,build,json,targets,window | L175-255 | ⚠ no-insert-before; read-toc-first
# - MRK:25_EVIDENCE — BUILD EVIDENCE MANIFEST | evidence,build,manifest,walk,sha256 | L256-354 | ⚠ no-insert-before; read-toc-first
# - MRK:25_FINDINGS — COLLECT FINDINGS | findings,collect,pattern,detect,jsonl | L355-620 | ⚠ no-insert-before; read-toc-first
# - MRK:25_BUNDLE — BUILD REPORT BUNDLE | bundle,build,report,residual,risk | L621-679 | ⚠ no-insert-before; read-toc-first
# - MRK:25_WRITE — WRITE OUTPUT FILES | write,output,export,dir | L680-744 | ⚠ no-insert-before; read-toc-first
# - MRK:25_AI_REPORT — AI REPORT HTML/PDF/JSON | ai,report,html,pdf,json | L745-1703 | ⚠ no-insert-before; read-toc-first
# - MRK:25_MAIN — MAIN entry point | main,entry,point | L1704-1779 | ⚠ no-insert-before; read-toc-first
# NAV-LEN: 11 entries | Integrity-hash: 8a1b9c0b90a405f7 | Last-indexed: 2026-06-16T15:34:52Z

# =============================================================================
# 25_report_pack.sh — TechGuard. [VAPT-Enhanced v1.0 — 2026-06-06]
# Report Pack — reads all scan evidence and produces 4 files for TG Audit Orchestrator
#
# Output files (strict Pydantic validation on import):
#   scope.json            — engagement scope, targets, window, RoE
#   evidence_manifest.jsonl — one evidence record per file (sha256, phase, summary)
#   findings.jsonl        — deduplicated, severity-ranked findings
#   report_bundle.json    — counts, residual risk, metadata
# =============================================================================
# USAGE:
#   ./25_report_pack.sh [OPTIONS]
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
# MRK:25_CONF — ENGAGEMENT CONFIGURATION | conf,engagement,configuration,edit,pt | L45-88
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
AI_MODEL="${AI_CLAUDE_MODEL:-claude-haiku-4-5-20251001}"
AI_BACKEND_MODE="${AI_BACKEND_MODE:-auto}"
BASELINE_RUN_DIR=""     # set via --baseline <prior_run_dir>; enables retest diff
RUN_DIR_ACTUAL=""       # set by write_output; consumed by generate_ai_report

# =============================================================================
# MRK:25_LOG — COLOURS AND LOGGING | log,colours,logging | L89-111
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
# MRK:25_ARGS — ARGUMENT PARSING | args,argument,parsing | L112-145
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
# MRK:25_VALIDATE — VALIDATION | validate,validation,project,id,required | L146-174
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
    echo "  Example: ./25_report_pack.sh --project-id a1b2c3d4-1234-5678-abcd-ef0123456789"
    echo ""
    exit 1
fi

if ! command -v jq &>/dev/null; then
    log_err "jq is required but not found. Install: apt-get install -y jq"
    exit 1
fi

log "25_report_pack.sh — TechGuard. | Project: ${ORCHESTRATOR_PROJECT_ID}"
log "Evidence base: ${EVIDENCE_BASE}"
log "Output dir:    ${OUTPUT_DIR}"
[[ "$DRY_RUN" -eq 1 ]] && log_warn "DRY-RUN mode — no output files will be written"

# =============================================================================
# MRK:25_SCOPE — BUILD SCOPE JSON | scope,build,json,targets,window | L175-255
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
# MRK:25_EVIDENCE — BUILD EVIDENCE MANIFEST | evidence,build,manifest,walk,sha256 | L256-354
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

# Global maps used by MRK:25_FINDINGS to link files to ev-NNN ids
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
        local phase="06_web"   # catchall default
        if [[ "$fdir" == *_dns* || "$fname" == *_dns_* ]]; then
            phase="01_dns"
        elif [[ "$fname" == ip_analysis* ]]; then
            phase="03_ip"
        elif [[ "$fname" == nmap_* || ( "$fdir" == *_sweep* && "$fname" == *comp_scan* ) ]]; then
            phase="04_network"
        elif [[ "$fname" == tls_* || "$fname" == testssl_* || "$fname" == cert_* ]]; then
            phase="05_tls"
        elif [[ "$fname" == headers_* || "$fname" == sec_headers_* || \
                "$fname" == gobuster_* || "$fname" == nikto_* || \
                "$fname" == whatweb_* || "$fname" == sensitive_* || \
                "$fname" == cors_*    || "$fname" == graphql_* || \
                "$fname" == api_endpoints_* ]]; then
            phase="06_web"
        elif [[ "$fname" == wp_* ]]; then
            phase="07_wordpress"
        elif [[ "$fname" == service_* ]]; then
            phase="08_service"
        elif [[ "$fname" == app_* ]]; then
            phase="14_app_api"
        elif [[ "$fname" == llm_* || "$fname" == ai_* ]]; then
            phase="16_ai_llm"
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
# MRK:25_FINDINGS — COLLECT FINDINGS | findings,collect,pattern,detect,jsonl | L355-620
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
        -name "${PROJ_SLUG}-*-findings-*.jsonl" \
        -type f -print0 2>/dev/null | sort -z)

    for pf in "${pregen_files[@]:-}"; do
        [[ -z "$pf" || ! -f "$pf" ]] && continue
        log_info "  Loading pre-generated findings: $(basename "$pf")"
        while IFS= read -r fline; do
            fline="${fline//$'\r'/}"   # strip CRLF carriage returns
            [[ -z "$fline" ]] && continue
            # Skip lines with malformed JSON (unescaped backslashes, control chars, etc.)
            if ! printf '%s' "$fline" | jq -e . >/dev/null 2>&1; then
                log_warn "  Skipping malformed finding line in $(basename "$pf")"
                continue
            fi
            (( f_count++ )) || true
            local new_id; new_id="f-$(printf '%03d' "$f_count")"
            local sev; sev=$(printf '%s' "$fline" | jq -r '.severity // "info"')

            # Remap evidence_ids: replace any source_file-based references with ev-NNN
            # Strategy: for each source_file name in the finding's evidence_ids field,
            # look up our manifest map; fall back to the original id if not found.
            local remapped_ev
            remapped_ev=$(printf '%s' "$fline" | jq -c '.evidence_ids // []')
            # Try to rebuild from source_file field if present
            local src_file; src_file=$(printf '%s' "$fline" | jq -r '.source_file // empty')
            if [[ -n "$src_file" ]]; then
                local mapped="${EV_ID_BY_BASE[$src_file]:-}"
                if [[ -n "$mapped" ]]; then
                    remapped_ev="[\"${mapped}\"]"
                fi
            fi

            local relined
            relined=$(printf '%s' "$fline" | jq -c \
                --arg new_id "$new_id" \
                --argjson ev_ids "$remapped_ev" \
                '.id = $new_id | .evidence_ids = $ev_ids') || continue
            FINDINGS_LINES+=("$relined")
            FINDING_SEVERITIES+=("$sev")
            log_find "Pre-generated [${sev}] $(printf '%s' "$fline" | jq -r '.title // "unknown"')"
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
                FINDINGS_LINES+=("$(_make_finding "$fid" "TLS 1.0/1.1 still active" "medium" "05_tls" "$ev_ids" "$desc" "$rec")")
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
                    FINDINGS_LINES+=("$(_make_finding "$fid" "testssl: ${ttext:0:80}" "$normalized_sev" "05_tls" "$ev_ids" "$desc" "$rec")")
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
                FINDINGS_LINES+=("$(_make_finding "$fid" "Multiple security headers missing" "medium" "06_web" "$ev_ids" "$desc" "$rec")")
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
                FINDINGS_LINES+=("$(_make_finding "$fid" "Sensitive file or directory exposed" "high" "06_web" "$ev_ids" "$desc" "$rec")")
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
                local nikto_phase="06_web"
                [[ "$fdir" == *wp* || "$fname" == *wp_* ]] && nikto_phase="07_wordpress"
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
                FINDINGS_LINES+=("$(_make_finding "$fid" "API endpoint accessible without authentication" "high" "14_app_api" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("high")
                log_find "high [14_app_api] API auth bypass candidates (${bypass_count}) — ${fname}"
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
                FINDINGS_LINES+=("$(_make_finding "$fid" "No rate limiting on API endpoints" "medium" "14_app_api" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("medium")
                log_find "medium [14_app_api] No rate limiting on API endpoints — ${fname}"
            fi
        fi

        # ---- 09_ai_llm: prompt injection ----
        if [[ "$fname" == llm_injection_* || "$fname" == ai_injection_* ]]; then
            if grep -qE "INJECTION_SUCCESS|INJECTION: SUCCESS" "$fpath" 2>/dev/null; then
                (( f_count++ )) || true
                local fid; fid="f-$(printf '%03d' "$f_count")"
                local desc="Prompt injection was confirmed against the AI/LLM endpoint. The model accepted injected instructions that overrode its system prompt or changed its output behaviour. This can lead to data exfiltration, safety bypass, and indirect command execution. Evidence: ${fname}"
                local rec="Implement robust input sanitisation and output validation for all LLM integrations. Use a separate instruction channel from user data. Apply content filtering and monitoring."
                FINDINGS_LINES+=("$(_make_finding "$fid" "Prompt injection vulnerability confirmed" "high" "16_ai_llm" "$ev_ids" "$desc" "$rec")")
                FINDING_SEVERITIES+=("high")
                log_find "high [16_ai_llm] Prompt injection confirmed — ${fname}"
            fi
        fi

    done < <(find "$EVIDENCE_BASE" -type f -print0 2>/dev/null | sort -z)

    FINDINGS_COUNT="${#FINDINGS_LINES[@]}"
    log_ok "Findings collected — ${FINDINGS_COUNT} total"
}

# =============================================================================
# MRK:25_BUNDLE — BUILD REPORT BUNDLE | bundle,build,report,residual,risk | L621-679
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
# MRK:25_WRITE — WRITE OUTPUT FILES | write,output,export,dir | L680-744
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
    # When running as root on behalf of a user (sudo), let that user own the run dir
    # so the Python AI report (which runs as SUDO_USER) can write files into it.
    [[ "$EUID" -eq 0 && -n "${SUDO_USER:-}" ]] && chown "${SUDO_USER}" "$run_dir"
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
        echo "# Session End — 25_report_pack.sh"
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
# MRK:25_AI_REPORT — AI REPORT HTML/PDF/JSON | ai,report,html,pdf,json | L745-1703
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

generate_ai_report() {
    [[ "$AI_REPORT" -eq 0 ]] && { log "AI report skipped (--no-ai-report)"; return 0; }
    [[ -z "$RUN_DIR_ACTUAL"  ]] && { log_err "No run dir — cannot generate AI report"; return 1; }

    local api_key="${ANTHROPIC_API_KEY:-}"
    local gemini_key="${GEMINI_API_KEY:-}"
    if [[ "${AI_BACKEND_MODE:-auto}" == "ollama_only" ]]; then
        api_key=""
        gemini_key=""
        log "AI mode: ollama_only — cloud backends disabled, using Ollama only"
    fi
    local ollama_host="${OLLAMA_HOST:-}"
    local ollama_model="${OLLAMA_MODEL:-qwen2.5:14b}"
    local ollama_ok=0

    local _try_ollama_hosts=()
    [[ -n "$ollama_host" ]] && _try_ollama_hosts+=("$ollama_host")
    [[ -n "${OLLAMA_HOST_FALLBACK:-}" && "${OLLAMA_HOST_FALLBACK}" != "$ollama_host" ]] \
        && _try_ollama_hosts+=("${OLLAMA_HOST_FALLBACK}")

    for _oh in "${_try_ollama_hosts[@]:-}"; do
        [[ -z "$_oh" ]] && continue
        if curl -sf --max-time 3 "${_oh}/api/tags" >/dev/null 2>&1; then
            ollama_ok=1
            ollama_host="$_oh"
            break
        else
            log_warn "Ollama not reachable at ${_oh}"
        fi
    done
    if [[ "$ollama_ok" -eq 0 ]]; then
        [[ "${#_try_ollama_hosts[@]}" -gt 0 ]] && log_warn "No Ollama endpoint reachable — skipping local backend"
        ollama_host=""
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
"""AI-Powered VAPT Report — embedded engine for 25_report_pack.sh"""
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
OLLAMA_MODEL = os.environ.get("TG_OLLAMA_MODEL", "qwen2.5:14b")
GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
NO_PDF       = os.environ.get("TG_NO_PDF", "0") == "1"
DRY_RUN      = os.environ.get("TG_DRY_RUN", "0") == "1"
SCRIPT_DIR   = Path(os.environ.get("TG_SCRIPT_DIR", ""))
WORKING_DIR  = SCRIPT_DIR / "working"
_bl_env      = os.environ.get("TG_BASELINE_DIR", "")
BASELINE_DIR = Path(_bl_env) if _bl_env else None

# Load pt-report skill from skills/pt-report/SKILL.md — used as writing methodology guide
# Skills live one level up from scripts/ (i.e. pt-orc/skills/), so resolve via parent
_SKILL_PATH = SCRIPT_DIR.parent / "skills" / "pt-report" / "SKILL.md"
_PT_REPORT_SKILL = ""
if _SKILL_PATH.exists():
    try:
        _PT_REPORT_SKILL = _SKILL_PATH.read_text(encoding="utf-8")
    except Exception as _e:
        print(f"[WARN] Could not load pt-report skill: {_e}")

# Load company report methodology prompt from skills/pt-report/REPORT_PROMPT.md
_REPORT_PROMPT_PATH = SCRIPT_DIR.parent / "skills" / "pt-report" / "REPORT_PROMPT.md"
_REPORT_PROMPT_MD = ""
if _REPORT_PROMPT_PATH.exists():
    try:
        _REPORT_PROMPT_MD = _REPORT_PROMPT_PATH.read_text(encoding="utf-8")
    except Exception as _e:
        print(f"[WARN] Could not load REPORT_PROMPT.md: {_e}")

MAX_EVIDENCE_LINES = 200
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
        # Per-phase findings JSONL: load ALL phase files (not just first 3) — they contain
        # phase-specific evidence that the AI needs to write detailed finding narratives.
        jsonl_seen = set()
        phase_patterns = (
            ([f"{slug}-web-*-findings-*.jsonl", f"{slug}_0*_*findings_*.jsonl"] if slug else [])
            + ["*-findings-*.jsonl", "0*_*findings_*.jsonl"]
        )
        for pat in phase_patterns:
            for jf in sorted(WORKING_DIR.glob(pat), key=lambda f: f.name):
                stem_key = re.sub(r'[\d-]{10,}', '', jf.stem)  # strip timestamps
                if stem_key in jsonl_seen or jf.stat().st_size < 10:
                    continue
                jsonl_seen.add(stem_key)
                try:
                    raw_lines = jf.read_text().strip().splitlines()
                    # Parse and format compactly: id | severity | title | description[:120]
                    compact_lines = []
                    for rl in raw_lines[:40]:
                        try:
                            fj = json.loads(rl)
                            compact_lines.append(
                                f"  [{fj.get('id','?')}] {fj.get('severity','?').upper()} | "
                                f"{fj.get('title','?')} | "
                                f"{(fj.get('description') or '')[:120].replace(chr(10),' ')}"
                            )
                        except Exception:
                            compact_lines.append(f"  {rl[:200]}")
                    blocks.append(f"=== Phase Findings: {jf.name} ===\n" + "\n".join(compact_lines))
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
                blocks.append(f"=== Evidence [{host_label}] {ev_file.name} ===\n{_read_truncated(ev_file, 100)}")
        ip_dir = evidence_dir / "_ip_analysis"
        if ip_dir.exists():
            for ip_subdir in ip_dir.iterdir():
                if ip_subdir.is_dir():
                    for sf in ip_subdir.glob("summary_*.md"):
                        blocks.append(f"=== IP Analysis: {ip_subdir.name} ===\n{_read_truncated(sf, 50)}")
    return "\n\n".join(blocks)

PROMPT_TEMPLATE = """\
You are a Tech Guard senior penetration tester preparing a customer-facing penetration testing report.
Follow the Tech Guard pt-report skill and Core Reporting Standard strictly.

## Tech Guard pt-report Skill — Writing Methodology
{skill_block}

---

## Tech Guard Methodology — Mandatory Rules

### Tone
Use formal, professional, evidence-based, non-dramatic language.
Use: "The assessment identified...", "Testing confirmed...", "The observed behaviour indicates..."
Never use: "we hacked", "severely broken", "critical disaster", "obviously insecure", blame-oriented language.

### Findings vs Observations
- Finding: real weakness, validated exposure, or justified Tentative risk requiring corrective action.
- Observation/Informational: strong control, intentional controlled exposure, positive validation, context.
- Observations must NOT be counted in severity totals.

### Severity Model
- Critical: direct, immediate, high-impact risk — emergency remediation required.
- High: significant exploitable weakness with material business impact.
- Medium: exploitable under specific conditions with moderate impact.
- Low: low-impact or difficult-to-exploit weakness.
- Informational: observation, positive control, or context — no corrective action.
Do NOT inflate severity because a scanner reported a high score. Assess actual exploitability and impact.

### Confidence Model (use for every finding)
- Certain: directly confirmed by current-engagement evidence.
- Firm: strongly supported by converging evidence; not every detail directly confirmed.
- Tentative: plausible risk not fully confirmable from the assessment vantage point; client must confirm-or-close.

### Evidence Discipline
- Every finding must trace to evidence in the input data.
- If a condition cannot be fully determined externally, mark it Tentative and say so explicitly.
- Do not present assumptions as confirmed facts.
- Do not copy raw tool output as a finding — synthesize and explain the risk.

### Finding Quality Rules
- Title: concise and specific (e.g. "Missing HTTP Strict-Transport-Security Header on Public Portal")
- Description: explain the condition, where observed, and why it matters — formal prose, not notes.
- Business impact: plain language for non-technical executives.
- Recommendations: numbered, actionable, specific, tied to the finding.
- CVSS: assign from evidence; do not invent scores. Use CVSS 3.1.
- OWASP: map to Top 10 2021 (A01–A10). CWE: assign accurate CWE IDs.

## Engagement Configuration
{config_block}

## Deduplicated Raw Findings ({finding_count} findings from automated scans)
{findings_json}

## Supporting Evidence and Summaries
{evidence_block}

## Output Instructions — CRITICAL

You MUST return a SINGLE valid JSON object. No markdown fences. No text before or after the JSON.
You MUST populate the "findings" array with ALL findings from the input data above.
An empty "findings" array is WRONG — the input contains {finding_count} findings; they must all appear.
Sort findings: Critical → High → Medium → Low → Informational.
Consolidate findings with the same root vulnerability into one entry.

Required JSON schema (populate every field — do not omit "findings"):
{{
  "engagement_summary": {{
    "project": "<project name from config>",
    "targets": ["<ip:port>"],
    "assessment_type": "External Web Application Penetration Test",
    "testing_period": "<month year>",
    "overall_risk_rating": "Critical|High|Medium|Low",
    "executive_summary": "<3-4 formal sentences summarising posture, key risks, and priority remediation — Tech Guard tone>",
    "risk_justification": "<1-2 sentences explaining the overall rating — evidence-based>",
    "severity_counts": {{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}},
    "tools_used": ["nmap", "nikto", "testssl", "wafw00f", "gobuster", "wpscan"]
  }},
  "findings": [
    {{
      "id": "F-01",
      "title": "<concise specific title>",
      "severity": "Critical|High|Medium|Low|Informational",
      "confidence": "Certain|Firm|Tentative",
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
      "affected_hosts": ["<host:port>"],
      "description": "<formal technical description — condition observed, where, why it matters>",
      "technical_detail": "<specific observed evidence>",
      "business_impact": "<plain-language executive risk — what could happen to the business>",
      "remediation": "<one-sentence primary fix>",
      "remediation_steps": ["1. <specific action>", "2. <specific action>"],
      "references": [],
      "evidence_refs": [],
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low",
      "effort": "Low|Medium|High",
      "priority": 1,
      "timeframe": "Immediate (0-7 days)|Short-term (1-4 weeks)|Medium-term (1-3 months)|Long-term (3+ months)"
    }}
  ],
  "attack_paths": [
    {{
      "id": "AP-01",
      "title": "<chain name>",
      "combined_severity": "Critical|High|Medium|Low",
      "combined_cvss_score": 9.0,
      "entry_point": "<initial access vector>",
      "finding_ids": ["F-01", "F-03"],
      "steps": [
        {{"step": 1, "finding_id": "F-01", "action": "<attacker action>", "outcome": "<what is gained>"}},
        {{"step": 2, "finding_id": "F-03", "action": "<next action>", "outcome": "<escalated access>"}}
      ],
      "narrative": "<2-3 sentence kill-chain story — formal Tech Guard tone>",
      "final_impact": "<worst-case business impact>"
    }}
  ],
  "methodology_notes": "<brief description of testing methodology used>",
  "disclaimer": "This report was produced for authorized penetration testing purposes only. It is confidential and intended solely for the named client."
}}"""

def _build_prompt(config, findings, evidence_block, evidence_limit=130000, findings_limit=30000):
    """Build the full AI prompt, injecting the pt-report skill and capping evidence/findings."""
    config_block = "\n".join(f"{k}: {v}" for k, v in config.items() if v)
    skill_block = _PT_REPORT_SKILL if _PT_REPORT_SKILL else "(pt-report skill not found — apply TechGuard standard methodology)"
    return PROMPT_TEMPLATE.format(
        skill_block=skill_block,
        config_block=config_block,
        finding_count=len(findings),
        findings_json=json.dumps(findings, indent=2)[:findings_limit],
        evidence_block=evidence_block[:evidence_limit],
    )

def _ollama_context_length(ollama_host, ollama_model):
    """Return the model's context_length from /api/tags, default 32768."""
    try:
        req = _urllib_req.Request(
            f"{ollama_host}/api/tags",
            headers={"Content-Type": "application/json"},
            method="GET",
        )
        with _urllib_req.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        for m in data.get("models", []):
            if m.get("model") == ollama_model or m.get("name") == ollama_model:
                return m.get("details", {}).get("context_length") or 32768
    except Exception:
        pass
    return 32768

def _compact_findings_text(findings):
    """Serialise findings to a dense line-per-finding format for small-model prompts.
    Keeps every field the model needs while staying ~200 chars/finding."""
    lines = []
    for f in findings:
        sev  = (f.get("severity") or "Low").upper()
        fid  = f.get("id") or f.get("finding_id") or "F-?"
        title = f.get("title", "Untitled")
        phase = f.get("phase", "")
        desc  = (f.get("description") or "")[:300].replace("\n", " ")
        rec   = (f.get("recommendation") or f.get("remediation") or "")[:200].replace("\n", " ")
        hosts = ", ".join(f.get("affected_hosts", []) or [])
        cvss  = f.get("cvss_score", "")
        owasp = f.get("owasp_id", "")
        cwe   = f.get("cwe_id", "")
        impact= (f.get("business_impact") or "")[:200].replace("\n", " ")
        block = f"[{fid}] {sev} | {title}"
        if phase:   block += f"\n  Phase: {phase}"
        if hosts:   block += f"\n  Hosts: {hosts}"
        if cvss:    block += f"\n  CVSS: {cvss}"
        if owasp:   block += f"  OWASP: {owasp}"
        if cwe:     block += f"  CWE: {cwe}"
        block += f"\n  Evidence/Condition: {desc}"
        if impact:  block += f"\n  Business Impact: {impact}"
        block += f"\n  Recommendation: {rec}"
        lines.append(block)
    return "\n\n".join(lines)


def _build_ollama_company_prompt(config, findings, evidence_block, input_budget):
    """Compact company-report prompt optimised for local models (qwen2.5:14b, llama3:8b etc.).
    Puts DATA first, keeps instructions short, never sends REPORT_PROMPT.md."""
    project   = config.get("PROJECT_NAME", "VAPT Assessment")
    targets   = config.get("TARGET_IPS", "See scope")
    atype     = config.get("ASSESSMENT_TYPE", "External Web Application Penetration Test")
    period    = config.get("TESTING_PERIOD", "")
    engineer  = config.get("LEAD_ENGINEER", "TechGuard Labs")
    # Budget split: 60% findings, 35% evidence, 5% frame
    frame_budget    = 2000
    findings_budget = int((input_budget - frame_budget) * 0.60)
    evidence_budget = int((input_budget - frame_budget) * 0.35)
    compact = _compact_findings_text(findings)
    if len(compact) > findings_budget:
        compact = compact[:findings_budget] + "\n...[findings truncated]"
    ev = evidence_block[:evidence_budget] if evidence_block else "(no evidence summaries available)"
    n = len(findings)
    # Count severity breakdown
    from collections import Counter as _Ctr
    sev_counts = _Ctr((f.get("severity") or "low").lower() for f in findings)
    sev_line = "  ".join(f"{k.upper()}: {v}" for k, v in sorted(sev_counts.items()))
    return f"""TASK: Write a complete professional HTML penetration testing report for TechGuard Labs.

ENGAGEMENT DETAILS:
  Project       : {project}
  Targets       : {targets}
  Assessment    : {atype}
  Period        : {period}
  Lead Engineer : {engineer}
  Total Findings: {n}  ({sev_line})

═══ ALL {n} FINDINGS — INCLUDE EVERY ONE IN THE REPORT ═══

{compact}

═══ EVIDENCE SUMMARIES FROM TESTING ═══

{ev}

═══ OUTPUT INSTRUCTIONS ═══

Write a COMPLETE HTML report. Begin with <!DOCTYPE html>. End with </html>.
Embed all CSS. Use a professional dark-navy and crimson colour scheme.

Required sections (include all {n} findings — DO NOT skip any):
  1. Cover / Title Block — project name, targets, date, overall risk rating
  2. Executive Summary — risk rating, finding counts by severity, 3-4 sentence narrative
  3. Scope & Methodology — targets table, testing phases, tools
  4. Assessment Findings — EVERY finding: ID badge, severity, condition observed, evidence, business impact, recommendations
  5. Risk Matrix — likelihood × impact grid with finding IDs placed in cells
  6. Remediation Roadmap — priority table: ID | Title | Severity | Effort | Timeframe
  7. Disclaimer — authorised testing statement

TechGuard style rules:
  - Formal, evidence-based prose. No speculation. No placeholder text.
  - Severity labels: Critical | High | Medium | Low | Informational
  - Every finding must appear with its ID (e.g. f-001), severity, description, and remediation
  - Observations are Informational; they DO NOT count toward severity totals
"""


def _normalize_ai_result(data):
    """Fix known key-name variations that models sometimes produce."""
    summary = data.get("engagement_summary", {})
    # Normalize dot-separated keys the model sometimes emits (e.g. risk.justification)
    for dotkey in list(summary.keys()):
        if "." in dotkey:
            underkey = dotkey.replace(".", "_")
            summary[underkey] = summary.pop(dotkey)
    # Ensure severity_counts is always present (small models often omit it)
    if not isinstance(summary.get("severity_counts"), dict):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for f in data.get("findings", []):
            sev = (f.get("severity") or "informational").lower()
            if sev in counts:
                counts[sev] += 1
        summary["severity_counts"] = counts
    data["engagement_summary"] = summary
    # Ensure findings is always a list
    if not isinstance(data.get("findings"), list):
        data["findings"] = []
    # Ensure attack_paths is always a list
    if not isinstance(data.get("attack_paths"), list):
        data["attack_paths"] = []
    return data

def _parse_ai_json(raw, provider):
    raw = re.sub(r'^```(?:json)?\s*', '', raw.strip())
    raw = re.sub(r'\s*```$', '', raw).strip()
    try:
        return _normalize_ai_result(json.loads(raw))
    except json.JSONDecodeError:
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            try:
                return _normalize_ai_result(json.loads(m.group()))
            except Exception:
                pass
        raise RuntimeError(f"{provider} returned non-JSON. First 400 chars:\n{raw[:400]}")

def analyze_with_claude(api_key, model, config, findings, evidence_block):
    if not _ANTHROPIC_AVAILABLE:
        raise RuntimeError("anthropic package not installed: pip install anthropic")
    # Cloud AI: send full evidence + full skill — Claude supports 200K context
    prompt = _build_prompt(config, findings, evidence_block,
                           evidence_limit=150000, findings_limit=30000)
    client = anthropic.Anthropic(api_key=api_key)
    print(f"[INFO] Calling Claude ({model}) — {len(prompt):,} chars prompt (full evidence)...")
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
    # Cloud AI: send full evidence + full skill — Gemini 2.5 flash supports 1M context
    prompt = _build_prompt(config, findings, evidence_block,
                           evidence_limit=150000, findings_limit=30000)
    genai.configure(api_key=gemini_key)
    if isinstance(gemini_models, str):
        gemini_models = [gemini_models]
    last_err = None
    for model_name in gemini_models:
        try:
            print(f"[INFO] Calling Gemini ({model_name}) — {len(prompt):,} chars prompt (full evidence)...")
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

def _ollama_capabilities(ollama_host, ollama_model):
    """Return capability list for the model, e.g. ['chat'] or ['completion']."""
    try:
        req = _urllib_req.Request(
            f"{ollama_host}/api/tags",
            headers={"Content-Type": "application/json"},
            method="GET",
        )
        with _urllib_req.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        for m in data.get("models", []):
            if m.get("model") == ollama_model or m.get("name") == ollama_model:
                return m.get("details", {}).get("capabilities") or m.get("capabilities") or []
    except Exception:
        pass
    return []

OLLAMA_PROMPT_TEMPLATE = """\
You are a penetration tester writing a VAPT report. Analyse the findings below and return ONLY a valid JSON object — no markdown, no extra text.

Project: {project}
Targets: {targets}

Findings ({finding_count} total — top {shown} shown):
{findings_brief}

Return this exact JSON structure:
{{
  "engagement_summary": {{
    "project": "{project}",
    "targets": {targets_json},
    "assessment_type": "External Web Application Penetration Test",
    "testing_period": "June 2026",
    "overall_risk_rating": "Critical",
    "executive_summary": "Write 2-3 sentences summarising the key risks found.",
    "risk_justification": "One sentence explaining the rating.",
    "severity_counts": {{"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}},
    "tools_used": ["nmap", "nikto", "testssl", "gobuster"]
  }},
  "findings": [
    {{
      "id": "F-001",
      "title": "Finding title",
      "severity": "Critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "owasp_id": "A05",
      "owasp_name": "Security Misconfiguration",
      "owasp_url": "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
      "cwe_id": "CWE-16",
      "cwe_name": "Configuration",
      "cwe_url": "https://cwe.mitre.org/data/definitions/16.html",
      "cve_ids": [],
      "chain_steps": [],
      "affected_hosts": ["host:port"],
      "description": "Technical description of the finding.",
      "technical_detail": "What was observed.",
      "business_impact": "Plain-language risk for executives.",
      "remediation": "Specific fix.",
      "retest_status": "open",
      "residual_risk": ""
    }}
  ],
  "attack_paths": [],
  "remediation_roadmap": {{
    "immediate": [],
    "short_term": [],
    "long_term": []
  }}
}}
"""

def analyze_with_ollama(ollama_host, ollama_model, config, findings, evidence_block):
    """Call local Ollama instance.
    Uses the full pt-report skill + evidence budgeted to the model's context_length.
    Uses /api/chat for chat-capable models; /api/generate for completion-only models."""
    if _urllib_req is None:
        raise RuntimeError("urllib.request unavailable")

    # Calculate safe input budget from the model's declared context_length.
    # Reserve 4 000 tokens (~14 000 chars) for JSON output.
    # Use 3.5 chars/token as a conservative estimate.
    ctx_tokens = _ollama_context_length(ollama_host, ollama_model)
    total_char_budget = int(ctx_tokens * 3.5)
    output_reserve   = 21000
    input_budget     = total_char_budget - output_reserve

    # Allocate: skill (~15K), template overhead (~5K), findings, then evidence with remainder.
    skill_chars    = len(_PT_REPORT_SKILL)
    template_overhead = 5000
    findings_limit = min(10000, (input_budget - skill_chars - template_overhead) // 3)
    evidence_limit = max(0, input_budget - skill_chars - template_overhead - findings_limit)

    prompt = _build_prompt(config, findings, evidence_block,
                           evidence_limit=evidence_limit, findings_limit=findings_limit)

    caps = _ollama_capabilities(ollama_host, ollama_model)
    use_chat = "chat" in caps or not caps  # default to chat if capabilities unknown
    print(f"[INFO] Calling Ollama ({ollama_model} @ {ollama_host}) — {len(prompt):,} chars prompt"
          f" [ctx:{ctx_tokens} tokens | evidence:{evidence_limit:,} chars | {'chat' if use_chat else 'generate'} endpoint]...")

    if use_chat:
        payload = json.dumps({
            "model": ollama_model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {"num_predict": 6000},
        }).encode()
        req = _urllib_req.Request(
            f"{ollama_host}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _urllib_req.urlopen(req, timeout=1800) as resp:
            data = json.loads(resp.read())
        text = data.get("message", {}).get("content", "")
    else:
        payload = json.dumps({
            "model": ollama_model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"num_predict": 6000},
        }).encode()
        req = _urllib_req.Request(
            f"{ollama_host}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with _urllib_req.urlopen(req, timeout=1800) as resp:
            data = json.loads(resp.read())
        text = data.get("response", "")

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
/* ── PAGE SETUP ──────────────────────────────────────────── */
@page          { margin: 20mm 18mm 20mm 18mm; size: A4; }
@page :first   { margin: 0; }
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
  font-size: 10pt; color: #1C2340; background: #fff; line-height: 1.55;
}

/* ── COVER PAGE ──────────────────────────────────────────── */
.cover {
  background: #0D1B3E;
  background-image:
    linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px);
  background-size: 28px 28px;
  color: #fff;
  min-height: 297mm;
  page-break-after: always;
  display: block;
}
.cover-top-stripe { height: 7px; background: #C41E3A; }
.cover-body       { padding: 52px 64px 0 64px; }
.cover-brand      { font-size: 11pt; font-weight: 800; letter-spacing: 5px; text-transform: uppercase; color: #C41E3A; }
.cover-brand-sub  { font-size: 8pt; color: #7B9EC8; letter-spacing: 2px; margin-top: 3px; text-transform: uppercase; }
.cover-spacer     { height: 88px; }
.cover-classif {
  display: inline-block; background: #C41E3A; color: #fff;
  font-size: 8pt; font-weight: 800; letter-spacing: 4px; text-transform: uppercase;
  padding: 5px 20px; margin-bottom: 22px;
}
.cover-title    { font-size: 32pt; font-weight: 700; line-height: 1.15; color: #fff; margin-bottom: 10px; }
.cover-subtitle { font-size: 13pt; color: #6B9BD2; font-weight: 300; letter-spacing: 0.5px; margin-bottom: 44px; }
.cover-rule     { height: 1px; background: rgba(255,255,255,0.15); margin-bottom: 28px; }
.cover-meta     { display: table; }
.cover-row      { display: table-row; }
.cover-lbl {
  display: table-cell; color: #7B9EC8; font-size: 8pt; font-weight: 700;
  text-transform: uppercase; letter-spacing: 1px; padding: 5px 28px 5px 0;
  white-space: nowrap;
}
.cover-val      { display: table-cell; color: #E8EEF8; font-size: 10pt; padding: 5px 0; }
.cover-risk-pill {
  display: inline-block; font-size: 9.5pt; font-weight: 800;
  text-transform: uppercase; letter-spacing: 1px; padding: 3px 16px; border-radius: 3px;
}
.cover-risk-pill.critical { background: #7F1D1D; color: #fff; }
.cover-risk-pill.high     { background: #C41E3A; color: #fff; }
.cover-risk-pill.medium   { background: #92400E; color: #fff; }
.cover-risk-pill.low      { background: #1E3A5F; color: #fff; }
.cover-bottom {
  padding: 14px 64px; margin-top: 56px;
  background: rgba(0,0,0,0.35); border-top: 1px solid rgba(255,255,255,0.1);
  display: table; width: 100%;
}
.cover-bottom-l { display: table-cell; color: rgba(255,255,255,0.45); font-size: 8pt; }
.cover-bottom-r { display: table-cell; color: rgba(255,255,255,0.45); font-size: 8pt; text-align: right; }

/* ── SECTION HEADERS ─────────────────────────────────────── */
h2.sec-hdr {
  background: #F4F6FA; border-left: 6px solid #C41E3A;
  padding: 11px 18px 11px 14px; font-size: 13pt; font-weight: 700;
  color: #0D1B3E; margin-bottom: 24px; page-break-before: always;
  display: table; width: 100%;
}
h2.sec-hdr .n {
  display: inline-block; background: #C41E3A; color: #fff;
  width: 26px; height: 26px; line-height: 26px; text-align: center;
  border-radius: 50%; font-size: 10pt; font-weight: 800;
  margin-right: 12px; vertical-align: middle;
}
.page-section { padding: 0; }
.scope-block  { margin-bottom: 24px; }
.scope-h3 {
  font-size: 9pt; font-weight: 800; color: #0D1B3E; margin-bottom: 10px;
  text-transform: uppercase; letter-spacing: 0.8px;
  border-bottom: 2px solid #DDE3EF; padding-bottom: 5px;
}

/* ── RISK BANNER ─────────────────────────────────────────── */
.risk-banner {
  border-radius: 6px; padding: 14px 20px; margin-bottom: 20px; display: table; width: 100%;
}
.risk-banner.critical { background: #FEF2F2; border: 1px solid #FECACA; border-left: 7px solid #7F1D1D; }
.risk-banner.high     { background: #FEF2F2; border: 1px solid #FECACA; border-left: 7px solid #C41E3A; }
.risk-banner.medium   { background: #FFFBEB; border: 1px solid #FDE68A; border-left: 7px solid #92400E; }
.risk-banner.low      { background: #EFF6FF; border: 1px solid #BFDBFE; border-left: 7px solid #1E3A5F; }
.risk-banner-left { display: table-cell; vertical-align: middle; width: 200px; }
.risk-banner-lbl  { font-size: 8pt; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: #5C6B8A; }
.risk-banner-val  { font-size: 15pt; font-weight: 800; margin-top: 2px; }
.risk-banner.critical .risk-banner-val,
.risk-banner.high     .risk-banner-val { color: #7F1D1D; }
.risk-banner.medium   .risk-banner-val { color: #92400E; }
.risk-banner.low      .risk-banner-val { color: #1E3A5F; }
.risk-banner-just { display: table-cell; vertical-align: middle; font-size: 9.5pt; color: #374151; line-height: 1.6; padding-left: 20px; }

/* ── EXECUTIVE SUMMARY BOX ───────────────────────────────── */
.exec-text {
  background: #F4F6FA; border-left: 5px solid #0D1B3E;
  padding: 16px 20px; margin-bottom: 24px;
  font-size: 10.5pt; line-height: 1.7; color: #1C2340; border-radius: 0 6px 6px 0;
}

/* ── SEVERITY DASHBOARD ──────────────────────────────────── */
.sev-cards { display: table; width: 100%; border-collapse: separate; border-spacing: 10px; margin-bottom: 28px; }
.sev-row   { display: table-row; }
.sev-card  { display: table-cell; text-align: center; padding: 18px 8px 14px; border-radius: 8px; width: 20%; }
.sev-card.critical      { background: #FEF2F2; border-top: 5px solid #7F1D1D; }
.sev-card.high          { background: #FEF2F2; border-top: 5px solid #C41E3A; }
.sev-card.medium        { background: #FFFBEB; border-top: 5px solid #92400E; }
.sev-card.low           { background: #EFF6FF; border-top: 5px solid #1E3A5F; }
.sev-card.informational { background: #F1F3F7; border-top: 5px solid #4B5563; }
.sev-count { font-size: 30pt; font-weight: 800; line-height: 1; margin-bottom: 4px; }
.sev-card.critical      .sev-count { color: #7F1D1D; }
.sev-card.high          .sev-count { color: #C41E3A; }
.sev-card.medium        .sev-count { color: #92400E; }
.sev-card.low           .sev-count { color: #1E3A5F; }
.sev-card.informational .sev-count { color: #4B5563; }
.sev-label { font-size: 8pt; text-transform: uppercase; letter-spacing: 1px; font-weight: 700; color: #5C6B8A; }

/* ── DATA TABLES ─────────────────────────────────────────── */
table.dt { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 9.5pt; }
table.dt thead th { background: #0D1B3E; color: #fff; padding: 9px 12px; text-align: left; font-weight: 600; font-size: 9pt; }
table.dt tbody td { padding: 8px 12px; border-bottom: 1px solid #DDE3EF; vertical-align: top; color: #1C2340; }
table.dt tbody tr:nth-child(even) td { background: #F4F6FA; }
table.dt tbody tr:last-child td { border-bottom: none; }

/* ── RISK MATRIX ─────────────────────────────────────────── */
.rm-wrap { margin-bottom: 28px; }
table.rm { border-collapse: collapse; width: 100%; font-size: 9pt; }
table.rm td, table.rm th { border: 3px solid #fff; padding: 11px 10px; text-align: center; vertical-align: middle; }
table.rm th { background: #162040; color: #fff; font-weight: 700; font-size: 9pt; }
table.rm .rh { background: #162040; color: #fff; font-weight: 700; width: 90px; font-size: 8.5pt; }
.rm-crit   { background: #FECACA; color: #7F1D1D; font-weight: 700; }
.rm-high   { background: #FED7AA; color: #7C2D12; font-weight: 600; }
.rm-medium { background: #FEF08A; color: #713F12; }
.rm-low    { background: #BFDBFE; color: #1E3A5F; }
.rm-info   { background: #E2E8F0; color: #475569; }
.rm-lbl { font-size: 8pt; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; }
.rm-ids { font-size: 7.5pt; margin-top: 4px; opacity: 0.75; }

/* ── OWASP TABLE ─────────────────────────────────────────── */
table.owasp { width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 9pt; }
table.owasp thead th { background: #162040; color: #fff; padding: 9px 12px; text-align: left; font-weight: 600; }
table.owasp tbody td { padding: 7px 12px; border-bottom: 1px solid #DDE3EF; }
table.owasp tbody tr:nth-child(even) td { background: #F4F6FA; }
.bar-wrap { background: #DDE3EF; border-radius: 10px; height: 8px; width: 130px; display: inline-block; vertical-align: middle; overflow: hidden; }
.bar-fill { height: 100%; background: #C41E3A; border-radius: 10px; }
.cnt { display: inline-block; background: #162040; color: #fff; font-size: 8pt; font-weight: 700; padding: 2px 8px; border-radius: 10px; min-width: 26px; text-align: center; }
.cnt.zero { background: #CBD5E1; color: #64748B; }

/* ── FINDING CARDS ───────────────────────────────────────── */
.fc { border: 1px solid #DDE3EF; border-radius: 8px; margin-bottom: 28px; overflow: hidden; page-break-inside: avoid; }
.fc-hdr { padding: 13px 18px; display: table; width: 100%; }
.fc-hdr.critical      { background: #FEF2F2; border-left: 7px solid #7F1D1D; }
.fc-hdr.high          { background: #FEF2F2; border-left: 7px solid #C41E3A; }
.fc-hdr.medium        { background: #FFFBEB; border-left: 7px solid #92400E; }
.fc-hdr.low           { background: #EFF6FF; border-left: 7px solid #1E3A5F; }
.fc-hdr.informational { background: #F1F3F7; border-left: 7px solid #4B5563; }
.fc-hdr-inner         { display: table-row; }
.fc-id {
  display: table-cell; font-size: 8.5pt; font-weight: 800; color: #5C6B8A;
  vertical-align: middle; width: 54px; font-family: 'Courier New', monospace;
}
.fc-title { display: table-cell; font-size: 11.5pt; font-weight: 700; vertical-align: middle; padding-right: 14px; }
.fc-hdr.critical      .fc-title { color: #7F1D1D; }
.fc-hdr.high          .fc-title { color: #881337; }
.fc-hdr.medium        .fc-title { color: #78350F; }
.fc-hdr.low           .fc-title { color: #1E3A5F; }
.fc-hdr.informational .fc-title { color: #374151; }
.fc-badge-cell { display: table-cell; vertical-align: middle; width: 94px; text-align: right; }
.sev-badge {
  display: inline-block; font-size: 8pt; font-weight: 800;
  text-transform: uppercase; letter-spacing: 0.5px; padding: 4px 14px;
  border-radius: 20px; color: #fff;
}
.sev-badge.critical      { background: #7F1D1D; }
.sev-badge.high          { background: #C41E3A; }
.sev-badge.medium        { background: #92400E; }
.sev-badge.low           { background: #1E3A5F; }
.sev-badge.informational { background: #4B5563; }
.fc-meta     { display: table; width: 100%; background: #F9FAFB; border-top: 1px solid #DDE3EF; border-bottom: 1px solid #DDE3EF; padding: 10px 18px; }
.fc-meta-row { display: table-row; }
.fc-meta-cell { display: table-cell; padding: 4px 22px 4px 0; font-size: 8.5pt; }
.fc-meta-cell .lbl { color: #5C6B8A; font-weight: 700; text-transform: uppercase; font-size: 7.5pt; letter-spacing: 0.5px; display: block; margin-bottom: 2px; }
.fc-meta-cell .val { color: #1C2340; font-weight: 500; }
.cvss-score { font-size: 14pt; font-weight: 800; }
.cvss-score.critical      { color: #7F1D1D; }
.cvss-score.high          { color: #C41E3A; }
.cvss-score.medium        { color: #92400E; }
.cvss-score.low           { color: #1E3A5F; }
.cvss-score.informational { color: #4B5563; }
.fc-body      { padding: 16px 18px; }
.fc-sec       { margin-bottom: 14px; }
.fc-sec:last-child { margin-bottom: 0; }
.fc-sec-title {
  font-size: 8pt; font-weight: 800; text-transform: uppercase; letter-spacing: 0.8px;
  color: #5C6B8A; margin-bottom: 6px; padding-bottom: 4px; border-bottom: 1px solid #EDF0F5;
}
.fc-sec p  { font-size: 9.5pt; line-height: 1.6; color: #2D3748; }
ol.steps   { margin: 6px 0 0 18px; font-size: 9.5pt; line-height: 1.65; }
ol.steps li { margin-bottom: 4px; color: #2D3748; }
.tag { display: inline-block; font-size: 7.5pt; font-weight: 700; padding: 2px 9px; border-radius: 12px; margin: 2px 3px 2px 0; }
.tag.cve  { background: #FEE2E2; color: #991B1B; }
.tag.host { background: #D1FAE5; color: #065F46; }
.tag.ref  { background: #E0E7FF; color: #3730A3; }
.ref-link { color: #1E40AF; font-size: 8.5pt; display: block; margin-bottom: 3px; word-break: break-all; }

/* ── ATTACK PATH CARDS ───────────────────────────────────── */
.ap-card { border: 1px solid #DDE3EF; border-radius: 8px; margin-bottom: 24px; overflow: hidden; page-break-inside: avoid; }
.ap-hdr  { padding: 12px 18px; display: table; width: 100%; background: #F4F6FA; border-left: 7px solid #162040; }
.ap-hdr.critical { border-left-color: #7F1D1D; background: #FEF2F2; }
.ap-hdr.high     { border-left-color: #C41E3A; background: #FEF2F2; }
.ap-hdr.medium   { border-left-color: #92400E; background: #FFFBEB; }
.ap-hdr.low      { border-left-color: #1E3A5F; background: #EFF6FF; }
.ap-hdr-inner    { display: table-row; }
.ap-id    { display: table-cell; font-size: 8.5pt; font-weight: 800; color: #5C6B8A; vertical-align: middle; width: 54px; font-family: 'Courier New', monospace; }
.ap-title { display: table-cell; font-size: 11pt; font-weight: 700; color: #0D1B3E; vertical-align: middle; padding-right: 14px; }
.ap-cvss  { display: table-cell; font-size: 8.5pt; color: #5C6B8A; vertical-align: middle; width: 110px; text-align: right; white-space: nowrap; }
.ap-badge-cell { display: table-cell; vertical-align: middle; width: 94px; text-align: right; }
.ap-body  { padding: 14px 18px; }
.ap-row   { margin-bottom: 10px; font-size: 9.5pt; }
.ap-lbl   { font-size: 7.5pt; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px; color: #5C6B8A; display: block; margin-bottom: 3px; }
.ap-chain { background: #F4F6FA; border-radius: 6px; padding: 10px 14px; margin-top: 4px; }
.ap-chain li { font-size: 9pt; line-height: 1.7; color: #2D3748; margin-bottom: 2px; }
.ap-chain li strong { color: #C41E3A; }

/* ── RETEST BANNER ───────────────────────────────────────── */
.retest-ok   { background: #F0FDF4; border: 1px solid #BBF7D0; border-left: 7px solid #15803D; border-radius: 6px; padding: 12px 18px; margin-bottom: 18px; font-size: 9.5pt; }
.retest-warn { background: #FEF2F2; border: 1px solid #FECACA; border-left: 7px solid #C41E3A; border-radius: 6px; padding: 12px 18px; margin-bottom: 18px; font-size: 9.5pt; }

/* ── ROADMAP TABLE ───────────────────────────────────────── */
table.roadmap { width: 100%; border-collapse: collapse; font-size: 9pt; margin-bottom: 20px; }
table.roadmap thead th { background: #0D1B3E; color: #fff; padding: 9px 12px; text-align: left; font-weight: 600; }
table.roadmap tbody td { padding: 8px 12px; border-bottom: 1px solid #DDE3EF; vertical-align: top; }
table.roadmap tbody tr:nth-child(even) td { background: #F4F6FA; }
.effort-Low    { color: #065F46; font-weight: 700; }
.effort-Medium { color: #92400E; font-weight: 700; }
.effort-High   { color: #7F1D1D; font-weight: 700; }

/* ── DISCLAIMER ──────────────────────────────────────────── */
.disc { background: #FFFBEB; border: 1px solid #FDE68A; border-radius: 8px; padding: 18px 22px; font-size: 9pt; color: #78350F; line-height: 1.65; }
.disc h3 { color: #B45309; font-size: 10pt; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 700; }

/* ── PAGE FOOTER ─────────────────────────────────────────── */
.footer { margin-top: 40px; border-top: 3px solid #0D1B3E; padding-top: 12px; display: table; width: 100%; font-size: 8pt; color: #5C6B8A; }
.footer-l { display: table-cell; }
.footer-r { display: table-cell; text-align: right; }
</style>
</head>
<body>

<!-- ══════════════════════════════════════════════════════════
     COVER PAGE
     ══════════════════════════════════════════════════════════ -->
<div class="cover">
  <div class="cover-top-stripe"></div>
  <div class="cover-body">
    <div>
      <div class="cover-brand">TechGuard Labs</div>
      <div class="cover-brand-sub">Security Intelligence &nbsp;·&nbsp; Penetration Testing &nbsp;·&nbsp; Red Team</div>
    </div>
    <div class="cover-spacer"></div>
    <div>
      <div class="cover-classif">Confidential</div>
      <div class="cover-title">Security Assessment<br/>Report</div>
      <div class="cover-subtitle">{{ summary.assessment_type }}</div>
      <div class="cover-rule"></div>
      <div class="cover-meta">
        <div class="cover-row">
          <div class="cover-lbl">Project</div>
          <div class="cover-val">{{ summary.project }}</div>
        </div>
        <div class="cover-row">
          <div class="cover-lbl">Target(s)</div>
          <div class="cover-val">{{ summary.targets | join(", ") }}</div>
        </div>
        <div class="cover-row">
          <div class="cover-lbl">Testing Period</div>
          <div class="cover-val">{{ summary.testing_period }}</div>
        </div>
        <div class="cover-row">
          <div class="cover-lbl">Report Date</div>
          <div class="cover-val">{{ report_date }}</div>
        </div>
        <div class="cover-row">
          <div class="cover-lbl">Overall Risk</div>
          <div class="cover-val">
            <span class="cover-risk-pill {{ summary.overall_risk_rating | lower }}">{{ summary.overall_risk_rating | upper }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div class="cover-bottom">
    <div class="cover-bottom-l">TechGuard Labs &bull; hari@techguardlabs.com</div>
    <div class="cover-bottom-r">Confidential — Authorised Recipients Only</div>
  </div>
</div>

<!-- ══════════════════════════════════════════════════════════
     SECTION 01 — ENGAGEMENT OVERVIEW
     ══════════════════════════════════════════════════════════ -->
<div class="page-section">
<h2 class="sec-hdr"><span class="n">01</span>Engagement Overview</h2>
<div class="scope-block">
  <div class="scope-h3">Target Scope</div>
  <table class="dt">
    <thead><tr><th>Host / IP</th><th>Port(s)</th><th>Protocol</th><th>Application</th></tr></thead>
    <tbody>
    {% for t in scope_targets %}
    <tr><td>{{ t.host }}</td><td>{{ t.ports }}</td><td>{{ t.protocol }}</td><td>{{ t.application }}</td></tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<div class="scope-block">
  <div class="scope-h3">Testing Phases &amp; Methodology</div>
  <table class="dt">
    <thead><tr><th>Phase</th><th>Activity</th><th>Tools</th></tr></thead>
    <tbody>
    <tr><td>01 DNS Recon</td><td>Domain enumeration, subdomain discovery, DNS record analysis</td><td>dig, subfinder, dnsx</td></tr>
    <tr><td>02 IP Analysis</td><td>ASN lookup, geolocation, cloud-provider identification, WHOIS</td><td>whois, ipinfo</td></tr>
    <tr><td>03 Network Scan</td><td>Port scanning, service fingerprinting, OS detection</td><td>nmap, masscan</td></tr>
    <tr><td>04 TLS Assessment</td><td>Certificate validation, cipher-suite enumeration, protocol checks</td><td>testssl.sh</td></tr>
    <tr><td>05 Web Enumeration</td><td>HTTP header analysis, WAF detection, directory/content discovery</td><td>curl, wafw00f, gobuster, nikto</td></tr>
    <tr><td>06 WordPress Scan</td><td>Plugin/theme enumeration, user harvesting, CVE identification</td><td>wpscan</td></tr>
    <tr><td>07 Service Verification</td><td>Manual probing and validation of identified open services</td><td>Manual</td></tr>
    <tr><td>08 Application &amp; API</td><td>Rate-limit testing, authentication bypass, API endpoint enumeration</td><td>curl, python-requests</td></tr>
    <tr><td>09 AI / LLM Endpoints</td><td>Prompt injection, data exfiltration, model abuse probes</td><td>PT-Orc AI Skill</td></tr>
    </tbody>
  </table>
</div>
{% if summary.tools_used %}
<div class="scope-block">
  <div class="scope-h3">Tools &amp; Frameworks</div>
  <p style="font-size:9.5pt;line-height:2.2;">{% for t in summary.tools_used %}<span class="tag ref">{{ t }}</span>{% endfor %}</p>
</div>
{% endif %}
</div>

<!-- ══════════════════════════════════════════════════════════
     SECTION 02 — EXECUTIVE SUMMARY
     ══════════════════════════════════════════════════════════ -->
<div class="page-section">
<h2 class="sec-hdr"><span class="n">02</span>Executive Summary</h2>
<div class="risk-banner {{ summary.overall_risk_rating | lower }}">
  <div class="risk-banner-left">
    <div class="risk-banner-lbl">Overall Risk Rating</div>
    <div class="risk-banner-val">{{ summary.overall_risk_rating | upper }}</div>
  </div>
  <div class="risk-banner-just">{{ summary.risk_justification }}</div>
</div>
<div class="sev-cards">
  <div class="sev-row">
    <div class="sev-card critical"><div class="sev-count">{{ summary.severity_counts.critical }}</div><div class="sev-label">Critical</div></div>
    <div class="sev-card high"><div class="sev-count">{{ summary.severity_counts.high }}</div><div class="sev-label">High</div></div>
    <div class="sev-card medium"><div class="sev-count">{{ summary.severity_counts.medium }}</div><div class="sev-label">Medium</div></div>
    <div class="sev-card low"><div class="sev-count">{{ summary.severity_counts.low }}</div><div class="sev-label">Low</div></div>
    <div class="sev-card informational"><div class="sev-count">{{ summary.severity_counts.informational }}</div><div class="sev-label">Info</div></div>
  </div>
</div>
<div class="exec-text">{{ summary.executive_summary }}</div>
</div>

<!-- ══════════════════════════════════════════════════════════
     SECTION 03 — ASSESSMENT FINDINGS
     ══════════════════════════════════════════════════════════ -->
<div class="page-section">
<h2 class="sec-hdr"><span class="n">03</span>Assessment Findings</h2>
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
    <div class="fc-sec"><div class="fc-sec-title">Affected Systems</div>{% for h in f.affected_hosts %}<span class="tag host">{{ h }}</span>{% endfor %}{% if not f.affected_hosts %}<span class="tag host">See description</span>{% endif %}</div>
    <div class="fc-sec"><div class="fc-sec-title">Condition &amp; Evidence</div><p>{{ f.description }}</p></div>
    {% if f.technical_detail %}<div class="fc-sec"><div class="fc-sec-title">Technical Detail</div><p>{{ f.technical_detail }}</p></div>{% endif %}
    <div class="fc-sec"><div class="fc-sec-title">Business Impact</div><p>{{ f.business_impact }}</p></div>
    <div class="fc-sec">
      <div class="fc-sec-title">Recommendations</div>
      {% if f.remediation_steps %}<ol class="steps">{% for step in f.remediation_steps %}<li>{{ step }}</li>{% endfor %}</ol>
      {% else %}<p>{{ f.remediation }}</p>{% endif %}
    </div>
    {% if f.chain_steps %}<div class="fc-sec"><div class="fc-sec-title">Attack Chain</div><ol class="steps">{% for step in f.chain_steps %}<li>{{ step }}</li>{% endfor %}</ol></div>{% endif %}
    {% if f.references %}<div class="fc-sec"><div class="fc-sec-title">References</div>{% for ref in f.references %}<a class="ref-link" href="{{ ref }}">{{ ref }}</a>{% endfor %}</div>{% endif %}
  </div>
</div>
{% endfor %}
</div>

<!-- ══════════════════════════════════════════════════════════
     SECTION 04 — RISK ANALYSIS
     ══════════════════════════════════════════════════════════ -->
<div class="page-section">
<h2 class="sec-hdr"><span class="n">04</span>Risk Analysis</h2>
<div class="rm-wrap">
  <div class="scope-h3">Risk Matrix — Likelihood × Impact</div>
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
    <thead><tr><th style="width:65px;">Code</th><th>Category</th><th style="width:170px;">Coverage</th><th style="width:60px;">Count</th></tr></thead>
    <tbody>
    {% for item in owasp_coverage %}
    <tr>
      <td><strong>{{ item.id }}</strong></td>
      <td>{{ item.name }}</td>
      <td><div class="bar-wrap"><div class="bar-fill" style="width:{{ item.pct }}%;"></div></div></td>
      <td><span class="cnt {% if item.count == 0 %}zero{% endif %}">{{ item.count }}</span></td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
</div>

<!-- ══════════════════════════════════════════════════════════
     SECTION 05 — ATTACK PATH ANALYSIS
     ══════════════════════════════════════════════════════════ -->
<div class="page-section">
<h2 class="sec-hdr"><span class="n">05</span>Attack Path Analysis</h2>
{% if attack_paths %}
{% for ap in attack_paths %}
<div class="ap-card">
  <div class="ap-hdr {{ ap.combined_severity | lower }}">
    <div class="ap-hdr-inner">
      <div class="ap-id">{{ ap.id }}</div>
      <div class="ap-title">{{ ap.title }}</div>
      <div class="ap-cvss">CVSS {{ ap.combined_cvss_score }}</div>
      <div class="ap-badge-cell"><span class="sev-badge {{ ap.combined_severity | lower }}">{{ ap.combined_severity }}</span></div>
    </div>
  </div>
  <div class="ap-body">
    <div class="ap-row"><span class="ap-lbl">Entry Point</span>{{ ap.entry_point }}</div>
    <div class="ap-row"><span class="ap-lbl">Findings Chained</span>{{ ap.finding_ids | join(", ") }}</div>
    <div class="ap-row">
      <span class="ap-lbl">Kill Chain</span>
      <ol class="ap-chain">{% for s in ap.steps %}<li><strong>{{ s.finding_id }}</strong> — {{ s.action }} → <em>{{ s.outcome }}</em></li>{% endfor %}</ol>
    </div>
    <div class="ap-row"><span class="ap-lbl">Narrative</span>{{ ap.narrative }}</div>
    <div class="ap-row"><span class="ap-lbl">Final Impact</span>{{ ap.final_impact }}</div>
  </div>
</div>
{% endfor %}
{% else %}
<p style="font-size:9.5pt;color:#5C6B8A;padding:16px 18px;background:#F4F6FA;border-radius:6px;border-left:5px solid #DDE3EF;">No multi-step attack chains were identified in this assessment.</p>
{% endif %}
</div>

<!-- ══════════════════════════════════════════════════════════
     SECTION 06 — RETEST COMPARISON (conditional)
     ══════════════════════════════════════════════════════════ -->
{% if retest_diff %}
<div class="page-section">
<h2 class="sec-hdr"><span class="n">06</span>Retest Comparison</h2>
{% set c = retest_diff.counts %}
<div class="{% if c.regressed > 0 or c.new > 0 %}retest-warn{% else %}retest-ok{% endif %}">
  <strong>Baseline:</strong> {{ retest_diff.baseline_count }} findings &nbsp;&bull;&nbsp;
  <strong>Current:</strong> {{ retest_diff.current_count }} findings &nbsp;&nbsp;
  <span style="color:#15803D;font-weight:700;">&#10003; Fixed: {{ c.fixed }}</span> &nbsp;&nbsp;
  <span style="color:#4B5563;font-weight:700;">&#8635; Persists: {{ c.persists }}</span> &nbsp;&nbsp;
  {% if c.new > 0 %}<span style="color:#C41E3A;font-weight:700;">+ New: {{ c.new }}</span> &nbsp;&nbsp;{% endif %}
  {% if c.regressed > 0 %}<span style="color:#7F1D1D;font-weight:700;">&#8593; Regressed: {{ c.regressed }}</span>{% endif %}
</div>
<table class="roadmap">
  <thead><tr><th>Status</th><th>Finding</th><th style="width:95px;">Severity</th><th style="width:70px;">Was</th></tr></thead>
  <tbody>
  {% for f in retest_diff.fixed %}
  <tr><td style="color:#15803D;font-weight:700;">Fixed</td><td>{{ f.title }}</td><td><span class="sev-badge {{ f.severity | lower }}" style="font-size:7.5pt;">{{ f.severity }}</span></td><td>—</td></tr>
  {% endfor %}
  {% for f in retest_diff.persists %}
  <tr><td style="color:#4B5563;">Persists</td><td>{{ f.title }}</td><td><span class="sev-badge {{ f.severity | lower }}" style="font-size:7.5pt;">{{ f.severity }}</span></td><td>—</td></tr>
  {% endfor %}
  {% for f in retest_diff.regressed %}
  <tr><td style="color:#7F1D1D;font-weight:700;">Regressed</td><td>{{ f.title }}</td><td><span class="sev-badge {{ f.severity | lower }}" style="font-size:7.5pt;">{{ f.severity }}</span></td><td>{{ f.was }}</td></tr>
  {% endfor %}
  {% for f in retest_diff.new %}
  <tr><td style="color:#C41E3A;font-weight:700;">New</td><td>{{ f.title }}</td><td><span class="sev-badge {{ f.severity | lower }}" style="font-size:7.5pt;">{{ f.severity }}</span></td><td>—</td></tr>
  {% endfor %}
  </tbody>
</table>
</div>
{% endif %}

<!-- ══════════════════════════════════════════════════════════
     REMEDIATION ROADMAP
     ══════════════════════════════════════════════════════════ -->
<div class="page-section">
<h2 class="sec-hdr"><span class="n">{{ '07' if retest_diff else '06' }}</span>Remediation Roadmap</h2>
<table class="roadmap">
  <thead><tr><th style="width:60px;">ID</th><th>Finding</th><th style="width:95px;">Severity</th><th style="width:82px;">Effort</th><th style="width:180px;">Timeframe</th></tr></thead>
  <tbody>
  {% for f in findings | sort(attribute='priority') %}
  {% if f.severity | lower != 'informational' %}
  <tr>
    <td style="font-family:'Courier New',monospace;font-size:9pt;">{{ f.id }}</td>
    <td>{{ f.title }}</td>
    <td><span class="sev-badge {{ f.severity | lower }}" style="font-size:7.5pt;">{{ f.severity }}</span></td>
    <td><span class="effort-{{ f.effort }}">{{ f.effort }}</span></td>
    <td>{{ f.timeframe }}</td>
  </tr>
  {% endif %}
  {% endfor %}
  </tbody>
</table>
</div>

<!-- ══════════════════════════════════════════════════════════
     DISCLAIMER & LEGAL
     ══════════════════════════════════════════════════════════ -->
<div class="page-section">
<h2 class="sec-hdr"><span class="n">{{ '08' if retest_diff else '07' }}</span>Disclaimer &amp; Legal</h2>
<div class="disc"><h3>Important Notice</h3><p>{{ disclaimer }}</p></div>
{% if methodology_notes %}
<div style="margin-top:20px;">
  <div class="scope-h3">Methodology Notes</div>
  <p style="font-size:9.5pt;line-height:1.65;color:#2D3748;margin-top:8px;">{{ methodology_notes }}</p>
</div>
{% endif %}
<div class="footer" style="margin-top:32px;">
  <div class="footer-l"><strong>TechGuard Labs</strong> &bull; hari@techguardlabs.com</div>
  <div class="footer-r">Report generated {{ report_date }} &bull; PT-Orc Suite v1.0</div>
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

def _build_company_prompt(config, findings, evidence_block, report_prompt,
                          evidence_limit=80000, findings_limit=20000, prompt_limit=80000):
    """Build prompt for the TechGuard company-standard free-form HTML report."""
    config_block = "\n".join(f"{k}: {v}" for k, v in config.items() if v)
    rp = report_prompt[:prompt_limit] if report_prompt else "(REPORT_PROMPT.md not found — apply TechGuard PTE methodology)"
    return f"""{rp}

---
# ENGAGEMENT DATA

## Engagement Configuration
{config_block}

## Findings ({len(findings)} total)
{json.dumps(findings, indent=2)[:findings_limit]}

## Evidence Summary
{evidence_block[:evidence_limit]}

---
# TASK

Using the Tech Guard Penetration Testing Report methodology and standards documented above, write a complete, professional, customer-ready HTML penetration testing report.

Requirements:
- Full HTML document with embedded CSS styling (professional, formal TechGuard appearance)
- Follow the exact structure from the methodology: Front Matter, Section 1 (Background, Objectives, Scope, Methodology, Team, Limitations, Executive Summary with Key Findings), Section 2 (Severity Grading Table, Findings Summary, Severity Distribution, Assessment Findings, Observations), Section 3 (Appendices and Evidence Index)
- Include ALL {len(findings)} findings with finding ID, severity, confidence, affected systems, condition, evidence basis, impact, recommendations
- Severity model: Critical, High, Medium, Low, Informational/Observation
- Confidence model: Certain, Firm, Tentative
- Use TechGuard formal tone — no "we hacked", no dramatic language, no placeholders
- Observations must not appear in severity totals

Output the complete HTML report. Begin with <!DOCTYPE html> and end with </html>.
"""


def _wrap_company_output(raw_text, config):
    """If AI returns Markdown rather than full HTML, wrap it in a styled page."""
    import re as _re
    stripped = raw_text.strip()
    # Strip markdown code fences that models often wrap HTML in
    stripped = _re.sub(r'^```(?:html)?\s*\n?', '', stripped, flags=_re.IGNORECASE)
    stripped = _re.sub(r'\n?```\s*$', '', stripped)
    stripped = stripped.strip()
    if stripped.lower().startswith("<!doctype") or stripped.lower().startswith("<html"):
        # Strip any model commentary the model appended after </html>
        m = _re.search(r'(.*</html>)', stripped, _re.DOTALL | _re.IGNORECASE)
        if m:
            stripped = m.group(1)
        return stripped
    project_name = config.get("PROJECT_NAME", "VAPT Assessment")
    lines = stripped.split("\n")
    html_lines = []
    in_code = False
    for line in lines:
        if line.startswith("```"):
            if in_code:
                html_lines.append("</pre>")
                in_code = False
            else:
                html_lines.append("<pre>")
                in_code = True
            continue
        if in_code:
            html_lines.append(line.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
            continue
        line = _re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', line)
        line = _re.sub(r'\*(.+?)\*', r'<em>\1</em>', line)
        line = _re.sub(r'^#### (.+)$', r'<h4>\1</h4>', line)
        line = _re.sub(r'^### (.+)$', r'<h3>\1</h3>', line)
        line = _re.sub(r'^## (.+)$', r'<h2>\1</h2>', line)
        line = _re.sub(r'^# (.+)$', r'<h1>\1</h1>', line)
        line = _re.sub(r'^[-*] (.+)$', r'<li>\1</li>', line)
        if not line.strip():
            html_lines.append("<br>")
        elif not _re.match(r'^<(h[1-4]|li|pre|br|p)', line):
            html_lines.append(f"<p>{line}</p>")
        else:
            html_lines.append(line)
    body = "\n".join(html_lines)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{project_name} — TechGuard Penetration Testing Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; max-width: 1100px; margin: 0 auto; padding: 2em; color: #1C2340; line-height: 1.6; background: #fff; }}
  h1 {{ color: #0D1B3E; border-bottom: 4px solid #C41E3A; padding-bottom: 0.35em; margin: 1.2em 0 0.6em; font-size: 1.6em; }}
  h2 {{ color: #0D1B3E; background: #F4F6FA; border-left: 5px solid #C41E3A; padding: 0.5em 0.8em; margin: 1.8em 0 0.8em; font-size: 1.2em; }}
  h3 {{ color: #162040; border-bottom: 1px solid #DDE3EF; padding-bottom: 0.25em; margin: 1.4em 0 0.5em; font-size: 1.05em; }}
  h4 {{ color: #1E3A5F; margin: 1em 0 0.4em; font-size: 0.95em; text-transform: uppercase; letter-spacing: 0.5px; }}
  p  {{ margin: 0.5em 0 1em; font-size: 0.95em; }}
  li {{ margin: 0.35em 0; font-size: 0.95em; }}
  pre {{ background: #F4F6FA; border: 1px solid #DDE3EF; border-left: 4px solid #162040; padding: 1em; border-radius: 4px; overflow-x: auto; font-size: 0.85em; }}
  strong {{ color: #0D1B3E; }}
</style>
</head>
<body>
{body}
</body>
</html>"""


def _ollama_company(ollama_host, ollama_model, config, findings, evidence_block, report_prompt):
    """Company report via Ollama — uses a compact data-first prompt; ignores REPORT_PROMPT.md
    (81K chars) so findings and evidence fill the context instead of methodology text."""
    import urllib.request as _ur
    ctx_tokens     = _ollama_context_length(ollama_host, ollama_model)
    total_chars    = int(ctx_tokens * 3.5)
    # Reserve 40% of context for output; floor at 32K so large-context models get decent output
    output_reserve = max(32000, min(50000, int(total_chars * 0.40)))
    input_budget   = total_chars - output_reserve
    prompt = _build_ollama_company_prompt(config, findings, evidence_block, input_budget)
    print(f"[INFO] Company prompt: {len(prompt):,} chars (ctx {ctx_tokens:,} tok, budget {input_budget:,}) → Ollama {ollama_model}")
    payload = json.dumps({
        "model": ollama_model,
        "prompt": prompt,
        "stream": False,
        "options": {"num_predict": 8192},
    }).encode()
    req = _ur.Request(f"{ollama_host}/api/generate", data=payload,
                      headers={"Content-Type": "application/json"}, method="POST")
    try:
        with _ur.urlopen(req, timeout=1800) as resp:
            data = json.loads(resp.read().decode())
        return data.get("response", "").strip()
    except Exception as e:
        print(f"[WARN] Ollama company report failed: {e}")
        return ""


def _claude_company(api_key, model, config, findings, evidence_block, report_prompt):
    """Company report via Claude — returns raw text (HTML or Markdown)."""
    import urllib.request as _ur
    # Claude 200K context: use last 100K of REPORT_PROMPT.md (most actionable sections)
    rp_excerpt = report_prompt[-100000:] if len(report_prompt) > 100000 else report_prompt
    prompt = _build_company_prompt(config, findings, evidence_block, rp_excerpt,
                                   evidence_limit=120000, findings_limit=30000,
                                   prompt_limit=len(rp_excerpt) + 10)
    print(f"[INFO] Company prompt: {len(prompt):,} chars → Claude {model}")
    payload = json.dumps({
        "model": model,
        "max_tokens": 8096,
        "messages": [{"role": "user", "content": prompt}]
    }).encode()
    req = _ur.Request("https://api.anthropic.com/v1/messages", data=payload,
                      headers={"Content-Type": "application/json",
                               "x-api-key": api_key,
                               "anthropic-version": "2023-06-01"}, method="POST")
    try:
        with _ur.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode())
        return data.get("content", [{}])[0].get("text", "").strip()
    except Exception as e:
        print(f"[WARN] Claude company report failed: {e}")
        return ""


def _gemini_company(gemini_key, gemini_models, config, findings, evidence_block, report_prompt):
    """Company report via Gemini — returns raw text (HTML or Markdown)."""
    import urllib.request as _ur
    # Gemini 1M context — can handle the full REPORT_PROMPT.md
    prompt = _build_company_prompt(config, findings, evidence_block, report_prompt,
                                   evidence_limit=150000, findings_limit=30000,
                                   prompt_limit=len(report_prompt) + 10)
    print(f"[INFO] Company prompt: {len(prompt):,} chars → Gemini")
    for gm in gemini_models:
        url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
               f"{gm}:generateContent?key={gemini_key}")
        payload = json.dumps({
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"maxOutputTokens": 8192}
        }).encode()
        req = _ur.Request(url, data=payload,
                          headers={"Content-Type": "application/json"}, method="POST")
        try:
            with _ur.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read().decode())
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                text = "".join(p.get("text", "") for p in parts).strip()
                if text:
                    return text
        except Exception as e:
            print(f"[WARN] Gemini company ({gm}) failed: {e}")
    return ""


def _is_valid_company_report(raw):
    """Return True only if the output looks like a genuine report, not echoed evidence."""
    if not raw or len(raw) < 3000:
        return False
    s = raw.strip().lower()
    # Must contain structural markers of a real HTML or markdown report
    has_html  = "<html" in s or "<!doctype" in s
    has_heads = s.count("<h") >= 4 or s.count("\n#") >= 4
    # Reject outputs that open with raw HTTP evidence snippets
    first500  = s[:500]
    looks_like_echo = any(p in first500 for p in [
        "http/1.1 200", "content-type:", "api response body",
        "{\"status\":", "\"message\":", "response_data",
    ])
    return not looks_like_echo and (has_html or has_heads)


# ── Two-pass company report helpers ──────────────────────────────────────

def _pass1_prompt(config, findings, evidence_block, findings_limit=20000, evidence_limit=30000):
    """Compact Pass 1 analysis prompt — data + JSON schema only, no REPORT_PROMPT.md."""
    config_lines = "\n".join(f"{k}: {v}" for k, v in config.items() if v)
    compact = _compact_findings_text(findings)
    if len(compact) > findings_limit:
        compact = compact[:findings_limit] + "\n...[findings truncated for length]"
    ev = (evidence_block[:evidence_limit] if evidence_block else "(no evidence)").rstrip()
    n = len(findings)
    return f"""You are a TechGuard senior penetration testing consultant. Analyse the raw findings below and return ONLY a JSON object matching the schema shown.

ENGAGEMENT
{config_lines}

RAW FINDINGS ({n} total — analyse every one)
{compact}

EVIDENCE CONTEXT
{ev}

OUTPUT SCHEMA — return ONLY this JSON, no markdown fences, no extra text:
{{
  "overall_rating": "Critical|High|Medium|Low",
  "executive_themes": ["<key risk theme, one sentence, max 5>"],
  "limitations": ["<any testing limitation>"],
  "totals": {{"high": 0, "medium": 0, "low": 0, "informational": 0, "observations": 0}},
  "sections": [
    {{
      "section_id": "2.2.1",
      "section_title": "<testing area, e.g. DNS Reconnaissance>",
      "findings": [
        {{
          "id": "F-11",
          "title": "<concise TechGuard-style title>",
          "severity": "Critical|High|Medium|Low|Informational",
          "confidence": "Certain|Firm|Tentative",
          "affected_systems": "<host:port — description>",
          "condition": "<observed condition and why it is security-relevant>",
          "evidence_basis": "<what evidence supports this>",
          "impact": "<business/operational impact>",
          "recommendations": ["1. <action>", "2. <action>"],
          "cwe_id": "CWE-XXX",
          "cwe_name": "<CWE name>"
        }}
      ],
      "observations": [
        {{
          "id": "P-01",
          "title": "<positive control title>",
          "narrative": "<validated control description>",
          "preservation_rec": "<preservation-oriented recommendation>"
        }}
      ]
    }}
  ]
}}

RULES:
- Group findings by testing area into sections (DNS, Network Services, TLS/PKI, Web Headers, Web Application, Authentication, API, etc.)
- Section IDs start at 2.2.1; section-based finding IDs: F-11 = first in 2.2.1, F-12 = second, F-21 = first in 2.2.2, etc.
- Separate true findings (corrective action required) from observations (positive controls)
- Severity reflects actual exploitability and business impact — do not blindly inherit scanner ratings
- Totals count only findings, not observations; all fields must be populated
"""


def _pass2_prompt(config, pass1_result, report_prompt, prompt_limit=80000):
    """Pass 2 HTML-writing prompt — REPORT_PROMPT.md + structured Pass 1 JSON."""
    config_lines = "\n".join(f"{k}: {v}" for k, v in config.items() if v)
    rp = report_prompt[:prompt_limit] if report_prompt else "(REPORT_PROMPT.md not available)"
    p1_json = json.dumps(pass1_result, indent=2)
    n_findings = sum(len(s.get("findings", [])) for s in pass1_result.get("sections", []))
    n_obs      = sum(len(s.get("observations", [])) for s in pass1_result.get("sections", []))
    return f"""{rp}

---

# TASK: Generate the Full HTML Penetration Testing Report

## Engagement Configuration
{config_lines}

## Structured Analysis ({n_findings} findings, {n_obs} observations across {len(pass1_result.get("sections", []))} sections)

The findings below have already been analysed and structured. Write the report FROM this data — do not add new findings, do not change severities or IDs.

{p1_json}

## HTML Output Requirements

- Start with <!DOCTYPE html> and end with </html>
- Embed ALL CSS in the <head> — professional TechGuard dark-navy (#0D1B3E) + crimson (#C41E3A) palette, print-friendly
- Follow this exact section structure:
  Front Matter: Cover page (client name, title, engagement, prepared by, date, version, classification), Confidentiality Notice, Table of Contents
  Section 1: 1.1 Background, 1.2 Objectives, 1.3 Scope & Boundaries, 1.4 Methodology, 1.5 The Team, 1.6 Special Notes/Assumptions/Limitations, 1.7 Executive Summary (6 paragraphs + Key Findings list)
  Section 2: 2.1 Severity Grading Table, Findings Summary Table (Section|Finding|Severity), Severity Distribution bar/table, 2.2 Assessment Findings (one subsection per section), 2.3 Observations
  Section 3: Appendices and Evidence Index
- Each finding card must show: ID badge, Severity badge, Confidence, Affected Systems, Condition, Evidence Basis, Business Impact, Recommendations (numbered list), CWE reference
- Observations (P-01 etc.) in 2.3 show: ID, title, narrative, Preservation-Oriented Recommendation
- Findings Summary table lists only findings (not observations): columns = Section | Finding Title | Severity
- Write complete professional customer-ready content — no placeholder text
"""


def _call_ai_for_pass1(prompt):
    """AI fallback chain for Pass 1 (JSON output). Returns raw text or None."""
    import urllib.request as _ur
    if OLLAMA_HOST:
        try:
            ctx_tokens  = _ollama_context_length(OLLAMA_HOST, OLLAMA_MODEL)
            total_chars = int(ctx_tokens * 3.5)
            out_reserve = max(6000, int(total_chars * 0.25))
            in_budget   = total_chars - out_reserve
            prompt_o    = prompt[:in_budget] if len(prompt) > in_budget else prompt
            print(f"[INFO] Pass 1 → Ollama {OLLAMA_MODEL} ({len(prompt_o):,} chars)")
            payload = json.dumps({
                "model": OLLAMA_MODEL, "prompt": prompt_o,
                "stream": False, "format": "json",
                "options": {"num_predict": 4096},
            }).encode()
            req = _ur.Request(f"{OLLAMA_HOST}/api/generate", data=payload,
                              headers={"Content-Type": "application/json"}, method="POST")
            with _ur.urlopen(req, timeout=900) as resp:
                data = json.loads(resp.read().decode())
            text = data.get("response", "").strip()
            if text and len(text) > 200:
                return text
        except Exception as e:
            print(f"[WARN] Pass 1 Ollama: {e}")
    if API_KEY:
        try:
            print(f"[INFO] Pass 1 → Claude {MODEL} ({len(prompt):,} chars)")
            payload = json.dumps({
                "model": MODEL, "max_tokens": 6000,
                "messages": [{"role": "user", "content": prompt}]
            }).encode()
            req = _ur.Request("https://api.anthropic.com/v1/messages", data=payload,
                              headers={"Content-Type": "application/json",
                                       "x-api-key": API_KEY,
                                       "anthropic-version": "2023-06-01"}, method="POST")
            with _ur.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read().decode())
            text = data.get("content", [{}])[0].get("text", "").strip()
            if text:
                return text
        except Exception as e:
            print(f"[WARN] Pass 1 Claude: {e}")
    if GEMINI_KEY:
        for gm in GEMINI_MODELS:
            try:
                print(f"[INFO] Pass 1 → Gemini {gm} ({len(prompt):,} chars)")
                url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
                       f"{gm}:generateContent?key={GEMINI_KEY}")
                payload = json.dumps({
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"maxOutputTokens": 6000}
                }).encode()
                req = _ur.Request(url, data=payload,
                                  headers={"Content-Type": "application/json"}, method="POST")
                with _ur.urlopen(req, timeout=300) as resp:
                    data = json.loads(resp.read().decode())
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    text = "".join(p.get("text", "") for p in parts).strip()
                    if text:
                        return text
            except Exception as e:
                err = str(e)
                if any(k in err for k in ("RESOURCE_EXHAUSTED", "429", "quota", "NOT_FOUND", "404")):
                    continue
                print(f"[WARN] Pass 1 Gemini {gm}: {e}")
    return None


def _call_ai_for_pass2(prompt):
    """AI fallback chain for Pass 2 (HTML output). Returns raw text or None."""
    import urllib.request as _ur
    # Claude first for Pass 2 — better at long-form structured HTML
    if API_KEY:
        try:
            print(f"[INFO] Pass 2 → Claude {MODEL} ({len(prompt):,} chars)")
            payload = json.dumps({
                "model": MODEL, "max_tokens": 8000,
                "messages": [{"role": "user", "content": prompt}]
            }).encode()
            req = _ur.Request("https://api.anthropic.com/v1/messages", data=payload,
                              headers={"Content-Type": "application/json",
                                       "x-api-key": API_KEY,
                                       "anthropic-version": "2023-06-01"}, method="POST")
            with _ur.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read().decode())
            text = data.get("content", [{}])[0].get("text", "").strip()
            if text:
                if not text.rstrip().lower().endswith("</html>"):
                    print(f"[WARN] Pass 2 Claude output may be truncated (no </html>, {len(text):,} chars) — consider AI_CLAUDE_MODEL=claude-sonnet-4-6 for higher output limit")
                return text
        except Exception as e:
            print(f"[WARN] Pass 2 Claude: {e}")
    if GEMINI_KEY:
        for gm in GEMINI_MODELS:
            try:
                print(f"[INFO] Pass 2 → Gemini {gm} ({len(prompt):,} chars)")
                url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
                       f"{gm}:generateContent?key={GEMINI_KEY}")
                payload = json.dumps({
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"maxOutputTokens": 8192}
                }).encode()
                req = _ur.Request(url, data=payload,
                                  headers={"Content-Type": "application/json"}, method="POST")
                with _ur.urlopen(req, timeout=300) as resp:
                    data = json.loads(resp.read().decode())
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    text = "".join(p.get("text", "") for p in parts).strip()
                    if text:
                        if not text.rstrip().lower().endswith("</html>"):
                            print(f"[WARN] Pass 2 Gemini output may be truncated ({len(text):,} chars)")
                        return text
            except Exception as e:
                err = str(e)
                if any(k in err for k in ("RESOURCE_EXHAUSTED", "429", "quota", "NOT_FOUND", "404")):
                    continue
                print(f"[WARN] Pass 2 Gemini {gm}: {e}")
    # Ollama last resort for Pass 2
    if OLLAMA_HOST:
        try:
            ctx_tokens  = _ollama_context_length(OLLAMA_HOST, OLLAMA_MODEL)
            total_chars = int(ctx_tokens * 3.5)
            out_reserve = max(32000, int(total_chars * 0.45))
            in_budget   = total_chars - out_reserve
            prompt_o    = prompt[:in_budget] if len(prompt) > in_budget else prompt
            print(f"[INFO] Pass 2 → Ollama {OLLAMA_MODEL} ({len(prompt_o):,} chars, last resort)")
            payload = json.dumps({
                "model": OLLAMA_MODEL, "prompt": prompt_o,
                "stream": False,
                "options": {"num_predict": 10000},
            }).encode()
            req = _ur.Request(f"{OLLAMA_HOST}/api/generate", data=payload,
                              headers={"Content-Type": "application/json"}, method="POST")
            with _ur.urlopen(req, timeout=1800) as resp:
                data = json.loads(resp.read().decode())
            text = data.get("response", "").strip()
            if text:
                if not text.rstrip().lower().endswith("</html>"):
                    print(f"[WARN] Pass 2 Ollama output may be truncated ({len(text):,} chars)")
                return text
        except Exception as e:
            print(f"[WARN] Pass 2 Ollama: {e}")
    return None


def _parse_pass1_json(raw):
    """Extract and parse JSON from Pass 1 model output. Returns dict or raises."""
    import re as _re2
    s = raw.strip()
    s = _re2.sub(r'^```(?:json)?\s*\n?', '', s, flags=_re2.IGNORECASE)
    s = _re2.sub(r'\n?```\s*$', '', s)
    s = s.strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        m = _re2.search(r'\{.*\}', s, _re2.DOTALL)
        if m:
            return json.loads(m.group())
        raise


def run_company_report(config, findings, evidence_block, report_prompt):
    """Two-pass company report: Pass 1 structures findings, Pass 2 writes HTML.
    Falls back to single-pass on any failure."""

    # ── Pass 1: Analyse & structure findings ─────────────────────────────
    print("[INFO] Company report Pass 1 — analysing and structuring findings...")
    p1_raw = _call_ai_for_pass1(_pass1_prompt(config, findings, evidence_block))
    pass1_result = None
    if p1_raw:
        try:
            pass1_result = _parse_pass1_json(p1_raw)
            sections = pass1_result.get("sections", [])
            n_f = sum(len(s.get("findings", [])) for s in sections)
            n_o = sum(len(s.get("observations", [])) for s in sections)
            if n_f == 0:
                print("[WARN] Pass 1 returned 0 findings — skipping to fallback")
                pass1_result = None
            else:
                print(f"[OK]   Pass 1 complete — {n_f} findings, {n_o} observations, {len(sections)} sections")
                try:
                    p1_path = RUN_DIR / f"company_pass1_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    p1_path.write_text(json.dumps(pass1_result, indent=2))
                    print(f"[INFO] Pass 1 debug saved: {p1_path.name}")
                except Exception:
                    pass
        except Exception as e:
            print(f"[WARN] Pass 1 JSON parse failed: {str(e)[:200]} — skipping to fallback")
            pass1_result = None

    if pass1_result:
        # ── Pass 2: Write HTML from structured analysis ───────────────────
        print("[INFO] Company report Pass 2 — writing HTML from structured analysis...")
        raw = _call_ai_for_pass2(_pass2_prompt(config, pass1_result, report_prompt))
        if raw:
            return raw
        print("[WARN] Pass 2 HTML writing failed — falling back to single-pass")

    # ── Fallback: single-pass (original behaviour) ────────────────────────
    print("[INFO] Company report fallback — single-pass generation...")
    if OLLAMA_HOST:
        raw = _ollama_company(OLLAMA_HOST, OLLAMA_MODEL, config, findings, evidence_block, report_prompt)
        if _is_valid_company_report(raw):
            return raw
        if raw:
            print(f"[WARN] Ollama fallback invalid ({len(raw):,} chars)")
    if API_KEY:
        raw = _claude_company(API_KEY, MODEL, config, findings, evidence_block, report_prompt)
        if raw:
            return raw
    if GEMINI_KEY:
        raw = _gemini_company(GEMINI_KEY, GEMINI_MODELS, config, findings, evidence_block, report_prompt)
        if raw:
            return raw
    return ""


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

    if _PT_REPORT_SKILL:
        print(f"[INFO] Skill     : pt-report/SKILL.md loaded ({len(_PT_REPORT_SKILL):,} chars)")
    else:
        print(f"[WARN] Skill     : pt-report/SKILL.md not found at {_SKILL_PATH}")
    if _REPORT_PROMPT_MD:
        print(f"[INFO] Co.Prompt : REPORT_PROMPT.md loaded ({len(_REPORT_PROMPT_MD):,} chars)")
    else:
        print(f"[WARN] Co.Prompt : REPORT_PROMPT.md not found at {_REPORT_PROMPT_PATH}")

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

    evidence_block = ""
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
        f_count = len(analysis.get("findings", []))
        print(f"[INFO] Analysis complete — {f_count} findings in report")

        # Fallback: if the AI returned an empty findings list but we have raw findings,
        # populate from the raw data so the HTML report is never empty.
        if f_count == 0 and findings:
            print(f"[WARN] AI returned 0 findings — falling back to {len(findings)} raw findings for HTML report")
            SEV_ORDER_FB = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4, "info": 4}
            raw_sorted = sorted(findings, key=lambda f: SEV_ORDER_FB.get(f.get("severity","info").lower(), 5))
            analysis["findings"] = [
                {
                    "id": f.get("id", f"F-{i+1:02d}"),
                    "title": f.get("title", "Untitled Finding"),
                    "severity": f.get("severity", "Low").capitalize(),
                    "confidence": "Firm",
                    "cvss_score": f.get("cvss_score", 0),
                    "cvss_vector": f.get("cvss_vector", ""),
                    "owasp_id": f.get("owasp_id", ""),
                    "owasp_name": f.get("owasp_name", ""),
                    "owasp_url": f.get("owasp_url", ""),
                    "cwe_id": f.get("cwe_id", ""),
                    "cwe_name": f.get("cwe_name", ""),
                    "cwe_url": f.get("cwe_url", ""),
                    "cve_ids": f.get("cve_ids", []),
                    "chain_steps": f.get("chain_steps", []),
                    "affected_hosts": f.get("affected_hosts", []),
                    "description": f.get("description", ""),
                    "technical_detail": f.get("technical_detail", f.get("evidence", "")),
                    "business_impact": f.get("business_impact", ""),
                    "remediation": f.get("recommendation", f.get("remediation", "")),
                    "remediation_steps": f.get("remediation_steps", []),
                    "references": f.get("references", []),
                    "evidence_refs": f.get("evidence_ids", []),
                    "likelihood": f.get("likelihood", "Medium"),
                    "impact": f.get("impact", "Medium"),
                    "effort": f.get("effort", "Medium"),
                    "priority": i + 1,
                    "timeframe": f.get("timeframe", "Medium-term (1-3 months)"),
                }
                for i, f in enumerate(raw_sorted)
            ]
            print(f"[INFO] Raw fallback applied — {len(analysis['findings'])} findings in HTML report")

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

    # -----------------------------------------------------------------------
    # Company-standard report: second AI pass using REPORT_PROMPT.md
    # -----------------------------------------------------------------------
    # Use enriched AI-analysis findings for the company report (they have CVSS, OWASP,
    # business impact etc.). Fall back to raw findings only if AI produced nothing.
    enriched_findings = analysis.get("findings") or findings

    if not DRY_RUN and evidence_block:
        print("")
        print("[INFO] ── Company-standard report pass ──")
        company_pdf_out  = OUTPUT_DIR / f"ai_report_{safe}_{ts}_company.pdf"
        try:
            raw_report = run_company_report(config, enriched_findings, evidence_block, _REPORT_PROMPT_MD)
            if raw_report:
                company_html = _wrap_company_output(raw_report, config)
                if not NO_PDF:
                    if generate_pdf(company_html, company_pdf_out):
                        print(f"[OK]   Company PDF : {company_pdf_out}")
                else:
                    print("[INFO] Company PDF skipped (TG_NO_PDF=1)")
            else:
                print("[WARN] Company report: AI returned empty response — skipped")
        except Exception as _ce:
            print(f"[WARN] Company report generation failed: {_ce}")
    elif DRY_RUN:
        print("[INFO] Company report: skipped (dry run)")
    elif not evidence_block:
        print("[WARN] Company report: no evidence block collected — skipped")

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
# MRK:25_MAIN — MAIN entry point | main,entry,point | L1704-1779
# NAV-RULE: no-insert-before; read-toc-first
# =============================================================================

main() {
    AI_REPORT_FILES=""

    echo -e "${GREEN}"
    echo "════════════════════════════════════════════════════════════"
    echo "  25_report_pack.sh"
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
        echo "# Session Start — 25_report_pack.sh"
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
    echo -e "${BOLD}${CYAN}  25_report_pack.sh — Export complete${NC}"
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
