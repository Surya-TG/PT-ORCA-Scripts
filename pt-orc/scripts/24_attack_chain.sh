#!/bin/bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:24_NAV_TOC — Section index | nav,toc,index | L5-38
# - MRK:24_CONF   — CONF + LOG + AI-LIB SOURCE          | conf,log,colors,session,lib  | L39-125
# - MRK:24_ARGS   — ARGUMENT PARSING                    | args,cli,flags,depth         | L126-185
# - MRK:24_FIND   — EMIT CHAIN FINDING                  | finding,jsonl,emit,chain     | L186-235
# - MRK:24_LOAD   — LOAD ALL PRIOR FINDINGS             | load,collect,findings,glob   | L236-310
# - MRK:24_SYNTH  — AI SYNTHESIS + HEURISTIC FALLBACK   | ai,synthesis,llm,heuristic   | L311-530
# - MRK:24_MAIN   — MAIN                                | main,entry,summary           | L531-640
# NAV-LEN: 6 entries | Integrity-hash: 0000000000000000 | Last-indexed: 2026-06-22T00:00:00Z

# =============================================================================
# 15_attack_chain.sh — AI Attack Path Synthesis — Step 15 of PT-Orc Suite
# TechGuard. | Mythos AI layer v1.0
# =============================================================================
# Reads all JSONL findings produced by steps 01-14, synthesises them into
# ranked attack chains using local ollama (or Anthropic Claude API fallback),
# and falls back to a CVSS-sorted heuristic ranking when no LLM is available.
#
# Attack chains are emitted as JSONL findings consumed by step 12 (report pack).
# The attack_paths field in each finding powers the Attack Path section of the
# HTML/PDF report.
#
# USAGE:
#   sudo ./15_attack_chain.sh [OPTIONS]
#
# OPTIONS:
#   --yes              Bypass scope prompt
#   --dry-run          Print prompt and heuristic chains; make no API calls
#   --no-ai            Skip AI synthesis; emit heuristic ranking only
#   -h|--help          Show this help and exit
# =============================================================================

set -uo pipefail

# =============================================================================
# MRK:24_CONF — CONF + LOG + AI-LIB SOURCE | conf,log,colors,session,lib | L39-125
# NAV-RULE: no-insert-before
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=pt-orc.conf
[[ -f "${SCRIPT_DIR}/pt-orc.conf" ]] && source "${SCRIPT_DIR}/pt-orc.conf" \
    || echo "[WARN] pt-orc.conf not found in ${SCRIPT_DIR}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

_now() { date +'%Y-%m-%d %H:%M:%S'; }
_ts()  { date +'%Y%m%d_%H%M%S'; }
_ev_ts() { date +'%Y-%m-%d-%H-%M-%S'; }
ev_fname() {
    local name="${1:?ev_fname: name required}" ext="${2:?ev_fname: ext required}" extra="${3:-}"
    local ts; ts="${EV_TS:-$(_ev_ts)}"
    local pfx="${PROJ_SLUG:-project}-${ENGAGEMENT_PROFILE:-web}"
    if [[ -n "$extra" ]]; then
        printf '%s-%s-%s-%s.%s' "$pfx" "$name" "$extra" "$ts" "$ext"
    else
        printf '%s-%s-%s.%s' "$pfx" "$name" "$ts" "$ext"
    fi
}
find_latest_ev() {
    local pattern="${1:?find_latest_ev: pattern required}"
    local wdir="${WORKING_DIR:-${SCRIPT_DIR:-$(pwd)}/working}"
    find "$wdir" -maxdepth 1 -name "$pattern" -type f 2>/dev/null | sort -r | head -1
}
SESSION_TS="$(_ts)"
EV_TS="$(_ev_ts)"

mkdir -p working evidence

LOG_FILE="working/15_attack_chain_${SESSION_TS}.log"
log()      { local m="[$(_now)] $1";     echo -e "${BLUE}${m}${NC}";    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_ok()   { local m="[$(_now)] ✓ $1";  echo -e "${GREEN}${m}${NC}";   echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_warn() { local m="[$(_now)] ⚠ $1";  echo -e "${YELLOW}${m}${NC}";  echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_err()  { local m="[$(_now)] ✗ $1";  echo -e "${RED}${m}${NC}" >&2; echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
log_info() { local m="[$(_now)]   $1";  echo -e "${CYAN}${m}${NC}";    echo "${m}" >> "$LOG_FILE" 2>/dev/null || true; }
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

PROJ_SLUG="${PROJECT_NAME:-PT-Orc}"
PROJ_SLUG="${PROJ_SLUG//[^a-zA-Z0-9_-]/_}"

FINDINGS_FILE="${SCRIPT_DIR:-$(pwd)}/working/$(ev_fname "15-chain-findings" "jsonl")"
EVIDENCE_BASE="evidence/${SESSION_TS}/15_attack_chain"
mkdir -p "$EVIDENCE_BASE"
FINDING_COUNT=0

# Source orc-ai-lib.sh for ai_query
_AI_LIB="${SCRIPT_DIR}/orc-ai-lib.sh"
if [[ -f "$_AI_LIB" ]]; then
    # shellcheck source=orc-ai-lib.sh
    source "$_AI_LIB"
    log_ok "orc-ai-lib.sh sourced"
else
    log_warn "orc-ai-lib.sh not found — AI synthesis disabled, heuristic mode only"
    ai_query() { return 1; }
fi

# =============================================================================
# MRK:24_ARGS — ARGUMENT PARSING | args,cli,flags,depth | L126-185
# NAV-RULE: no-insert-before
# =============================================================================
usage() {
    sed -n '/^# USAGE:/,/^# ====/{s/^# \?//; /^===/ q; p}' "$0"
}

AUTO_YES=0
DRY_RUN=0
NO_AI=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --yes)      AUTO_YES=1; shift ;;
        --dry-run)  DRY_RUN=1; shift ;;
        --no-ai)    NO_AI=1; shift ;;
        -h|--help)  usage; exit 0 ;;
        *)          log_err "Unknown argument: $1"; usage; exit 1 ;;
    esac
done

# =============================================================================
# MRK:24_FIND — EMIT CHAIN FINDING | finding,jsonl,emit,chain | L186-235
# NAV-RULE: no-insert-before
# =============================================================================
# emit_chain_finding — write one JSONL attack chain record.
# Args: sev title desc rec chain_steps_json cve_ids_json [ev_tag]
# chain_steps_json: JSON array of step strings e.g. '["Exploit CVE-...", "Escalate via..."]'
# cve_ids_json: JSON array of CVE IDs e.g. '["CVE-2024-1234"]' or '[]'
emit_chain_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4"
    local chain_steps_json="${5:-[]}" cve_ids_json="${6:-[]}" ev_tag="${7:-}"
    FINDING_COUNT=$(( FINDING_COUNT + 1 ))
    local id; id="$(printf 'f-15-chain-%04d' "$FINDING_COUNT")"
    local ev_arr="[]"
    [[ -n "$ev_tag" ]] && ev_arr="[\"${ev_tag}\"]"
    local ts; ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
    _esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r'; }
    printf '{"id":"%s","title":"%s","severity":"%s","phase":"15_attack_chain","evidence_ids":%s,"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":"","discovered_at":"%s","chain_steps":%s,"cve_ids":%s}\n' \
        "$id" "$(_esc "$title")" "$sev" "$ev_arr" \
        "$(_esc "$desc")" "$(_esc "$rec")" "$ts" \
        "$chain_steps_json" "$cve_ids_json" \
        >> "$FINDINGS_FILE"
    log_ok "  [${id}] ${sev^^} — ${title}"
}

# =============================================================================
# MRK:24_LOAD — LOAD ALL PRIOR FINDINGS | load,collect,findings,glob | L236-310
# NAV-RULE: no-insert-before
# =============================================================================
# _load_all_findings — collect JSONL from all prior step findings files.
# Prints the combined JSONL to stdout, one object per line.
# Capped at CHAIN_MAX_INPUT_FINDINGS to stay within LLM context limits.
_load_all_findings() {
    local max_findings="${CHAIN_MAX_INPUT_FINDINGS:-200}"
    local total=0
    local f

    # All step findings JSONL files in working/ — ordered oldest-first so
    # earlier (recon) steps appear before later (attack) steps in the prompt.
    for f in $(ls -t "${SCRIPT_DIR}/working"/*_findings*.jsonl 2>/dev/null | tac); do
        [[ -f "$f" ]] || continue
        # Skip our own output file if it exists from a previous run
        [[ "$(basename "$f")" == *"15_attack_chain_findings"* ]] && continue

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            echo "$line"
            total=$(( total + 1 ))
            [[ "$total" -ge "$max_findings" ]] && return 0
        done < "$f"
    done
    log_info "Total findings loaded for synthesis: ${total}"
}

# _compact_findings_for_prompt — reduce each finding to a concise one-liner
# to maximise the number of findings that fit in LLM context.
# Output: one JSON object per line with only the fields the LLM needs.
_compact_findings_for_prompt() {
    local jsonl_input="$1"

    echo "$jsonl_input" | _real_jq -c '{
        id:       .id,
        sev:      .severity,
        phase:    .phase,
        title:    .title,
        cve_ids:  (.cve_ids // []),
        desc:     (.description[0:200] // "")
    }' 2>/dev/null || echo "$jsonl_input"
}

# =============================================================================
# MRK:24_SYNTH — AI SYNTHESIS + HEURISTIC FALLBACK | ai,synthesis,llm,heuristic | L311-530
# NAV-RULE: no-insert-before
# =============================================================================

# _ai_attack_chains <compact_jsonl> → prints JSON object {"attack_chains":[...]}
# Sends findings to LLM and extracts the structured attack chain response.
# Returns rc=1 if LLM fails (caller triggers heuristic fallback).
_ai_attack_chains() {
    local compact_jsonl="$1"
    local chain_count="${CHAIN_OUTPUT_PATHS:-5}"

    # Use CHAIN_AI_MODEL if set; otherwise fall through to orc-ai-lib defaults.
    local orig_model="${AI_CLAUDE_MODEL:-}"
    [[ -n "${CHAIN_AI_MODEL:-}" ]] && AI_CLAUDE_MODEL="$CHAIN_AI_MODEL"

    local sys_prompt
    sys_prompt="You are a senior penetration tester at TechGuard Labs performing a VAPT engagement.
Analyse the provided findings and synthesise the most likely attack chains.
An attack chain is a sequence of steps an adversary would use: initial access → exploitation → privilege escalation → impact.
Be specific: name the CVEs, tools, and techniques. Base your answer only on the provided findings.
Output valid JSON only — no markdown, no prose."

    local usr_prompt
    usr_prompt="VAPT target: ${PROJECT_NAME:-[unset]}
Total findings: $(echo "$compact_jsonl" | wc -l)

FINDINGS (one JSON object per line):
${compact_jsonl}

Task: identify the top ${chain_count} attack chains ordered by likelihood × impact.

For each chain output exactly this JSON schema:
{
  \"rank\": 1,
  \"title\": \"concise chain title\",
  \"severity\": \"critical|high|medium\",
  \"entry_point\": \"service or URL where attack begins\",
  \"steps\": [\"step 1 description\", \"step 2 description\"],
  \"cve_ids\": [\"CVE-YYYY-NNNNN\"],
  \"techniques\": [\"T1190\", \"T1068\"],
  \"impact\": \"what an attacker achieves at end of chain\",
  \"likelihood\": \"high|medium|low\",
  \"confidence\": \"confirmed|unverified|speculative\"
}

Wrap all chains in: {\"attack_chains\": [ ... ]}"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "[DRY-RUN] AI synthesis prompt (${#usr_prompt} chars) — skipping actual LLM call"
        log_info "System prompt: ${sys_prompt:0:120}..."
        AI_CLAUDE_MODEL="$orig_model"
        return 1
    fi

    local raw_response
    raw_response=$(ai_query "$sys_prompt" "$usr_prompt" 2>/dev/null) || {
        AI_CLAUDE_MODEL="$orig_model"
        return 1
    }
    AI_CLAUDE_MODEL="$orig_model"

    # Save raw response as evidence
    [[ -d "$EVIDENCE_BASE" ]] && echo "$raw_response" > "${EVIDENCE_BASE}/$(ev_fname "chain-ai-raw" "txt")" 2>/dev/null || true

    # Extract JSON — handle LLM wrapping in markdown fences
    local json_response
    json_response=$(echo "$raw_response" \
        | sed -n '/^{/,/^}$/p' \
        | head -500) || true

    # Fallback: try extracting from a fenced code block
    if [[ -z "$json_response" ]]; then
        json_response=$(echo "$raw_response" \
            | sed -n '/```json/,/```/p' \
            | grep -v '```') || true
    fi

    # Validate it's a JSON object with attack_chains
    if ! echo "$json_response" | _real_jq '.attack_chains | length' >/dev/null 2>&1; then
        log_warn "AI response did not contain valid attack_chains JSON — falling back to heuristic"
        return 1
    fi

    echo "$json_response"
}

# _severity_rank <sev> → integer (lower = higher priority for sorting)
_severity_rank() {
    case "${1,,}" in
        critical) echo 1 ;;
        high)     echo 2 ;;
        medium)   echo 3 ;;
        low)      echo 4 ;;
        *)        echo 5 ;;
    esac
}

# _heuristic_chains <all_findings_jsonl> — fallback when LLM is unavailable.
# Groups findings by service context and emits chains based on:
#   1. Severity (critical first)
#   2. Presence of public PoC (ExploitDB xref findings from T02)
#   3. CVE availability (NVD sweep findings from T01)
# Each critical/high finding with cve_ids becomes a standalone chain.
# Groups of medium findings sharing a phase are combined into one chain.
_heuristic_chains() {
    local all_findings="$1"
    local max_chains="${CHAIN_OUTPUT_PATHS:-5}"
    local min_conf="${CHAIN_MIN_CONFIDENCE:-unverified}"

    log_warn "T01: LLM unavailable — using heuristic attack chain ranking"
    log_warn "     Set OLLAMA_HOST or ANTHROPIC_API_KEY in pt-orc.conf for AI synthesis"

    local chain_rank=0

    # Pass 1: critical/high findings with public PoC (phase 14_vuln_corpus T02)
    while IFS= read -r fj; do
        [[ "$chain_rank" -ge "$max_chains" ]] && break
        [[ -z "$fj" ]] && continue

        local title sev cve_arr phase
        title=$(_real_jq -r '.title // ""' <<< "$fj" 2>/dev/null)
        sev=$(_real_jq -r '.severity // "info"' <<< "$fj" 2>/dev/null)
        cve_arr=$(_real_jq -r '.cve_ids // [] | @json' <<< "$fj" 2>/dev/null || echo "[]")
        phase=$(_real_jq -r '.phase // ""' <<< "$fj" 2>/dev/null)

        [[ "$title" != "Public PoC"* ]] && continue

        chain_rank=$(( chain_rank + 1 ))
        emit_chain_finding "$sev" \
            "Chain ${chain_rank}: Weaponisable — ${title}" \
            "A public proof-of-concept exploit exists for this finding. This significantly increases the likelihood of successful exploitation. Finding: ${title}. Phase: ${phase}. Adversaries with access to ExploitDB can directly use this PoC to exploit the vulnerability." \
            "Treat this finding as actively exploitable. Apply the vendor patch immediately. Consider isolating the affected service until patched. Verify with a retest after remediation." \
            "[\"Reconnaissance\", \"Exploit ${cve_arr}\", \"Establish foothold\"]" \
            "$cve_arr"

    done < <(echo "$all_findings" | _real_jq -r 'select(.severity=="critical" or .severity=="high")' 2>/dev/null | _real_jq -c '.' 2>/dev/null)

    # Pass 2: critical/high NVD CVE findings
    while IFS= read -r fj; do
        [[ "$chain_rank" -ge "$max_chains" ]] && break
        [[ -z "$fj" ]] && continue

        local title sev cve_arr phase desc
        title=$(_real_jq -r '.title // ""' <<< "$fj" 2>/dev/null)
        sev=$(_real_jq -r '.severity // "info"' <<< "$fj" 2>/dev/null)
        cve_arr=$(_real_jq -r '.cve_ids // [] | @json' <<< "$fj" 2>/dev/null || echo "[]")
        phase=$(_real_jq -r '.phase // ""' <<< "$fj" 2>/dev/null)
        desc=$(_real_jq -r '.description // "" | .[0:200]' <<< "$fj" 2>/dev/null)

        # Skip PoC findings already handled in Pass 1
        [[ "$title" == "Public PoC"* ]] && continue
        # Only include findings with CVEs
        local cve_count; cve_count=$(_real_jq '.cve_ids | length' <<< "$fj" 2>/dev/null || echo 0)
        [[ "$cve_count" -eq 0 ]] && continue

        chain_rank=$(( chain_rank + 1 ))
        emit_chain_finding "$sev" \
            "Chain ${chain_rank}: CVE-Based — ${title}" \
            "Known CVE(s) detected on a live service. ${desc}. Phase: ${phase}." \
            "Apply vendor patch for the identified CVE(s). Cross-reference with ExploitDB for available exploits. Verify fix with a targeted retest." \
            "[\"Identify vulnerable service\", \"Research ${cve_arr}\", \"Exploit if PoC available\", \"Escalate privileges\"]" \
            "$cve_arr"

    done < <(echo "$all_findings" | _real_jq -r 'select(.severity=="critical" or .severity=="high")' 2>/dev/null | _real_jq -c '.' 2>/dev/null)

    # Pass 3: remaining high/medium findings (generic chaining)
    local remaining_count
    remaining_count=$(echo "$all_findings" \
        | _real_jq -r 'select(.severity=="high" or .severity=="medium") | .title' 2>/dev/null \
        | wc -l)

    if [[ "$chain_rank" -lt "$max_chains" && "$remaining_count" -gt 0 ]]; then
        chain_rank=$(( chain_rank + 1 ))
        emit_chain_finding "medium" \
            "Chain ${chain_rank}: Compound — Multiple High/Medium Findings" \
            "The engagement identified ${remaining_count} high/medium findings that could be combined by a skilled adversary to establish persistent access. Individual findings may not be critical in isolation but present a chained attack surface when exploited sequentially." \
            "Address all high and medium findings systematically. Prioritise those with network-accessible attack vectors. Conduct a full retest after remediation to verify effectiveness." \
            "[\"Enumerate attack surface\", \"Exploit highest-severity accessible service\", \"Pivot internally\", \"Exfiltrate or persist\"]" \
            "[]"
    fi

    log_ok "Heuristic chains emitted: ${chain_rank}"
}

# _emit_ai_chains <attack_chains_json> — parse LLM JSON output and emit findings.
_emit_ai_chains() {
    local chains_json="$1"
    local min_conf="${CHAIN_MIN_CONFIDENCE:-unverified}"

    local chain_count
    chain_count=$(echo "$chains_json" | _real_jq '.attack_chains | length' 2>/dev/null || echo 0)
    log "AI returned ${chain_count} attack chain(s)"

    local i=0
    while [[ "$i" -lt "$chain_count" ]]; do
        local chain; chain=$(echo "$chains_json" | _real_jq ".attack_chains[$i]" 2>/dev/null)
        i=$(( i + 1 ))

        local confidence; confidence=$(_real_jq -r '.confidence // "speculative"' <<< "$chain" 2>/dev/null)

        # Skip chains below minimum confidence threshold
        case "${min_conf}" in
            confirmed)
                [[ "$confidence" != "confirmed" ]] && {
                    log_info "  Skipping chain (confidence=${confidence} < ${min_conf}): $(_real_jq -r '.title//"?"' <<< "$chain" 2>/dev/null)"
                    continue
                } ;;
            unverified)
                [[ "$confidence" == "speculative" ]] && {
                    log_info "  Skipping speculative chain: $(_real_jq -r '.title//"?"' <<< "$chain" 2>/dev/null)"
                    continue
                } ;;
            speculative) : ;; # accept all
        esac

        local rank title sev entry_point steps cve_ids impact likelihood
        rank=$(_real_jq -r '.rank // 0' <<< "$chain" 2>/dev/null)
        title=$(_real_jq -r '.title // "Attack Chain"' <<< "$chain" 2>/dev/null)
        sev=$(_real_jq -r '.severity // "high"' <<< "$chain" 2>/dev/null)
        entry_point=$(_real_jq -r '.entry_point // ""' <<< "$chain" 2>/dev/null)
        steps=$(_real_jq -c '.steps // []' <<< "$chain" 2>/dev/null || echo "[]")
        cve_ids=$(_real_jq -c '.cve_ids // []' <<< "$chain" 2>/dev/null || echo "[]")
        impact=$(_real_jq -r '.impact // ""' <<< "$chain" 2>/dev/null)
        likelihood=$(_real_jq -r '.likelihood // "medium"' <<< "$chain" 2>/dev/null)

        local desc
        desc="AI-synthesised attack chain (rank ${rank}, confidence: ${confidence}, likelihood: ${likelihood}). Entry point: ${entry_point}. Impact: ${impact}."

        local rec
        rec="Address the vulnerabilities in this attack chain starting at the entry point: ${entry_point}. Remediate associated CVE(s): $(echo "$cve_ids" | _real_jq -r 'join(", ")' 2>/dev/null). Verify with a targeted retest of the full chain after patching."

        emit_chain_finding "$sev" \
            "AI Chain ${rank}: ${title}" \
            "$desc" \
            "$rec" \
            "$steps" \
            "$cve_ids" \
            "ai_chain_${rank}"

    done
}

# =============================================================================
# MRK:24_MAIN — MAIN | main,entry,summary | L531-640
# NAV-RULE: no-insert-before
# =============================================================================
main() {
    log_step 15 "Attack Chain AI Synthesis" "$0"
    log "Project    : ${PROJECT_NAME:-[unset]}"
    log "Dry-run    : ${DRY_RUN}"
    log "No-AI      : ${NO_AI}"
    log "Max chains : ${CHAIN_OUTPUT_PATHS:-5}"
    log "Min conf   : ${CHAIN_MIN_CONFIDENCE:-unverified}"
    log "Findings   : ${FINDINGS_FILE}"

    if [[ "$AUTO_YES" -ne 1 ]]; then
        echo ""
        echo -e "${YELLOW}${BOLD}  ╔══ ATTACK CHAIN AI — SCOPE CONFIRMATION ══╗${NC}"
        echo -e "${YELLOW}  Project  : ${PROJECT_NAME:-[unset]}${NC}"
        echo -e "${YELLOW}  AI model : ${CHAIN_AI_MODEL:-${AI_CLAUDE_MODEL:-ollama/${OLLAMA_MODEL:-mistral}}}${NC}"
        echo -e "${YELLOW}  This step sends findings to the configured LLM.${NC}"
        echo -e "${YELLOW}${BOLD}  Confirm? [y/N] ${NC}"
        read -r _ans
        [[ "$_ans" =~ ^[Yy]$ ]] || { log "Aborted"; exit 0; }
    fi

    log ""
    log "═══════════════════════════════════════════════════════"
    log "  Loading findings from all prior steps"
    log "═══════════════════════════════════════════════════════"

    local all_findings
    all_findings="$(_load_all_findings)"

    if [[ -z "$all_findings" ]]; then
        log_warn "No findings found in working/ — run steps 01-14 first"
        log_warn "Emitting placeholder chain finding"
        emit_chain_finding "info" \
            "No findings to synthesise" \
            "Step 15 found no JSONL findings in working/. Ensure steps 01-14 have been run and produced findings before running step 15." \
            "Run the full engagement suite (steps 01-14) then re-run step 15." \
            "[]" "[]"
        return 0
    fi

    local finding_count
    finding_count=$(echo "$all_findings" | wc -l)
    log_ok "Loaded ${finding_count} finding(s) for synthesis"

    local compact_jsonl
    compact_jsonl=$(_compact_findings_for_prompt "$all_findings")

    # Save compacted input as evidence
    [[ -d "$EVIDENCE_BASE" ]] && echo "$compact_jsonl" > "${EVIDENCE_BASE}/$(ev_fname "chain-synthesis-input" "jsonl")" 2>/dev/null || true

    if [[ "$NO_AI" -eq 1 ]]; then
        log_warn "--no-ai: skipping AI synthesis, using heuristic ranking only"
        _heuristic_chains "$all_findings"
    else
        log ""
        log "═══════════════════════════════════════════════════════"
        log "  Running AI synthesis (${finding_count} findings → ${CHAIN_OUTPUT_PATHS:-5} chains)"
        log "═══════════════════════════════════════════════════════"

        local ai_chains_json
        if ai_chains_json=$(_ai_attack_chains "$compact_jsonl"); then
            _emit_ai_chains "$ai_chains_json"
        else
            _heuristic_chains "$all_findings"
        fi
    fi

    # Summary
    local total_findings=0
    [[ -f "$FINDINGS_FILE" ]] && total_findings=$(wc -l < "$FINDINGS_FILE")

    local line; line="$(printf '═%.0s' {1..52})"
    echo ""
    echo -e "${BOLD}${BLUE}${line}${NC}"
    echo -e "${BOLD}${BLUE}  STEP 15 — Attack Chain AI — COMPLETE${NC}"
    echo -e "${BOLD}${BLUE}${line}${NC}"
    echo -e "  ${GREEN}Attack chains emitted : ${total_findings}${NC}"
    echo -e "  ${GREEN}Findings file         : ${FINDINGS_FILE}${NC}"
    echo -e "  ${GREEN}Evidence dir          : ${EVIDENCE_BASE}${NC}"
    echo -e "  ${CYAN}Next step             : 12_report_pack.sh${NC}"
    echo ""

    log "Step 15 complete — ${total_findings} chain finding(s) in ${FINDINGS_FILE}"
}

main "$@"
