#!/usr/bin/env bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:AI_NAV_TOC — Section index | nav,toc,index | L5-57
# - MRK:AI_GUARD  — SOURCE GUARD + LOG / ALERT BOOTSTRAP   | guard,source,loaded,alert,log      | L58-122
# - MRK:AI_CONST  — DEFAULTS + RATE STATE + CACHE DIR      | defaults,const,rate,cache,state    | L123-175
# - MRK:AI_CHECK  — CONNECTIVITY PROBES                    | check,probe,ollama,nvd,status      | L176-244
# - MRK:AI_QUERY  — LLM INFERENCE (ollama → Claude)        | query,llm,ollama,anthropic,infer   | L245-393
# - MRK:AI_NVD    — NVD API v2 CVE LOOKUP                  | nvd,cve,lookup,nist,api,cache      | L394-570
# - MRK:AI_OSV    — OSV.DEV PACKAGE VULNERABILITY LOOKUP   | osv,package,ecosystem,vuln         | L571-650
# - MRK:AI_EDB       — EXPLOITDB / SEARCHSPLOIT LOOKUP        | exploitdb,searchsploit,poc,edb     | L651-715
# - MRK:AI_CORRELATE — FINDING CORRELATOR + STEP RECOMMENDER | correlate,findings,recommend,chain | L716-800
# - MRK:AI_BANNER    — STANDALONE BANNER + USAGE              | banner,standalone,usage,help       | L801-891
# NAV-LEN: 9 entries | Integrity-hash: 0000000000000000 | Last-indexed: 2026-06-29T00:00:00Z

# =============================================================================
# orc-ai-lib.sh — PT-Orc AI & Intelligence Library
# TechGuard. | Suite v1.0 | Mythos AI layer (steps 14–15)
# =============================================================================
# Purpose: shared AI inference and threat-intelligence API helpers.
# Source once per script — provides ai_query, nvd_cve_lookup_keyword,
# nvd_cpe_lookup, osv_lookup, and exploitdb_search.
#
# Backend priority:
#   LLM:     ollama (local) → Anthropic Claude API → warn + rc=1
#   CVE:     NVD API v2 (file-cached, rate-limited) + jq parse
#   Package: OSV.dev REST API
#   PoC:     searchsploit --json (local ExploitDB)
#
# USAGE (from a script):
#   source "$(dirname "$0")/orc-ai-lib.sh"
#
#   ai_status                             # check what's available
#   ai_query "You are a VAPT assistant." \
#            "Synthesise attack chains from these findings: ..."
#
#   nvd_cve_lookup_keyword "OpenSSH 8.9p1"    # → JSONL to stdout
#   nvd_cpe_lookup "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
#   osv_lookup "werkzeug" "PyPI"
#   exploitdb_search "Apache Tomcat 10.1"
#
# RATE LIMITS (NVD API v2):
#   No key:  5 req / 30 s  → sleep 7 between API calls (cache misses only)
#   API key: 50 req / 30 s → sleep 0.6 between API calls (cache misses only)
#   Set NVD_API_KEY in pt-orc.conf for full-rate access.
#
# DEPENDENCIES:
#   Required: bash 4+, curl, jq
#   Optional: searchsploit (apt install exploitdb), ollama, ANTHROPIC_API_KEY
# =============================================================================
set -uo pipefail

# =============================================================================
# MRK:AI_GUARD — SOURCE GUARD + LOG / ALERT BOOTSTRAP | guard,source,loaded,alert,log | L58-122
# NAV-RULE: no-insert-before
# =============================================================================
# Idempotent source guard — safe to source from multiple scripts in the same
# shell session. The _ORC_AI_LIB_LOADED flag prevents double-registration of
# global state and avoids duplicate log lines.
if [[ "${_ORC_AI_LIB_LOADED:-0}" -eq 1 ]]; then
    # Already sourced — only skip if we are being sourced, not executed.
    [[ "${BASH_SOURCE[0]}" != "$0" ]] && return 0
fi
declare -g _ORC_AI_LIB_LOADED=1

# Bootstrap colour codes if the calling script has not already set them.
[[ -z "${RED:-}"    ]] && RED='\033[0;31m'
[[ -z "${GREEN:-}"  ]] && GREEN='\033[0;32m'
[[ -z "${YELLOW:-}" ]] && YELLOW='\033[1;33m'
[[ -z "${BLUE:-}"   ]] && BLUE='\033[0;34m'
[[ -z "${CYAN:-}"   ]] && CYAN='\033[0;36m'
[[ -z "${NC:-}"     ]] && NC='\033[0m'

# Bootstrap minimal log functions if calling script has not defined them.
# Uses >&2 so stdout remains clean for function return values.
if ! declare -F log_ok >/dev/null 2>&1; then
    _now_ai() { date +'%Y-%m-%d %H:%M:%S'; }
    log()      { echo -e "${BLUE}[$(_now_ai)] $1${NC}" >&2; }
    log_ok()   { echo -e "${GREEN}[$(_now_ai)] ✓ $1${NC}" >&2; }
    log_warn() { echo -e "${YELLOW}[$(_now_ai)] ⚠ $1${NC}" >&2; }
    log_err()  { echo -e "${RED}[$(_now_ai)] ✗ $1${NC}" >&2; }
    log_info() { echo -e "${CYAN}[$(_now_ai)]   $1${NC}" >&2; }
fi

# Bootstrap ev_fname helpers if orc-common-lib.sh was not sourced first.
if ! declare -F ev_fname >/dev/null 2>&1; then
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
fi

# Bootstrap _alert if orc-common-lib.sh was not sourced first.
# _alert is used for conditions that should never happen in normal operation.
if ! declare -F _alert >/dev/null 2>&1; then
    _bold_red='\033[1;97;41m'
    _alert() {
        echo -e "${_bold_red}[$(date +'%Y-%m-%d %H:%M:%S')] [ALERT] $1${NC}" >&2
    }
fi

# =============================================================================
# MRK:AI_CONST — DEFAULTS + RATE STATE + CACHE DIR | defaults,const,rate,cache,state | L123-175
# NAV-RULE: no-insert-before
# =============================================================================

# Ollama local inference — override in pt-orc.conf
# OLLAMA_HOST         primary endpoint (tried first)
# OLLAMA_HOST_FALLBACK secondary endpoint (tried if primary unreachable; empty = disabled)
: "${OLLAMA_HOST:=http://127.0.0.1:11434}"
: "${OLLAMA_HOST_FALLBACK:=}"
: "${OLLAMA_MODEL:=qwen:7b}"

# Anthropic Claude API — set ANTHROPIC_API_KEY in pt-orc.conf or environment.
# Model used for ai_query fallback. Haiku is fast and cheap for synthesis prompts.
: "${ANTHROPIC_API_KEY:=}"
: "${AI_CLAUDE_MODEL:=claude-haiku-4-5-20251001}"

# NVD API key — optional. Raises rate limit from 5→50 req/30s.
# Register free at https://nvd.nist.gov/developers/request-an-api-key
: "${NVD_API_KEY:=}"

# NVD response cache — prevents redundant API calls across retries and runs.
# Defaults to working/nvd_cache/ relative to where the calling script runs.
_AI_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
: "${NVD_CACHE_DIR:=${_AI_LIB_DIR}/working/nvd_cache}"
: "${NVD_CACHE_TTL_DAYS:=7}"

# Create cache dir once on source so callers never need to think about it.
mkdir -p "${NVD_CACHE_DIR}" 2>/dev/null || true

# Connectivity probe result cache — checked once per session, not per call.
declare -g _AI_OLLAMA_OK=""             # "" = unchecked, "1" = ok, "0" = not ok
declare -g _AI_OLLAMA_ACTIVE_HOST=""    # resolved host that responded (primary or fallback)
declare -g _AI_NVD_OK=""               # same pattern

# OSV inter-call politeness delay (ms → enforced via sleep).
: "${OSV_CALL_DELAY:=0.5}"

# _real_jq — use the real jq binary, bypassing any local shims.
# A Python shim at $HOME/.local/bin/jq handles simple patterns only;
# the ai-lib needs full jq 1.6+ semantics (hyphenated keys, ? operators,
# multi-fallback chains). Prefer /usr/bin/jq when available.
declare -g _REAL_JQ_BIN=""
_real_jq() {
    if [[ -z "$_REAL_JQ_BIN" ]]; then
        if /usr/bin/jq --version >/dev/null 2>&1; then
            _REAL_JQ_BIN="/usr/bin/jq"
        elif jq --version >/dev/null 2>&1; then
            _REAL_JQ_BIN="jq"
        else
            _REAL_JQ_BIN="false"
        fi
    fi
    [[ "$_REAL_JQ_BIN" == "false" ]] && return 1
    "$_REAL_JQ_BIN" "$@"
}

# =============================================================================
# MRK:AI_CHECK — CONNECTIVITY PROBES | check,probe,ollama,nvd,status | L176-244
# NAV-RULE: no-insert-before
# =============================================================================

# _ai_ollama_available — probes ollama once, caches result for the session.
# Tries OLLAMA_HOST first; if unreachable and OLLAMA_HOST_FALLBACK is set, tries that too.
# Sets _AI_OLLAMA_ACTIVE_HOST to whichever endpoint responds.
# Returns 0 if reachable, 1 if not.
_ai_ollama_available() {
    if [[ -z "$_AI_OLLAMA_OK" ]]; then
        local _try_hosts=("$OLLAMA_HOST")
        [[ -n "${OLLAMA_HOST_FALLBACK:-}" ]] && _try_hosts+=("$OLLAMA_HOST_FALLBACK")
        local _h
        for _h in "${_try_hosts[@]}"; do
            if curl -sf --connect-timeout 3 --max-time 5 \
                    "${_h}/api/tags" >/dev/null 2>&1; then
                _AI_OLLAMA_OK="1"
                _AI_OLLAMA_ACTIVE_HOST="$_h"
                log_ok "ai-lib: ollama reachable at ${_h} (model: ${OLLAMA_MODEL})"
                break
            else
                log_warn "ai-lib: ollama not reachable at ${_h}"
            fi
        done
        if [[ "$_AI_OLLAMA_OK" != "1" ]]; then
            _AI_OLLAMA_OK="0"
            log_warn "ai-lib: no ollama endpoint reachable — Claude API fallback active"
        fi
    fi
    [[ "$_AI_OLLAMA_OK" == "1" ]]
}

# _nvd_reachable — probes NVD API once, caches result.
# Returns 0 if reachable, 1 if not.
_nvd_reachable() {
    if [[ -z "$_AI_NVD_OK" ]]; then
        if curl -sf --connect-timeout 8 --max-time 15 \
                "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1&keywordSearch=test" \
                >/dev/null 2>&1; then
            _AI_NVD_OK="1"
            log_ok "ai-lib: NVD API v2 reachable"
        else
            _AI_NVD_OK="0"
            log_warn "ai-lib: NVD API v2 not reachable — corpus CVE correlation will be skipped"
        fi
    fi
    [[ "$_AI_NVD_OK" == "1" ]]
}

# ai_status — print a summary of what backends are available. Public API.
ai_status() {
    local line; line="$(printf '─%.0s' {1..52})"
    echo -e "${CYAN}${line}${NC}" >&2
    echo -e "${CYAN}  orc-ai-lib — backend status${NC}" >&2
    echo -e "${CYAN}${line}${NC}" >&2
    if _ai_ollama_available; then
        echo -e "  ${GREEN}✓${NC} ollama       ${_AI_OLLAMA_ACTIVE_HOST} / ${OLLAMA_MODEL}" >&2
        [[ "${_AI_OLLAMA_ACTIVE_HOST}" != "${OLLAMA_HOST}" ]] && \
            echo -e "  ${CYAN}  ${NC}             (primary ${OLLAMA_HOST} unreachable; using fallback)" >&2
    else
        echo -e "  ${YELLOW}✗${NC} ollama       not reachable" >&2
        echo -e "  ${YELLOW}  ${NC}             primary:  ${OLLAMA_HOST}" >&2
        [[ -n "${OLLAMA_HOST_FALLBACK:-}" ]] && \
            echo -e "  ${YELLOW}  ${NC}             fallback: ${OLLAMA_HOST_FALLBACK}" >&2
    fi
    [[ -n "$ANTHROPIC_API_KEY" ]] \
        && echo -e "  ${GREEN}✓${NC} Anthropic    key set (model: ${AI_CLAUDE_MODEL})" >&2 \
        || echo -e "  ${YELLOW}✗${NC} Anthropic    ANTHROPIC_API_KEY not set" >&2
    _nvd_reachable \
        && echo -e "  ${GREEN}✓${NC} NVD API v2   reachable${NVD_API_KEY:+ (key set — 50 req/30s)}" >&2 \
        || echo -e "  ${YELLOW}✗${NC} NVD API v2   not reachable" >&2
    command -v searchsploit &>/dev/null \
        && echo -e "  ${GREEN}✓${NC} searchsploit $(searchsploit --version 2>/dev/null | head -1)" >&2 \
        || echo -e "  ${YELLOW}✗${NC} searchsploit not installed (apt install exploitdb)" >&2
    _real_jq --version >/dev/null 2>&1 \
        && echo -e "  ${GREEN}✓${NC} jq           $(_real_jq --version 2>/dev/null)" >&2 \
        || echo -e "  ${RED}✗${NC} jq           REQUIRED — install: apt install jq" >&2
    echo -e "${CYAN}${line}${NC}" >&2
}

# =============================================================================
# MRK:AI_QUERY — LLM INFERENCE (ollama → Claude) | query,llm,ollama,anthropic,infer | L245-393
# NAV-RULE: no-insert-before
# =============================================================================

# _ai_ollama_query <system_prompt> <user_prompt> → response text on stdout
# Internal. Called only by ai_query. Returns empty string on failure.
_ai_ollama_query() {
    local sys_prompt="$1" usr_prompt="$2"

    local body; body=$(_real_jq -nc \
        --arg model  "$OLLAMA_MODEL" \
        --arg sys    "$sys_prompt" \
        --arg usr    "$usr_prompt" \
        '{"model": $model, "messages": [{"role": "system", "content": $sys}, {"role": "user", "content": $usr}], "stream": false}') || return 1

    local _active_host="${_AI_OLLAMA_ACTIVE_HOST:-$OLLAMA_HOST}"
    local resp
    resp=$(curl -sf --connect-timeout 10 --max-time 180 \
        -X POST "${_active_host}/api/chat" \
        -H "Content-Type: application/json" \
        -d "$body" 2>/dev/null) || return 1

    [[ -z "$resp" ]] && return 1

    # Extract .message.content — empty string if parse fails
    local text; text=$(echo "$resp" | _real_jq -r '.message.content // empty' 2>/dev/null) || return 1
    [[ -z "$text" ]] && return 1

    echo "$text"
}

# _ai_anthropic_query <system_prompt> <user_prompt> → response text on stdout
# Internal. Called only by ai_query when ollama is unavailable.
# Requires ANTHROPIC_API_KEY to be set.
_ai_anthropic_query() {
    local sys_prompt="$1" usr_prompt="$2"

    local body; body=$(_real_jq -nc \
        --arg model  "$AI_CLAUDE_MODEL" \
        --arg sys    "$sys_prompt" \
        --arg usr    "$usr_prompt" \
        '{
            model:      $model,
            max_tokens: 4096,
            system:     $sys,
            messages:   [{"role": "user", "content": $usr}]
        }') || return 1

    local resp
    resp=$(curl -sf --connect-timeout 15 --max-time 180 \
        -X POST "https://api.anthropic.com/v1/messages" \
        -H "x-api-key: ${ANTHROPIC_API_KEY}" \
        -H "anthropic-version: 2023-06-01" \
        -H "content-type: application/json" \
        -d "$body" 2>/dev/null) || {
        log_warn "ai-lib: Anthropic API call failed (network or auth)"
        return 1
    }

    [[ -z "$resp" ]] && return 1

    # Check for API error object {"type":"error",...}
    local err_type; err_type=$(echo "$resp" | _real_jq -r '.type // empty' 2>/dev/null)
    if [[ "$err_type" == "error" ]]; then
        local err_msg; err_msg=$(echo "$resp" | _real_jq -r '.error.message // "unknown"' 2>/dev/null)
        log_warn "ai-lib: Anthropic API error — ${err_msg}"
        return 1
    fi

    local text; text=$(echo "$resp" | _real_jq -r '.content[0].text // empty' 2>/dev/null) || return 1
    [[ -z "$text" ]] && return 1

    echo "$text"
}

# ai_query <system_prompt> <user_prompt> → response text on stdout
# Public API. Tries ollama first, falls back to Anthropic Claude API.
# Returns 0 on success, 1 if all backends unavailable/fail.
#
# Example:
#   result=$(ai_query \
#       "You are a senior penetration tester. Be concise and structured." \
#       "Identify attack chains from these findings: $(cat findings.jsonl)")
ai_query() {
    local sys_prompt="${1:-You are a senior penetration tester.}"
    local usr_prompt="${2:-}"

    if [[ -z "$usr_prompt" ]]; then
        log_warn "ai_query: empty user_prompt — skipping"
        return 1
    fi

    # jq is required to safely build JSON bodies from arbitrary prompt text.
    # A bash fallback cannot handle quotes, newlines, and Unicode reliably.
    if ! _real_jq --version >/dev/null 2>&1; then
        log_warn "ai_query: jq is required but not found — install: apt install jq"
        return 1
    fi

    # Attempt 1: ollama (local, no network dependency, no cost)
    if _ai_ollama_available; then
        local resp; resp=$(_ai_ollama_query "$sys_prompt" "$usr_prompt" 2>/dev/null) || true
        if [[ -n "${resp:-}" ]]; then
            echo "$resp"
            return 0
        fi
        log_warn "ai-lib: ollama call returned empty — falling back to Anthropic"
    fi

    # Attempt 2: Anthropic Claude API
    if [[ -n "${ANTHROPIC_API_KEY:-}" ]]; then
        local resp; resp=$(_ai_anthropic_query "$sys_prompt" "$usr_prompt" 2>/dev/null) || true
        if [[ -n "${resp:-}" ]]; then
            echo "$resp"
            return 0
        fi
    fi

    log_warn "ai_query: all LLM backends failed (ollama down; Anthropic API key unset or error)"
    log_warn "  Set ANTHROPIC_API_KEY or start ollama to enable AI synthesis"
    return 1
}

# =============================================================================
# MRK:AI_NVD — NVD API v2 CVE LOOKUP | nvd,cve,lookup,nist,api,cache | L394-570
# NAV-RULE: no-insert-before
#
# Rate limits (NVD API v2):
#   No key : 5 req / 30 s → minimum 6 s between calls; we sleep 7 for safety
#   API key: 50 req / 30 s → minimum 0.6 s between calls
#   Sleep is applied ONLY on cache misses (actual API calls), not cache hits.
# =============================================================================

# _nvd_rate_limit — enforces the correct inter-call delay.
# Called inside cache-miss paths only.
_nvd_rate_limit() {
    if [[ -n "${NVD_API_KEY:-}" ]]; then
        sleep 0.6
    else
        sleep 7
    fi
}

# _nvd_cache_key <string> → prints a filesystem-safe cache key (md5 hex, 32 chars)
_nvd_cache_key() {
    echo -n "$1" | md5sum | cut -d' ' -f1
}

# _nvd_cache_get <cache_key> → prints cached JSON if valid, returns 0; else rc=1
_nvd_cache_get() {
    local key="$1"
    local cache_file="${NVD_CACHE_DIR}/${key}.json"
    [[ -f "$cache_file" ]] || return 1

    # Respect TTL — regenerate if stale
    local age_days
    age_days=$(( ( $(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0) ) / 86400 ))
    [[ "$age_days" -ge "${NVD_CACHE_TTL_DAYS}" ]] && return 1

    cat "$cache_file"
}

# _nvd_cache_put <cache_key> <json_data> — writes response to cache file
_nvd_cache_put() {
    local key="$1" data="$2"
    echo "$data" > "${NVD_CACHE_DIR}/${key}.json" 2>/dev/null || true
}

# _nvd_parse_cves <raw_json> → prints one JSON object per line to stdout
# Each object: {"cve_id":"...","description":"...","cvss_score":"...","severity":"..."}
# Handles NVD v2 response with CVSS v3.1 / v3.0 / v2 fallback chain.
_nvd_parse_cves() {
    local raw="$1"
    [[ -z "$raw" ]] && return 0

    echo "$raw" | _real_jq -c '
        .vulnerabilities[]? | .cve |
        {
            cve_id:      .id,
            published:   .published,
            description: ([ .descriptions[]? | select(.lang=="en") | .value ] | first // ""),
            cvss_score: (
                (.metrics.cvssMetricV31[0]?.cvssData.baseScore? //
                 .metrics.cvssMetricV30[0]?.cvssData.baseScore? //
                 .metrics.cvssMetricV2[0]?.cvssData.baseScore?  //
                 "N/A") | tostring
            ),
            severity: (
                .metrics.cvssMetricV31[0]?.cvssData.baseSeverity? //
                .metrics.cvssMetricV30[0]?.cvssData.baseSeverity? //
                "UNKNOWN"
            ),
            references: [ .references[0:3][]?.url? ]
        }
    ' 2>/dev/null || true
}

# _nvd_fetch <url_suffix> → prints raw NVD JSON response to stdout; rc=1 on error
# Caller is responsible for calling _nvd_rate_limit() before this.
_nvd_fetch() {
    local url_suffix="$1"
    local base_url="https://services.nvd.nist.gov/rest/json/cves/2.0"
    local auth_header=""
    [[ -n "${NVD_API_KEY:-}" ]] && auth_header="apiKey: ${NVD_API_KEY}"

    local resp
    if [[ -n "$auth_header" ]]; then
        resp=$(curl -sf --connect-timeout 15 --max-time 30 \
            -H "$auth_header" \
            "${base_url}${url_suffix}" 2>/dev/null) || return 1
    else
        resp=$(curl -sf --connect-timeout 15 --max-time 30 \
            "${base_url}${url_suffix}" 2>/dev/null) || return 1
    fi

    [[ -z "$resp" ]] && return 1
    echo "$resp"
}

# nvd_cve_lookup_keyword <keyword> [results_per_page]
# Searches NVD by keyword (e.g. "OpenSSH 8.9p1"). Returns parsed CVEs as JSONL.
# Results are cached; only actual API calls incur the rate-limit sleep.
#
# Keyword tip: pass "product_name version" only — strip OS/distro suffixes.
# Example: "OpenSSH 8.9p1" not "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10"
#
# Returns 0 always (empty output = no results or API unavailable — not an error).
nvd_cve_lookup_keyword() {
    local keyword="$1"
    local limit="${2:-100}"

    if [[ -z "$keyword" ]]; then
        log_warn "nvd_cve_lookup_keyword: empty keyword — skipping"
        return 0
    fi

    if ! _real_jq --version >/dev/null 2>&1; then
        log_warn "nvd_cve_lookup_keyword: jq required — skipping"
        return 0
    fi

    local cache_key; cache_key=$(_nvd_cache_key "kw:${keyword}:${limit}")
    local raw

    # Check cache first (no rate-limit sleep on hit)
    raw=$(_nvd_cache_get "$cache_key") && {
        log_info "NVD cache hit: ${keyword}"
        _nvd_parse_cves "$raw"
        return 0
    }

    # Cache miss — check connectivity, then rate-limit, then fetch
    if ! _nvd_reachable; then
        return 0
    fi

    _nvd_rate_limit

    local encoded; encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" \
        "$keyword" 2>/dev/null || echo "${keyword// /+}")

    log_info "NVD API lookup: ${keyword} (limit: ${limit})"
    raw=$(_nvd_fetch "?keywordSearch=${encoded}&resultsPerPage=${limit}") || {
        log_warn "nvd_cve_lookup_keyword: API call failed for '${keyword}'"
        return 0
    }

    local total; total=$(echo "$raw" | _real_jq -r '.totalResults // 0' 2>/dev/null || echo 0)
    log_info "  NVD: ${total} CVE(s) found for '${keyword}'"

    _nvd_cache_put "$cache_key" "$raw"
    _nvd_parse_cves "$raw"
}

# nvd_cpe_lookup <cpe_string> [results_per_page]
# Looks up CVEs by exact CPE 2.3 name. Use when the calling script has a clean CPE.
# Example: nvd_cpe_lookup "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
nvd_cpe_lookup() {
    local cpe="$1"
    local limit="${2:-100}"

    if [[ -z "$cpe" ]]; then
        log_warn "nvd_cpe_lookup: empty CPE — skipping"
        return 0
    fi

    if ! _real_jq --version >/dev/null 2>&1; then
        log_warn "nvd_cpe_lookup: jq required — skipping"
        return 0
    fi

    local cache_key; cache_key=$(_nvd_cache_key "cpe:${cpe}:${limit}")
    local raw

    raw=$(_nvd_cache_get "$cache_key") && {
        log_info "NVD cache hit (CPE): ${cpe}"
        _nvd_parse_cves "$raw"
        return 0
    }

    if ! _nvd_reachable; then
        return 0
    fi

    _nvd_rate_limit

    local encoded; encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" \
        "$cpe" 2>/dev/null || echo "${cpe// /+}")

    log_info "NVD API lookup (CPE): ${cpe}"
    raw=$(_nvd_fetch "?cpeName=${encoded}&resultsPerPage=${limit}") || {
        log_warn "nvd_cpe_lookup: API call failed for CPE '${cpe}'"
        return 0
    }

    local total; total=$(echo "$raw" | _real_jq -r '.totalResults // 0' 2>/dev/null || echo 0)
    log_info "  NVD: ${total} CVE(s) found for CPE"

    _nvd_cache_put "$cache_key" "$raw"
    _nvd_parse_cves "$raw"
}

# =============================================================================
# MRK:AI_OSV — OSV.DEV PACKAGE VULNERABILITY LOOKUP | osv,package,ecosystem,vuln | L571-650
# NAV-RULE: no-insert-before
# =============================================================================
# OSV.dev covers npm, PyPI, Go, Maven, RubyGems, crates.io, Packagist, etc.
# Useful when step 14 detects specific package names from web app responses.
#
# Recognised ecosystems: PyPI, npm, Go, Maven, RubyGems, crates.io, Packagist,
#   NuGet, Hex, Pub, SwiftURL, CocoaPods, Bioconductor, CRAN, Linux (kernel),
#   OSS-Fuzz, GSD, GitHub Actions

# osv_lookup <package_name> <ecosystem> → JSONL to stdout
# Each line: {"osv_id":"...","aliases":["CVE-..."],"summary":"...","severity":"..."}
#
# Example:
#   osv_lookup "werkzeug" "PyPI"
#   osv_lookup "lodash" "npm"
osv_lookup() {
    local package="$1" ecosystem="$2"

    if [[ -z "$package" || -z "$ecosystem" ]]; then
        log_warn "osv_lookup: package and ecosystem both required — skipping"
        return 0
    fi

    if ! _real_jq --version >/dev/null 2>&1; then
        log_warn "osv_lookup: jq required — skipping"
        return 0
    fi

    local body; body=$(_real_jq -nc \
        --arg name "$package" \
        --arg eco  "$ecosystem" \
        '{"package": {"name": $name, "ecosystem": $eco}}') || return 0

    log_info "OSV lookup: ${package} / ${ecosystem}"

    local resp
    resp=$(curl -sf --connect-timeout 10 --max-time 30 \
        -X POST "https://api.osv.dev/v1/query" \
        -H "Content-Type: application/json" \
        -d "$body" 2>/dev/null) || {
        log_warn "osv_lookup: API call failed for ${package} / ${ecosystem}"
        return 0
    }

    sleep "${OSV_CALL_DELAY}"

    local count; count=$(echo "$resp" | _real_jq '.vulns | length' 2>/dev/null || echo 0)
    log_info "  OSV: ${count} vulnerability(ies) for ${package}"

    # Emit one JSON object per vuln
    echo "$resp" | _real_jq -c '
        .vulns[]? |
        {
            osv_id:    .id,
            aliases:   (.aliases // []),
            summary:   (.summary // ""),
            severity:  ((.severity[0]?.type // "UNKNOWN") + " / " + (.severity[0]?.score // "")),
            published: (.published // ""),
            database_specific: (.database_specific // {})
        }
    ' 2>/dev/null || true
}

# =============================================================================
# MRK:AI_EDB — EXPLOITDB / SEARCHSPLOIT LOOKUP | exploitdb,searchsploit,poc,edb | L651-715
# NAV-RULE: no-insert-before
# =============================================================================
# searchsploit is part of the exploitdb package (apt install exploitdb).
# The local database is updated with: searchsploit -u
# This function gates on tool availability — soft-fail if not installed.

# exploitdb_search <keyword> → JSONL to stdout
# Each line: {"edb_id":"...","title":"...","path":"...","type":"...","date":"..."}
#
# Example:
#   exploitdb_search "Apache Tomcat 10.1"
#   exploitdb_search "OpenSSH 8.9"
exploitdb_search() {
    local keyword="$1"

    if [[ -z "$keyword" ]]; then
        log_warn "exploitdb_search: empty keyword — skipping"
        return 0
    fi

    if ! command -v searchsploit >/dev/null 2>&1; then
        log_warn "exploitdb_search: searchsploit not found (apt install exploitdb) — skipping"
        return 0
    fi

    if ! _real_jq --version >/dev/null 2>&1; then
        log_warn "exploitdb_search: jq required — skipping"
        return 0
    fi

    log_info "ExploitDB search: ${keyword}"

    local raw
    raw=$(searchsploit --json "${keyword}" 2>/dev/null) || {
        log_warn "exploitdb_search: searchsploit returned error for '${keyword}'"
        return 0
    }

    local count
    count=$(echo "$raw" | _real_jq '(.RESULTS_EXPLOIT | length) + (.RESULTS_SHELLCODE | length)' 2>/dev/null || echo 0)
    log_info "  ExploitDB: ${count} result(s) for '${keyword}'"

    # Emit exploits
    echo "$raw" | _real_jq -c '
        (.RESULTS_EXPLOIT // [])[] |
        {
            edb_id: (."EDB-ID" // ""),
            title:  (.Title   // ""),
            date:   (.Date_Published // .Date // ""),
            type:   (.Type    // "webapps"),
            path:   (.Path    // ""),
            source: "exploitdb"
        }
    ' 2>/dev/null || true

    # Emit shellcodes separately (lower priority but still interesting)
    echo "$raw" | _real_jq -c '
        (.RESULTS_SHELLCODE // [])[] |
        {
            edb_id: (."EDB-ID" // ""),
            title:  (.Title   // ""),
            date:   (.Date    // ""),
            type:   "shellcode",
            path:   (.Path    // ""),
            source: "exploitdb"
        }
    ' 2>/dev/null || true
}

# =============================================================================
# MRK:AI_CORRELATE — FINDING CORRELATOR + STEP RECOMMENDER | correlate,findings,recommend,chain | L716-800
# NAV-RULE: no-insert-before
# =============================================================================

# correlate_findings [working_dir] → markdown report on stdout; rc=0 always
# Reads all *findings*.jsonl files in working_dir, aggregates them, and asks the AI
# to identify attack chains, finding clusters, quick-win remediations, and risk
# amplifiers. Returns 0 always; empty output means no findings or no AI backend.
#
# Example:
#   result=$(correlate_findings "./working")
#   echo "$result" | tee working/chain_analysis.md
correlate_findings() {
    local wdir="${1:-${WORKING_DIR:-${_AI_LIB_DIR}/working}}"

    if ! _real_jq --version >/dev/null 2>&1; then
        log_warn "correlate_findings: jq required — skipping"
        return 0
    fi

    # Discover all JSONL findings files
    local -a jsonl_files
    while IFS= read -r f; do
        jsonl_files+=("$f")
    done < <(find "$wdir" -maxdepth 2 -name "*findings*.jsonl" -type f 2>/dev/null | sort)

    if [[ ${#jsonl_files[@]} -eq 0 ]]; then
        log_warn "correlate_findings: no findings JSONL files found in ${wdir}"
        return 0
    fi

    # Aggregate findings into a single annotated block
    local all_findings=""
    local total_count=0
    local f
    for f in "${jsonl_files[@]}"; do
        local count; count=$(wc -l < "$f" 2>/dev/null || echo 0)
        (( total_count += count ))
        all_findings+="## Source: $(basename "$f")
$(cat "$f" 2>/dev/null)

"
    done

    if [[ -z "$all_findings" || "$total_count" -eq 0 ]]; then
        log_warn "correlate_findings: all JSONL files are empty — nothing to correlate"
        return 0
    fi

    log_info "correlate_findings: ${total_count} finding(s) from ${#jsonl_files[@]} file(s)"

    local sys_prompt="You are a senior penetration testing analyst. Analyse the provided VAPT findings (JSONL format) and identify attack chains, clusters, quick-win remediations, and risk amplifiers. Output structured markdown only — no tool names, no scan dates."

    local usr_prompt="Analyse these penetration testing findings and produce:

1. **Attack Chain Analysis** — identify 2–5 multi-step chains where one finding enables or amplifies another. For each chain: list finding IDs in order, explain the pivot logic, and rate chain risk (Critical/High/Medium).

2. **High-Priority Clusters** — group findings sharing a root cause or remediation owner. Suggest consolidation where multiple findings should be one.

3. **Quick-Win Remediations** — top 3–5 findings with highest severity-to-fix-effort ratio (fixes achievable in under one day preferred).

4. **Risk Amplifiers** — any finding appearing in multiple chains (highest-leverage remediation target).

Findings data (JSONL):
${all_findings}"

    ai_query "$sys_prompt" "$usr_prompt"
}

# recommend_steps_ai [working_dir] [profile] → markdown recommendation on stdout; rc=0 always
# Reads discovered service data and existing findings from working_dir, then asks the AI
# which remaining PT-Orc steps are most relevant given what has been discovered.
# profile: external|web|api|internal|hybrid (default: external)
# Returns 0 always; empty output means no data or no AI backend available.
#
# Example:
#   recommend_steps_ai "./working" "external"
recommend_steps_ai() {
    local wdir="${1:-${WORKING_DIR:-${_AI_LIB_DIR}/working}}"
    local profile="${2:-external}"

    if ! _real_jq --version >/dev/null 2>&1; then
        log_warn "recommend_steps_ai: jq required — skipping"
        return 0
    fi

    # Aggregate available context: findings + service summary files
    local context=""

    # Findings
    local findings_data=""
    local findings_count=0
    while IFS= read -r f; do
        local lc; lc=$(wc -l < "$f" 2>/dev/null || echo 0)
        (( findings_count += lc ))
        findings_data+="$(cat "$f" 2>/dev/null)
"
    done < <(find "$wdir" -maxdepth 2 -name "*findings*.jsonl" -type f 2>/dev/null | sort)
    [[ -n "$findings_data" ]] && context+="### Current Findings (${findings_count} total, JSONL)
${findings_data}
"

    # Service summary files (markdown/txt from nmap/masscan steps)
    local svc_data=""
    while IFS= read -r f; do
        svc_data+="### $(basename "$f")
$(head -80 "$f" 2>/dev/null)
"
    done < <(find "$wdir" -maxdepth 2 \
        \( -name "*service*" -o -name "*scan*" -o -name "*summary*" \) \
        -name "*.md" -o -name "*.txt" 2>/dev/null | sort | head -5)
    [[ -n "$svc_data" ]] && context+="### Discovered Services
${svc_data}
"

    if [[ -z "$context" ]]; then
        log_warn "recommend_steps_ai: no service data or findings found in ${wdir} — cannot recommend steps"
        return 0
    fi

    log_info "recommend_steps_ai: building step recommendation for profile '${profile}'"

    # Step catalogue for the AI to choose from
    local step_catalogue="Available PT-Orc steps:
  1  DNS Recon         — passive/active DNS, AXFR, subdomain enum
  2  OSINT Recon       — GitHub, Shodan, WHOIS, certificate transparency
  3  IP Analysis       — RDAP, ASN, geolocation, reverse DNS
  4  Comprehensive Scan — nmap/masscan TCP+UDP port sweep
  5  TLS Scan          — testssl.sh, cipher analysis, certificate review
  6  Web Enumeration   — gobuster, nikto, technology fingerprinting
  7  WPScan            — WordPress-specific audit (XML-RPC, user enum, plugins)
  8  Service Verify    — targeted service probes, auth checks, CVE validation
  9  App / API Review  — OWASP API Top 10, JWT, CORS, auth, injection
 10  AI / LLM Review   — LLM endpoint security, prompt injection, RAG
 11  Cloud Testing     — IMDS, bucket exposure, IAM, K8s API
 12  AD Testing        — Kerberoasting, ADCS, BloodHound, DCSync
 13  Active Fuzz       — Burp/sqlmap/dalfox/nuclei/ffuf
 14  Vuln Corpus       — NVD CVE correlation for discovered versions
 15  Attack Chain AI   — AI synthesis of attack chains from findings
 16  Report Pack       — consolidate findings for reporting
 17  Network Infra     — SNMP, network device audit, VLAN, CDP/LLDP
 18  CI/CD DevOps      — Jenkins, GitLab CI, ArgoCD, K8s pipeline audit
 23  Auth / SSO        — OAuth 2.0, SAML, OIDC, session management
 24  API Deep          — GraphQL, REST business logic, BOLA, mass assignment
 25  Content Sec       — CSP quality, SRI, clickjacking, mixed content, cookies"

    local sys_prompt="You are a senior penetration tester advising on which test steps to run next. Be specific and concise. Output structured markdown only."

    local usr_prompt="Based on the discovered services and current findings below, recommend which PT-Orc steps to run next (and in what order) for a '${profile}' engagement.

For each recommended step:
- State the step number and name
- Explain WHY it is relevant given the specific services or findings discovered
- Rate priority: Immediate / High / Medium / Low
- Note any prerequisite (e.g. 'run step 4 first for port list')

Also flag any steps that are NOT relevant to this engagement (so the consultant can skip them).

${step_catalogue}

Current engagement context:
${context}"

    ai_query "$sys_prompt" "$usr_prompt"
}

# =============================================================================
# MRK:AI_BANNER — STANDALONE BANNER + USAGE | banner,standalone,usage,help | L801-891
# NAV-RULE: no-insert-before
# =============================================================================

_orc_ai_banner() {
    local line; line="$(printf '═%.0s' {1..70})"
    echo -e "${CYAN}${line}${NC}" >&2
    echo -e "${CYAN}  orc-ai-lib  —  PT-Orc AI & Intelligence Library${NC}" >&2
    echo -e "${CYAN}  TechGuard.  |  Suite v1.0 (Mythos AI)${NC}" >&2
    echo -e "${CYAN}${line}${NC}" >&2
    cat <<'EOF' >&2

Purpose: shared AI inference and threat-intelligence API helpers for
  steps 14 (14_vuln_corpus.sh) and 15 (15_attack_chain.sh).

Usage (from a script):
  source "$(dirname "$0")/orc-ai-lib.sh"

  # Check what backends are available
  ai_status

  # LLM synthesis — ollama-first, Claude API fallback
  result=$(ai_query \
      "You are a senior penetration tester. Be concise." \
      "Rank these findings by exploitability: $(cat findings.jsonl)")

  # CVE lookup by keyword (strips OS suffix first)
  while read -r info; do
      kw=$(echo "$info" | awk '{print $1, $2}')
      nvd_cve_lookup_keyword "$kw" 50 | while read -r cve_json; do
          echo "$cve_json"
      done
  done < <(...)

  # CVE lookup by CPE string
  nvd_cpe_lookup "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"

  # Package vulnerability lookup
  osv_lookup "werkzeug" "PyPI"
  osv_lookup "lodash" "npm"

  # ExploitDB PoC search
  exploitdb_search "Apache Tomcat 10.1"

Rate limits (NVD API v2):
  Without NVD_API_KEY : 5 req / 30 s → 7 s sleep between API calls
  With NVD_API_KEY    : 50 req / 30 s → 0.6 s sleep between API calls
  Cache hits          : no sleep — responses cached in working/nvd_cache/
  Cache TTL           : 7 days (NVD_CACHE_TTL_DAYS)

pt-orc.conf variables consumed:
  OLLAMA_HOST           (default: http://127.0.0.1:11434)
  OLLAMA_MODEL          (default: qwen:7b)
  ANTHROPIC_API_KEY     (default: empty — Anthropic fallback disabled)
  AI_CLAUDE_MODEL       (default: claude-haiku-4-5-20251001)
  NVD_API_KEY           (default: empty — 5 req/30s mode)
  NVD_CACHE_DIR         (default: <script_dir>/working/nvd_cache/)
  NVD_CACHE_TTL_DAYS    (default: 7)
  OSV_CALL_DELAY        (default: 0.5 seconds)

Dependencies:
  Required: bash 4+, curl, jq
  Optional: searchsploit (apt install exploitdb)
  Optional: ollama running locally
  Optional: ANTHROPIC_API_KEY for Claude API fallback

EOF
    # Run status check when executed standalone
    ai_status
    echo -e "${CYAN}${line}${NC}" >&2
}

# =============================================================================
# Sourced-vs-executed detection
# =============================================================================
# When sourced: $0 is the calling script, BASH_SOURCE[0] is this file.
# When executed directly: both equal this file → print banner and exit.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    _orc_ai_banner
    exit 0
fi

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
