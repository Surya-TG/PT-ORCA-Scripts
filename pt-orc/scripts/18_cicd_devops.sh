#!/usr/bin/env bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:18_NAV_TOC — Section index | nav,toc,index | L5-26
# - MRK:18_T01 — T01 JENKINS DISCOVERY & UNAUTHENTICATED ACCESS | t01,jenkins,discovery,unauth | L27-27
# - MRK:18_T02 — T02 GITLAB SELF-HOSTED MISCONFIGS | t02,gitlab,selfhosted,misconfig | L28-28
# - MRK:18_T03 — T03 GITHUB ACTIONS / GHE SECRET EXPOSURE | t03,github,actions,ghe,secrets | L29-29
# - MRK:18_T04 — T04 ARGOCD DEFAULT CREDENTIALS & API EXPOSURE | t04,argocd,default,creds,api | L30-30
# - MRK:18_T05 — T05 EXPOSED .GIT DIRECTORIES ON WEB TARGETS | t05,git,exposed,directory,dump | L31-31
# - MRK:18_T06 — T06 CONTAINER REGISTRY API EXPOSURE | t06,container,registry,docker,harbor | L32-32
# - MRK:18_T07 — T07 KUBERNETES API SERVER EXPOSURE | t07,kubernetes,k8s,api,anonymous | L33-33
# NAV-LEN: 7 entries | Integrity-hash: NEEDS-REINDEX | Last-indexed: 2026-06-25

# =============================================================================
# 18_cicd_devops.sh — CI/CD and DevOps Infrastructure Security Testing
# TechGuard Labs | PT-Orc Suite v0.8
# =============================================================================
# NAV: MRK:18_TOC (this block) | MRK:18_ROOT | MRK:18_CONF | MRK:18_LOG
#      MRK:18_ARGS | MRK:18_CONFIRM | MRK:18_TARGETS
#      MRK:18_FIND | MRK:18_UTILS | MRK:18_PROF
#      MRK:18_T01 — T01 JENKINS DISCOVERY & UNAUTHENTICATED ACCESS
#      MRK:18_T02 — T02 GITLAB SELF-HOSTED MISCONFIGS
#      MRK:18_T03 — T03 GITHUB ACTIONS / GHE SECRET EXPOSURE
#      MRK:18_T04 — T04 ARGOCD DEFAULT CREDENTIALS & API EXPOSURE
#      MRK:18_T05 — T05 EXPOSED .GIT DIRECTORIES ON WEB TARGETS
#      MRK:18_T06 — T06 CONTAINER REGISTRY API EXPOSURE
#      MRK:18_T07 — T07 KUBERNETES API SERVER EXPOSURE
#      MRK:18_TRUN | MRK:18_MAIN
# =============================================================================

# - MRK:18_ROOT
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# - MRK:18_CONF
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
CICD_TIMEOUT=15

# CICD service URL overrides (may also be set in pt-orc.conf)
CICD_JENKINS_URL="${CICD_JENKINS_URL:-}"
CICD_GITLAB_URL="${CICD_GITLAB_URL:-}"
CICD_ARGOCD_URL="${CICD_ARGOCD_URL:-}"
CICD_K8S_API_URL="${CICD_K8S_API_URL:-}"
CICD_REGISTRY_URLS="${CICD_REGISTRY_URLS:-}"
CICD_GITHUB_ENTERPRISE_URL="${CICD_GITHUB_ENTERPRISE_URL:-}"

# - MRK:18_LOG
_R='\033[0;31m'; _G='\033[0;32m'; _Y='\033[1;33m'; _B='\033[0;34m'; _C='\033[0;36m'; _W='\033[1;37m'; _N='\033[0m'
SESSION_TS="$(date +%Y%m%d_%H%M%S)"
EV_TS="$(date +'%Y-%m-%d-%H-%M-%S')"
LOG_FILE="${SCRIPT_DIR}/working/${PROJ_SLUG}_18_cicd_${SESSION_TS}.log"
mkdir -p "${SCRIPT_DIR}/working" "${EVIDENCE_BASE}"

_log()    { local ts; ts="$(date +%H:%M:%S)"; printf "[%s] %s\n" "$ts" "$*" | tee -a "$LOG_FILE"; }
log_ok()  { printf "${_G}[+]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_inf() { printf "${_B}[*]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_wrn() { printf "${_Y}[!]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_err() { printf "${_R}[-]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_dry() { printf "${_C}[DRY]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }

# - MRK:18_ARGS
_SKIP_CONFIRM=0
_ONLY_TESTS=()
_SKIP_TESTS=()

_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

CI/CD and DevOps Infrastructure Security Testing (step 18)

Probes Jenkins, GitLab, GitHub Enterprise, ArgoCD, exposed .git directories,
container registries, and Kubernetes API servers for misconfigurations and
unauthenticated access. Service URLs are read from CICD_* vars in pt-orc.conf
or overridden via CLI flags. Auto-discovery scans TARGET_IPS when no URL is set.

Options:
  --jenkins-url <URL>         Jenkins base URL (overrides CICD_JENKINS_URL from conf)
  --gitlab-url <URL>          GitLab base URL (overrides CICD_GITLAB_URL)
  --argocd-url <URL>          ArgoCD base URL (overrides CICD_ARGOCD_URL)
  --k8s-url <URL>             Kubernetes API server URL (overrides CICD_K8S_API_URL)
  -p, --profile <name>        Scan profile: quick|standard|deep  [default: standard]
  --only <T01,T05,...>        Run only specified tests
  --skip <T02,T06,...>        Skip specified tests
  -y, --yes                   Skip confirmation prompt
  --dry-run                   Print actions without executing
  -h, --help                  Show this help

Profiles:
  quick    : T01, T02, T05
  standard : T01, T02, T04, T05, T06
  deep     : all (T01-T07)

CICD conf vars (pt-orc.conf):
  CICD_JENKINS_URL            Jenkins base URL (leave empty for auto-discover)
  CICD_GITLAB_URL             GitLab base URL
  CICD_ARGOCD_URL             ArgoCD base URL
  CICD_K8S_API_URL            Kubernetes API server URL
  CICD_REGISTRY_URLS          Space-separated container registry URLs
  CICD_GITHUB_ENTERPRISE_URL  GitHub Enterprise base URL
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --jenkins-url)   CICD_JENKINS_URL="$2"; shift 2 ;;
        --gitlab-url)    CICD_GITLAB_URL="$2"; shift 2 ;;
        --argocd-url)    CICD_ARGOCD_URL="$2"; shift 2 ;;
        --k8s-url)       CICD_K8S_API_URL="$2"; shift 2 ;;
        -p|--profile)    SCAN_PROFILE="$2"; shift 2 ;;
        --only)          IFS=',' read -ra _ONLY_TESTS <<< "$2"; shift 2 ;;
        --skip)          IFS=',' read -ra _SKIP_TESTS <<< "$2"; shift 2 ;;
        -y|--yes)        _SKIP_CONFIRM=1; shift ;;
        --dry-run)       DRY_RUN=1; shift ;;
        -h|--help)       _usage; exit 0 ;;
        *)               log_err "Unknown option: $1"; _usage; exit 1 ;;
    esac
done

# - MRK:18_CONFIRM
_confirm() {
    [[ "$_SKIP_CONFIRM" -eq 1 ]] && return 0
    printf "\n${_Y}[CONFIRM]${_N} CI/CD & DevOps security testing. Profile: ${_W}%s${_N}\n" "$SCAN_PROFILE"
    printf "  Project       : %s\n" "$PROJECT_NAME"
    printf "  Target IPs    : %s\n" "${TARGET_IPS:-<not set>}"
    printf "  Target Domains: %s\n" "${TARGET_DOMAINS:-<not set>}"
    printf "  Jenkins URL   : %s\n" "${CICD_JENKINS_URL:-<auto-discover>}"
    printf "  GitLab URL    : %s\n" "${CICD_GITLAB_URL:-<auto-discover>}"
    printf "  ArgoCD URL    : %s\n" "${CICD_ARGOCD_URL:-<auto-discover>}"
    printf "  K8s API URL   : %s\n" "${CICD_K8S_API_URL:-<auto-discover>}"
    printf "  Registry URLs : %s\n" "${CICD_REGISTRY_URLS:-<auto-discover>}"
    printf "  GHE URL       : %s\n" "${CICD_GITHUB_ENTERPRISE_URL:-<not set>}"
    printf "\n  ${_R}WARNING:${_N} This script sends active probes to CI/CD infrastructure.\n"
    printf "  Only run within authorised scope and agreed engagement window.\n"
    printf "\n  Continue? [y/N] "
    read -r _ans
    [[ "${_ans,,}" == "y" ]] || { log_err "Aborted by user."; exit 0; }
}

# - MRK:18_TARGETS
_validate_config() {
    local ok=1
    if [[ -z "${TARGET_IPS:-}" && -z "${TARGET_DOMAINS:-}" \
        && -z "$CICD_JENKINS_URL" && -z "$CICD_GITLAB_URL" \
        && -z "$CICD_ARGOCD_URL" && -z "$CICD_K8S_API_URL" \
        && -z "$CICD_REGISTRY_URLS" && -z "$CICD_GITHUB_ENTERPRISE_URL" ]]; then
        log_err "No targets configured. Set TARGET_IPS or any CICD_* URL in pt-orc.conf."
        ok=0
    fi
    [[ "$ok" -eq 1 ]]
}

# Build an array of all IPs to scan (TARGET_IPS + resolved TARGET_DOMAINS)
_build_target_ips() {
    local -a ips=()
    for ip in ${TARGET_IPS:-}; do
        ips+=("$ip")
    done
    for dom in ${TARGET_DOMAINS:-}; do
        local resolved
        resolved=$(getent hosts "$dom" 2>/dev/null | awk '{print $1}' | head -1 || true)
        [[ -n "$resolved" ]] && ips+=("$resolved")
    done
    echo "${ips[@]+"${ips[@]}"}"
}

# Build an array of all hostnames: IPs + domain names
_build_target_hosts() {
    local -a hosts=()
    for ip in ${TARGET_IPS:-}; do
        hosts+=("$ip")
    done
    for dom in ${TARGET_DOMAINS:-}; do
        hosts+=("$dom")
    done
    echo "${hosts[@]+"${hosts[@]}"}"
}

# - MRK:18_FIND
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "18-cicd-findings" "jsonl")"
_FIND_CTR=0
: > "$FINDINGS_FILE"

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="${5:-}"
    (( _FIND_CTR++ )) || true
    local fid
    fid="f-18-cicd-$(printf '%04d' "$_FIND_CTR")"
    local ev_id="${ev_tag:-${fid}-ev}"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"18_cicd_devops","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
        "$fid" \
        "$(echo "$title" | sed 's/"/\\"/g')" \
        "$sev" \
        "$ev_id" \
        "$(echo "$desc" | sed 's/"/\\"/g')" \
        "$(echo "$rec"  | sed 's/"/\\"/g')")
    echo "$payload" >> "$FINDINGS_FILE"
    log_wrn "FINDING [${sev^^}] ${title}"
}

# - MRK:18_UTILS
_check_tool() {
    local tool="$1"
    command -v "$tool" &>/dev/null
}

_ev_file() {
    local tag="$1"
    echo "${EVIDENCE_BASE}/$(ev_fname "cicd-${tag}" "txt")"
}

# Probe a URL and return its HTTP status code
_http_status() {
    local url="$1"
    curl -sk --max-time "$CICD_TIMEOUT" \
        -A "Mozilla/5.0 (compatible; TG-Audit/1.0)" \
        -o /dev/null -w "%{http_code}" \
        "$url" 2>/dev/null || echo "000"
}

# Fetch a URL body (silently)
_http_body() {
    local url="$1"
    curl -sk --max-time "$CICD_TIMEOUT" \
        -A "Mozilla/5.0 (compatible; TG-Audit/1.0)" \
        "$url" 2>/dev/null || true
}

# Fetch a URL body with response headers
_http_headers_and_body() {
    local url="$1"
    curl -sk --max-time "$CICD_TIMEOUT" \
        -A "Mozilla/5.0 (compatible; TG-Audit/1.0)" \
        -D - "$url" 2>/dev/null || true
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

# - MRK:18_PROF
setup_profile() {
    local prof="${1:-standard}"
    for n in T01 T02 T03 T04 T05 T06 T07; do
        _T_ENABLED[$n]=1
    done
    case "$prof" in
        quick)
            # Quick: Jenkins, GitLab, exposed .git only
            for n in T03 T04 T06 T07; do _T_ENABLED[$n]=0; done ;;
        standard)
            # Standard: all except GHE secrets (T03) and K8s (T07)
            for n in T03 T07; do _T_ENABLED[$n]=0; done ;;
        deep)
            # All enabled
            : ;;
        *)
            log_wrn "Unknown profile '${prof}' — defaulting to standard"
            for n in T03 T07; do _T_ENABLED[$n]=0; done ;;
    esac
    _apply_cli_filters
}

# =============================================================================
# TESTS
# =============================================================================

# - MRK:18_T01 — T01 JENKINS DISCOVERY & UNAUTHENTICATED ACCESS
test_T01_jenkins() {
    local ev_f; ev_f="$(_ev_file "t01-jenkins")"

    log_inf "[T01] Jenkins discovery and unauthenticated access check"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "Probe Jenkins at ${CICD_JENKINS_URL:-<auto-discover on TARGET_IPS:8080,8443,80,443>}"; return; }

    {
        echo "=== T01 Jenkins Discovery & Unauthenticated Access ==="
        echo "Date: $(date -u)"
    } > "$ev_f"

    # Build list of candidate Jenkins base URLs
    local -a jenkins_urls=()
    if [[ -n "$CICD_JENKINS_URL" ]]; then
        jenkins_urls+=("${CICD_JENKINS_URL%/}")
        log_inf "  Using configured CICD_JENKINS_URL: ${CICD_JENKINS_URL}"
    else
        log_inf "  No CICD_JENKINS_URL set — auto-discovering via TARGET_IPS..."
        local ips_str; ips_str="$(_build_target_ips)"
        local -a target_ips=()
        [[ -n "$ips_str" ]] && read -ra target_ips <<< "$ips_str"
        if [[ ${#target_ips[@]} -eq 0 ]]; then
            log_wrn "  No target IPs available for auto-discovery — skipping T01"
            return
        fi
        for ip in "${target_ips[@]}"; do
            for port in 8080 8443 80 443; do
                # Quick port check before full HTTP probe
                if timeout 3 bash -c "echo > /dev/tcp/${ip}/${port}" 2>/dev/null; then
                    local scheme="http"
                    [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
                    local candidate="${scheme}://${ip}:${port}"
                    local hdrs
                    hdrs=$(_http_headers_and_body "${candidate}/login")
                    if echo "$hdrs" | grep -qi 'X-Jenkins\|Jenkins-Version\|<title>.*Jenkins'; then
                        log_ok "  Jenkins detected at ${candidate}"
                        jenkins_urls+=("$candidate")
                        echo "[T01] Jenkins detected at ${candidate}" >> "$ev_f"
                    fi
                fi
            done
        done
    fi

    if [[ ${#jenkins_urls[@]} -eq 0 ]]; then
        log_inf "  No Jenkins instances found"
        echo "[T01] No Jenkins instances found" >> "$ev_f"
        return
    fi

    for base_url in "${jenkins_urls[@]}"; do
        log_inf "  Probing Jenkins at ${base_url}..."
        echo "" >> "$ev_f"
        echo "--- Probing: ${base_url} ---" >> "$ev_f"

        # Check X-Jenkins version header
        local login_hdrs
        login_hdrs=$(_http_headers_and_body "${base_url}/login")
        echo "${login_hdrs}" >> "$ev_f"
        local jenkins_version
        jenkins_version=$(echo "$login_hdrs" | grep -i '^X-Jenkins:' | awk '{print $2}' | tr -d '\r' || true)
        if [[ -n "$jenkins_version" ]]; then
            log_wrn "  Jenkins version disclosed: ${jenkins_version}"
            emit_finding "low" \
                "Jenkins Version Disclosure: ${jenkins_version}" \
                "Jenkins at ${base_url} discloses its version (${jenkins_version}) via the X-Jenkins response header. Version disclosure aids targeted exploitation." \
                "Suppress X-Jenkins and X-Hudson response headers via Jenkins security configuration or a reverse-proxy header filter. Keep Jenkins patched to the latest LTS release." \
                "cicd_jenkins_version_${base_url//[^A-Za-z0-9._-]/_}"
        fi

        # GET /api/json — unauthenticated job listing
        local api_status
        api_status=$(_http_status "${base_url}/api/json")
        local api_body
        api_body=$(_http_body "${base_url}/api/json")
        {
            echo "--- /api/json (status: ${api_status}) ---"
            echo "${api_body}" | head -50
        } >> "$ev_f"

        if [[ "$api_status" == "200" ]] && echo "$api_body" | grep -qi '"jobs"\|"_class"'; then
            local job_count
            job_count=$(echo "$api_body" | grep -o '"name"' | wc -l || echo 0)
            emit_finding "high" \
                "Jenkins Unauthenticated API Access (/api/json) — ${job_count} Job(s) Visible" \
                "Jenkins at ${base_url}/api/json returns a job listing without authentication. ${job_count} job(s) are exposed, potentially revealing pipeline names, build history, and artifact URLs." \
                "Enable Jenkins security (Manage Jenkins → Configure Global Security → Enable Security). Set Authorization to 'Logged-in users can do anything' or finer-grained matrix-based security. Restrict /api to authenticated users." \
                "cicd_jenkins_api_unauth_${base_url//[^A-Za-z0-9._-]/_}"
        fi

        # GET /script — Groovy console accessibility
        local script_status
        script_status=$(_http_status "${base_url}/script")
        local script_body
        script_body=$(_http_body "${base_url}/script")
        {
            echo "--- /script (status: ${script_status}) ---"
            echo "${script_body}" | head -20
        } >> "$ev_f"

        if [[ "$script_status" == "200" ]] && echo "$script_body" | grep -qi 'Groovy\|Script Console\|<title>'; then
            emit_finding "critical" \
                "Jenkins Groovy Script Console Accessible Without Authentication" \
                "The Jenkins Groovy Script Console at ${base_url}/script is accessible without authentication. This provides direct OS command execution on the Jenkins server as the Jenkins service account, constituting full system compromise." \
                "Immediately enable Jenkins authentication. Restrict the script console to Jenkins admins only. If public internet-facing, place behind a VPN or network ACL. Review for signs of prior exploitation (unexpected executors, unusual builds)." \
                "cicd_jenkins_script_console_${base_url//[^A-Za-z0-9._-]/_}"
        fi

        # GET /jnlpJars/jenkins-cli.jar — CLI exposure
        local cli_status
        cli_status=$(_http_status "${base_url}/jnlpJars/jenkins-cli.jar")
        echo "--- /jnlpJars/jenkins-cli.jar (status: ${cli_status}) ---" >> "$ev_f"

        if [[ "$cli_status" == "200" ]]; then
            log_wrn "  Jenkins CLI jar downloadable at ${base_url}/jnlpJars/jenkins-cli.jar"
            emit_finding "high" \
                "Jenkins CLI Jar Exposed Without Authentication" \
                "The Jenkins CLI JAR (jenkins-cli.jar) is downloadable from ${base_url}/jnlpJars/jenkins-cli.jar without authentication. The CLI can be used to enumerate and potentially exploit the Jenkins instance if remote CLI is enabled." \
                "Disable the Jenkins CLI if not required (Manage Jenkins → Configure Global Security → uncheck 'Enable CLI over Remoting'). If CLI is needed, restrict access to authenticated users and specific IP ranges." \
                "cicd_jenkins_cli_${base_url//[^A-Za-z0-9._-]/_}"
        fi

        log_ok "  Jenkins probe at ${base_url} complete"
    done
}

# - MRK:18_T02 — T02 GITLAB SELF-HOSTED MISCONFIGS
test_T02_gitlab() {
    local ev_f; ev_f="$(_ev_file "t02-gitlab")"

    log_inf "[T02] GitLab self-hosted misconfiguration check"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "Probe GitLab at ${CICD_GITLAB_URL:-<auto-discover on TARGET_IPS>}"; return; }

    {
        echo "=== T02 GitLab Self-Hosted Misconfigs ==="
        echo "Date: $(date -u)"
    } > "$ev_f"

    # Build list of candidate GitLab base URLs
    local -a gitlab_urls=()
    if [[ -n "$CICD_GITLAB_URL" ]]; then
        gitlab_urls+=("${CICD_GITLAB_URL%/}")
        log_inf "  Using configured CICD_GITLAB_URL: ${CICD_GITLAB_URL}"
    else
        log_inf "  No CICD_GITLAB_URL set — auto-discovering via TARGET_IPS..."
        local ips_str; ips_str="$(_build_target_ips)"
        local -a target_ips=()
        [[ -n "$ips_str" ]] && read -ra target_ips <<< "$ips_str"
        for ip in "${target_ips[@]+"${target_ips[@]}"}"; do
            for port in 80 443 8080 8443; do
                if timeout 3 bash -c "echo > /dev/tcp/${ip}/${port}" 2>/dev/null; then
                    local scheme="http"
                    [[ "$port" == "443" || "$port" == "8443" ]] && scheme="https"
                    local candidate="${scheme}://${ip}:${port}"
                    local hdrs
                    hdrs=$(_http_headers_and_body "${candidate}/users/sign_in")
                    if echo "$hdrs" | grep -qi 'X-Gitlab-\|gitlab-rails\|GitLab.*sign.*in\|<title>.*GitLab'; then
                        log_ok "  GitLab detected at ${candidate}"
                        gitlab_urls+=("$candidate")
                        echo "[T02] GitLab detected at ${candidate}" >> "$ev_f"
                    fi
                fi
            done
        done
    fi

    if [[ ${#gitlab_urls[@]} -eq 0 ]]; then
        log_inf "  No GitLab instances found"
        echo "[T02] No GitLab instances found" >> "$ev_f"
        return
    fi

    for base_url in "${gitlab_urls[@]}"; do
        log_inf "  Probing GitLab at ${base_url}..."
        echo "" >> "$ev_f"
        echo "--- Probing: ${base_url} ---" >> "$ev_f"

        # Check version from /help
        local help_body
        help_body=$(_http_body "${base_url}/help")
        local gl_version
        gl_version=$(echo "$help_body" | grep -oiE 'GitLab [0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
        {
            echo "--- /help version check ---"
            echo "${gl_version:-not disclosed}"
        } >> "$ev_f"

        # GET /api/v4/projects?visibility=public — count of public repos
        local api_status
        api_status=$(_http_status "${base_url}/api/v4/projects?visibility=public&per_page=100")
        local api_body
        api_body=$(_http_body "${base_url}/api/v4/projects?visibility=public&per_page=100")
        {
            echo "--- /api/v4/projects?visibility=public (status: ${api_status}) ---"
            echo "${api_body}" | head -80
        } >> "$ev_f"

        if [[ "$api_status" == "200" ]]; then
            local pub_count
            pub_count=$(echo "$api_body" | grep -o '"id"' | wc -l || echo 0)
            if [[ "$pub_count" -gt 0 ]]; then
                log_wrn "  GitLab public projects count: ${pub_count}"
                emit_finding "low" \
                    "GitLab Public Projects Accessible: ${pub_count} Repository/Repositories" \
                    "GitLab at ${base_url} exposes ${pub_count} public project(s) via the unauthenticated API. Public repositories may contain sensitive configuration, source code, credentials, or CI/CD pipeline definitions." \
                    "Review all public projects for sensitive data. Set project visibility to 'Internal' or 'Private' where external access is not required. Ensure CI/CD variable secrets are masked and protected." \
                    "cicd_gitlab_public_repos_${base_url//[^A-Za-z0-9._-]/_}"
            fi
        fi

        # GET /users/sign_up — check if open registration is enabled
        local signup_status
        signup_status=$(_http_status "${base_url}/users/sign_up")
        local signup_body
        signup_body=$(_http_body "${base_url}/users/sign_up")
        {
            echo "--- /users/sign_up (status: ${signup_status}) ---"
            echo "${signup_body}" | head -30
        } >> "$ev_f"

        if [[ "$signup_status" == "200" ]] && echo "$signup_body" | grep -qi 'Register\|sign.up\|Create.*account\|New user'; then
            emit_finding "medium" \
                "GitLab Open User Registration Enabled" \
                "GitLab at ${base_url} permits open user registration (/users/sign_up returns 200 with registration form). Any internet user can create an account, potentially accessing internal or private projects via misconfigured permissions." \
                "Disable open registration if this is an internal GitLab instance (Admin Area → Settings → General → Sign-up restrictions → uncheck 'Sign-up enabled'). Enable admin approval for new signups, or restrict registration to specific email domains." \
                "cicd_gitlab_open_reg_${base_url//[^A-Za-z0-9._-]/_}"
        fi

        # GET /admin — unauthenticated admin panel access
        local admin_status
        admin_status=$(_http_status "${base_url}/admin")
        local admin_body
        admin_body=$(_http_body "${base_url}/admin")
        {
            echo "--- /admin (status: ${admin_status}) ---"
            echo "${admin_body}" | head -20
        } >> "$ev_f"

        if [[ "$admin_status" == "200" ]] && echo "$admin_body" | grep -qi 'Admin Area\|administration\|<title>.*Admin'; then
            emit_finding "critical" \
                "GitLab Admin Panel Accessible Without Authentication" \
                "The GitLab admin panel at ${base_url}/admin is accessible without authentication (HTTP 200). This grants full administrative control over the GitLab instance, repositories, users, and CI/CD pipelines." \
                "Immediately enable GitLab authentication. Ensure admin routes are protected. Review access logs for any unauthorized admin actions. Update GitLab to the latest stable release and check for related CVEs." \
                "cicd_gitlab_admin_unauth_${base_url//[^A-Za-z0-9._-]/_}"
        fi

        log_ok "  GitLab probe at ${base_url} complete"
    done
}

# - MRK:18_T03 — T03 GITHUB ACTIONS / GHE SECRET EXPOSURE
test_T03_github_enterprise() {
    local ev_f; ev_f="$(_ev_file "t03-ghe")"

    log_inf "[T03] GitHub Enterprise / GitHub Actions secret exposure check"

    if [[ -z "$CICD_GITHUB_ENTERPRISE_URL" ]]; then
        log_inf "  CICD_GITHUB_ENTERPRISE_URL not set — skipping GHE probe"
        echo "[T03] CICD_GITHUB_ENTERPRISE_URL not configured — no GHE target to probe" > "$ev_f"
        return
    fi

    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "Probe GHE API at ${CICD_GITHUB_ENTERPRISE_URL}/api/v3/repos"; return; }

    local base_url="${CICD_GITHUB_ENTERPRISE_URL%/}"

    {
        echo "=== T03 GitHub Enterprise Secret Exposure ==="
        echo "GHE URL: ${base_url}"
        echo "Date: $(date -u)"
    } > "$ev_f"

    # Probe /api/v3/repos for anonymous access
    local api_status
    api_status=$(_http_status "${base_url}/api/v3/repos")
    local api_body
    api_body=$(_http_body "${base_url}/api/v3/repos")
    {
        echo "--- /api/v3/repos (status: ${api_status}) ---"
        echo "${api_body}" | head -100
    } >> "$ev_f"

    if [[ "$api_status" == "200" ]] && echo "$api_body" | grep -qi '"full_name"\|"id"\|"html_url"'; then
        local repo_count
        repo_count=$(echo "$api_body" | grep -o '"id"' | wc -l || echo 0)
        emit_finding "high" \
            "GitHub Enterprise Anonymous API Access: ${repo_count} Repository/Repositories Exposed" \
            "GitHub Enterprise at ${base_url}/api/v3/repos returns repository data without authentication. ${repo_count} repositories are enumerable. This may expose source code, CI/CD pipelines, and sensitive workflow definitions." \
            "Require authentication for all API endpoints. Set GITHUB_ENTERPRISE_URL visibility to private. Review site admin settings: Site admin → Management Console → Authentication → require authentication. Audit anonymous access policies." \
            "cicd_ghe_anon_api"
    elif [[ "$api_status" == "401" || "$api_status" == "403" ]]; then
        log_ok "  GHE /api/v3/repos requires authentication (${api_status}) — expected"
        echo "[T03] GHE API requires authentication — status ${api_status}" >> "$ev_f"
    else
        log_inf "  GHE /api/v3/repos returned ${api_status} — review manually"
        echo "[T03] GHE API status ${api_status} — manual review recommended" >> "$ev_f"
    fi

    # Check /api/v3/orgs for anonymous organization listing
    local orgs_status
    orgs_status=$(_http_status "${base_url}/api/v3/organizations")
    local orgs_body
    orgs_body=$(_http_body "${base_url}/api/v3/organizations")
    {
        echo "--- /api/v3/organizations (status: ${orgs_status}) ---"
        echo "${orgs_body}" | head -40
    } >> "$ev_f"

    if [[ "$orgs_status" == "200" ]] && echo "$orgs_body" | grep -qi '"login"\|"id"'; then
        local org_count
        org_count=$(echo "$orgs_body" | grep -o '"login"' | wc -l || echo 0)
        log_wrn "  GHE organizations enumerable without auth: ${org_count} org(s)"
        emit_finding "high" \
            "GitHub Enterprise Anonymous Organization Enumeration: ${org_count} Organization(s)" \
            "GitHub Enterprise at ${base_url}/api/v3/organizations returns ${org_count} organizations without authentication. Org enumeration reveals team structure, project names, and repository namespaces useful for targeted attacks." \
            "Disable anonymous API access. Set GHE authentication policy to require login for all operations. Review organization visibility settings." \
            "cicd_ghe_anon_orgs"
    fi

    # Probe for workflow files with secrets. references if any repos are accessible
    if [[ "$api_status" == "200" ]]; then
        log_inf "  Checking accessible repos for workflow secret references..."
        # Extract up to 3 full_name values from the API response
        local -a repo_names=()
        while IFS= read -r rname; do
            [[ -n "$rname" ]] && repo_names+=("$rname")
        done < <(echo "$api_body" | grep -o '"full_name":"[^"]*"' | cut -d'"' -f4 | head -3)

        for rname in "${repo_names[@]+"${repo_names[@]}"}"; do
            local wf_url="${base_url}/api/v3/repos/${rname}/contents/.github/workflows"
            local wf_status; wf_status=$(_http_status "$wf_url")
            local wf_body;   wf_body=$(_http_body "$wf_url")
            echo "--- Workflows for ${rname} (status: ${wf_status}) ---" >> "$ev_f"
            echo "${wf_body}" | head -40 >> "$ev_f"

            if [[ "$wf_status" == "200" ]] && echo "$wf_body" | grep -qi '"name"'; then
                # Download first workflow file and check for secrets. references
                local first_wf_path
                first_wf_path=$(echo "$wf_body" | grep -o '"path":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
                if [[ -n "$first_wf_path" ]]; then
                    local wf_file_body
                    wf_file_body=$(_http_body "${base_url}/api/v3/repos/${rname}/contents/${first_wf_path}")
                    local wf_content
                    wf_content=$(echo "$wf_file_body" | grep -o '"content":"[^"]*"' | cut -d'"' -f4 | \
                        tr -d '\n' | base64 -d 2>/dev/null || true)
                    echo "--- Workflow content (${first_wf_path}) ---" >> "$ev_f"
                    echo "${wf_content}" | head -60 >> "$ev_f"
                    if echo "$wf_content" | grep -qi 'secrets\.'; then
                        log_wrn "  Workflow ${first_wf_path} in ${rname} references secrets — review for exposure"
                        emit_finding "high" \
                            "GitHub Actions Workflow Secrets Referenced in Publicly Accessible Repo: ${rname}" \
                            "Workflow file ${first_wf_path} in ${rname} references GitHub Actions secrets (secrets.*). The repository is accessible without authentication. Workflow definitions reveal which secrets are consumed, aiding targeted credential theft or pipeline injection attacks." \
                            "Make the repository private or internal. Review workflow secret usage — use environment secrets with required reviewers for sensitive deployments. Rotate any secrets that may have been exposed." \
                            "cicd_ghe_workflow_secrets_${rname//[^A-Za-z0-9._-]/_}"
                    fi
                fi
            fi
        done
    fi

    log_ok "  GitHub Enterprise probe complete"
}

# - MRK:18_T04 — T04 ARGOCD DEFAULT CREDENTIALS & API EXPOSURE
test_T04_argocd() {
    local ev_f; ev_f="$(_ev_file "t04-argocd")"

    log_inf "[T04] ArgoCD default credentials and API exposure check"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "Probe ArgoCD at ${CICD_ARGOCD_URL:-<auto-discover ports 443,8080>}"; return; }

    {
        echo "=== T04 ArgoCD Default Credentials & API Exposure ==="
        echo "Date: $(date -u)"
    } > "$ev_f"

    # Build list of candidate ArgoCD base URLs
    local -a argocd_urls=()
    if [[ -n "$CICD_ARGOCD_URL" ]]; then
        argocd_urls+=("${CICD_ARGOCD_URL%/}")
        log_inf "  Using configured CICD_ARGOCD_URL: ${CICD_ARGOCD_URL}"
    else
        log_inf "  No CICD_ARGOCD_URL set — auto-discovering via TARGET_IPS..."
        local ips_str; ips_str="$(_build_target_ips)"
        local -a target_ips=()
        [[ -n "$ips_str" ]] && read -ra target_ips <<< "$ips_str"
        for ip in "${target_ips[@]+"${target_ips[@]}"}"; do
            for port in 443 8080; do
                if timeout 3 bash -c "echo > /dev/tcp/${ip}/${port}" 2>/dev/null; then
                    local scheme="https"
                    [[ "$port" == "8080" ]] && scheme="http"
                    local candidate="${scheme}://${ip}:${port}"
                    local ver_status
                    ver_status=$(_http_status "${candidate}/api/version")
                    if [[ "$ver_status" == "200" ]]; then
                        local ver_body
                        ver_body=$(_http_body "${candidate}/api/version")
                        if echo "$ver_body" | grep -qi '"Version"\|"BuildDate"\|argocd'; then
                            log_ok "  ArgoCD detected at ${candidate}"
                            argocd_urls+=("$candidate")
                            echo "[T04] ArgoCD detected at ${candidate}" >> "$ev_f"
                        fi
                    fi
                fi
            done
        done
    fi

    if [[ ${#argocd_urls[@]} -eq 0 ]]; then
        log_inf "  No ArgoCD instances found"
        echo "[T04] No ArgoCD instances found" >> "$ev_f"
        return
    fi

    for base_url in "${argocd_urls[@]}"; do
        log_inf "  Probing ArgoCD at ${base_url}..."
        echo "" >> "$ev_f"
        echo "--- Probing: ${base_url} ---" >> "$ev_f"

        # GET /api/version — version disclosure
        local ver_body
        ver_body=$(_http_body "${base_url}/api/version")
        {
            echo "--- /api/version ---"
            echo "${ver_body}" | head -10
        } >> "$ev_f"

        local argocd_version
        argocd_version=$(echo "$ver_body" | grep -o '"Version":"[^"]*"' | cut -d'"' -f4 || true)
        if [[ -n "$argocd_version" ]]; then
            log_wrn "  ArgoCD version: ${argocd_version}"
            emit_finding "low" \
                "ArgoCD Version Disclosure: ${argocd_version}" \
                "ArgoCD at ${base_url}/api/version discloses its version (${argocd_version}) without authentication. Version disclosure aids targeted vulnerability exploitation." \
                "Restrict /api/version to authenticated users via RBAC policy. Keep ArgoCD updated to the latest stable release. Review RBAC settings in argocd-rbac-cm ConfigMap." \
                "cicd_argocd_version_${base_url//[^A-Za-z0-9._-]/_}"
        fi

        # Try default credentials: admin/admin via POST /api/v1/session
        local session_body
        session_body=$(curl -sk --max-time "$CICD_TIMEOUT" \
            -A "Mozilla/5.0 (compatible; TG-Audit/1.0)" \
            -X POST "${base_url}/api/v1/session" \
            -H "Content-Type: application/json" \
            -d '{"username":"admin","password":"admin"}' 2>/dev/null || true)
        {
            echo "--- POST /api/v1/session (admin:admin) ---"
            echo "${session_body}" | head -10
        } >> "$ev_f"

        if echo "$session_body" | grep -qi '"token"\|"jwtToken"'; then
            emit_finding "critical" \
                "ArgoCD Default Credentials Valid: admin/admin" \
                "ArgoCD at ${base_url} accepts the default credentials admin/admin. Full administrative access to all ArgoCD applications, secrets, and Kubernetes clusters is possible without further exploitation." \
                "Immediately change the admin password (argocd account update-password). Disable the 'admin' account if SSO is configured (set accounts.admin.enabled: 'false' in argocd-cm). Enable MFA via SSO integration." \
                "cicd_argocd_default_creds_${base_url//[^A-Za-z0-9._-]/_}"
        else
            log_ok "  ArgoCD default creds admin/admin rejected"
        fi

        # GET /api/v1/applications — anonymous app listing
        local apps_status
        apps_status=$(_http_status "${base_url}/api/v1/applications")
        local apps_body
        apps_body=$(_http_body "${base_url}/api/v1/applications")
        {
            echo "--- /api/v1/applications (status: ${apps_status}) ---"
            echo "${apps_body}" | head -40
        } >> "$ev_f"

        if [[ "$apps_status" == "200" ]] && echo "$apps_body" | grep -qi '"items"\|"metadata"'; then
            local app_count
            app_count=$(echo "$apps_body" | grep -o '"name"' | wc -l || echo 0)
            emit_finding "high" \
                "ArgoCD Anonymous Application Listing: ${app_count} Application(s) Exposed" \
                "ArgoCD at ${base_url}/api/v1/applications returns ${app_count} application(s) without authentication. Application definitions expose Kubernetes cluster names, namespaces, Git repository URLs, and deployment configurations." \
                "Enable ArgoCD authentication (disable anonymous access in argocd-cm: server.anonymousUserEnabled: 'false'). Apply RBAC policies restricting API access to authenticated users. Use SSO (Dex/OIDC) for strong authentication." \
                "cicd_argocd_anon_apps_${base_url//[^A-Za-z0-9._-]/_}"
        fi

        log_ok "  ArgoCD probe at ${base_url} complete"
    done
}

# - MRK:18_T05 — T05 EXPOSED .GIT DIRECTORIES ON WEB TARGETS
test_T05_git_exposure() {
    local ev_f; ev_f="$(_ev_file "t05-git-exposure")"

    log_inf "[T05] Exposed .git directory check on web targets"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "Probe /.git/HEAD and /.git/config on all TARGET_IPS + TARGET_DOMAINS"; return; }

    {
        echo "=== T05 Exposed .git Directories ==="
        echo "Date: $(date -u)"
    } > "$ev_f"

    # Build host list
    local -a all_hosts=()
    read -ra all_hosts <<< "$(_build_target_hosts)"

    if [[ ${#all_hosts[@]} -eq 0 ]]; then
        log_inf "  No hosts available for .git probe"
        echo "[T05] No hosts configured" >> "$ev_f"
        return
    fi

    for host in "${all_hosts[@]}"; do
        for scheme in https http; do
            local base_url="${scheme}://${host}"
            log_inf "  Checking ${base_url}/.git/HEAD..."

            # Probe /.git/HEAD
            local head_status
            head_status=$(_http_status "${base_url}/.git/HEAD")
            local head_body
            head_body=$(_http_body "${base_url}/.git/HEAD")
            {
                echo "--- ${base_url}/.git/HEAD (status: ${head_status}) ---"
                echo "${head_body}" | head -5
            } >> "$ev_f"

            if [[ "$head_status" == "200" ]] && echo "$head_body" | grep -qi '^ref:\|^[0-9a-f]\{40\}'; then
                log_wrn "  .git/HEAD exposed at ${base_url}/.git/HEAD"

                # Probe /.git/config
                local config_status
                config_status=$(_http_status "${base_url}/.git/config")
                local config_body
                config_body=$(_http_body "${base_url}/.git/config")
                {
                    echo "--- ${base_url}/.git/config (status: ${config_status}) ---"
                    echo "${config_body}" | head -30
                } >> "$ev_f"

                # Probe /.git/COMMIT_EDITMSG
                local commit_status
                commit_status=$(_http_status "${base_url}/.git/COMMIT_EDITMSG")
                local commit_body
                commit_body=$(_http_body "${base_url}/.git/COMMIT_EDITMSG")
                {
                    echo "--- ${base_url}/.git/COMMIT_EDITMSG (status: ${commit_status}) ---"
                    echo "${commit_body}" | head -5
                } >> "$ev_f"

                # Probe /.git/info/refs
                local refs_status
                refs_status=$(_http_status "${base_url}/.git/info/refs")
                local refs_body
                refs_body=$(_http_body "${base_url}/.git/info/refs")
                {
                    echo "--- ${base_url}/.git/info/refs (status: ${refs_status}) ---"
                    echo "${refs_body}" | head -10
                } >> "$ev_f"

                if [[ "$config_status" == "200" ]] && echo "$config_body" | grep -qi '\[core\]\|\[remote\]'; then
                    # Remote URL may contain credentials or disclose internal infra
                    local remote_url
                    remote_url=$(echo "$config_body" | grep -i 'url\s*=' | head -1 | awk -F= '{print $2}' | tr -d ' \r' || true)
                    emit_finding "high" \
                        "Exposed .git Directory with Config Dump at ${base_url}" \
                        "The .git directory at ${base_url} is publicly accessible. The git config file is readable${remote_url:+ — remote URL: ${remote_url}}. An attacker can use git-dumper or gitdumper.sh to reconstruct the full source repository, recovering source code, credentials embedded in code, and application secrets." \
                        "Configure the web server to deny access to .git directories (e.g., nginx: location ~ /\\.git { deny all; }). Remove .git directories from web roots in production deployments. Scan the repository for embedded secrets and rotate any found." \
                        "cicd_git_exposed_config_${host//[^A-Za-z0-9._-]/_}_${scheme}"
                else
                    emit_finding "medium" \
                        "Exposed .git/HEAD at ${base_url} (Config Not Confirmed)" \
                        "The .git/HEAD file at ${base_url}/.git/HEAD is publicly accessible (HTTP ${head_status}). Full repository contents may be recoverable depending on directory listing and file exposure configuration." \
                        "Configure the web server to deny access to .git directories. Verify no further .git files are accessible. Remove .git from all web-reachable directories." \
                        "cicd_git_exposed_head_${host//[^A-Za-z0-9._-]/_}_${scheme}"
                fi

                # Attempt git-dumper if available
                if _check_tool git-dumper; then
                    log_inf "  git-dumper available — attempting repository dump from ${base_url}/.git"
                    local dump_dir="${EVIDENCE_BASE}/$(ev_fname "cicd-git-dump" "dir" "${host//[^A-Za-z0-9._-]/_}")"
                    mkdir -p "$dump_dir"
                    # git-dumper may install as git_dumper or git-dumper
                    local dumper_bin="git-dumper"
                    _check_tool git_dumper && dumper_bin="git_dumper"
                    local dump_out
                    dump_out=$(timeout 120 "$dumper_bin" "${base_url}/.git" "$dump_dir" 2>&1 | tail -20 || true)
                    {
                        echo "--- git-dumper output ---"
                        echo "${dump_out}"
                    } >> "$ev_f"
                    if find "$dump_dir" -name "*.py" -o -name "*.js" -o -name "*.conf" -o -name "*.env" 2>/dev/null | grep -q .; then
                        log_wrn "  git-dumper: source files recovered in ${dump_dir}"
                        emit_finding "critical" \
                            "Source Repository Dumped from Exposed .git at ${base_url}" \
                            "git-dumper successfully reconstructed the Git repository from ${base_url}/.git. Full source code is now available locally at ${dump_dir}. Review for embedded credentials, API keys, database connection strings, and other secrets." \
                            "Immediately remove .git from the web root. Rotate all secrets potentially exposed. Review the git log for sensitive data committed historically. Use git-secrets or truffleHog to scan history." \
                            "cicd_git_dumped_${host//[^A-Za-z0-9._-]/_}_${scheme}"
                    else
                        log_inf "  git-dumper ran but recovered limited files — see ${dump_dir}"
                    fi
                else
                    log_inf "  git-dumper not found — manual dump recommended (pip install git-dumper)"
                fi

                # Only probe one scheme if already found exposed
                break
            else
                log_ok "  ${base_url}/.git/HEAD: not exposed (${head_status})"
            fi
        done
    done
    log_ok "  .git exposure check complete"
}

# - MRK:18_T06 — T06 CONTAINER REGISTRY API EXPOSURE
test_T06_registry() {
    local ev_f; ev_f="$(_ev_file "t06-registry")"

    log_inf "[T06] Container registry API exposure check"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "Probe Docker Registry, Nexus, Artifactory, Harbor on TARGET_IPS and CICD_REGISTRY_URLS"; return; }

    {
        echo "=== T06 Container Registry API Exposure ==="
        echo "Date: $(date -u)"
    } > "$ev_f"

    # Build list of registry candidates
    local -a registry_urls=()
    if [[ -n "$CICD_REGISTRY_URLS" ]]; then
        read -ra registry_urls <<< "$CICD_REGISTRY_URLS"
        log_inf "  Using configured CICD_REGISTRY_URLS: ${CICD_REGISTRY_URLS}"
    fi

    # Auto-discover on TARGET_IPS for common registry ports
    local ips_str; ips_str="$(_build_target_ips)"
    local -a target_ips=()
    [[ -n "$ips_str" ]] && read -ra target_ips <<< "$ips_str"
    for ip in "${target_ips[@]+"${target_ips[@]}"}"; do
        # Docker Registry: 5000
        if timeout 3 bash -c "echo > /dev/tcp/${ip}/5000" 2>/dev/null; then
            registry_urls+=("http://${ip}:5000")
            echo "[T06] Port 5000 open on ${ip} — adding as Docker registry candidate" >> "$ev_f"
        fi
        # Nexus: 8081
        if timeout 3 bash -c "echo > /dev/tcp/${ip}/8081" 2>/dev/null; then
            registry_urls+=("http://${ip}:8081")
            echo "[T06] Port 8081 open on ${ip} — adding as Nexus candidate" >> "$ev_f"
        fi
        # Artifactory: 8082
        if timeout 3 bash -c "echo > /dev/tcp/${ip}/8082" 2>/dev/null; then
            registry_urls+=("http://${ip}:8082")
            echo "[T06] Port 8082 open on ${ip} — adding as Artifactory candidate" >> "$ev_f"
        fi
        # Harbor on HTTPS/HTTP
        for port in 443 80; do
            if timeout 3 bash -c "echo > /dev/tcp/${ip}/${port}" 2>/dev/null; then
                local scheme="http"; [[ "$port" == "443" ]] && scheme="https"
                local harbor_candidate="${scheme}://${ip}:${port}"
                local harbor_body
                harbor_body=$(_http_body "${harbor_candidate}/api/v2.0/ping")
                if echo "$harbor_body" | grep -qi '"pong"\|harbor'; then
                    registry_urls+=("$harbor_candidate")
                    echo "[T06] Harbor detected at ${harbor_candidate}" >> "$ev_f"
                fi
            fi
        done
    done

    # Deduplicate
    local -a uniq_registries=()
    local seen_urls=""
    for u in "${registry_urls[@]+"${registry_urls[@]}"}"; do
        if ! echo "$seen_urls" | grep -qF "$u"; then
            uniq_registries+=("$u")
            seen_urls+="$u "
        fi
    done

    if [[ ${#uniq_registries[@]} -eq 0 ]]; then
        log_inf "  No container registry candidates found"
        echo "[T06] No registries found" >> "$ev_f"
        return
    fi

    for reg_url in "${uniq_registries[@]}"; do
        log_inf "  Probing registry at ${reg_url}..."
        echo "" >> "$ev_f"
        echo "--- Probing: ${reg_url} ---" >> "$ev_f"

        # Docker Registry API v2: GET /v2/
        local v2_status
        v2_status=$(_http_status "${reg_url}/v2/")
        local v2_body
        v2_body=$(_http_body "${reg_url}/v2/")
        {
            echo "--- /v2/ (status: ${v2_status}) ---"
            echo "${v2_body}" | head -10
        } >> "$ev_f"

        if [[ "$v2_status" == "200" ]]; then
            log_wrn "  Docker Registry /v2/ returns 200 (unauthenticated access)"

            # GET /v2/_catalog — image listing
            local catalog_status
            catalog_status=$(_http_status "${reg_url}/v2/_catalog")
            local catalog_body
            catalog_body=$(_http_body "${reg_url}/v2/_catalog")
            {
                echo "--- /v2/_catalog (status: ${catalog_status}) ---"
                echo "${catalog_body}" | head -40
            } >> "$ev_f"

            if [[ "$catalog_status" == "200" ]] && echo "$catalog_body" | grep -qi '"repositories"'; then
                local image_count
                image_count=$(echo "$catalog_body" | grep -o '"[^"]*"' | grep -v '"repositories"' | wc -l || echo 0)
                emit_finding "critical" \
                    "Container Registry Catalog Unauthenticated: ${image_count} Image(s) Exposed at ${reg_url}" \
                    "The Docker Registry at ${reg_url}/v2/_catalog is accessible without authentication, exposing ${image_count} image name(s). Images may contain proprietary application code, embedded secrets (API keys, passwords, certificates), and sensitive configuration." \
                    "Enable registry authentication (REGISTRY_AUTH with htpasswd or token-based auth). Place the registry behind a VPN or network ACL. Rotate any secrets present in exposed images. Implement image signing and scanning." \
                    "cicd_registry_catalog_${reg_url//[^A-Za-z0-9._-]/_}"

                # Enumerate first repo's tags
                local first_repo
                first_repo=$(echo "$catalog_body" | grep -o '"[^"]*"' | grep -v '"repositories"' | head -1 | tr -d '"' || true)
                if [[ -n "$first_repo" ]]; then
                    local tags_body
                    tags_body=$(_http_body "${reg_url}/v2/${first_repo}/tags/list")
                    {
                        echo "--- /v2/${first_repo}/tags/list ---"
                        echo "${tags_body}" | head -20
                    } >> "$ev_f"
                    log_inf "  Sample image tags for '${first_repo}': $(echo "${tags_body}" | head -2)"
                fi
            else
                emit_finding "high" \
                    "Container Registry API Accessible Without Authentication at ${reg_url}" \
                    "The Docker Registry v2 API at ${reg_url}/v2/ returns HTTP 200 without authentication. Even if catalog listing is restricted, push/pull operations or other API calls may be exploitable." \
                    "Enable registry authentication. Restrict API access to authorised clients. Audit all recently pushed or pulled images for anomalies." \
                    "cicd_registry_v2_unauth_${reg_url//[^A-Za-z0-9._-]/_}"
            fi
        elif [[ "$v2_status" == "401" ]]; then
            log_ok "  Docker Registry at ${reg_url}/v2/ requires authentication (401) — expected"
        fi

        # Check for Nexus Repository Manager
        local nexus_body
        nexus_body=$(_http_body "${reg_url}/service/rest/v1/repositories")
        if echo "$nexus_body" | grep -qi '"name"\|"format"\|"type"'; then
            local nexus_status
            nexus_status=$(_http_status "${reg_url}/service/rest/v1/repositories")
            {
                echo "--- Nexus /service/rest/v1/repositories (status: ${nexus_status}) ---"
                echo "${nexus_body}" | head -30
            } >> "$ev_f"
            if [[ "$nexus_status" == "200" ]]; then
                local repo_count
                repo_count=$(echo "$nexus_body" | grep -o '"name"' | wc -l || echo 0)
                emit_finding "high" \
                    "Nexus Repository Manager API Unauthenticated Access: ${repo_count} Repository/Repositories at ${reg_url}" \
                    "Nexus Repository Manager at ${reg_url}/service/rest/v1/repositories is accessible without authentication, exposing ${repo_count} repository definition(s). An attacker can enumerate all hosted artifacts, download packages, and potentially upload malicious artifacts if write access is also unauthenticated." \
                    "Enable Nexus authentication (Security → Anonymous Access → uncheck 'Allow anonymous users to access the server'). Apply strict repository-level privileges. Audit anonymous access permissions." \
                    "cicd_nexus_unauth_${reg_url//[^A-Za-z0-9._-]/_}"
            fi
        fi

        # Check for Artifactory
        local art_body
        art_body=$(_http_body "${reg_url}/artifactory/api/repositories")
        if echo "$art_body" | grep -qi '"key"\|"type"\|"url"'; then
            local art_status
            art_status=$(_http_status "${reg_url}/artifactory/api/repositories")
            {
                echo "--- Artifactory /artifactory/api/repositories (status: ${art_status}) ---"
                echo "${art_body}" | head -30
            } >> "$ev_f"
            if [[ "$art_status" == "200" ]]; then
                local art_count
                art_count=$(echo "$art_body" | grep -o '"key"' | wc -l || echo 0)
                emit_finding "high" \
                    "JFrog Artifactory API Unauthenticated Access: ${art_count} Repository/Repositories at ${reg_url}" \
                    "JFrog Artifactory at ${reg_url}/artifactory/api/repositories is accessible without authentication, exposing ${art_count} repository key(s). Artifact enumeration, download, and potentially malicious artifact upload may be possible." \
                    "Disable Artifactory anonymous access (Admin → Security → General → uncheck 'Allow Anonymous Access'). Apply repository-level read/write controls. Audit recently published artifacts for tampering." \
                    "cicd_artifactory_unauth_${reg_url//[^A-Za-z0-9._-]/_}"
            fi
        fi

        log_ok "  Registry probe at ${reg_url} complete"
    done
}

# - MRK:18_T07 — T07 KUBERNETES API SERVER EXPOSURE
test_T07_kubernetes() {
    local ev_f; ev_f="$(_ev_file "t07-kubernetes")"

    log_inf "[T07] Kubernetes API server exposure check"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "Probe K8s API at ${CICD_K8S_API_URL:-<auto-discover ports 6443,8443,8080 on TARGET_IPS+TARGET_SUBNETS>}"; return; }

    {
        echo "=== T07 Kubernetes API Server Exposure ==="
        echo "Date: $(date -u)"
    } > "$ev_f"

    # Build list of candidate K8s API URLs
    local -a k8s_urls=()
    if [[ -n "$CICD_K8S_API_URL" ]]; then
        k8s_urls+=("${CICD_K8S_API_URL%/}")
        log_inf "  Using configured CICD_K8S_API_URL: ${CICD_K8S_API_URL}"
    else
        log_inf "  No CICD_K8S_API_URL set — auto-discovering on TARGET_IPS + TARGET_SUBNETS..."

        # Scan TARGET_IPS directly
        local ips_str; ips_str="$(_build_target_ips)"
        local -a target_ips=()
        [[ -n "$ips_str" ]] && read -ra target_ips <<< "$ips_str"
        for ip in "${target_ips[@]+"${target_ips[@]}"}"; do
            for port in 6443 8443 8080; do
                if timeout 3 bash -c "echo > /dev/tcp/${ip}/${port}" 2>/dev/null; then
                    local scheme="https"; [[ "$port" == "8080" ]] && scheme="http"
                    local candidate="${scheme}://${ip}:${port}"
                    local api_body
                    api_body=$(_http_body "${candidate}/api")
                    if echo "$api_body" | grep -qi '"versions"\|"kind".*"APIVersions"'; then
                        log_ok "  Kubernetes API detected at ${candidate}"
                        k8s_urls+=("$candidate")
                        echo "[T07] K8s API detected at ${candidate}" >> "$ev_f"
                    fi
                fi
            done
        done

        # Also scan TARGET_SUBNETS with nmap if configured
        if [[ -n "${TARGET_SUBNETS:-}" ]]; then
            if _check_tool nmap; then
                log_inf "  Scanning TARGET_SUBNETS for K8s API ports: ${TARGET_SUBNETS}"
                local nmap_out
                nmap_out=$(timeout 120 nmap -sV --open -p 6443,8443,8080 \
                    --script-args 'max-hostgroup=16' \
                    -oN - ${TARGET_SUBNETS} 2>/dev/null | grep -E 'open|Nmap scan report' | head -60 || true)
                echo "--- nmap TARGET_SUBNETS K8s port scan ---" >> "$ev_f"
                echo "${nmap_out}" >> "$ev_f"
                # Extract discovered IPs with open K8s ports
                while IFS= read -r nmap_line; do
                    local disc_ip; disc_ip=$(echo "$nmap_line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
                    [[ -z "$disc_ip" ]] && continue
                    local disc_port; disc_port=$(echo "$nmap_line" | grep -oE '^[0-9]+' | head -1 || true)
                    [[ -z "$disc_port" ]] && continue
                    local scheme="https"; [[ "$disc_port" == "8080" ]] && scheme="http"
                    local candidate="${scheme}://${disc_ip}:${disc_port}"
                    local api_body
                    api_body=$(_http_body "${candidate}/api")
                    if echo "$api_body" | grep -qi '"versions"\|"kind".*"APIVersions"'; then
                        k8s_urls+=("$candidate")
                        echo "[T07] K8s API detected at ${candidate} (subnet scan)" >> "$ev_f"
                    fi
                done < <(echo "$nmap_out" | grep '/tcp.*open')
            else
                log_wrn "  nmap not available — TARGET_SUBNETS scan skipped for K8s discovery"
            fi
        fi
    fi

    if [[ ${#k8s_urls[@]} -eq 0 ]]; then
        log_inf "  No Kubernetes API servers found"
        echo "[T07] No Kubernetes API servers found" >> "$ev_f"
        return
    fi

    for api_url in "${k8s_urls[@]}"; do
        log_inf "  Probing Kubernetes API at ${api_url}..."
        echo "" >> "$ev_f"
        echo "--- Probing: ${api_url} ---" >> "$ev_f"

        # GET /api — anonymous API discovery
        local api_status
        api_status=$(_http_status "${api_url}/api")
        local api_body
        api_body=$(_http_body "${api_url}/api")
        {
            echo "--- /api (status: ${api_status}) ---"
            echo "${api_body}" | head -20
        } >> "$ev_f"

        local k8s_version=""
        if echo "$api_body" | grep -qi '"serverVersion"\|"gitVersion"'; then
            k8s_version=$(echo "$api_body" | grep -o '"gitVersion":"[^"]*"' | head -1 | cut -d'"' -f4 || true)
            log_wrn "  K8s version disclosure: ${k8s_version}"
            emit_finding "low" \
                "Kubernetes API Version Disclosure: ${k8s_version:-detected}" \
                "The Kubernetes API server at ${api_url}/api discloses its version (${k8s_version:-see evidence}) without authentication. Version disclosure assists targeted CVE exploitation." \
                "Require authentication for all API endpoints. Configure the API server with --anonymous-auth=false. Place the API server behind a network ACL restricted to management hosts." \
                "cicd_k8s_version_${api_url//[^A-Za-z0-9._-]/_}"
        fi

        # GET /api/v1/namespaces — anonymous namespace listing
        local ns_status
        ns_status=$(_http_status "${api_url}/api/v1/namespaces")
        local ns_body
        ns_body=$(_http_body "${api_url}/api/v1/namespaces")
        {
            echo "--- /api/v1/namespaces (status: ${ns_status}) ---"
            echo "${ns_body}" | head -40
        } >> "$ev_f"

        if [[ "$ns_status" == "200" ]] && echo "$ns_body" | grep -qi '"items"\|"namespace"'; then
            local ns_count
            ns_count=$(echo "$ns_body" | grep -o '"name"' | wc -l || echo 0)
            emit_finding "critical" \
                "Kubernetes Anonymous API Read Access — Namespace Listing: ${ns_count} Namespace(s) at ${api_url}" \
                "The Kubernetes API server at ${api_url}/api/v1/namespaces returns ${ns_count} namespace(s) without authentication. Anonymous read access to the API allows full cluster enumeration, potentially exposing Secrets, ConfigMaps, ServiceAccounts, and pod specifications depending on RBAC configuration." \
                "Set --anonymous-auth=false on the kube-apiserver. Audit ClusterRoleBindings and RoleBindings for 'system:anonymous' or 'system:unauthenticated'. Apply network policies restricting API server access to management CIDR ranges. Rotate any exposed Secrets." \
                "cicd_k8s_anon_namespaces_${api_url//[^A-Za-z0-9._-]/_}"

            # GET /api/v1/pods — pod listing
            local pods_status
            pods_status=$(_http_status "${api_url}/api/v1/pods")
            local pods_body
            pods_body=$(_http_body "${api_url}/api/v1/pods")
            {
                echo "--- /api/v1/pods (status: ${pods_status}) ---"
                echo "${pods_body}" | head -40
            } >> "$ev_f"

            if [[ "$pods_status" == "200" ]] && echo "$pods_body" | grep -qi '"items"\|"pod"'; then
                local pod_count
                pod_count=$(echo "$pods_body" | grep -o '"name"' | wc -l || echo 0)
                log_wrn "  K8s anonymous pod listing: ${pod_count} pod(s)"
                emit_finding "critical" \
                    "Kubernetes Anonymous Pod Listing: ${pod_count} Pod(s) Exposed at ${api_url}" \
                    "The Kubernetes API server at ${api_url}/api/v1/pods lists ${pod_count} pod(s) without authentication. Pod specifications may contain environment variables with credentials, secret references, volume mounts, and image registry paths." \
                    "Disable anonymous authentication immediately (--anonymous-auth=false). Review /api/v1/pods output for credential exposure. Rotate all Secrets referenced by exposed pods." \
                    "cicd_k8s_anon_pods_${api_url//[^A-Za-z0-9._-]/_}"
            fi
        elif [[ "$ns_status" == "403" ]]; then
            log_ok "  K8s API at ${api_url}/api/v1/namespaces: access denied (403) — RBAC working"
        fi

        # kubectl additional checks if available
        if _check_tool kubectl; then
            log_inf "  kubectl available — checking cluster-info for ${api_url}..."
            local kubectl_out
            kubectl_out=$(timeout 15 kubectl --server="${api_url}" --insecure-skip-tls-verify=true \
                cluster-info 2>&1 | head -20 || true)
            {
                echo "--- kubectl cluster-info ---"
                echo "${kubectl_out}"
            } >> "$ev_f"
            if echo "$kubectl_out" | grep -qi 'Kubernetes.*is running\|control plane'; then
                log_wrn "  kubectl cluster-info succeeded anonymously at ${api_url}"
            fi
        fi

        log_ok "  Kubernetes probe at ${api_url} complete"
    done
}

# =============================================================================
# - MRK:18_TRUN
# =============================================================================
_run_tests() {
    local find_before="$_FIND_CTR"

    log_inf "=== Running CI/CD & DevOps security tests ==="

    _test_skip T01 || test_T01_jenkins
    _test_skip T02 || test_T02_gitlab
    _test_skip T03 || test_T03_github_enterprise
    _test_skip T04 || test_T04_argocd
    _test_skip T05 || test_T05_git_exposure
    _test_skip T06 || test_T06_registry
    _test_skip T07 || test_T07_kubernetes

    local find_delta=$(( _FIND_CTR - find_before ))
    echo "SUMMARY_ROW|cicd_devops|${PROJECT_NAME}|findings=${find_delta}"
}

# =============================================================================
# - MRK:18_MAIN
# =============================================================================
main() {
    printf "\n${_W}╔══════════════════════════════════════════════════════╗${_N}\n"
    printf "${_W}║  PT-Orc  ·  Step 18: CI/CD & DevOps Security        ║${_N}\n"
    printf "${_W}╚══════════════════════════════════════════════════════╝${_N}\n\n"

    log_inf "Project  : ${PROJECT_NAME}"
    log_inf "Profile  : ${SCAN_PROFILE}"
    log_inf "Targets  : ${TARGET_IPS:-<none>} | ${TARGET_DOMAINS:-<none>}"
    log_inf "Session  : ${SESSION_TS}"
    log_inf "Log      : ${LOG_FILE}"

    _validate_config || exit 1
    setup_profile "$SCAN_PROFILE"
    _confirm

    command -v trail_phase_start &>/dev/null && trail_phase_start "18_cicd_devops"

    local row
    row=$(_run_tests)
    local total_findings
    total_findings=$(echo "$row" | grep -oE 'findings=[0-9]+' | grep -oE '[0-9]+' || echo 0)

    command -v trail_phase_end &>/dev/null && trail_phase_end "18_cicd_devops"

    # Summary report
    local report_f="${SCRIPT_DIR}/working/$(ev_fname "18-cicd-summary" "md")"
    {
        printf "# CI/CD & DevOps Security Testing Summary — %s\n\n" "$PROJECT_NAME"
        printf "| Phase | Project | Findings |\n|-------|---------|----------|\n"
        local phase_col proj_col finds_col
        phase_col=$(echo "$row" | cut -d'|' -f2)
        proj_col=$(echo "$row" | cut -d'|' -f3)
        finds_col=$(echo "$row" | grep -oE 'findings=[0-9]+')
        printf "| %s | %s | %s |\n" "$phase_col" "$proj_col" "$finds_col"
        printf "\n**Total Findings:** %d\n" "$total_findings"
        printf "\nFindings JSONL: \`%s\`\n" "$FINDINGS_FILE"
        printf "\nEvidence dir  : \`%s\`\n" "$EVIDENCE_BASE"
    } > "$report_f"

    printf "\n${_G}[DONE]${_N} CI/CD & DevOps security testing complete.\n"
    printf "  Profile  : %s\n" "${SCAN_PROFILE}"
    printf "  Targets  : %s\n" "${TARGET_IPS:-<none>} | ${TARGET_DOMAINS:-<none>}"
    printf "  Findings : %d\n" "$total_findings"
    printf "  Summary  : %s\n" "$report_f"
    printf "  Evidence : %s\n\n" "$EVIDENCE_BASE"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
