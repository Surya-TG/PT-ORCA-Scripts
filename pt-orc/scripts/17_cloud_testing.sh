#!/usr/bin/env bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ./LOCAL-INDEX.md

# MRK:17_NAV_TOC — Section index | nav,toc,index | L5-29
# - MRK:17_T01 — T01 CLOUD PROVIDER DETECTION | t01,cloud,provider,detection | L30-30
# - MRK:17_T02 — T02 IMDS SSRF PROBE | t02,imds,ssrf,probe | L31-31
# - MRK:17_T03 — T03 STORAGE BUCKET DISCOVERY | t03,storage,bucket,discovery | L32-32
# - MRK:17_T04 — T04 IAM ROLE / CREDENTIAL METADATA | t04,iam,role,credential,metadata | L33-33
# - MRK:17_T05 — T05 SERVERLESS / FUNCTION ENDPOINTS | t05,serverless,function,endpoints | L34-34
# - MRK:17_T06 — T06 CONTAINER REGISTRY DETECTION | t06,container,registry,detection | L35-35
# - MRK:17_T07 — T07 KUBERNETES API EXPOSURE | t07,kubernetes,api,exposure | L36-36
# - MRK:17_T08 — T08 SECURITY HEADERS (CLOUD-SPECIFIC) | t08,security,headers,cloud,specific | L37-37
# - MRK:17_T09 — T09 CORS POLICY CHECK | t09,cors,policy,check | L38-38
# - MRK:17_T10 — T10 CLOUD MANAGEMENT CONSOLE EXPOSURE | t10,cloud,management,console,exposure | L39-39
# - MRK:17_T11 — T11 CDN / ORIGIN IP DISCLOSURE | t11,cdn,origin,ip,disclosure | L40-40
# - MRK:17_T12 — T12 SUBDOMAIN TAKEOVER (CLOUD SERVICES) | t12,subdomain,takeover,cloud,services | L41-41
# - MRK:17_T13 — T13 CLOUD TOKEN / API KEY EXPOSURE | t13,cloud,token,api,key | L42-42
# - MRK:17_T14 — T14 OBJECT STORAGE ACL / PUBLIC LISTING | t14,object,storage,acl,public | L43-43
# - MRK:17_T15 — T15 WAF DETECTION & BYPASS FINGERPRINTING | t15,waf,detection,bypass,fingerprinting | L44-1207
# NAV-LEN: 15 entries | Integrity-hash: 03840855921e18f5 | Last-indexed: 2026-06-16T13:41:02Z

# =============================================================================
# 11_cloud_testing.sh — Cloud Infrastructure Security Testing
# TechGuard Labs | PT-Orc Suite v0.8
# =============================================================================
# NAV: MRK:17_TOC (this block) | MRK:17_ROOT | MRK:17_CONF | MRK:17_LOG
#      MRK:17_ARGS | MRK:17_DB | MRK:17_CONFIRM | MRK:17_TARGETS
#      MRK:17_FIND | MRK:17_UTILS | MRK:17_PROF
#      MRK:17_T01 — T01 CLOUD PROVIDER DETECTION | t01,cloud,provider,detection | L30-30
#      MRK:17_T02 — T02 IMDS SSRF PROBE | t02,imds,ssrf,probe | L31-31
#      MRK:17_T03 — T03 STORAGE BUCKET DISCOVERY | t03,storage,bucket,discovery | L32-32
#      MRK:17_T04 — T04 IAM ROLE / CREDENTIAL METADATA | t04,iam,role,credential,metadata | L33-33
#      MRK:17_T05 — T05 SERVERLESS / FUNCTION ENDPOINTS | t05,serverless,function,endpoints | L34-34
#      MRK:17_T06 — T06 CONTAINER REGISTRY DETECTION | t06,container,registry,detection | L35-35
#      MRK:17_T07 — T07 KUBERNETES API EXPOSURE | t07,kubernetes,api,exposure | L36-36
#      MRK:17_T08 — T08 SECURITY HEADERS (CLOUD-SPECIFIC) | t08,security,headers,cloud,specific | L37-37
#      MRK:17_T09 — T09 CORS POLICY CHECK | t09,cors,policy,check | L38-38
#      MRK:17_T10 — T10 CLOUD MANAGEMENT CONSOLE EXPOSURE | t10,cloud,management,console,exposure | L39-39
#      MRK:17_T11 — T11 CDN / ORIGIN IP DISCLOSURE | t11,cdn,origin,ip,disclosure | L40-40
#      MRK:17_T12 — T12 SUBDOMAIN TAKEOVER (CLOUD SERVICES) | t12,subdomain,takeover,cloud,services | L41-41
#      MRK:17_T13 — T13 CLOUD TOKEN / API KEY EXPOSURE | t13,cloud,token,api,key | L42-42
#      MRK:17_T14 — T14 OBJECT STORAGE ACL / PUBLIC LISTING | t14,object,storage,acl,public | L43-43
#      MRK:17_T15 — T15 WAF DETECTION & BYPASS FINGERPRINTING | t15,waf,detection,bypass,fingerprinting | L44-1207
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
CLOUD_TIMEOUT="${CLOUD_TIMEOUT:-10}"
DRY_RUN=0
SCAN_PROFILE="${SCAN_PROFILE:-standard}"

# - MRK:17_LOG
_R='\033[0;31m'; _G='\033[0;32m'; _Y='\033[1;33m'; _B='\033[0;34m'; _C='\033[0;36m'; _W='\033[1;37m'; _N='\033[0m'
SESSION_TS="$(date +%Y%m%d_%H%M%S)"
EV_TS="$(_ev_ts)"
LOG_FILE="${SCRIPT_DIR}/working/${PROJ_SLUG}_10_cloud_${SESSION_TS}.log"
mkdir -p "${SCRIPT_DIR}/working" "${EVIDENCE_BASE}"

_log()  { local ts; ts="$(date +%H:%M:%S)"; printf "[%s] %s\n" "$ts" "$*" | tee -a "$LOG_FILE"; }
log_ok()  { printf "${_G}[+]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_inf() { printf "${_B}[*]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_wrn() { printf "${_Y}[!]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_err() { printf "${_R}[-]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }
log_dry() { printf "${_C}[DRY]${_N} %s\n" "$*" | tee -a "$LOG_FILE"; }

# - MRK:17_ARGS
EXTRA_TARGETS=()
_SKIP_CONFIRM=0
_ONLY_TESTS=()
_SKIP_TESTS=()

_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Cloud Infrastructure Security Testing (step 10)

Options:
  -t, --target <IP:PORT>     Add extra web target (repeatable)
  -p, --profile <name>       Scan profile: quick|standard|deep  [default: standard]
  --provider <aws|azure|gcp|auto>  Cloud provider hint         [default: auto]
  --bucket-prefix <prefix>   Prefix for bucket name permutations
  --only <T01,T03,...>       Run only specified tests
  --skip <T02,T05,...>       Skip specified tests
  -y, --yes                  Skip confirmation prompt
  --dry-run                  Print actions without executing
  -h, --help                 Show this help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)    EXTRA_TARGETS+=("$2"); shift 2 ;;
        -p|--profile)   SCAN_PROFILE="$2"; shift 2 ;;
        --provider)     CLOUD_PROVIDER="$2"; shift 2 ;;
        --bucket-prefix) CLOUD_BUCKET_PREFIX="$2"; shift 2 ;;
        --only)         IFS=',' read -ra _ONLY_TESTS <<< "$2"; shift 2 ;;
        --skip)         IFS=',' read -ra _SKIP_TESTS <<< "$2"; shift 2 ;;
        -y|--yes)       _SKIP_CONFIRM=1; shift ;;
        --dry-run)      DRY_RUN=1; shift ;;
        -h|--help)      _usage; exit 0 ;;
        *)              log_err "Unknown option: $1"; _usage; exit 1 ;;
    esac
done

# - MRK:17_DB
_web_hosts_from_db() {
    # Pull HTTPS+HTTP hosts from MSF DB — same pattern as 08/09
    local rows
    if command -v psql &>/dev/null && [[ -f "${MSF_DB_CONF:-}" ]]; then
        rows=$(psql -U "${MSF_DB_USER:-msf}" -d "${MSF_DB_NAME:-msf}" -p "${MSF_DB_PORT:-5432}" \
            -tAc "SELECT DISTINCT address||':'||port FROM services \
                  WHERE workspace='${PROJECT_NAME}' \
                  AND (proto='tcp') \
                  AND (name IN ('https','http','ssl/https') OR port IN (80,443,4443,8080,8443,8444)) \
                  ORDER BY 1;" 2>/dev/null)
    fi
    echo "${rows:-}"
}

# - MRK:17_CONFIRM
_confirm() {
    [[ "$_SKIP_CONFIRM" -eq 1 ]] && return 0
    printf "\n${_Y}[CONFIRM]${_N} Cloud testing on scope targets. Profile: ${_W}%s${_N}  Provider: ${_W}%s${_N}\n" \
        "$SCAN_PROFILE" "${CLOUD_PROVIDER:-auto}"
    printf "  Project : %s\n" "$PROJECT_NAME"
    printf "  Targets : %s\n" "$(wc -l < "${SCRIPT_DIR}/working/${PROJ_SLUG}_cloud_targets.txt" 2>/dev/null || echo 0) hosts"
    printf "\n  Continue? [y/N] "
    read -r _ans
    [[ "${_ans,,}" == "y" ]] || { log_err "Aborted by user."; exit 0; }
}

# - MRK:17_TARGETS
assemble_targets() {
    local tf="${SCRIPT_DIR}/working/$(ev_fname "cloud-targets" "txt")"
    : > "$tf"

    # From MSF DB
    while IFS= read -r line; do
        [[ -n "$line" ]] && echo "$line" >> "$tf"
    done < <(_web_hosts_from_db)

    # From script targets.txt (parsed as ip:port pairs — default 443)
    if [[ -f "${SCRIPT_DIR}/targets.txt" ]]; then
        while IFS= read -r t; do
            t="${t%%#*}"; t="${t// /}"
            [[ -z "$t" ]] && continue
            [[ "$t" == *:* ]] || t="${t}:443"
            echo "$t" >> "$tf"
        done < "${SCRIPT_DIR}/targets.txt"
    fi

    # Extra targets from CLI
    for t in "${EXTRA_TARGETS[@]+"${EXTRA_TARGETS[@]}"}"; do
        [[ "$t" == *:* ]] || t="${t}:443"
        echo "$t" >> "$tf"
    done

    sort -u "$tf" -o "$tf"
    cp "$tf" "${SCRIPT_DIR}/working/${PROJ_SLUG}_cloud_targets.txt" 2>/dev/null || true
    log_inf "Cloud targets assembled: $(wc -l < "$tf" | tr -d ' ') host:port pairs → ${tf}"
}

# - MRK:17_FIND
FINDINGS_FILE="${SCRIPT_DIR}/working/$(ev_fname "11-cloud-findings" "jsonl")"
_FIND_CTR=0
: > "$FINDINGS_FILE"

emit_finding() {
    local sev="$1" title="$2" desc="$3" rec="$4" ev_tag="${5:-}"
    (( _FIND_CTR++ )) || true
    local fid
    fid="f-11-cloud-$(printf '%04d' "$_FIND_CTR")"
    local ev_id="${ev_tag:-${fid}-ev}"
    local payload
    payload=$(printf '{"id":"%s","title":"%s","severity":"%s","phase":"11_cloud","evidence_ids":["%s"],"description":"%s","recommendation":"%s","retest_status":"n/a","residual_risk":""}' \
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
_curl() {
    # Wrapper: timeout, silent, insecure (testing context), follow redirects
    curl -sk --max-time "${CLOUD_TIMEOUT}" -L "$@"
}

_curl_head() {
    curl -skI --max-time "${CLOUD_TIMEOUT}" "$@"
}

_scheme_for_port() {
    local port="${1#*:}"
    case "$port" in 443|4443|8443) echo "https" ;; *) echo "http" ;; esac
}

_base_url() {
    local tgt="$1"
    local ip="${tgt%%:*}" port="${tgt##*:}"
    echo "$(_scheme_for_port ":$port")://${ip}:${port}"
}

_ev_file() {
    # Return evidence file path for a target+tag
    local tgt="$1" tag="$2"
    local slug="${tgt//:/_}"
    echo "${EVIDENCE_BASE}/$(ev_fname "$tag" "txt" "$slug")"
}

declare -A _T_ENABLED
_test_skip() {
    local n="$1"
    [[ "${_T_ENABLED[$n]:-1}" -eq 0 ]] && return 0
    return 1
}

# Apply --only / --skip CLI filters on top of profile
_apply_cli_filters() {
    if [[ ${#_ONLY_TESTS[@]} -gt 0 ]]; then
        for k in "${!_T_ENABLED[@]}"; do
            _T_ENABLED[$k]=0
        done
        for t in "${_ONLY_TESTS[@]}"; do
            _T_ENABLED["${t^^}"]=1
        done
    fi
    for t in "${_SKIP_TESTS[@]+"${_SKIP_TESTS[@]}"}"; do
        _T_ENABLED["${t^^}"]=0
    done
}

# - MRK:17_PROF
setup_profile() {
    local prof="${1:-standard}"
    # Defaults — all enabled
    for n in T01 T02 T03 T04 T05 T06 T07 T08 T09 T10 T11 T12 T13 T14 T15; do
        _T_ENABLED[$n]=1
    done
    case "$prof" in
        quick)
            # Quick: provider detect, headers, CORS, storage public listing, WAF
            for n in T02 T04 T05 T06 T07 T10 T11 T12 T13; do _T_ENABLED[$n]=0; done ;;
        standard)
            # Standard: skip container registry, K8s, mgmt console (expensive/noisy)
            for n in T06 T07 T10; do _T_ENABLED[$n]=0; done ;;
        deep)
            : ;; # all enabled
        *)
            log_wrn "Unknown profile '${prof}' — defaulting to standard"
            for n in T06 T07 T10; do _T_ENABLED[$n]=0; done ;;
    esac
    _apply_cli_filters
}

# =============================================================================
# TESTS
# =============================================================================

# - MRK:17_T01 — T01 CLOUD PROVIDER DETECTION
test_T01_cloud_provider() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ev_f; ev_f="$(_ev_file "$tgt" "cloud_provider")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T01] Cloud provider detection → ${base_url}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "curl headers + cert + DNS"; return; }

    local headers body detected=""
    headers=$(_curl_head "$base_url" 2>/dev/null)
    body=$(_curl -o /dev/null -w '%{url_effective}' "$base_url" 2>/dev/null || true)

    {
        echo "=== T01 Cloud Provider Detection ==="
        echo "Target: $base_url"
        echo "--- Response Headers ---"
        echo "$headers"
    } > "$ev_f"

    # AWS indicators
    if echo "$headers" | grep -qiE 'x-amz|amazonaws|cloudfront|awselb|aws-'; then
        detected="AWS"
    # Azure indicators
    elif echo "$headers" | grep -qiE 'x-ms-|azure|azurewebsites|afd\.ms|windows\.net'; then
        detected="Azure"
    # GCP indicators
    elif echo "$headers" | grep -qiE 'x-goog|googleusercontent|ghs\.googlehosted|googleapis'; then
        detected="GCP"
    # Cloudflare
    elif echo "$headers" | grep -qiE 'cf-ray|cf-cache|cloudflare'; then
        detected="Cloudflare"
    fi

    # DNS-based detection
    local ip="${tgt%%:*}"
    local rdns
    rdns=$(dig +short -x "$ip" 2>/dev/null | head -1 || true)
    echo "--- Reverse DNS: ${rdns:-none} ---" >> "$ev_f"
    if [[ -z "$detected" ]]; then
        case "${rdns,,}" in
            *amazonaws*|*aws*) detected="AWS" ;;
            *azure*|*windows.net*|*msecnd*) detected="Azure" ;;
            *google*|*gcp*) detected="GCP" ;;
            *fastly*) detected="Fastly CDN" ;;
            *akamai*) detected="Akamai CDN" ;;
        esac
    fi

    echo "--- Detected Provider: ${detected:-Unknown} ---" >> "$ev_f"
    [[ -n "$detected" ]] && log_ok "  Provider identified: ${detected}" || log_inf "  Provider: could not fingerprint"

    echo "CLOUD_PROVIDER_DETECTED=${detected:-unknown}"
}

# - MRK:17_T02 — T02 IMDS SSRF PROBE
test_T02_imds_ssrf() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ev_f; ev_f="$(_ev_file "$tgt" "imds_ssrf")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T02] IMDS SSRF probe → ${base_url}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "test SSRF paths for IMDS endpoints"; return; }

    # Common IMDS endpoint paths — probe via open redirect / SSRF-like params
    local -a ssrf_params=("url=" "redirect=" "next=" "dest=" "target=" "path=" "uri=" "u=")
    local -a imds_urls=(
        "http://169.254.169.254/latest/meta-data/"
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
        "http://169.254.169.254/computeMetadata/v1/?recursive=true"
        "http://fd00:ec2::254/latest/meta-data/"
        "http://metadata.google.internal/computeMetadata/v1/"
        "http://169.254.170.2/v2/credentials"
    )

    {
        echo "=== T02 IMDS SSRF Probe ==="
        echo "Target: $base_url"
    } > "$ev_f"

    local hit=0
    for param in "${ssrf_params[@]}"; do
        for imds in "${imds_urls[@]}"; do
            local probe_url="${base_url}?${param}${imds}"
            local resp
            resp=$(_curl -m 5 "$probe_url" 2>/dev/null | head -c 512)
            if echo "$resp" | grep -qiE 'ami-id|instance-id|iam|AccessKeyId|SecretAccessKey|placement|computeMetadata|instance-name'; then
                echo "HIT: param=${param} imds=${imds}" >> "$ev_f"
                echo "Response: ${resp}" >> "$ev_f"
                emit_finding "critical" \
                    "IMDS Accessible via SSRF" \
                    "The cloud Instance Metadata Service is reachable through SSRF parameter '${param}' at ${probe_url}. Cloud credentials or IAM role data may be exfiltrable." \
                    "Disable IMDS v1 (AWS IMDSv2 only). Block SSRF at application layer. Restrict egress to 169.254.169.254 at network level." \
                    "imds_ssrf_${tgt//:/_}"
                hit=1
                break 2
            fi
        done
    done

    [[ "$hit" -eq 0 ]] && log_ok "  IMDS SSRF: no leakage detected via common parameters"
}

# - MRK:17_T03 — T03 STORAGE BUCKET DISCOVERY
test_T03_storage_buckets() {
    local tgt="$1"
    local ip="${tgt%%:*}"
    local ev_f; ev_f="$(_ev_file "$tgt" "storage_buckets")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T03] Storage bucket discovery"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "enumerate bucket name permutations for ${CLOUD_BUCKET_PREFIX:-<proj>}"; return; }

    local prefix="${CLOUD_BUCKET_PREFIX:-${PROJ_SLUG,,}}"
    prefix="${prefix//_/-}"
    local -a suffixes=("" "-prod" "-dev" "-staging" "-backup" "-assets" "-static" "-public" "-private" "-data" "-logs" "-media" "-uploads" "-files" "-images" "-config" "-archive" "-test" "-demo")

    {
        echo "=== T03 Storage Bucket Discovery ==="
        echo "Prefix: ${prefix}"
    } > "$ev_f"

    local public_count=0
    for suf in "${suffixes[@]}"; do
        local bucket="${prefix}${suf}"

        # AWS S3
        local s3_url="https://${bucket}.s3.amazonaws.com/"
        local s3_resp s3_code
        s3_resp=$(_curl -m 8 "$s3_url" 2>/dev/null)
        s3_code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "$s3_url" 2>/dev/null)
        if [[ "$s3_code" == "200" ]] || echo "$s3_resp" | grep -qiE '<ListBucketResult|<Key>'; then
            echo "PUBLIC S3: ${s3_url} [HTTP ${s3_code}]" >> "$ev_f"
            emit_finding "high" \
                "Public S3 Bucket: ${bucket}" \
                "S3 bucket '${bucket}' is publicly listable (HTTP ${s3_code}). Contents may include sensitive files." \
                "Apply bucket policy to deny public access. Enable S3 Block Public Access at account level. Audit bucket ACLs." \
                "storage_s3_${bucket}"
            (( public_count++ )) || true
        elif [[ "$s3_code" == "403" ]]; then
            echo "EXISTS(403) S3: ${s3_url}" >> "$ev_f"
            log_inf "  S3 bucket exists (access denied): ${bucket}"
        fi

        # Azure Blob
        local az_url="https://${bucket}.blob.core.windows.net/\$web/"
        local az_code
        az_code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "$az_url" 2>/dev/null)
        if [[ "$az_code" == "200" ]]; then
            echo "PUBLIC Azure Blob: ${az_url}" >> "$ev_f"
            emit_finding "high" \
                "Public Azure Blob Container: ${bucket}" \
                "Azure Blob container '${bucket}' at ${az_url} is publicly accessible." \
                "Set container access level to Private. Enable Azure Storage public access block at account level." \
                "storage_azure_${bucket}"
            (( public_count++ )) || true
        fi

        # GCS
        local gcs_url="https://storage.googleapis.com/${bucket}/"
        local gcs_resp gcs_code
        gcs_resp=$(_curl -m 8 "$gcs_url" 2>/dev/null)
        gcs_code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "$gcs_url" 2>/dev/null)
        if [[ "$gcs_code" == "200" ]] || echo "$gcs_resp" | grep -qiE '<ListBucketResult'; then
            echo "PUBLIC GCS: ${gcs_url}" >> "$ev_f"
            emit_finding "high" \
                "Public GCS Bucket: ${bucket}" \
                "GCS bucket '${bucket}' at ${gcs_url} is publicly listable." \
                "Remove allUsers IAM binding. Apply uniform bucket-level access policy." \
                "storage_gcs_${bucket}"
            (( public_count++ )) || true
        fi
    done

    if [[ "$public_count" -eq 0 ]]; then
        log_ok "  No publicly accessible buckets found for prefix '${prefix}'"
    else
        log_wrn "  ${public_count} publicly accessible buckets found — review evidence"
    fi
}

# - MRK:17_T04 — T04 IAM ROLE / CREDENTIAL METADATA
test_T04_iam_creds() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ev_f; ev_f="$(_ev_file "$tgt" "iam_creds")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T04] IAM role / credential metadata probe → ${base_url}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "probe SSRF to IAM credential paths"; return; }

    {
        echo "=== T04 IAM Credential Metadata ==="
        echo "Target: $base_url"
    } > "$ev_f"

    # Probe via common path traversal / SSRF-accessible endpoints on the app
    local -a cred_paths=(
        "/latest/meta-data/iam/security-credentials/"
        "/.aws/credentials"
        "/.azure/credentials"
        "/.config/gcloud/application_default_credentials.json"
        "/proc/1/environ"
        "/.env"
        "/env"
        "/config"
        "/config.json"
        "/settings.json"
    )

    local hit=0
    for path in "${cred_paths[@]}"; do
        local resp http_code
        resp=$(_curl -m 8 "${base_url}${path}" 2>/dev/null | head -c 1024)
        http_code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "${base_url}${path}" 2>/dev/null)
        if echo "$resp" | grep -qiE 'AccessKeyId|SecretAccessKey|aws_access_key|aws_secret|AZURE_CLIENT|private_key|client_email|token'; then
            echo "CRED EXPOSURE: ${base_url}${path} [HTTP ${http_code}]" >> "$ev_f"
            echo "Response snippet: ${resp:0:256}" >> "$ev_f"
            emit_finding "critical" \
                "Cloud Credential Exposure at ${path}" \
                "Cloud credentials or IAM role data returned at ${base_url}${path}. Immediate revocation required." \
                "Remove credential files from web-accessible paths. Rotate all exposed keys. Use instance roles instead of static credentials." \
                "iam_creds_${tgt//:/_}"
            hit=1
        fi
    done

    [[ "$hit" -eq 0 ]] && log_ok "  IAM credential paths: no direct exposure detected"
}

# - MRK:17_T05 — T05 SERVERLESS / FUNCTION ENDPOINTS
test_T05_serverless() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ev_f; ev_f="$(_ev_file "$tgt" "serverless")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T05] Serverless / function endpoint discovery → ${base_url}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "probe common function URL patterns"; return; }

    {
        echo "=== T05 Serverless Function Discovery ==="
        echo "Target: $base_url"
    } > "$ev_f"

    local ip="${tgt%%:*}"
    local domain
    domain=$(dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//' || echo "$ip")

    # Common serverless patterns
    local -a fn_patterns=(
        "/.netlify/functions/"
        "/api/"
        "/.functions/"
        "/functions/"
        "/lambda/"
        "/_functions/"
        "/vercel/"
        "/.vercel/api/"
    )

    # Cloud-specific function domains to check
    local -a fn_domains=()
    local bucket_pfx="${CLOUD_BUCKET_PREFIX:-${PROJ_SLUG,,}}"
    bucket_pfx="${bucket_pfx//_/-}"
    fn_domains+=(
        "https://${bucket_pfx}.azurewebsites.net/api/"
        "https://${bucket_pfx}.azurefd.net/api/"
        "https://us-central1-${bucket_pfx}.cloudfunctions.net/"
    )

    local found=0
    for path in "${fn_patterns[@]}"; do
        local code
        code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "${base_url}${path}" 2>/dev/null)
        if [[ "$code" =~ ^(200|401|403|405)$ ]]; then
            echo "FN_PATH [${code}]: ${base_url}${path}" >> "$ev_f"
            log_inf "  Function path responds (${code}): ${path}"
            if [[ "$code" == "200" ]]; then
                emit_finding "medium" \
                    "Unauthenticated Serverless Function Endpoint: ${path}" \
                    "Function endpoint at ${base_url}${path} returned HTTP 200 without authentication." \
                    "Require authentication for all serverless function endpoints. Apply IAM-based access controls. Review function execution roles." \
                    "serverless_${tgt//:/_}"
                (( found++ )) || true
            fi
        fi
    done

    for fn_url in "${fn_domains[@]}"; do
        local code
        code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "$fn_url" 2>/dev/null)
        if [[ "$code" =~ ^(200|401|403)$ ]]; then
            echo "FN_DOMAIN [${code}]: ${fn_url}" >> "$ev_f"
            [[ "$code" == "200" ]] && (( found++ )) || true
        fi
    done

    [[ "$found" -eq 0 ]] && log_ok "  No unauthenticated serverless endpoints detected"
}

# - MRK:17_T06 — T06 CONTAINER REGISTRY DETECTION
test_T06_container_registry() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ev_f; ev_f="$(_ev_file "$tgt" "container_registry")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T06] Container registry detection → ${base_url}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "probe /v2/ Docker registry endpoints"; return; }

    {
        echo "=== T06 Container Registry Detection ==="
        echo "Target: $base_url"
    } > "$ev_f"

    local -a reg_paths=("/v2/" "/v2/_catalog" "/v2/tags/list")
    local prefix="${CLOUD_BUCKET_PREFIX:-${PROJ_SLUG,,}}"
    prefix="${prefix//_/-}"

    # Also test cloud-specific registry hostnames
    local -a reg_hosts=(
        "${base_url}"
        "https://${prefix}.azurecr.io"
        "https://gcr.io/v2/"
        "https://registry-1.docker.io/v2/"
    )

    for host in "${reg_hosts[@]}"; do
        for path in "${reg_paths[@]}"; do
            [[ "$host" == *"/v2/"* ]] && path="" # already has /v2/
            local resp code
            resp=$(_curl -m 8 "${host}${path}" 2>/dev/null | head -c 512)
            code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "${host}${path}" 2>/dev/null)
            if echo "$resp" | grep -qiE '"repositories"|"tags"|"name"' && [[ "$code" == "200" ]]; then
                echo "REGISTRY [${code}]: ${host}${path}" >> "$ev_f"
                echo "Response: ${resp:0:256}" >> "$ev_f"
                emit_finding "high" \
                    "Unauthenticated Container Registry Access: ${host}${path}" \
                    "Container registry catalog is accessible without authentication at ${host}${path}. Image names, tags, and layers may be enumerable." \
                    "Require authentication for all registry endpoints. Restrict public pull access. Audit image contents for secrets." \
                    "container_registry_${tgt//:/_}"
            fi
        done
    done

    log_ok "  Container registry scan complete — see evidence for details"
}

# - MRK:17_T07 — T07 KUBERNETES API EXPOSURE
test_T07_k8s_api() {
    local tgt="$1"
    local ip="${tgt%%:*}"
    local ev_f; ev_f="$(_ev_file "$tgt" "k8s_api")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T07] Kubernetes API server exposure"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "probe K8s API ports 6443/8080/10250 on ${ip}"; return; }

    {
        echo "=== T07 Kubernetes API Exposure ==="
        echo "IP: $ip"
    } > "$ev_f"

    local -a k8s_endpoints=(
        "https://${ip}:6443/version"
        "https://${ip}:6443/api/v1/namespaces"
        "http://${ip}:8080/api/v1/namespaces"
        "https://${ip}:10250/pods"
        "https://${ip}:10255/pods"
        "https://${ip}:2379/version"
    )

    local exposed=0
    for ep in "${k8s_endpoints[@]}"; do
        local resp code
        resp=$(_curl -m 8 "$ep" 2>/dev/null | head -c 1024)
        code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "$ep" 2>/dev/null)
        if echo "$resp" | grep -qiE '"major"|"minor"|"gitVersion"|namespace|pods|items' && [[ "$code" == "200" ]]; then
            echo "K8S_EXPOSED [${code}]: ${ep}" >> "$ev_f"
            echo "Response: ${resp:0:512}" >> "$ev_f"
            emit_finding "critical" \
                "Kubernetes API Server Exposed: ${ep}" \
                "The Kubernetes API server at ${ep} is accessible without authentication. Full cluster takeover may be possible." \
                "Restrict K8s API access to authorised management networks only. Disable anonymous authentication (--anonymous-auth=false). Enable RBAC. Require client certificate authentication." \
                "k8s_api_${tgt//:/_}"
            (( exposed++ )) || true
        elif echo "$resp" | grep -qiE 'Forbidden|Unauthorized' && [[ "$code" =~ ^(401|403)$ ]]; then
            echo "K8S_EXISTS_AUTH [${code}]: ${ep}" >> "$ev_f"
            log_inf "  K8s endpoint exists but requires auth: ${ep}"
        fi
    done

    [[ "$exposed" -eq 0 ]] && log_ok "  No unauthenticated K8s API endpoints detected"
}

# - MRK:17_T08 — T08 SECURITY HEADERS (CLOUD-SPECIFIC)
test_T08_security_headers() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ev_f; ev_f="$(_ev_file "$tgt" "cloud_headers")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T08] Cloud security headers → ${base_url}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "check response headers"; return; }

    local headers
    headers=$(_curl_head "$base_url" 2>/dev/null)
    {
        echo "=== T08 Cloud Security Headers ==="
        echo "Target: $base_url"
        echo "--- Headers ---"
        echo "$headers"
    } > "$ev_f"

    # Check essential security headers
    local -A required_headers=(
        ["strict-transport-security"]="HSTS missing — HTTPS downgrade risk"
        ["x-content-type-options"]="X-Content-Type-Options missing — MIME sniffing risk"
        ["x-frame-options"]="X-Frame-Options missing — clickjacking risk"
        ["content-security-policy"]="Content-Security-Policy missing — XSS/injection risk"
        ["permissions-policy"]="Permissions-Policy missing"
    )

    local missing_count=0
    for hdr in "${!required_headers[@]}"; do
        if ! echo "${headers,,}" | grep -q "^${hdr}:"; then
            log_wrn "  Missing: ${hdr}"
            echo "MISSING: ${hdr}" >> "$ev_f"
            (( missing_count++ )) || true
        fi
    done

    if [[ "$missing_count" -ge 3 ]]; then
        emit_finding "medium" \
            "Multiple Security Headers Missing" \
            "${missing_count} recommended security headers are absent on ${base_url}. This degrades defence-in-depth against XSS, MIME sniffing, and clickjacking." \
            "Add Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, and Permissions-Policy to all responses." \
            "cloud_headers_${tgt//:/_}"
    fi

    # Cloud-specific info header leakage
    if echo "${headers,,}" | grep -qiE 'x-powered-by|server:|x-aspnet|x-generator'; then
        local leaked
        leaked=$(echo "$headers" | grep -iE 'x-powered-by:|server:|x-aspnet|x-generator' | head -3)
        emit_finding "info" \
            "Server/Technology Version Disclosure" \
            "Response headers reveal technology stack details: ${leaked}" \
            "Remove or genericise Server, X-Powered-By, and X-AspNet-Version headers." \
            "cloud_headers_${tgt//:/_}"
    fi

    [[ "$missing_count" -eq 0 ]] && log_ok "  All required security headers present"
}

# - MRK:17_T09 — T09 CORS POLICY CHECK
test_T09_cors() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ev_f; ev_f="$(_ev_file "$tgt" "cloud_cors")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T09] CORS policy check → ${base_url}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "test CORS with attacker origin"; return; }

    local -a origins=(
        "https://evil.com"
        "https://attacker.${CLOUD_BUCKET_PREFIX:-example}.com"
        "null"
    )

    {
        echo "=== T09 CORS Policy Check ==="
        echo "Target: $base_url"
    } > "$ev_f"

    for origin in "${origins[@]}"; do
        local resp_headers
        resp_headers=$(_curl_head -H "Origin: ${origin}" "$base_url" 2>/dev/null)
        local acao
        acao=$(echo "$resp_headers" | grep -i 'access-control-allow-origin' | head -1 || true)
        local acac
        acac=$(echo "$resp_headers" | grep -i 'access-control-allow-credentials' | head -1 || true)
        echo "Origin: ${origin} → ACAO: ${acao:-none}  ACAC: ${acac:-none}" >> "$ev_f"

        if echo "$acao" | grep -qiE 'evil\.com|null|\*'; then
            local sev="medium"
            local desc="CORS policy reflects untrusted origin '${origin}'."
            if echo "$acac" | grep -qi 'true'; then
                sev="high"
                desc="CORS reflects '${origin}' AND Access-Control-Allow-Credentials: true — cross-origin credential theft is possible."
            fi
            emit_finding "$sev" \
                "Permissive CORS Policy" \
                "$desc Target: ${base_url}" \
                "Restrict ACAO to a whitelist of trusted origins. Never combine wildcard or reflected origins with Allow-Credentials: true." \
                "cloud_cors_${tgt//:/_}"
        fi
    done

    log_ok "  CORS check complete — see evidence"
}

# - MRK:17_T10 — T10 CLOUD MANAGEMENT CONSOLE EXPOSURE
test_T10_mgmt_console() {
    local tgt="$1"
    local ip="${tgt%%:*}"
    local ev_f; ev_f="$(_ev_file "$tgt" "mgmt_console")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T10] Cloud management console exposure"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "probe common management ports/paths on ${ip}"; return; }

    {
        echo "=== T10 Cloud Management Console Exposure ==="
        echo "IP: $ip"
    } > "$ev_f"

    local -a mgmt_endpoints=(
        "http://${ip}:9000"           # Portainer / MinIO console
        "http://${ip}:9001"           # MinIO console v2
        "http://${ip}:4040"           # ngrok / Spark UI
        "http://${ip}:8001"           # K8s kubectl proxy
        "http://${ip}:10000"          # Webmin
        "http://${ip}:8088"           # Hadoop YARN
        "http://${ip}:50070"          # HDFS NameNode
        "http://${ip}:2375"           # Docker daemon (plain)
        "http://${ip}:2376"           # Docker daemon (TLS)
        "http://${ip}:4243"           # Docker alt port
    )

    local exposed=0
    for ep in "${mgmt_endpoints[@]}"; do
        local resp code
        resp=$(_curl -m 6 "$ep" 2>/dev/null | head -c 512)
        code=$(_curl -m 6 -o /dev/null -w '%{http_code}' "$ep" 2>/dev/null)
        if [[ "$code" =~ ^(200|301|302)$ ]] && [[ -n "$resp" ]]; then
            echo "MGMT_CONSOLE [${code}]: ${ep}" >> "$ev_f"
            echo "Snippet: ${resp:0:128}" >> "$ev_f"
            emit_finding "high" \
                "Cloud Management Console Exposed: ${ep}" \
                "Management interface at ${ep} responded (HTTP ${code}). Unauthenticated access to admin consoles enables full infrastructure control." \
                "Restrict management interfaces to private network / VPN only. Apply authentication and IP allow-lists." \
                "mgmt_console_${tgt//:/_}"
            (( exposed++ )) || true
        fi
    done

    [[ "$exposed" -eq 0 ]] && log_ok "  No exposed management consoles detected"
}

# - MRK:17_T11 — T11 CDN / ORIGIN IP DISCLOSURE
test_T11_cdn_origin() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ip="${tgt%%:*}"
    local ev_f; ev_f="$(_ev_file "$tgt" "cdn_origin")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T11] CDN fingerprinting / origin IP disclosure"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "check CDN headers and X-* headers for origin IP"; return; }

    local headers
    headers=$(_curl_head "$base_url" 2>/dev/null)
    {
        echo "=== T11 CDN / Origin IP Disclosure ==="
        echo "Target: $base_url"
        echo "--- Headers ---"
        echo "$headers"
    } > "$ev_f"

    # Check for origin IP leakage in headers
    local leaked_ip
    leaked_ip=$(echo "$headers" | grep -iE 'x-origin-ip|x-real-ip|x-backend|x-upstream|x-forwarded-server|via' | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v '^10\.\|^172\.1[6-9]\.\|^172\.2[0-9]\.\|^172\.3[01]\.\|^192\.168\.' | head -1 || true)

    if [[ -n "$leaked_ip" ]] && [[ "$leaked_ip" != "$ip" ]]; then
        emit_finding "medium" \
            "CDN Origin IP Disclosed in Response Headers" \
            "The origin/backend server IP ${leaked_ip} is visible in response headers. This allows bypassing CDN/WAF protections by targeting the origin directly." \
            "Remove or sanitise X-Real-IP, X-Origin-IP, Via, and X-Upstream-* headers in CDN configuration. Restrict origin server to CDN IP ranges only." \
            "cdn_origin_${tgt//:/_}"
        log_wrn "  Origin IP leaked: ${leaked_ip}"
    fi

    # Security headers around CDN
    if ! echo "${headers,,}" | grep -q 'strict-transport-security'; then
        log_wrn "  HSTS missing — possible CDN downgrade"
    fi

    # CF-specific checks
    if echo "$headers" | grep -qi 'cf-ray'; then
        log_inf "  Cloudflare detected (cf-ray present)"
        local cf_status
        cf_status=$(echo "$headers" | grep -i 'cf-cache-status' | head -1 || true)
        echo "CF-Cache-Status: ${cf_status:-unknown}" >> "$ev_f"
    fi

    [[ -z "$leaked_ip" ]] && log_ok "  No origin IP disclosure detected"
}

# - MRK:17_T12 — T12 SUBDOMAIN TAKEOVER (CLOUD SERVICES)
test_T12_subdomain_takeover() {
    local tgt="$1"
    local ip="${tgt%%:*}"
    local ev_f; ev_f="$(_ev_file "$tgt" "subdomain_takeover")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T12] Subdomain takeover check"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "check CNAME chains for unclaimed cloud services"; return; }

    {
        echo "=== T12 Subdomain Takeover ==="
        echo "IP: $ip"
    } > "$ev_f"

    # Resolve the target to its CNAME chain
    local cname_chain
    cname_chain=$(dig +short CNAME "$ip" 2>/dev/null; dig +short "$ip" 2>/dev/null)
    echo "CNAME/A records:" >> "$ev_f"
    echo "$cname_chain" >> "$ev_f"

    # Known dangling CNAME signatures (cloud service "not found" pages)
    local -A takeover_signatures=(
        ["azurewebsites.net"]="The page cannot be found"
        ["github.io"]="There isn't a GitHub Pages site here"
        ["s3.amazonaws.com"]="NoSuchBucket"
        ["s3-website"]="NoSuchBucket"
        ["cloudfront.net"]="ERROR: The request could not be satisfied"
        ["elasticbeanstalk.com"]="HTTP Status 404"
        ["herokudns.com"]="No such app"
        ["fastly.net"]="Fastly error"
        ["pantheon.io"]="404 error unknown site"
        ["netlify.app"]="Not Found"
    )

    # Check TARGET_DOMAINS subdomains for dangling CNAMEs
    local takeover_found=0
    for domain in ${TARGET_DOMAINS:-}; do
        # Get a quick list of subdomains from DNS + existing targets
        local -a sub_candidates=("www" "cdn" "static" "assets" "media" "api" "mail" "dev" "staging" "app")
        for sub in "${sub_candidates[@]}"; do
            local fqdn="${sub}.${domain}"
            local sub_cname
            sub_cname=$(dig +short CNAME "$fqdn" 2>/dev/null | head -1 || true)
            [[ -z "$sub_cname" ]] && continue
            echo "CNAME: ${fqdn} → ${sub_cname}" >> "$ev_f"
            for cloud_svc in "${!takeover_signatures[@]}"; do
                if echo "$sub_cname" | grep -q "$cloud_svc"; then
                    local resp
                    resp=$(_curl -m 8 "https://${fqdn}" 2>/dev/null | head -c 1024)
                    if echo "$resp" | grep -qi "${takeover_signatures[$cloud_svc]}"; then
                        emit_finding "high" \
                            "Subdomain Takeover: ${fqdn} → ${sub_cname}" \
                            "CNAME ${fqdn} points to ${sub_cname} which returned a '${takeover_signatures[$cloud_svc]}' page — the cloud resource is unclaimed and can be registered by an attacker." \
                            "Remove or update the dangling CNAME. Reclaim the cloud resource or delete the DNS record." \
                            "subdomain_takeover_${fqdn//./_}"
                        (( takeover_found++ )) || true
                    fi
                fi
            done
        done
    done

    [[ "$takeover_found" -eq 0 ]] && log_ok "  No dangling subdomain CNAMEs detected"
}

# - MRK:17_T13 — T13 CLOUD TOKEN / API KEY EXPOSURE
test_T13_token_exposure() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ev_f; ev_f="$(_ev_file "$tgt" "token_exposure")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T13] Cloud token / API key exposure → ${base_url}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "grep responses for cloud keys and tokens"; return; }

    {
        echo "=== T13 Cloud Token / API Key Exposure ==="
        echo "Target: $base_url"
    } > "$ev_f"

    local -a paths=("/" "/robots.txt" "/sitemap.xml" "/.git/config" "/config.js" "/env.js" "/app.js" "/main.js" "/bundle.js" "/.env" "/config.json" "/settings.json" "/appsettings.json" "/appsettings.Development.json")

    # Regex patterns for cloud keys
    local key_pattern='(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|(?:client_secret|aws_secret|api_key|access_token|private_key|AZURE_CLIENT_SECRET)["\s:=]+[A-Za-z0-9+/=_-]{20,})'

    local found=0
    for path in "${paths[@]}"; do
        local resp code
        code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "${base_url}${path}" 2>/dev/null)
        [[ "$code" =~ ^(200|304)$ ]] || continue
        resp=$(_curl -m 8 "${base_url}${path}" 2>/dev/null | head -c 8192)
        local matches
        matches=$(echo "$resp" | grep -oiE 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|[a-z0-9_-]*(?:secret|key|token|password)[a-z0-9_-]*\s*[=:]\s*["\047][A-Za-z0-9+/=_\-]{16,}' | head -10 || true)
        if [[ -n "$matches" ]]; then
            echo "KEY MATCH at ${path}:" >> "$ev_f"
            echo "$matches" >> "$ev_f"
            emit_finding "critical" \
                "Cloud API Key / Token Exposed at ${path}" \
                "Credentials or API keys found in publicly accessible file at ${base_url}${path}: ${matches:0:120}" \
                "Remove credentials from all files in the web root. Rotate all exposed keys immediately. Use secrets management (AWS Secrets Manager, Azure Key Vault, GCP Secret Manager)." \
                "token_exposure_${tgt//:/_}"
            (( found++ )) || true
        fi
    done

    [[ "$found" -eq 0 ]] && log_ok "  No cloud tokens/keys found in checked paths"
}

# - MRK:17_T14 — T14 OBJECT STORAGE ACL / PUBLIC LISTING
test_T14_storage_acl() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ev_f; ev_f="$(_ev_file "$tgt" "storage_acl")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T14] Object storage ACL / presigned URL abuse"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "probe storage paths for directory listing and path traversal"; return; }

    {
        echo "=== T14 Object Storage ACL ==="
        echo "Target: $base_url"
    } > "$ev_f"

    # Probe for directory listing / storage misconfiguration via path traversal
    local -a storage_paths=("/uploads/" "/files/" "/static/" "/media/" "/assets/" "/backup/" "/export/" "/dump/" "/data/")

    local vuln_count=0
    for path in "${storage_paths[@]}"; do
        local resp code
        code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "${base_url}${path}" 2>/dev/null)
        resp=$(_curl -m 8 "${base_url}${path}" 2>/dev/null | head -c 2048)
        if echo "$resp" | grep -qiE '<ListBucketResult|Index of |Parent Directory|<a href="[^"]*\.(sql|bak|tar|zip|gz|csv|xlsx|json|env|log)'; then
            echo "LISTING [${code}]: ${base_url}${path}" >> "$ev_f"
            echo "Content: ${resp:0:512}" >> "$ev_f"
            emit_finding "high" \
                "Object Storage Directory Listing Enabled: ${path}" \
                "Directory listing or bucket object enumeration is enabled at ${base_url}${path}. Sensitive files may be downloadable." \
                "Disable directory listing on all storage paths. Enforce bucket policies to deny public LIST operations. Move sensitive files out of the web root." \
                "storage_acl_${tgt//:/_}"
            (( vuln_count++ )) || true
        fi
    done

    # Check for presigned URL abuse: if a presigned URL pattern is in responses
    local home_resp
    home_resp=$(_curl -m 8 "$base_url" 2>/dev/null | head -c 8192)
    if echo "$home_resp" | grep -qiE 'X-Amz-Signature|X-Amz-Security-Token|sig=[A-Za-z0-9%]{20}|se=[0-9]{10}'; then
        emit_finding "medium" \
            "Presigned Storage URLs Exposed in Page Source" \
            "Time-limited presigned URLs for cloud storage objects are visible in the page source of ${base_url}. These may allow unintended data access during their validity window." \
            "Use short expiry times (< 15 min) for presigned URLs. Avoid embedding presigned URLs in HTML. Serve objects via authenticated API calls instead." \
            "storage_acl_${tgt//:/_}"
    fi

    [[ "$vuln_count" -eq 0 ]] && log_ok "  No public storage listing or presigned URL exposure detected"
}

# - MRK:17_T15 — T15 WAF DETECTION & BYPASS FINGERPRINTING
test_T15_waf_detection() {
    local tgt="$1" base_url
    base_url="$(_base_url "$tgt")"
    local ev_f; ev_f="$(_ev_file "$tgt" "waf_detection")"
    mkdir -p "$(dirname "$ev_f")"

    log_inf "[T15] WAF detection and bypass fingerprinting → ${base_url}"
    [[ "$DRY_RUN" -eq 1 ]] && { log_dry "send probe payloads and examine block responses"; return; }

    {
        echo "=== T15 WAF Detection ==="
        echo "Target: $base_url"
    } > "$ev_f"

    local waf_detected="" waf_evidence=""

    # Baseline response
    local base_code
    base_code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "$base_url" 2>/dev/null)

    # WAF probe payloads — safe strings that trigger WAF signatures
    local -a probes=(
        "?q=<script>alert(1)</script>"
        "?id=1%27%20OR%201%3D1"
        "?file=../../../etc/passwd"
        "?cmd=cat%20/etc/passwd"
    )

    for probe in "${probes[@]}"; do
        local probe_url="${base_url}${probe}"
        local probe_resp probe_code probe_headers
        probe_headers=$(_curl_head "$probe_url" 2>/dev/null)
        probe_code=$(_curl -m 8 -o /dev/null -w '%{http_code}' "$probe_url" 2>/dev/null)
        probe_resp=$(_curl -m 8 "$probe_url" 2>/dev/null | head -c 1024)

        echo "PROBE [${probe_code}]: ${probe}" >> "$ev_f"

        # WAF fingerprinting via headers + response body
        if echo "$probe_headers" | grep -qi 'x-sucuri-id\|x-sucuri-cache'; then waf_detected="Sucuri"; fi
        if echo "$probe_headers" | grep -qi 'cf-ray\|__cfduid'; then waf_detected="Cloudflare"; fi
        if echo "$probe_headers" | grep -qi 'x-waf-event-info\|x-firewall-protection'; then waf_detected="F5 WAF"; fi
        if echo "$probe_headers" | grep -qi 'x-akamai\|akamaighost'; then waf_detected="Akamai"; fi
        if echo "$probe_resp" | grep -qi 'request blocked\|your IP has been blocked\|Barracuda\|ModSecurity\|NAXSI\|Access Denied.*Imperva\|Incapsula'; then
            waf_detected="${waf_detected:-Generic WAF}"
        fi

        if [[ "$probe_code" == "403" ]] || [[ "$probe_code" == "406" ]] || [[ "$probe_code" == "429" ]]; then
            waf_evidence="Probe '${probe}' blocked with HTTP ${probe_code}"
        fi
    done

    if [[ -n "$waf_detected" ]]; then
        log_ok "  WAF detected: ${waf_detected}"
        echo "WAF: ${waf_detected}" >> "$ev_f"
        # WAF is positive — but log info finding so report shows coverage
        emit_finding "info" \
            "WAF Detected: ${waf_detected}" \
            "A Web Application Firewall (${waf_detected}) is active on ${base_url}. ${waf_evidence:-Probe payloads were blocked.} Further bypass testing recommended." \
            "Confirm WAF rules cover OWASP Top-10. Test for common bypass encodings. Ensure WAF is in blocking (not detection-only) mode." \
            "waf_detection_${tgt//:/_}"
    else
        log_wrn "  No WAF detected — application may have no request-level filtering"
        emit_finding "medium" \
            "No WAF Detected on ${base_url}" \
            "Probe payloads (XSS, SQLi, path traversal) were not blocked. No WAF fingerprint headers detected. The application may lack perimeter request filtering." \
            "Deploy a WAF (e.g. AWS WAF, Cloudflare, Azure Front Door WAF). Enable OWASP Core Rule Set. Monitor for attack traffic." \
            "waf_detection_${tgt//:/_}"
    fi
}

# =============================================================================
# - MRK:17_TRUN
# =============================================================================
test_target() {
    local tgt="$1"
    local find_before="$_FIND_CTR"

    log_inf "=== Testing target: ${tgt} ==="

    _test_skip T01 || test_T01_cloud_provider   "$tgt"
    _test_skip T02 || test_T02_imds_ssrf         "$tgt"
    _test_skip T03 || test_T03_storage_buckets   "$tgt"
    _test_skip T04 || test_T04_iam_creds         "$tgt"
    _test_skip T05 || test_T05_serverless        "$tgt"
    _test_skip T06 || test_T06_container_registry "$tgt"
    _test_skip T07 || test_T07_k8s_api           "$tgt"
    _test_skip T08 || test_T08_security_headers  "$tgt"
    _test_skip T09 || test_T09_cors              "$tgt"
    _test_skip T10 || test_T10_mgmt_console      "$tgt"
    _test_skip T11 || test_T11_cdn_origin        "$tgt"
    _test_skip T12 || test_T12_subdomain_takeover "$tgt"
    _test_skip T13 || test_T13_token_exposure    "$tgt"
    _test_skip T14 || test_T14_storage_acl       "$tgt"
    _test_skip T15 || test_T15_waf_detection     "$tgt"

    local find_delta=$(( _FIND_CTR - find_before ))
    echo "SUMMARY_ROW|${tgt}|findings=${find_delta}"
}

# =============================================================================
# - MRK:17_MAIN
# =============================================================================
main() {
    printf "\n${_W}╔══════════════════════════════════════════════════════╗${_N}\n"
    printf "${_W}║  PT-Orc  ·  Step 10: Cloud Security Testing          ║${_N}\n"
    printf "${_W}╚══════════════════════════════════════════════════════╝${_N}\n\n"

    log_inf "Project  : ${PROJECT_NAME}"
    log_inf "Profile  : ${SCAN_PROFILE}"
    log_inf "Provider : ${CLOUD_PROVIDER:-auto}"
    log_inf "Session  : ${SESSION_TS}"
    log_inf "Log      : ${LOG_FILE}"

    setup_profile "$SCAN_PROFILE"
    assemble_targets

    local tf="${SCRIPT_DIR}/working/${PROJ_SLUG}_cloud_targets.txt"
    if [[ ! -s "$tf" ]]; then
        log_err "No targets found. Add hosts to targets.txt or ensure MSF DB is populated."
        exit 1
    fi

    _confirm

    declare -i total_targets=0 total_findings=0
    declare -a summary_rows=()

    command -v trail_phase_start &>/dev/null && trail_phase_start "11_cloud_testing"

    while IFS= read -r tgt; do
        [[ -z "$tgt" || "$tgt" == "#"* ]] && continue
        local row
        row=$(test_target "$tgt")
        summary_rows+=("$row")
        local n_finds
        n_finds=$(echo "$row" | grep -oE 'findings=[0-9]+' | grep -oE '[0-9]+' || echo 0)
        total_findings=$(( total_findings + n_finds ))
        (( total_targets++ )) || true
    done < "$tf"

    command -v trail_phase_end &>/dev/null && trail_phase_end "11_cloud_testing"

    # Summary report
    local report_f="${SCRIPT_DIR}/working/$(ev_fname "10-cloud-summary" "md")"
    {
        printf "# Cloud Testing Summary — %s\n\n" "$PROJECT_NAME"
        printf "| Target | Findings |\n|--------|----------|\n"
        for row in "${summary_rows[@]+"${summary_rows[@]}"}"; do
            local tgt_col finds_col
            tgt_col=$(echo "$row" | cut -d'|' -f2)
            finds_col=$(echo "$row" | grep -oE 'findings=[0-9]+')
            printf "| %s | %s |\n" "$tgt_col" "$finds_col"
        done
        printf "\n**Total Targets:** %d  |  **Total Findings:** %d\n" "$total_targets" "$total_findings"
        printf "\nFindings JSONL: \`%s\`\n" "$FINDINGS_FILE"
    } > "$report_f"

    printf "\n${_G}[DONE]${_N} Cloud testing complete.\n"
    printf "  Targets  : %d\n" "$total_targets"
    printf "  Findings : %d\n" "$total_findings"
    printf "  Summary  : %s\n" "$report_f"
    printf "  Evidence : %s\n\n" "$EVIDENCE_BASE"
}

main "$@"

# L2 NAV:v1 → ./LOCAL-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
