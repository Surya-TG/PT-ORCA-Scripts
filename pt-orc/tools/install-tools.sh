#!/usr/bin/env bash
# install-tools.sh — PT-Orc-Suite dependency installer for Kali Linux
#
# Checks and installs all tools required by steps 01–25 of PT-Orc-Suite.
# Safe to re-run: already-installed tools are skipped with a SKIP notice.
#
# Usage:
#   sudo bash tools/install-tools.sh            # install everything
#   sudo bash tools/install-tools.sh --check    # report missing tools only (no install)
#   sudo bash tools/install-tools.sh --dry-run  # show what would be installed
#   sudo bash tools/install-tools.sh --group <name>  # install one group only
#
# Groups: core | recon | web | fuzz | wireless | db | ad | cloud | secrets | exploit
#
# Requirements: Kali Linux (apt), Go ≥ 1.21, Python 3.10+, pip3
# =============================================================================

set -uo pipefail

# --- colour ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

log()   { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[SKIP]${NC}  $* — already installed"; }
inst()  { echo -e "${BLUE}[INST]${NC}  installing $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR] ${NC}  $*" >&2; }
hdr()   { echo -e "\n${YELLOW}━━━ $* ━━━${NC}"; }

MODE="install"    # install | check | dry-run
ONLY_GROUP=""
INSTALLED=0
SKIPPED=0
FAILED=0
FAILED_LIST=()

for arg in "$@"; do
    case "$arg" in
        --check)   MODE="check" ;;
        --dry-run) MODE="dry-run" ;;
        --group)   ;;  # next arg captured below
        --help|-h) grep -E "^#" "$0" | sed 's/^# \{0,1\}//' | head -30; exit 0 ;;
    esac
done
# capture --group value
prev=""
for i in "$@"; do
    [[ "$prev" == "--group" ]] && ONLY_GROUP="$i"
    prev="$i"
done

# --- privilege check ---
if [[ "$MODE" == "install" && $EUID -ne 0 ]]; then
    err "Run as root:  sudo bash tools/install-tools.sh"
    exit 1
fi

# --- helpers ---

# check_cmd <cmd> [<display-name>]
check_cmd() {
    command -v "${1}" &>/dev/null
}

# apt_install <pkg> [<cmd-to-check>]
apt_install() {
    local pkg="$1" cmd="${2:-$1}"
    if check_cmd "$cmd"; then ok "$cmd ($pkg)"; SKIPPED=$((SKIPPED+1)); return; fi
    [[ "$MODE" == "check" ]]   && { warn "MISSING  $cmd (apt: $pkg)"; FAILED=$((FAILED+1)); FAILED_LIST+=("$pkg"); return; }
    [[ "$MODE" == "dry-run" ]] && { inst "$cmd (apt: $pkg) [dry-run]"; return; }
    inst "$cmd (apt: $pkg)"
    if apt-get install -y -qq "$pkg" &>/dev/null; then
        INSTALLED=$((INSTALLED+1))
    else
        err "apt install failed: $pkg"; FAILED=$((FAILED+1)); FAILED_LIST+=("$pkg")
    fi
}

# pip_install <package> [<cmd>]
pip_install() {
    local pkg="$1" cmd="${2:-$1}"
    if check_cmd "$cmd"; then ok "$cmd (pip: $pkg)"; SKIPPED=$((SKIPPED+1)); return; fi
    [[ "$MODE" == "check" ]]   && { warn "MISSING  $cmd (pip: $pkg)"; FAILED=$((FAILED+1)); FAILED_LIST+=("pip:$pkg"); return; }
    [[ "$MODE" == "dry-run" ]] && { inst "$cmd (pip: $pkg) [dry-run]"; return; }
    inst "$cmd (pip: $pkg)"
    if pip3 install --quiet "$pkg" &>/dev/null; then
        INSTALLED=$((INSTALLED+1))
    else
        err "pip install failed: $pkg"; FAILED=$((FAILED+1)); FAILED_LIST+=("pip:$pkg")
    fi
}

# go_install <import-path> <cmd>
go_install() {
    local pkg="$1" cmd="$2"
    if check_cmd "$cmd"; then ok "$cmd (go: $pkg)"; SKIPPED=$((SKIPPED+1)); return; fi
    if ! check_cmd go; then
        warn "SKIP $cmd — go not found; install Go ≥ 1.21 first"
        FAILED=$((FAILED+1)); FAILED_LIST+=("go:$cmd"); return
    fi
    [[ "$MODE" == "check" ]]   && { warn "MISSING  $cmd (go: $pkg)"; FAILED=$((FAILED+1)); FAILED_LIST+=("go:$pkg"); return; }
    [[ "$MODE" == "dry-run" ]] && { inst "$cmd (go: $pkg) [dry-run]"; return; }
    inst "$cmd (go: $pkg)"
    if GOPATH="${GOPATH:-$HOME/go}" go install "${pkg}@latest" &>/dev/null; then
        INSTALLED=$((INSTALLED+1))
    else
        err "go install failed: $pkg"; FAILED=$((FAILED+1)); FAILED_LIST+=("go:$pkg")
    fi
}

# git_install <repo-url> <install-dir> <cmd> [<post-cmd>]
git_install() {
    local url="$1" dir="$2" cmd="$3" post="${4:-}"
    if check_cmd "$cmd"; then ok "$cmd (git: $url)"; SKIPPED=$((SKIPPED+1)); return; fi
    [[ "$MODE" == "check" ]]   && { warn "MISSING  $cmd (git: $url)"; FAILED=$((FAILED+1)); FAILED_LIST+=("git:$cmd"); return; }
    [[ "$MODE" == "dry-run" ]] && { inst "$cmd (git: $url) [dry-run]"; return; }
    inst "$cmd from $url"
    if git clone --depth 1 "$url" "$dir" &>/dev/null && [[ -n "$post" ]]; then
        bash -c "$post" &>/dev/null && INSTALLED=$((INSTALLED+1)) || { err "post-install failed for $cmd"; FAILED=$((FAILED+1)); FAILED_LIST+=("git:$cmd"); }
    elif [[ -z "$post" ]]; then
        INSTALLED=$((INSTALLED+1))
    else
        err "git clone failed: $url"; FAILED=$((FAILED+1)); FAILED_LIST+=("git:$cmd")
    fi
}

run_group() {
    [[ -z "$ONLY_GROUP" || "$ONLY_GROUP" == "$1" ]]
}

# =============================================================================
# GROUP: core — system utilities pre-installed on Kali but verified anyway
# =============================================================================
if run_group core; then
hdr "Core utilities"
apt_install curl
apt_install wget
# Go — required for projectdiscovery tools, dalfox, crlfuzz, gitleaks
if ! check_cmd go; then
    [[ "$MODE" == "check" ]]   && { warn "MISSING  go (golang)  — required for several tools"; FAILED=$((FAILED+1)); FAILED_LIST+=("golang"); } || \
    [[ "$MODE" == "dry-run" ]] && inst "golang [dry-run]" || {
        inst "golang (via apt)"
        if apt-get install -y -qq golang &>/dev/null; then
            INSTALLED=$((INSTALLED+1))
            export PATH="$PATH:$(go env GOPATH)/bin"
        else
            err "golang install failed — go tools will be skipped"
            FAILED=$((FAILED+1)); FAILED_LIST+=("golang")
        fi
    }
else
    ok "go (golang)"
    SKIPPED=$((SKIPPED+1))
    export PATH="$PATH:$(go env GOPATH)/bin"
fi
apt_install jq
apt_install whois
apt_install traceroute
apt_install iproute2       ip
apt_install openssl
apt_install ncat           ncat
apt_install python3
apt_install python3-pip    pip3
apt_install libimage-exiftool-perl exiftool
fi

# =============================================================================
# GROUP: recon — DNS, OSINT, passive recon
# =============================================================================
if run_group recon; then
hdr "Recon / OSINT (steps 01–02)"
apt_install nmap
apt_install masscan
apt_install dnsutils       dig
apt_install amass
apt_install subfinder
go_install  github.com/projectdiscovery/dnsx/cmd/dnsx       dnsx
go_install  github.com/projectdiscovery/httpx/cmd/httpx     httpx
go_install  github.com/d3mondev/puredns/v2                  puredns
pip_install shodan          shodan
apt_install theharvester   theHarvester
apt_install trufflehog
apt_install gitleaks
fi

# =============================================================================
# GROUP: web — HTTP enumeration (steps 05, 08–10, 12, 13)
# =============================================================================
if run_group web; then
hdr "Web enumeration (steps 05, 08–13)"
apt_install gobuster
apt_install ffuf
apt_install nikto
apt_install whatweb
apt_install wafw00f
apt_install wpscan
# testssl.sh — installed as 'testssl' on Kali
if ! check_cmd testssl; then
    apt_install testssl.sh testssl
fi
go_install  github.com/projectdiscovery/naabu/v2/cmd/naabu  naabu
# ssh-audit
if ! check_cmd ssh-audit; then
    pip_install ssh-audit ssh-audit
fi
fi

# =============================================================================
# GROUP: fuzz — active fuzzing / injection (step 11)
# =============================================================================
if run_group fuzz; then
hdr "Active fuzzing (step 11)"
apt_install sqlmap
# dalfox XSS fuzzer
go_install  github.com/hahwul/dalfox/v2     dalfox
# nuclei
go_install  github.com/projectdiscovery/nuclei/v3/cmd/nuclei nuclei
# commix
apt_install commix
# arjun — hidden parameter discovery
pip_install arjun arjun
# tplmap — SSTI
if ! check_cmd tplmap; then
    git_install https://github.com/epinna/tplmap.git /opt/tplmap tplmap \
        "pip3 install -r /opt/tplmap/requirements.txt -q && ln -sf /opt/tplmap/tplmap.py /usr/local/bin/tplmap && chmod +x /opt/tplmap/tplmap.py"
fi
# ghauri — advanced SQLi
if ! check_cmd ghauri; then
    git_install https://github.com/r0oth3x49/ghauri.git /opt/ghauri ghauri \
        "pip3 install -r /opt/ghauri/requirements.txt -q && ln -sf /opt/ghauri/ghauri.py /usr/local/bin/ghauri && chmod +x /opt/ghauri/ghauri.py"
fi
# crlfuzz
go_install  github.com/dwisiswant0/crlfuzz/cmd/crlfuzz  crlfuzz
fi

# =============================================================================
# GROUP: wireless — 802.11 tools (step 07)
# =============================================================================
if run_group wireless; then
hdr "Wireless (step 07)"
apt_install aircrack-ng    airmon-ng
apt_install hcxdumptool
fi

# =============================================================================
# GROUP: db — database clients (step 22)
# =============================================================================
if run_group db; then
hdr "Database clients (step 22)"
apt_install postgresql-client psql
apt_install default-mysql-client mysql
apt_install redis-tools       redis-cli
# mongosh — MongoDB shell
if ! check_cmd mongosh; then
    warn "mongosh not in apt; install manually: https://www.mongodb.com/docs/mongodb-shell/install/"
    FAILED=$((FAILED+1)); FAILED_LIST+=("mongosh")
fi
fi

# =============================================================================
# GROUP: ad — Active Directory testing (steps 20–21)
# =============================================================================
if run_group ad; then
hdr "Active Directory (steps 20–21)"
apt_install ldap-utils       ldapsearch
# netexec / crackmapexec
if ! check_cmd netexec && ! check_cmd crackmapexec; then
    pip_install netexec netexec
fi
[[ "$(check_cmd netexec; echo $?)" -ne 0 ]] && ok "netexec or crackmapexec"
# impacket suite
if ! check_cmd impacket-GetUserSPNs; then
    pip_install impacket impacket-GetUserSPNs
fi
# bloodhound-python
pip_install bloodhound bloodhound
# certipy-ad (ADCS enumeration)
pip_install certipy-ad certipy
fi

# =============================================================================
# GROUP: cloud — cloud & CI/CD testing (steps 17–19)
# =============================================================================
if run_group cloud; then
hdr "Cloud & CI/CD (steps 17–19)"
# awscli v2
if ! check_cmd aws; then
    [[ "$MODE" == "check" ]] && { warn "MISSING  aws (awscli)"; FAILED=$((FAILED+1)); FAILED_LIST+=("awscli"); } || \
    [[ "$MODE" == "dry-run" ]] && inst "awscli [dry-run]" || {
        inst "awscli v2"
        curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip &>/dev/null \
            && unzip -q /tmp/awscliv2.zip -d /tmp/aws-install \
            && /tmp/aws-install/aws/install &>/dev/null \
            && INSTALLED=$((INSTALLED+1)) || { err "awscli install failed"; FAILED=$((FAILED+1)); FAILED_LIST+=("awscli"); }
        rm -rf /tmp/awscliv2.zip /tmp/aws-install
    }
fi
# kubectl
if ! check_cmd kubectl; then
    [[ "$MODE" == "check" ]] && { warn "MISSING  kubectl"; FAILED=$((FAILED+1)); FAILED_LIST+=("kubectl"); } || \
    [[ "$MODE" == "dry-run" ]] && inst "kubectl [dry-run]" || {
        inst "kubectl"
        curl -fsSL "https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
            -o /usr/local/bin/kubectl &>/dev/null \
            && chmod +x /usr/local/bin/kubectl \
            && INSTALLED=$((INSTALLED+1)) || { err "kubectl install failed"; FAILED=$((FAILED+1)); FAILED_LIST+=("kubectl"); }
    }
fi
fi

# =============================================================================
# GROUP: secrets — secrets / config scanning (step 19)
# =============================================================================
if run_group secrets; then
hdr "Secrets scanning (step 19)"
# gitleaks — try apt first, fall back to go install
if ! check_cmd gitleaks; then
    apt_install gitleaks
fi
if ! check_cmd gitleaks; then
    go_install github.com/zricethezav/gitleaks/v8  gitleaks
fi
# trufflehog — try apt first
apt_install trufflehog
fi

# =============================================================================
# GROUP: exploit — MSF, ExploitDB (steps 03, 06, 22)
# =============================================================================
if run_group exploit; then
hdr "Exploitation framework (steps 03, 06, 22)"
apt_install metasploit-framework msfconsole
apt_install exploitdb            searchsploit
fi

# =============================================================================
# POST-INSTALL: nuclei templates + PATH reminder
# =============================================================================
if [[ "$MODE" == "install" ]]; then
    if check_cmd nuclei && [[ ! -d "${HOME}/.local/nuclei-templates" ]] && [[ ! -d "${HOME}/nuclei-templates" ]]; then
        log "Pulling nuclei community templates…"
        nuclei -update-templates &>/dev/null || true
    fi
    # Ensure Go bin is in PATH
    if check_cmd go; then
        GOBIN="$(go env GOPATH)/bin"
        if [[ ":$PATH:" != *":${GOBIN}:"* ]]; then
            warn "Add Go bin to PATH:  export PATH=\"\$PATH:${GOBIN}\""
            warn "  Add to ~/.bashrc or ~/.zshrc to persist"
        fi
    fi
fi

# =============================================================================
# SUMMARY
# =============================================================================
echo ""
echo -e "${YELLOW}━━━ Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
printf "  Installed : %d\n" "$INSTALLED"
printf "  Skipped   : %d (already present)\n" "$SKIPPED"
printf "  Failed    : %d\n" "$FAILED"
if [[ ${#FAILED_LIST[@]} -gt 0 ]]; then
    echo -e "\n${RED}  Failed packages:${NC}"
    for f in "${FAILED_LIST[@]}"; do echo "    - $f"; done
fi
echo ""
if [[ "$FAILED" -eq 0 ]]; then
    echo -e "${GREEN}  All tools accounted for.${NC}"
else
    echo -e "${YELLOW}  Run with --check to re-verify after manual fixes.${NC}"
fi
