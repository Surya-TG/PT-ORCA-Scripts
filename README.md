# PT-Orc Suite — VAPT Edition

**TechGuard Labs | v0.8.1-VAPT**

A 12-script Bash-based penetration testing orchestration suite covering DNS recon through AD/cloud security testing and consolidated report generation.

---

## Quick Start

```bash
# 1. Set your project name and targets
cd /home/kali/audit-orc-vapt/pt-orc/scripts
nano pt-orc.conf          # set PROJECT_NAME, MODE, WPSCAN_API_TOKEN

# 2. Add targets (one domain or IP per line)
nano targets.txt

# 3. Run a full web assessment
sudo ./00_pt-orc.sh --profile web --yes

# 4. Collect all findings into a report
sudo ./12_report_pack.sh --yes
```

---

## Requirements

### Kali Linux packages

```bash
sudo apt update && sudo apt install -y \
  nmap masscan curl wget jq openssl \
  dnsutils whois amass subfinder dnsx puredns \
  gobuster ffuf nikto wpscan \
  ncat smbclient enum4linux-ng ldapsearch \
  snmpwalk showmount swaks \
  redis-tools default-mysql-client postgresql-client \
  mongodb-clients tshark python3-pip
```

### Python / pip tools

```bash
pip3 install impacket certipy-ad bloodhound
```

### Optional (extends coverage)

```bash
# Nuclei (template-based vulnerability scanner)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Metasploit (used by 07_service_verify for database probes)
sudo msfdb init
```

---

## Project Layout

```
pt-orc/
  scripts/
    pt-orc.conf          ← engagement configuration (edit before running)
    targets.txt          ← target domains/IPs (one per line)
    wp_targets.txt       ← WordPress targets (auto-populated by 05/06)
    orc-common-lib.sh    ← shared functions (sourced by all scripts)
    00_pt-orc.sh         ← orchestrator — runs all steps in sequence
    01_dns_recon.sh      ← Step 1: DNS
    02_ip_analysis.sh    ← Step 2: IP/ASN/threat intel
    03_comp_scan.sh      ← Step 3: port/service scan
    04_tls_scan.sh       ← Step 4: TLS/certificate audit
    05_web_enum.sh       ← Step 5: web enumeration
    06_wpscan.sh         ← Step 6: WordPress assessment
    07_service_verify.sh ← Step 7: service vulnerability probes
    08_app_api_review.sh ← Step 8: application/API security
    09_ai_llm_review.sh  ← Step 9: AI/LLM endpoint security
    10_cloud_testing.sh  ← Step 10: cloud infrastructure
    11_active_directory.sh ← Step 11: Active Directory / Windows
    12_report_pack.sh    ← Step 12: collect findings + generate report
    evidence/            ← raw evidence files (per-IP subdirectories)
    working/             ← structured JSONL findings + markdown summaries
```

---

## Configuration (`pt-orc.conf`)

Edit before every engagement:

```bash
PROJECT_NAME="CLIENT-Jun2026-Orc"   # used in all output filenames
MODE="pte"                           # pte = external | pti = internal

WPSCAN_API_TOKEN=""                  # paste your wpscan.io API token here
WPSCAN_API_BUDGET=25                 # API calls allowed per run

# Active Directory (required for --profile ad / internal)
AD_DOMAIN="corp.example.com"
AD_DC_IP="10.10.10.1"
AD_USERNAME="user"
AD_PASSWORD="pass"                   # or leave empty and set AD_NT_HASH

# Cloud (optional — auto-detected if left empty)
CLOUD_PROVIDER="auto"               # aws | azure | gcp | auto
```

---

## Running the Suite

### Option A — Orchestrator (recommended)

The orchestrator (`00_pt-orc.sh`) runs the correct steps for your selected profile automatically.

```bash
cd pt-orc/scripts
sudo ./00_pt-orc.sh --profile <profile> --yes [OPTIONS]
```

#### Profiles

| Profile | Steps run | Use case |
|---------|-----------|----------|
| `web` | 1 2 3 4 5 6 7 8 12 | Web application PT |
| `external` | 1 2 3 4 5 6 7 8 9 12 | Full external PT |
| `internal` | 1 2 3 4 5 6 7 8 9 11 12 | Full internal PT (includes AD) |
| `api` | 1 2 4 5 7 8 12 | API-only assessment |
| `ai_llm` | 4 5 8 9 12 | AI/LLM endpoint assessment |
| `cloud` | 1 2 4 5 7 8 10 12 | Cloud infrastructure |
| `ad` | 1 2 3 7 11 12 | Active Directory only |
| `hybrid` | 1–12 | Full suite — all steps |
| `retest` | 4 5 7 8 9 12 | Retest / verification pass |

#### Common options

```bash
--yes                    # skip interactive scope prompts (required for automation)
--dry-run                # print what would run without sending packets
--from <N>               # resume from step N
--only <N>               # run exactly one step
--skip <N>               # skip a step (repeatable)
--tier ghost             # stealth mode (throttled, random UA)
--tier loud              # aggressive timing
--aggressive             # Step 7: deeper CVE probes + extra NSE scripts
--nuclei                 # Step 7: run Nuclei templates after probes
--skip-gobuster          # Step 5: skip directory brute-force
--fast                   # Steps 4+5: headers only, skip gobuster + nikto
--continue-on-error      # do not abort if a step fails
```

#### Examples

```bash
# Standard web assessment
sudo ./00_pt-orc.sh --profile web --yes

# External PT in ghost/stealth mode
sudo ./00_pt-orc.sh --profile external --tier ghost --yes

# Resume a failed run from step 5
sudo ./00_pt-orc.sh --profile web --yes --from 5

# Run only TLS scan
sudo ./00_pt-orc.sh --only 4 --yes

# Full hybrid with aggressive probes
sudo ./00_pt-orc.sh --profile hybrid --aggressive --nuclei --yes

# Dry run to preview
sudo ./00_pt-orc.sh --profile external --dry-run --yes
```

---

### Option B — Run scripts individually

Each script is self-contained and can be run standalone.

```bash
cd pt-orc/scripts
sudo ./01_dns_recon.sh
sudo ./02_ip_analysis.sh
sudo ./03_comp_scan.sh --phase all
sudo ./04_tls_scan.sh
sudo ./05_web_enum.sh
sudo ./06_wpscan.sh --detect        # detection sweep first
sudo ./06_wpscan.sh                 # then full assessment
sudo ./07_service_verify.sh
sudo ./08_app_api_review.sh
sudo ./09_ai_llm_review.sh
sudo ./10_cloud_testing.sh
sudo ./11_active_directory.sh
sudo ./12_report_pack.sh --yes
```

---

## Step-by-Step Description

| Step | Script | What it does |
|------|--------|-------------|
| 01 | `01_dns_recon.sh` | Subdomain enum (amass/subfinder/puredns), zone transfer, DNSSEC, DoH, CDN detection, 40+ takeover patterns, DNS threat intel |
| 02 | `02_ip_analysis.sh` | ASN lookup, PTR/reverse DNS, cloud IP range detection, AbuseIPDB, VirusTotal threat intel |
| 03 | `03_comp_scan.sh` | masscan + nmap port/service scan; NSE CVE scripts (EternalBlue, Shellshock, Heartbleed, POODLE, RDP, FTP, DB) |
| 04 | `04_tls_scan.sh` | Certificate validity/SAN/key size, CT log lookup, ALPACA, ROBOT, Lucky13, HSTS preload, security headers |
| 05 | `05_web_enum.sh` | gobuster/ffuf dir brute, nikto, 80+ API endpoints, GraphQL introspection, sensitive file check, CMS detection, CORS, WAF fingerprint |
| 06 | `06_wpscan.sh` | WordPress detection sweep, WPScan full enum (plugins/themes/users/vulns), XML-RPC/multicall, wp-json user enum, config file exposure, malicious plugin detection |
| 07 | `07_service_verify.sh` | 28+ service probes: Redis/MySQL/Postgres/MongoDB/Elasticsearch/etcd NOAUTH, SSH CVEs, SMB null sessions, SNMP, SMTP relay, SSRF→IMDS, Jenkins CVE-2024-23897, CUPS CVE-2024-47076 chain, Spring Actuator, and more |
| 08 | `08_app_api_review.sh` | Auth header analysis, IDOR, CORS, JWT inspection, rate-limit, OWASP API Top 10 checks |
| 09 | `09_ai_llm_review.sh` | OWASP LLM Top 10 (2025): prompt injection (21 payloads), jailbreak, training data leakage, RAG exposure, agentic SSRF, thread IDOR, model file exposure, context window attacks |
| 10 | `10_cloud_testing.sh` | Cloud provider detection, IMDS SSRF, S3/Azure/GCS bucket discovery, IAM metadata, K8s API exposure, CORS, WAF detection, subdomain takeover via cloud CNAMEs |
| 11 | `11_active_directory.sh` | DC port map, LDAP null/auth enum, Kerberoasting, AS-REP roasting, BloodHound collection, ADCS ESC1-ESC8 (certipy), GPO/SYSVOL, ACL/AdminSDHolder, delegation, domain trust mapping, DCSync rights |
| 12 | `12_report_pack.sh` | Collects JSONL findings from all steps, deduplicates, severity-ranks, builds consolidated `findings.jsonl` + markdown report |

---

## Output Files

All outputs land in `pt-orc/scripts/`:

```
working/
  <PROJECT>_01_dns_findings_<TS>.jsonl        ← structured findings per step
  <PROJECT>_02_ip_analysis_findings_<TS>.jsonl
  ...
  <PROJECT>_12_findings.jsonl                  ← consolidated (from 12_report_pack)
  <PROJECT>_wpscan_report_<TS>.md              ← WPScan markdown report
  <PROJECT>_manual_followup_<TS>.md            ← items requiring manual verification

evidence/
  <IP>/
    *.txt                                       ← raw tool output per probe
    *.json                                      ← structured evidence
```

Each JSONL finding has this structure:

```json
{
  "id": "f-07-10_10_10_1-0001",
  "title": "Redis NOAUTH — 10.10.10.1:6379",
  "severity": "critical",
  "phase": "07_service_verify",
  "evidence_ids": ["ev-07-..."],
  "description": "...",
  "recommendation": "...",
  "retest_status": "n/a",
  "residual_risk": ""
}
```

Severity levels: `critical` · `high` · `medium` · `low` · `info`

---

## Workflow for a New Engagement

```bash
cd /home/kali/audit-orc-vapt/pt-orc/scripts

# 1. Configure the engagement
nano pt-orc.conf        # set PROJECT_NAME, MODE, API tokens

# 2. Add targets
echo "target.example.com" > targets.txt

# 3. Run the appropriate profile
sudo ./00_pt-orc.sh --profile web --yes

# 4. Review inline findings
grep -h "" working/*_findings_*.jsonl | jq '.severity,.title' 2>/dev/null

# 5. Generate the final report
sudo ./12_report_pack.sh --yes

# 6. Open the report
ls working/*.md
```

---

## Notes

- All scripts require **root** (`sudo`) for raw socket operations (nmap SYN scan, masscan).
- `--dry-run` mode never sends packets — safe to test configuration.
- `--tier ghost` adds request throttling and random user-agents — use for sensitive targets.
- WordPress targets are auto-populated in `wp_targets.txt` by Step 5 and consumed by Step 6.
- AD and cloud steps require their respective config vars in `pt-orc.conf`.
- Evidence is never overwritten — each run appends with a unique `SESSION_TS` timestamp.
