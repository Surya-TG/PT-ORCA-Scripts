---
name: pt-evidence
version: "0.82"
description: >
  [v0.82] L2 — Evidence processor. Converts raw tool output into structured finding
  stubs. Input: pasted tool output, JSONL file reference, or evidence file. Output:
  validated finding stub ready to append to Findings .md. Handles three-stream
  correlation, JSONL finding ingestion, and validation state assignment.
  Covers all 12 script phases including JSONL output from 06–11 and consolidated
  12_findings.jsonl. Do NOT load directly — pt-orc dispatches this.
---

<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../../AUDIT-ORC-INDEX.md -->

<!-- MRK:SKILL_NAV_TOC — Section index | nav,toc,index | L14-26 -->
<!-- - MRK:PT_EVIDENCE_RECEIVED — Received from L1 (pt-orc) | pt,evidence,received,l1,orc | L27-37 -->
<!-- - MRK:PT_EVIDENCE_EXIT — Exit Criteria | pt,evidence,exit,criteria | L38-47 -->
<!-- - MRK:PT_EVIDENCE_PIPELINE — Processing Pipeline | pt,evidence,pipeline,processing,steps | L48-154 | ⚠ read-toc-first -->
<!-- - MRK:PT_EVIDENCE_TOOL_GUIDE — Tool Output Interpretation Guide | pt,evidence,tool,guide,output | L155-225 | ⚠ read-toc-first -->
<!-- - MRK:PT_EVIDENCE_OUTPUT — Output — Evidence Processing Block | pt,evidence,output,processing,block | L226-263 -->
<!-- NAV-LEN: 5 entries | Integrity-hash: 823035b042462217 | Last-indexed: 2026-06-09T07:09:41Z -->

# pt-evidence — Evidence Processor
*L2 — Loaded when raw output needs processing into structured findings. Drop after stubs produced.*

---

## MRK:PT_EVIDENCE_RECEIVED — Received from L1 (pt-orc) | pt,evidence,received,l1,orc | L27-37

On dispatch, L1 passes:
- Raw output: pasted text OR file reference (`evidence/<IP>/<file>` or `evidence/_wpscan/<label>/<file>`)
- Source tool: what generated the output (or "unknown" if unclear)
- Target IP and port/service if known
- Existing findings index (to check for duplicates / updates vs. new)
- Any analyst annotation accompanying the output

---

## MRK:PT_EVIDENCE_EXIT — Exit Criteria | pt,evidence,exit,criteria | L38-47

- All issues in the raw output identified and classified
- Each issue: new stub produced OR existing stub updated
- Validation states assigned
- Nothing in the raw output left unclassified
- Output block handed to L1

---

## MRK:PT_EVIDENCE_PIPELINE — Processing Pipeline | pt,evidence,pipeline,processing,steps | L48-154
<!-- NAV-RULE: read-toc-first -->

### Step 1 — Parse and Inventory

Read the raw output. Produce an inventory of all security-relevant items found:

```
[ITEM] <brief description> | <tool signal> | <potential severity>
```

Flag items that are:
- Definitive findings (clear misconfiguration, confirmed vulnerability, anonymous access, etc.)
- Potential findings (version number requiring CVE check, non-default behaviour, unexpected open port)
- Noise (expected services, informational only, tester's own IPs)
- Ambiguous (needs second stream or analyst confirmation)

**DNS/OSINT output (from 01_dns_recon.sh or pasted recon output):**
- Subdomain takeover candidate → definitive finding (Critical or High depending on service)
- Third-party/CDN IP in scope → flag as out-of-scope, do not create finding
- Zone transfer success (AXFR) → High finding — internal DNS data exposed
- Subdomain resolving to internal RFC1918 IP → flag for scope review
- CNAME pointing to unclaimed service → definitive finding (takeover candidate)

**IP range analysis output (from 02_ip_range_analysis.sh):**
- Cloud-hosted IP confirmed client-owned → inventory note only; no finding
- Cloud-hosted IP with unclear ownership → flag as open issue; do not create finding until confirmed
- BGP/ASN mismatch with stated scope → flag for client confirmation
- Multiple IPs sharing ASN/prefix → group in inventory; may indicate scope expansion opportunity

### Step 2 — Deduplicate Against Existing Findings

For each item, check against the findings index from L1:
- **Exact match:** Update existing stub — add this evidence as additional stream. Promote validation state if warranted.
- **Related match:** Note relationship in both stubs.
- **New:** Assign next available FID (or placeholder `F-NEW-<desc>` if FID sequence not confirmed).

### Step 3 — Three-Stream Classification

For each issue, determine which streams are populated:

| Stream | Signal |
|---|---|
| MSF DB | Output from `db_nmap`, `hosts`, `services`, or imported scan |
| Automated | Tool output: nmap, testssl, masscan, snmpwalk, nikto, enum4linux, wpscan, hydra, etc. |
| Manual | curl, smbclient, dig, manual terminal session, analyst observation |

Assign validation state:
- 1 stream only → `detected`
- 2 streams or 1 stream + analyst annotation → `suspected`
- Confirmed by exploitation / active proof / 2 independent tool streams → `validated`
- Validated + screenshot or console log excerpt → `high_confidence`

### Step 4 — Severity Assignment

Assign severity based on **impact**, not tool rating:

| Severity | Basis |
|---|---|
| Critical | RCE, unauthenticated admin access, exfiltration path, privileged credential exposure |
| High | Strong path to Critical (e.g. write access to sensitive share, auth bypass, CVE with known exploit) |
| Medium | Information disclosure, weak auth, exploitable with credentials or chaining |
| Low | Minor misconfiguration, hardening gap, limited exposure |
| Informational | No direct risk; context for the assessor |

**Precautionary rule:** If severity is Critical or High based on version match / CVE but exploitation was not performed or not possible under RoE — mark `[Precautionary]` and set confidence to LIKELY. Do not downgrade severity; downgrade confidence instead.

**PTI scale:** No Critical tier. High is the maximum severity for internal engagements. Any finding that would be Critical externally is rated High in PTI.

**PTE external exposure escalation:** When processing output from a PTE engagement, apply the following severity baseline — external exposure alone escalates severity regardless of exploitability:

| Service externally exposed | Minimum severity |
|---|---|
| Any database (MySQL, MSSQL, MongoDB, Redis, Elasticsearch) | Critical candidate |
| Telnet | Critical |
| RDP | High |
| LDAP (anonymous bind or open) | High |
| FTP (anonymous login) | High |
| SNMP (public community) | High |
| Admin panel / management interface | High |
| WordPress XML-RPC enabled (brute vector) | Medium–High |
| WordPress user enumeration via REST API | Medium |

Cross-reference with pt-enum external exposure severity table when mode is PTE.

### Step 5 — Produce Stubs

One stub per finding using the schema from pt-enum. For updates to existing stubs, produce a delta block:

```markdown
## UPDATE: <FID> — <Title>

### New Evidence Added
| Stream | Path | Description |
|---|---|---|
| <stream> | <path> | <what it adds> |

### Validation State Change
<old state> → <new state>
Basis: <what justified the promotion>

### Notes
<any analyst context or caveats>
```

---

## MRK:PT_EVIDENCE_TOOL_GUIDE — Tool Output Interpretation Guide | pt,evidence,tool,guide,output | L155-225
<!-- NAV-RULE: read-toc-first -->

Quick reference for common tools — what to look for:

**nmap / db_nmap**
- Open ports → inventory; unexpected ports → potential finding
- Service version → CVE lookup trigger
- Script output (smb-protocols, smb2-security-mode, ftp-anon, snmp-info) → direct finding signals
- OS fingerprint → inventory; EOL OS → finding

**testssl**
- Grade F / expired cert → Critical or High
- SSLv2/SSLv3/TLS 1.0/1.1 enabled → Medium or High depending on exposure
- Weak ciphers (RC4, DES, EXPORT) → Medium-High
- Missing HSTS / cert chain issues → Low-Medium
- POODLE, BEAST, LUCKY13, LOGJAM, SWEET32, DROWN, Heartbleed → severity per CVE

**snmpwalk / snmp-check**
- Response to `public` community → confirmed SNMPv1/v2c misconfiguration
- Sensitive MIB data (interface IPs, routing table, installed software) → escalates severity

**enum4linux / enum4linux-ng**
- Null session → High
- User enumeration → Medium
- Share list without auth → High if sensitive shares exposed

**showmount / nfs**
- `*` in exports or world-accessible export → Critical (write) or High (read)
- Confirm with mount attempt if RoE permits

**ftp (nmap ftp-anon script or manual)**
- Anonymous login → confirm with STOR test
- Write confirmed → Critical (persistent access path)
- Read only → High (data exposure)

**nikto / dirb / ffuf**
- Admin panels exposed → High
- Default credentials page → High
- Backup files / config exposure → Medium-High
- Directory listing → Low-Medium

**CrackMapExec / crackmapexec smb**
- Signing: False → High (relay attack surface)
- Guest / anonymous access → High
- Password policy → context for brute force findings

**wpscan / 06_wpscan.sh output**
- Vulnerable plugin with known CVE → High if RCE/auth bypass, Medium if info disclosure
- Vulnerable theme → same severity logic as plugin
- XML-RPC enabled → Medium (brute-force vector); escalate if paired with user enumeration
- User enumeration via REST API (`/wp-json/wp/v2/users`) → Medium
- wp-config.php / debug.log exposed → Critical (credentials) or High (debug data)
- readme.html / install.php exposed → Low-Medium (version disclosure, installer exposure)
- wp-admin login with no rate limiting → Medium
- Outdated WordPress core with known CVE → severity per CVE

**02_ip_range_analysis.sh / ip_range_report**
- Cloud-hosted IP with client-confirmed ownership → inventory note, no finding
- Cloud-hosted IP (AWS/GCP/Azure/CF) not confirmed client-owned → open issue, do not scan
- IP in BGP prefix not matching stated ASN → flag for client review
- PTR resolving to cloud provider pattern → cloud flag; verify ownership

**05_web_enum.sh headers / CORS output**
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.) → Low-Medium per header
- CORS reflected origin + `Access-Control-Allow-Credentials: true` → High
- CORS wildcard (`*`) without credentials → Low-Medium
- API endpoint returning non-404 with unexpected data → potential finding; requires follow-up

**07_service_verify.sh JSONL output (working/*_07_service_verify_findings_*.jsonl)**
- Load with `jq '.' findings.jsonl` — each line is a structured finding
- severity: critical/high/medium/low/info — use as-is; do not re-rate without additional evidence
- Jenkins CVE-2024-23897 → Critical; always Precautionary until `@/etc/passwd` content confirmed
- CUPS CVE-2024-47076 chain → Critical; mark as chain (4 CVEs) in finding body
- etcd NOAUTH → Critical; evidence at `evidence/_verify/<ip>/etcd_noauth_*.txt`
- Spring Actuator → High (env/credentials) or Medium (metrics only)
- Elasticsearch/Kibana NOAUTH → Critical (data exposure path); confirm index contents

**08_app_api_review.sh output (app_api_headers_*.txt, api_endpoints_*.txt)**
- CORS reflected-origin + `Access-Control-Allow-Credentials: true` → High
- Auth header absent on authenticated endpoints → Medium (needs Burp chaining to confirm IDOR)
- Rate-limit absent on auth/brute-force-able endpoint → Medium
- JWT `alg: none` → Critical (authentication bypass); JWT weak HS256 secret → High
- IDOR candidate (predictable IDs in responses) → flag as MANUAL; needs chained confirmation
- OWASP API Top 10 items surfaced → assign per individual issue, not blanket rating

**09_ai_llm_review.sh JSONL output (working/*_09_ai_llm_findings_*.jsonl)**
- Prompt injection (payload reflected/executed) → Critical; include payload + response as evidence
- Training data leakage (PII/confidential output) → High; screenshot/capture the response
- RAG document exposure (internal doc titles/content surfaced) → High
- Agentic SSRF (out-of-band callback received) → Critical; confirm with `evidence/<IP>/_llm/ssrf_*.txt`
- Thread IDOR (cross-session data contamination) → High; two-session PoC required for high_confidence
- Items in `manual_followup_*.md` from step 09 → always MANUAL status; requires human verification

**10_cloud_testing.sh JSONL output (working/*_10_cloud_findings_*.jsonl)**
- IMDS 169.254.169.254 response received → Critical; `evidence/<IP>/_cloud/imds_*.txt` is the evidence
- Public bucket list/read confirmed (S3/GCS/Azure blob) → Critical if sensitive data, High if empty/public-by-design — confirm data type before rating
- K8s API `/api/v1/namespaces` returns namespaces without auth → Critical (unauthenticated cluster access)
- IAM key metadata in IMDS response → Critical; flag as potential lateral movement / cloud privesc vector
- Cloud CNAME takeover candidate → High; confirm DNS CNAME still points to unclaimed endpoint

**11_active_directory.sh JSONL output (working/*_11_ad_findings_*.jsonl, evidence/_ad/bloodhound_*.zip)**
- Kerberoastable accounts returned → High (offline cracking vector); list SPNs in finding body
- AS-REP roasting targets (no pre-auth) → Medium-High; escalate if privileged accounts
- ADCS ESC1 confirmed (certipy find output) → Critical (certificate-based domain privesc)
- ADCS ESC2–ESC8 → High-Critical per template; include certipy finding name in stub
- DCSync rights outside Domain Admins group → Critical; include samAccountName in evidence
- AdminSDHolder misconfiguration → High; include affected principal in stub
- BloodHound path to Domain Admin → severity depends on hop count: 1-2 hops = Critical, 3+ = High
- Domain trust relationships → High if trust allows SID history or unconstrained delegation

**12_report_pack.sh consolidated findings (working/*_12_findings.jsonl)**
- Load as primary structured source for all report phase work
- `jq -c '[.severity,.title,.phase]' findings.jsonl | sort` — grouped severity view
- `retest_status` field: "n/a" = not yet retested, "fixed" = resolved, "open" = persists post-retest
- `residual_risk` field — populated during re-test phase; empty = not yet assessed
- Duplicate detection: 12 deduplicates across phases; if same issue in multiple JSONL files, one entry survives in consolidated output
- `evidence_ids` array — cross-reference to raw evidence files in `evidence/`

---

## MRK:PT_EVIDENCE_OUTPUT — Output — Evidence Processing Block | pt,evidence,output,processing,block | L226-263

Return to L1 on exit:

```markdown
## Evidence Processing — <OrgCode> — <source> — <YYYYMMDD>

### Source
- Tool: <tool name>
- Target: <IP>:<port> or <hostname> or <WordPress URL>
- File: evidence/<IP>/<filename> (or evidence/_wpscan/<label>/<filename>) (or "pasted")

### Items Identified
| Item | Classification | Action |
|---|---|---|
| XML-RPC enabled, methodResponse returned | New finding — Medium (brute vector) | F-NEW-xmlrpc → stub below |
| WP user enumeration via REST API | New finding — Medium | F-NEW-wp-usenum → stub below |
| readme.html exposed | Low | F-NEW-wp-readme → stub below |

### Stubs Produced
<paste stubs here>

### Updates to Existing Findings
<paste delta blocks here>

### Unclassified / Needs Follow-up
- <item requiring second stream, analyst verification, or client input>

### Recommended Next Actions
- <e.g. "Confirm wp-config.php exposure with curl; screenshot required for high_confidence">
- <e.g. "Confirm cloud IP ownership with client before including in active scan">
```

---
*pt-evidence SKILL.md v0.82 — L2 | dispatched by pt-orc*
*VAPT enhancements: tool guides for 07 JSONL, 08 App/API, 09 AI/LLM, 10 Cloud, 11 AD, 12 consolidated findings*
<!-- NAV-NEEDS-REINDEX: 2026-06-16 — extended tool guide; line ranges shifted -->

<!-- L2 NAV:v1 → ../../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
