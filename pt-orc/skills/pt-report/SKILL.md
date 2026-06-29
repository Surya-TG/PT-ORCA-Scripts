---
name: pt-report
version: "2.0"
description: >
  [v2.0] L2 — Report content generator. Converts finding stubs and JSONL findings into
  polished report sections using TechGuard house style. Covers finding bodies, section
  text, executive summary, appendices, attack chain narratives, compliance mapping
  (OWASP/PCI-DSS 4.0/ISO 27001:2022), and retest diff documentation. Input: finding
  stubs + JSONL findings from 16_report_pack + pt-chain output (optional) + engagement
  metadata from state snapshot. Output: report-ready text for insertion into .docx via
  pt-orc → docx skill handoff. Covers all 25 PT-Orc phases including Network Infra (17),
  CI/CD (18), DB Audit (19), Secrets Scan (20), Lateral Movement (21), Wireless (22),
  Auth/SSO (23), API Deep (24), Content Sec (25).
  Do NOT load directly — pt-orc dispatches this.
---

<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../../AUDIT-ORC-INDEX.md -->

<!-- MRK:SKILL_NAV_TOC — Section index | nav,toc,index | L17-47 -->
<!-- - MRK:PT_REPORT_RECEIVED    — Received from L1 (pt-orc)              | pt,report,received,l1,orc         | L48-62  -->
<!-- - MRK:PT_REPORT_INPUTS      — Input Sources                          | pt,report,inputs,input,sources    | L63-170 -->
<!-- - MRK:PT_REPORT_EXIT        — Exit Criteria                          | pt,report,exit,criteria           | L171-179 -->
<!-- - MRK:PT_REPORT_STRUCTURE   — Report Structure (PTI / PTE)           | pt,report,structure,pti,pte       | L180-236 | ⚠ read-toc-first -->
<!-- - MRK:PT_REPORT_VERSIONING  — Document Versioning                    | pt,report,versioning,document,version | L237-252 -->
<!-- - MRK:PT_REPORT_HEADINGS    — PTI Heading Structure                  | pt,report,headings,pti,heading    | L253-272 -->
<!-- - MRK:PT_REPORT_EXEC_SUMMARY — Executive Summary                     | pt,report,exec,summary,executive  | L273-315 -->
<!-- - MRK:PT_REPORT_BODY_RULES  — Finding Body Writing Rules             | pt,report,body,rules,finding      | L316-375 | ⚠ read-toc-first -->
<!-- - MRK:PT_REPORT_OBSERVATIONS — Observations Writing Rules            | pt,report,observations,writing,rules | L376-387 -->
<!-- - MRK:PT_REPORT_IDENTITY    — Device Identity Verification Rule      | pt,report,identity,device,verification | L388-408 -->
<!-- - MRK:PT_REPORT_PENDING     — Pending Actions Pre-Delivery Checklist | pt,report,pending,actions,pre     | L409-433 -->
<!-- - MRK:PT_REPORT_SUMMARY_TABLE — Findings Summary Table               | pt,report,summary,table,findings  | L434-448 -->
<!-- - MRK:PT_REPORT_SEVERITY    — Severity Classification                | pt,report,severity,classification,colors | L449-470 -->
<!-- - MRK:PT_REPORT_FINDING_TEMPLATE — Finding Body Template             | pt,report,finding,template,body   | L471-503 -->
<!-- - MRK:PT_REPORT_OBS_TEMPLATE — Observation Body Template             | pt,report,obs,template,observation | L504-520 -->
<!-- - MRK:PT_REPORT_RETEST      — Re-test Documentation (S8)            | pt,report,retest,re,test,diff     | L521-570 -->
<!-- - MRK:PT_REPORT_SEC1        — Section 1 Introduction Templates       | pt,report,sec1,section,introduction | L571-616 -->
<!-- - MRK:PT_REPORT_EVIDENCE_INDEX — Appendix C Evidence Index Template  | pt,report,evidence,index,appendix | L617-632 -->
<!-- - MRK:PT_REPORT_STYLE       — Style Rules Summary                    | pt,report,style,rules,summary     | L633-648 -->
<!-- - MRK:PT_REPORT_PITFALLS    — Common Pitfalls                        | pt,report,pitfalls,common,mistakes | L649-672 -->
<!-- - MRK:PT_REPORT_PHASE2_STUBS — Phase 2 Finding Stub Templates (17–25) | pt,report,phase2,stubs,17,25     | L673-780 -->
<!-- - MRK:PT_REPORT_CHAIN       — Attack Chain Insertion Guidance        | pt,report,chain,diagram,ascii     | L781-840 -->
<!-- - MRK:PT_REPORT_COMPLIANCE  — Compliance Mapping (OWASP/PCI-DSS/ISO 27001) | pt,report,compliance,owasp,pci,iso | L841-910 -->
<!-- NAV-LEN: 23 entries | Integrity-hash: 0000000000000000 | Last-indexed: 2026-06-29T00:00:00Z -->

# pt-report — Report Content Generator
*L2 — Loaded for S7 (report generation). Drop after report section(s) complete.*

---

## MRK:PT_REPORT_RECEIVED — Received from L1 (pt-orc) | pt,report,received,l1,orc | L48-62

On dispatch, L1 passes:
- Findings index (full list of F-XX and OBS-XX from state snapshot)
- Finding stubs (from `working/<OrgCode>_Findings_vX.X.md`) — L1 fetches relevant stubs
- Engagement metadata (scope, type PTI/PTE, client, tester, dates)
- Severity distribution table
- Report version to produce
- Specific request: "write finding F-03", "draft section 2.3.1", "executive summary", etc.
- **Optional:** pt-chain output (Section PT_REPORT_CHAIN) — pass if chains have been built
- **Optional:** baseline run dir for retest diff (Section PT_REPORT_RETEST)

---

## MRK:PT_REPORT_INPUTS — Input Sources | pt,report,inputs,input,sources | L55-94

### verify_summary_*.md (from 07_service_verify)
- **PRIMARY source** for service-level findings (DB NOAUTH, SSH CVE, FTP anon, web headers)
- Load before generating stubs for: database access, authentication, cleartext protocols
- Format: markdown tables with VULN / SAFE / UNKNOWN / MANUAL sections
- Evidence path per finding: `evidence/_verify/<ip>/<probe_type>_*.txt`
- Use VULN section rows directly as finding stubs — detail column → finding description
- UNKNOWN/MANUAL rows → flag for manual testing section of report; do not report as confirmed

### Finding Stub Templates from 07 Output

**DB NOAUTH → High finding stub (PTI) / Critical candidate (PTE):**
```
Title: Unauthenticated [MySQL/PostgreSQL/MSSQL] Access
Evidence: verify_summary VULN row + evidence/_verify/<ip>/[mysql|postgres|mssql]_noauth_*.txt
```

**SSH CVE-2024-6387 → High finding stub:**
```
Title: SSH regreSSHion Vulnerability Candidate (CVE-2024-6387)
Evidence: verify_summary VULN row + evidence/_verify/<ip>/ssh_version_*.txt
Note: "CANDIDATE" — exploitation requires race condition; confirm version before escalating
```

**FTP Anonymous → High finding stub:**
```
Title: FTP Anonymous Access Enabled
Evidence: verify_summary VULN row + evidence/_verify/<ip>/ftp_anon_*.txt
```

**Web Headers → Medium finding stub:**
```
Title: Missing HTTP Security Headers
Evidence: verify_summary VULN row + evidence/_verify/<ip>/web_generic_<port>_*.txt
Group all hosts missing same headers into one finding with affected hosts table
```

### JSONL input sources (all phases — preferred primary source from 12_report_pack)

Load `working/*_12_findings.jsonl` as the consolidated source. Each line is a complete finding record:
```json
{"id":"f-07-10_10_10_1-0001","title":"...","severity":"critical","phase":"07_service_verify",
 "evidence_ids":["ev-07-..."],"description":"...","recommendation":"...",
 "retest_status":"n/a","residual_risk":""}
```
- `severity` field maps directly to report severity — no re-rating without additional evidence
- `phase` field identifies source script for evidence path derivation
- `evidence_ids` → cross-reference to `evidence/` files for Appendix C evidence index
- Group findings by phase for section assignment, then by severity within each section

**Per-phase JSONL sources (use when 16 not yet run or for step-level detail):**
- `*_07_service_verify_findings_*.jsonl` — service probe findings (07)
- `*_08_app_api_findings_*.jsonl` — App/API review (08)
- `*_09_ai_llm_findings_*.jsonl` — AI/LLM assessment (09)
- `*_10_cloud_findings_*.jsonl` — cloud infrastructure (10)
- `*_11_ad_findings_*.jsonl` — Active Directory (11)
- `*_17_network_infra_findings_*.jsonl` — network infra (17)
- `*_18_cicd_findings_*.jsonl` — CI/CD DevOps (18)
- `*_19_database_findings_*.jsonl` — database audit (19)
- `*_20_secrets_findings_*.jsonl` — secrets scan (20)
- `*_21_lateral_findings_*.jsonl` — lateral movement (21)
- `*_22_wireless_findings_*.jsonl` — wireless (22)
- `*_23_auth_sso_findings_*.jsonl` — auth/SSO (23)
- `*_24_api_deep_findings_*.jsonl` — API deep (24)
- `*_25_content_sec_findings_*.jsonl` — content security (25)

### Finding Stub Templates for VAPT-Enhanced Phases

**Cloud IMDS Access → Critical finding stub:**
```
Title: Cloud Instance Metadata Service (IMDS) Accessible via SSRF
Evidence: working/*_10_cloud_findings_*.jsonl (severity:critical) + evidence/<IP>/_cloud/imds_*.txt
Phase: Cloud Infrastructure (Step 10)
Note: Immediate credential rotation required if keys present in response
```

**S3/GCS/Azure Bucket Exposure → High–Critical finding stub:**
```
Title: Publicly Accessible Cloud Storage Bucket — [bucket-name]
Evidence: working/*_10_cloud_findings_*.jsonl + evidence/<IP>/_cloud/bucket_*.txt
Severity: Critical if sensitive data confirmed; High if empty/public-by-design
```

**Kerberoasting → High finding stub:**
```
Title: Kerberoastable Service Accounts Identified
Evidence: working/*_11_ad_findings_*.jsonl (severity:high) + evidence/<IP>/_ad/kerberoast_*.txt
Note: List SPNs in affected hosts; offline cracking vector — no exploitation required
```

**ADCS ESC1 → Critical finding stub:**
```
Title: Active Directory Certificate Services — ESC1 Privilege Escalation (ADCS)
Evidence: working/*_11_ad_findings_*.jsonl (severity:critical) + evidence/_ad/certipy_*.txt
Phase: Active Directory (Step 11)
Note: Full certipy find output as Appendix evidence
```

**AI/LLM Prompt Injection → Critical finding stub:**
```
Title: Prompt Injection — [Endpoint Name]
Evidence: working/*_09_ai_llm_findings_*.jsonl + evidence/<IP>/_llm/prompt_injection_*.txt
Note: Include payload and response excerpt; OWASP LLM01:2025 reference
```

**JWT Algorithm:None → Critical finding stub:**
```
Title: JWT Authentication Bypass — Algorithm:None Accepted
Evidence: working/*_08_app_api_findings_*.jsonl + evidence/<IP>/_api/jwt_*.txt
Phase: App/API Review (Step 08)
```

---

## MRK:PT_REPORT_EXIT — Exit Criteria | pt,report,exit,criteria | L95-103

- Requested content produced in report-ready format
- All content evidence-based (no speculative statements)
- Style rules applied (typography, severity indicators, recommendation verbs)
- Handed back to L1 for insertion into `.docx` via docx skill

---

## MRK:PT_REPORT_STRUCTURE — Report Structure (PTI / PTE) | pt,report,structure,pti,pte | L104-150
<!-- NAV-RULE: read-toc-first -->

### PTI Report
```
Cover Page                          ← version field must match filename
Section 1 — Introduction
  1.1 Scope and Objectives
  1.2 Methodology
  1.3 Limitations
  1.6 Executive Summary             ← written last; three bold callouts + body paragraphs
Section 2 — Findings and Recommendations
  2.1 Severity of Findings — Grading Table
  2.1.1 Findings Summary            ← Section column uses 2.3.x.y subsection numbers
  2.2 External findings (PTE)       ← placeholder text if PTE not yet conducted
  2.3 Internal findings (PTI)
    2.3.x. <Thematic section>       ← Heading3; ≤8 sections, hard cap 15
      2.3.x.y. F-YY — <Title>      ← Heading4; one per finding, immediately above severity table
Appendix A — Scope Details
Appendix B — Severity Classification
Appendix C — Evidence Index / Pending Actions Checklist
Appendix D — Evidence Screenshots
```

### PTE Report
```
Cover Page
Section 1 — Introduction
Section 2 — Findings
  2.2.1 DNS Reconnaissance
  2.2.2 Network Infrastructure
  2.2.3 TLS / Certificate Assessment
  2.2.4 Security Headers
  2.2.5 Outdated Software
  2.2.6 Authentication and Access Control
  2.2.7 WordPress Security          ← include only if WordPress assessed (06_wpscan.sh)
  2.2.8 Application and API Security ← include only if 08_app_api_review.sh run with findings
  2.2.9 AI/LLM Endpoint Security    ← include only if 09_ai_llm_review.sh run with findings
  2.2.10 Cloud Infrastructure       ← include only if 10_cloud_testing.sh run with findings
  2.2.11 Network Infrastructure     ← include only if 17_network_infra.sh run with findings
  2.2.12 CI/CD and DevOps Security  ← include only if 18_cicd_devops.sh run with findings
  2.2.13 Database Security          ← include only if 19_database_audit.sh run with findings
  2.2.14 Secrets and Credential Exposure ← include only if 20_secrets_scan.sh run with findings
  2.2.15 Authentication and SSO     ← include only if 23_auth_sso.sh run with findings
  2.2.16 API Security (Deep)        ← include only if 24_api_deep.sh run with findings
  2.2.17 Content Security           ← include only if 25_content_sec.sh run with findings
  [2.2.18+ additional categories if required]
  [2.2.x  Attack Chains]            ← include only if pt-chain was run and produced chains
Appendices
```

**PTE category sequence is fixed.** Do not reorder. Add categories after 2.2.6 only.
**WordPress (2.2.7):** Include this section only when `06_wpscan.sh` was run and produced findings. If WordPress was detected but not assessed (e.g. out of RoE), note in 1.3 Limitations instead. Typical findings grouped here: XML-RPC exposure, user enumeration, vulnerable plugins/themes, config file exposure, wp-admin access without rate limiting. Evidence from `evidence/_wpscan/<label>/`.
**PTI categories are thematic.** Group findings by technology/service area. Max 8
categories, ~15 findings across all.

---

## MRK:PT_REPORT_VERSIONING — Document Versioning | pt,report,versioning,document,version | L151-166

| Change type | Increment |
|---|---|
| Typo / minor fix | +0.01 |
| Multiple small fixes | +0.02–+0.03 |
| New finding or significant rewrite | +0.1 |
| Major restructure | +1.0 |
| Coordinated final release | Round to X.0 |

**CRITICAL:** Version must be bumped in BOTH the cover page field AND the filename
before every pack. Never reissue the same version number. Never skip incrementing.
This applies even for a single-field fix.

---

## MRK:PT_REPORT_HEADINGS — PTI Heading Structure | pt,report,headings,pti,heading | L167-186

### Section headings (Heading3)
Each thematic section (2.3.x) gets a Heading3. Example:
```
2.3.1. Network Segmentation and OT Boundary Failures
2.3.2. Unauthenticated Access to OT Devices
```

### Finding headings (Heading4)
Each individual finding gets a Heading4 immediately above its severity table.
Format: `2.3.x.y. F-YY — <Short title matching summary table>`

Heading4 style: bold, navy (#1F3864), 11pt. Not italic, not blue — override Word default.

The Heading4 subsection number must also appear in the **Findings Summary table**
Section column (e.g. 2.3.1.3, not just 2.3.1).

---

## MRK:PT_REPORT_EXEC_SUMMARY — Executive Summary | pt,report,exec,summary,executive | L187-225

Write last. Structure:

1. **Engagement overview** (1–2 sentences): what was tested, when, by whom.
2. **Overall posture** (2–3 sentences): high-level characterisation. Reference severity
   distribution. Do not list individual findings.
3. **Three bold callouts** — the most significant risk themes. Each callout:
   - Opens with a **bold statement** of the risk (not a finding title)
   - Followed by 3–5 sentences of plain-English explanation
   - References specific F-XX numbers inline (not in parenthetical footnotes)
   - Includes concrete details (IP counts, storage sizes, CVE numbers where material)
   - Does NOT name tools, scan dates, or methodology
4. **Immediate priority list** — 4–6 bullet points with F-XX references.

**Bold callout tone:** Direct, specific, risk-forward. Not alarmist. Not vague.
Each callout should tell a non-technical executive exactly what is broken and why it matters.

**Example structure (not content):**
```
**OT network segmentation is effectively absent.** Five independent confirmed bridges
exist between the corporate LAN and the OT/calibration subnet: [specifics]. One bridge
additionally [compound risk]. [Consequence sentence]. F-01, F-02, F-03.

**OT devices accept unauthenticated remote access.** [Device name and IP] accepts
[access type] and allows [confirmed capability]. [Specific risk to operations].
F-04, F-05.

**The perimeter firewall patch status is unverified against critical-severity CVEs.**
[Device] is confirmed as a model affected by [CVE, CVSS score]. [Attack surface].
[Consequence if unpatched]. F-07.
```

Tone: professional, direct, non-alarmist. Readable by a non-technical executive.
**No tool names. No scan dates. IP addresses MAY appear in callouts for specificity.**
CVE numbers MAY appear in callouts when the severity/score is the key risk driver.

---

## MRK:PT_REPORT_BODY_RULES — Finding Body Writing Rules | pt,report,body,rules,finding | L226-271
<!-- NAV-RULE: read-toc-first -->

These rules are derived from Greg's editing style across the WTech PTI engagement.
They override any general guidance where they conflict.

### What to include
- What was found and where (device, IP, service, port)
- How it was confirmed (one clean sentence — no tool names, no dates, no file refs)
- The specific risk to this client's environment
- Concrete detail: IP addresses, storage sizes, version strings, CVE numbers
- Write access / read access distinction — always state which was confirmed

### What to exclude
- Tool names in finding bodies (nmap, enum4linux, services-f3.csv, etc.)
- Scan dates (2026-04-07, D-05 verification, etc.)
- File references (services-f3.csv, goahead_banner_20260407T1125.txt, etc.)
- Internal tracking codes (C-01, D-05, D-06, etc.)
- Methodology narrative ("during passive capture", "Phase 1/2 enumeration")
- Scanning methodology language ("confirmed by NSE script", "returned by db_nmap")
- Verbose technical acronym explanations (SCPI, SAMR — use them without explaining)
- Duplicate recommendations (check for overlap before adding)

### Tone and structure
- State the risk clearly without storytelling
- Bold the sub-finding title; follow immediately with the evidence-based body
- 2–4 sentences per sub-finding — tight, factual, outcome-focused
- Recommendations: outcome-focused verbs, specific config paths where known

### Host(s) table cell
- Always list specific IPs — never "Multiple hosts" without IPs
- For large host lists (10+): group by subnet prefix, list last octets only
  Format: `192.168.1.x — .15 · .25 · .39 · .71 · [...]`
          `192.168.10.x — .5 · .6 · .10`
          `Signing enforced on 192.168.1.48 only` (italic, separate line)
- Notable hosts: call out role inline (e.g. `.243 (PCRDP) · .245 (SRV2019_2)`)
- OBS Host(s) cells: populate with confirmed IPs from evidence — never leave as
  "Multiple hosts" without the actual list

### Confidence cell
- Do not include scan dates, file names, or verification session codes
- State the confirmation method in plain terms: "anonymous FTP login confirmed;
  write access demonstrated by successful directory creation"

---

## MRK:PT_REPORT_OBSERVATIONS — Observations Writing Rules | pt,report,observations,writing,rules | L272-283

- 2–4 sentences max
- Factual, neutral — no risk language, no recommendations
- No tool names, no dates, no file references, no internal tracking codes
- No SCPI explanations, no Italian app names, no URL paths unless essential
- No "was not assessed" repeated multiple times — state once what was not assessed
- No "during passive capture" — just state what was observed
- Host(s) cell: always specific IPs, never "Multiple hosts" alone

---

## MRK:PT_REPORT_IDENTITY — Device Identity Verification Rule | pt,report,identity,device,verification | L284-304

**Always verify device identity from evidence before writing any finding.**
Nmap service banners are frequently wrong. The following are known failure modes:

- **Telnet service label** — nmap commonly misidentifies generic login prompts
  (User name / Password) as specific device types (e.g. "HP Integrated Lights Out
  telnetd"). This is a false positive pattern. Always cross-reference with:
  - MAC OUI (primary — confirms vendor)
  - OS fingerprint from hosts export (ZyNOS, ZyXEL = Zyxel device)
  - FTP banner (often names the actual device/vendor)
  - Browser login page screenshot (definitive)
- **iLO / BMC identification** — requires confirmed MAC OUI (HP = 3C:D9:2B etc.)
  plus management interface login page. A telnet banner alone is not sufficient.
- **When identity is wrong in an early version** — correct ALL occurrences:
  finding title, H4 heading, summary table, finding body, all recommendations,
  cross-references in other findings (e.g. F-19 "outdated components"), appendix
  evidence index entries, appendix screenshot captions.

---

## MRK:PT_REPORT_PENDING — Pending Actions Pre-Delivery Checklist | pt,report,pending,actions,pre | L305-329

The checklist table lives in Appendix B (or C depending on template). It tracks:
- **Blocking items** (🔴 BLOCKING) — report cannot be finalized without these
- **Required client actions** (🔴 REQUIRED) — client must act before delivery

Rules:
- This table must NOT appear in the Severity Grading Table (2.1) — if an orphaned
  row appears there, delete it and add to the checklist instead
- Completed items are removed from the checklist (not marked done)
- New tester artefacts requiring client cleanup are added as 🔴 REQUIRED rows
- Each artefact row names the specific file/directory, the host IP, and the method
  to remove it (e.g. "QNAP management interface or authenticated NFS session")

**Standard artefact cleanup row format:**
```
Item:   TechGuard IT artefact on .<last_octet>
Status: 🔴 REQUIRED
Detail: <Directory/file name> created at <path> on <IP> during active testing
        (<confirmation method>). Cannot be removed by tester session. Client must
        delete manually via <method> before report delivery (F-XX).
```

---

## MRK:PT_REPORT_SUMMARY_TABLE — Findings Summary Table | pt,report,summary,table,findings | L330-344

The Section column must use **full subsection numbers** (2.3.x.y), not section numbers
(2.3.x). These correspond to the Heading4 subsections added above each finding's
severity table.

Example:
```
High | NFS World-Readable Exports (~21 TB) (F-03) | 2.3.1.3
High | Dual-NIC QNAP OT Bridge (F-01)             | 2.3.1.1
High | SMB Signing Not Enforced (F-08)             | 2.3.3.2
```

---

## MRK:PT_REPORT_SEVERITY — Severity Classification | pt,report,severity,classification,colors | L345-366

| Severity | Hex | Definition |
|---|---|---|
| Critical | #7B1C2E | RCE, unauthenticated privileged access, exfiltration path, data destruction |
| High | #C25B6E | Strong path to Critical, auth bypass, sensitive data exposure, exploitable misconfiguration |
| Medium | #C47C3A | Exploitable with credentials or chaining, information disclosure, weak auth |
| Low | #8FAF6E | Minor misconfiguration, hardening gap, limited exploitability |
| Informational | #4A7BA7 | No direct risk; context for assessor or client |
| Observation | — | No severity assigned; informational only |

**PTI scale:** No Critical tier — High is the highest. Finding severity tops at High
for internal engagements unless engagement scope explicitly permits Critical.

Applied as: left border stripe + filled circle indicator in Word. **Never coloured text.**
Body text always #000000. Header text in report always #000000 (not styled to severity colour).

**Header "Confidential" label:** Must be navy (#1F3864), not severity red. This is a
common error — check header1.xml when building or editing the template.

---

## MRK:PT_REPORT_FINDING_TEMPLATE — Finding Body Template | pt,report,finding,template,body | L367-399

Every finding body follows this structure exactly. Adapt content; do not adapt structure.

```markdown
### F-XX — <Title> [Precautionary — if applicable]

**Severity:** High / Medium / Low / Informational   ← no Critical in PTI
**Confidence:** CERTAIN / LIKELY / UNCERTAIN
**Affected Systems:** <specific IP list — never "Multiple hosts" alone>
**CVE:** <CVE-YYYY-NNNNN> / N/A

---

#### Finding(s)

1. **F-XX — <Sub-finding title>:** <Body. What was found, where, what it means.
   No tool names, no dates, no file refs. Evidence-based only. 2–4 sentences.>

2. **F-XX — <Second sub-finding if applicable>:** <Same format.>

#### Recommendation(s)

1. <Action verb> <specific action>. <Config path or method if known.>
2. <Action verb> <specific action.>
```

**Precautionary findings:** Add `[Precautionary]` to title. State explicitly in body:
*"The firmware version could not be confirmed by any unauthenticated method. This finding
is rated [severity] on a precautionary basis and will be reviewed upon receipt of [D-XX]."*

---

## MRK:PT_REPORT_OBS_TEMPLATE — Observation Body Template | pt,report,obs,template,observation | L400-416

```markdown
### OBS-XX — <Title>

**Affected Systems:** <specific IPs>

<2–4 sentences. Factual. No risk language. No recommendations.
No tool names. No dates. No internal codes.>

*Informational observation. No remediation action required.*
```

No Recommendation section. No severity. If action is needed, promote to a Finding.

---

## MRK:PT_REPORT_RETEST — Re-test Documentation (S8) | pt,report,retest,re,test,diff | L521-570

When re-testing previously reported findings, document the delta only.

```markdown
### F-XX — <Original Title> — Re-test

**Re-test date:** <date>
**Original report version:** <vX.X>
**Remediation status:** Resolved / Partially resolved / Not resolved

#### Re-test Evidence
<What was tested, how, what result was observed. No tool names in summary.>

Evidence file: `evidence/<IP>/retest_<TS>/<tool>_<TS>.txt`

#### Verdict
- **Resolved:** Vulnerability no longer present. <Brief confirmation.>
- **Partially resolved:** <What was fixed, what remains.>
- **Not resolved:** Finding stands. Original evidence and recommendation unchanged.
```

### Automated Retest Diff (16_report_pack.sh --baseline)

When step 16 was run with `--baseline <prior_run_dir>`, a `retest_diff` block is injected
into the HTML report (Section 06 Retest Comparison). The diff categorises each finding as:

| Category | Meaning |
|---|---|
| `fixed` | Present in baseline, absent in current run — verified resolved |
| `persists` | Present in both — finding unchanged |
| `regressed` | Present in both but severity INCREASED — escalate urgency in narrative |
| `new` | Absent in baseline, present in current — new finding since original test |

**Report section guidance when diff is available:**
1. Open Section 06 with a one-sentence status line: *"N of M findings from the original
   assessment have been resolved; P findings persist; Q new issues were identified."*
2. For each `regressed` finding: add a severity-bump note in the finding body —
   *"This finding was originally assessed as [old_severity]; re-test evidence indicates
   escalation to [new_severity] due to [reason]."*
3. For `new` findings: write full finding bodies as normal.
4. For `fixed` findings: write a condensed resolved stub (no recommendations).

**Executive summary language for retest engagements:**
Replace the overall posture paragraph with a before/after summary:
*"[N] of [M] previously identified findings have been remediated. [P] findings
remain unresolved, including [highest-severity persisting finding]. [Q] new issues
were identified during re-test."*

---

## MRK:PT_REPORT_SEC1 — Section 1 Introduction Templates | pt,report,sec1,section,introduction | L441-486

### 1.1 Scope and Objectives

```
TechGuard. was engaged by <Client> to conduct a <PTI/PTE>
penetration test of <scope description>. The assessment was conducted between
<start date> and <end date>.

The objectives of this engagement were to:
- Identify vulnerabilities within the assessed environment
- Evaluate the effectiveness of existing security controls
- Provide actionable recommendations to reduce risk

[PTI:] The internal assessment covered <N> hosts across <N> subnets.
[PTE:] The external assessment covered <N> confirmed in-scope IP addresses across <N> domains.
```

### 1.2 Methodology

```
Testing was conducted in accordance with industry-standard methodologies, incorporating
elements of OWASP, PTES, and NIST SP 800-115. The engagement proceeded through the
following phases: reconnaissance, enumeration, vulnerability assessment, and
[exploitation / validation — if applicable under RoE].

All testing was performed from [tester network position]. No social engineering or
physical testing was performed unless explicitly noted.
```

### 1.3 Limitations

```
This assessment represents a point-in-time evaluation. The security posture of the
environment may change after the assessment date.

[Add if applicable:]
- Certain hosts were excluded from active testing at the client's request: <list>
- Exploitation was limited by the Rules of Engagement to [describe limitation]
- Domain authentication enumeration required domain credentials not available during
  this engagement; targeted follow-up is recommended.
- [Any other scoping limitation]
```

---

## MRK:PT_REPORT_EVIDENCE_INDEX — Appendix C Evidence Index Template | pt,report,evidence,index,appendix | L487-502

```markdown
| Finding | Evidence File | Tool | Description |
|---|---|---|---|
| F-01 | evidence/<IP>/<tool>_<TS>.txt | <tool> | <what output shows> |
| F-01 | evidence/<IP>/manual_<desc>_<TS>.txt | manual | <what was confirmed> |
```

Screenshot captions in Appendix D: when a nmap service label is a known false positive
(e.g. "HP Integrated Lights Out telnetd" on a Zyxel switch), note it explicitly in the
caption: *"The Telnet service was incorrectly labeled by nmap as [label] — a false
positive on the generic login prompt. Right pane: browser confirms [actual device]."*

---

## MRK:PT_REPORT_STYLE — Style Rules Summary | pt,report,style,rules,summary | L503-518

- Body text: Arial, #000000, no exceptions
- H1 (section titles): Arial, #1F3864, white text on navy fill
- H2 (subsection): Arial, #2E75B6
- H4 (finding subsection): Arial, bold, #1F3864, 11pt — not italic, not blue
- Finding title row: severity colour fill, white bold text
- Tables: navy header (#1F3864) white bold text; alternating white/#F2F2F2 rows; thin #CCCCCC borders
- Severity indicator: left border stripe (4pt, severity colour) + filled circle (●) before title
- No coloured body text. No coloured Rating columns. Severity by fill/stripe only.
- Header "Confidential" label: #1F3864 navy — never severity red (#C25B6E)
- Finding IDs: F-XX (zero-padded), OBS-XX
- Version in filename AND internal cover page field — both must match

---

## MRK:PT_REPORT_PITFALLS — Common Pitfalls | pt,report,pitfalls,common,mistakes | L519-542

| Pitfall | Correct approach |
|---|---|
| Version not bumped before packing | Bump cover page field AND filename before every pack — no exceptions |
| "Multiple hosts" in Host(s) cell | Always list specific IPs; group by subnet prefix for large lists |
| Tool names in finding body | Remove — state what was found, not how it was found |
| Scan dates in finding body | Remove — no dates in finding prose |
| File references in body | Remove — no services-f3.csv, no log filenames |
| Internal codes (C-01, D-05) in body | Remove — for analyst working notes only |
| Nmap service banner accepted as device identity | Cross-check MAC OUI + OS fingerprint + FTP banner + browser screenshot |
| TechGuard IT artefact row in Grading Table | Move to Pending Actions checklist |
| Findings Summary Section column shows 2.3.x | Must be 2.3.x.y (full subsection number) |
| H4 heading missing above finding table | Insert Heading4 with subsection number before every severity table |
| F-18 body starts with "Life OS" | Correct prefix is "End-of-Life OS" — check replacement didn't strip "End-of" |
| Duplicate recommendation added | Review all existing recs before adding; merge if overlapping |
| Observation body references tool or date | Strip — observations are 2–4 factual sentences only |
| "Confidential" in header is red | Set to #1F3864 navy in header1.xml |

---

## MRK:PT_REPORT_PHASE2_STUBS — Phase 2 Finding Stub Templates (17–25) | pt,report,phase2,stubs,17,25 | L673-780

JSONL source pattern: `working/*_NN_<step>_findings_*.jsonl` where NN = step number.

**Network Device Default Credentials (17) → High finding stub:**
```
Title: Network Device — Default or Weak Credentials
Evidence: working/*_17_network_infra_findings_*.jsonl + evidence/<IP>/_netinfra/snmp_*.txt
Phase: Network Infrastructure (Step 17)
Note: Include affected device IPs and community strings or credentials confirmed
```

**SNMP Community String Exposure (17) → Medium finding stub:**
```
Title: SNMP Community String Readable — Device Configuration Exposed
Evidence: working/*_17_network_infra_findings_*.jsonl + evidence/<IP>/_netinfra/snmp_walk_*.txt
Note: Confirm if write-community also disclosed; group all affected devices into one finding
```

**Jenkins Unauthenticated Access (18) → Critical finding stub:**
```
Title: CI/CD Platform — Unauthenticated Script Console Access (Jenkins)
Evidence: working/*_18_cicd_findings_*.jsonl + evidence/<IP>/_cicd/jenkins_*.txt
Note: Script console = arbitrary code execution on build agent; immediate lockdown required
```

**K8s API Unauthenticated (18) → Critical finding stub:**
```
Title: Kubernetes API Server — Unauthenticated Access
Evidence: working/*_18_cicd_findings_*.jsonl + evidence/<IP>/_cicd/k8s_api_*.txt
Note: Confirm namespace list and pod create capability; if present → Critical
```

**Database Unauthenticated Access (19) → High-Critical finding stub:**
```
Title: Unauthenticated [MySQL/MSSQL/PostgreSQL/MongoDB] Access
Evidence: working/*_19_database_findings_*.jsonl + evidence/<IP>/_db/[dbtype]_noauth_*.txt
Severity: Critical for production PII stores, High for dev/staging
Note: State confirmed databases/collections accessible; data type if determinable
```

**Hardcoded Credentials in Web-Accessible Path (20) → High finding stub:**
```
Title: Credentials Exposed in Publicly Accessible File
Evidence: working/*_20_secrets_findings_*.jsonl + evidence/<IP>/_secrets/secret_file_*.txt
Note: Redact credential value in finding body; include only file path and credential type
```

**SMB Share with Sensitive Files (20) → High finding stub:**
```
Title: Sensitive Files Accessible via Unauthenticated SMB Share
Evidence: working/*_20_secrets_findings_*.jsonl + evidence/<IP>/_secrets/smb_spider_*.txt
Note: List share name(s) and file category (config, backup, credentials); no file contents
```

**Pass-the-Hash Lateral Movement Surface (21) → High finding stub:**
```
Title: Pass-the-Hash Lateral Movement Possible
Evidence: working/*_21_lateral_findings_*.jsonl + evidence/<IP>/_lateral/pth_*.txt
Phase: Lateral Movement (Step 21)
Note: State which hosts accept NTLM auth without credential validation; no actual hash used
```

**WPA2 Weak Passphrase / PMKID Exposure (22) → High finding stub:**
```
Title: Wireless Network — Weak Pre-Shared Key (PMKID Captured)
Evidence: working/*_22_wireless_findings_*.jsonl + evidence/_wireless/pmkid_*.txt
Note: State SSID and cipher suite; confirm offline cracking surface only — no actual crack
```

**OAuth Token Leakage via Open Redirect (23) → High finding stub:**
```
Title: OAuth 2.0 — Authorization Code/Token Leakage via Open Redirect
Evidence: working/*_23_auth_sso_findings_*.jsonl + evidence/<IP>/_auth/oauth_redirect_*.txt
Phase: Auth / SSO (Step 23)
```

**SAML Signature Bypass (23) → Critical finding stub:**
```
Title: SAML Authentication Bypass — Signature Validation Not Enforced
Evidence: working/*_23_auth_sso_findings_*.jsonl + evidence/<IP>/_auth/saml_*.txt
Note: Confirm whether unsigned SAML assertions are accepted; if yes → Critical
```

**GraphQL Introspection Enabled (24) → Medium finding stub:**
```
Title: GraphQL Introspection Enabled in Production
Evidence: working/*_24_api_deep_findings_*.jsonl + evidence/<IP>/_api/graphql_introspect_*.txt
Note: List discovered types and mutations; flag any admin mutations reachable without auth
```

**BOLA / IDOR on Object Identifier (24) → High finding stub:**
```
Title: Broken Object Level Authorisation (BOLA) — [Endpoint Name]
Evidence: working/*_24_api_deep_findings_*.jsonl + evidence/<IP>/_api/bola_*.txt
Note: State object type, ID range confirmed accessible, data type exposed; OWASP API1:2023
```

**Missing Content Security Policy — unsafe-inline (25) → Medium finding stub:**
```
Title: Permissive Content Security Policy — unsafe-inline Permitted
Evidence: working/*_25_content_sec_findings_*.jsonl + evidence/<IP>/_csp/csp_header_*.txt
Note: State which directives are affected; note if combined with XSS finding (chain candidate)
```

---

## MRK:PT_REPORT_CHAIN — Attack Chain Insertion Guidance | pt,report,chain,diagram,ascii | L781-840

Use this section when pt-chain output has been passed alongside finding stubs.

### Where to place chains in the report

| Report type | Chain placement |
|---|---|
| PTE | Dedicated subsection at end of Section 2 (e.g. 2.2.x Attack Chains) |
| PTI | As callout boxes inside the most relevant thematic section (2.3.x) |
| Executive Summary | Reference chains by number in bold callouts ("Attack Chain 1 demonstrates...") |

### Insertion format

For each chain from pt-chain, insert the ASCII diagram block verbatim, then follow
with the chain narrative:

```markdown
#### Attack Chain [N] — [Short description] (Risk: [Critical/High/Medium])

[INSERT ASCII DIAGRAM FROM pt-chain — verbatim, inside a code block]

**Chain narrative:** [2–4 sentences from pt-chain output. Entry point → pivot → terminal
outcome → business risk. No tool names.]

**Findings in this chain:**
- [F-XX] — [title] (severity) — see Section 2.x.y
- [F-YY] — [title] (severity) — see Section 2.x.z

**Remediation priority:** Breaking [F-XX] (the entry point) eliminates this chain.
```

### ASCII diagram rules

- Use pt-chain diagram verbatim — do not reformulate box-drawing characters in Word
- Wrap diagram in a monospace text box (Courier New, 9pt, no border) in the .docx
- Keep each diagram under 70 characters wide — Word will not auto-wrap
- Diagram nodes reference finding IDs (f-XX-NNN) — these must match the F-XX IDs
  used in the report (strip the step-number prefix when formatting: f-08-001 → F-01)

### Executive summary integration

When chains are present, replace or extend Bold Callout 1 with the highest-risk chain:
*"**A multi-step attack chain leads from [entry finding] to [terminal outcome] without
requiring authentication.** [Chain narrative sentence.] This chain is detailed in
Section 2.x.y (Attack Chain 1)."*

List the number of distinct chains in the Immediate Priority list:
*"Resolve Attack Chain 1 (Critical) — fixing [F-XX] eliminates this chain entirely."*

---

## MRK:PT_REPORT_COMPLIANCE — Compliance Mapping (OWASP/PCI-DSS/ISO 27001) | pt,report,compliance,owasp,pci,iso | L841-910

Include a compliance mapping appendix (Appendix D or E) when explicitly requested
or when the engagement scope includes compliance-relevant systems.

### OWASP Top 10 2021 — mapping guide

Each finding's `owasp_id` (set by 16_report_pack.sh AI enrichment) maps to:

| ID | Category | Typical PT-Orc findings |
|---|---|---|
| A01 | Broken Access Control | BOLA (24), IDOR, unauth admin, privilege escalation |
| A02 | Cryptographic Failures | Weak TLS (05), missing HSTS, plaintext creds (20) |
| A03 | Injection | SQLi (13), GraphQL injection (24), command injection |
| A04 | Insecure Design | Business logic bypass (24), race conditions |
| A05 | Security Misconfiguration | Missing headers (06/25), SNMP (17), K8s open API (18) |
| A06 | Vulnerable and Outdated Components | CVE findings from 08/14 |
| A07 | Identification and Authentication Failures | JWT bypass (09/24), OAuth issues (23) |
| A08 | Software and Data Integrity Failures | CI/CD supply chain (18), SRI missing (25) |
| A09 | Security Logging and Monitoring Failures | Rate limiting absent (09) |
| A10 | SSRF | SSRF findings (08/09) |

### PCI-DSS 4.0 — key requirement mappings

Include only when scope includes card-data environments (CDE) or pre-auth to CDE.

| Requirement | Scope | PT-Orc finding types |
|---|---|---|
| 6.2.4 | Secure coding practices | Injection, XSS, SSTI |
| 6.3.2 | Software inventory | Outdated components (14) |
| 6.4.1 | Web app protection (WAF/review) | Any unmitigated High web finding |
| 8.3.6 | Password complexity | Weak/default creds (17, 19, 21) |
| 8.6.1 | System/app accounts | Service account exposure (12, 21) |
| 10.7 | Failure to detect security events | Rate limiting absent, logging gaps |
| 11.3.1 | Internal penetration testing | Confirms scope coverage |
| 12.3.2 | Targeted risk analysis | Use finding severity + chain risk |

**PCI-DSS note:** State requirement number inline in recommendations only, not in finding
body. Format: *"(PCI-DSS 4.0 Req 6.4.1)"* at end of relevant recommendation bullet.

### ISO 27001:2022 — Annex A control mappings

Include only when client has ISO 27001 certification or is seeking certification.

| Control | Title | PT-Orc finding types |
|---|---|---|
| A.8.7 | Protection against malware | Outdated software, unpatched CVEs |
| A.8.8 | Management of technical vulnerabilities | CVE findings, missing patches |
| A.8.9 | Configuration management | Misconfigs (05, 06, 17, 18, 25) |
| A.8.20 | Networks security | SNMP (17), VLAN hopping (17), wireless (22) |
| A.8.22 | Segregation of networks | Segmentation failures (17, 21) |
| A.8.23 | Web filtering | CSP absent (25), content injection |
| A.8.24 | Use of cryptography | TLS failures (05), weak ciphers |
| A.8.25 | Secure development lifecycle | CI/CD security (18), SRI (25) |
| A.8.28 | Secure coding | Injection, XSS, SSTI, deserialization |
| A.5.14 | Information transfer | Plaintext protocols, credential exposure (20) |

**ISO 27001 note:** Reference Annex A controls in Appendix only. Do not embed control
numbers in finding bodies — they clutter the prose and are meaningless to non-ISO clients.

---
*pt-report SKILL.md v2.0 — L2 | dispatched by pt-orc*
*v2.0: Phase 2 (17–25) stub templates, attack chain insertion, compliance mapping (OWASP/PCI-DSS/ISO 27001), baseline retest diff guidance*

<!-- L2 NAV:v1 → ../../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
