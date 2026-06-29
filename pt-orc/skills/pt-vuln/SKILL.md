---
name: pt-vuln
version: "0.91"
description: >
  [v0.91] L2 — CVE exploitation path advisor. Loaded by pt-orc for deep vulnerability
  analysis. Accepts a CVE ID (CVE-YYYY-NNNNN) or product+version string. Looks up
  CVE details via NVD API v2 and ExploitDB using orc-ai-lib.sh helpers, decodes the
  CVSS attack vector, assesses PoC availability and weaponization likelihood, then
  cross-references the engagement's JSONL findings for chaining opportunities.
  Output enriches finding stubs for pt-chain and pt-report. Covers external PTE and
  web/API scope. Do NOT load directly — pt-orc dispatches this.
---

<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../../AUDIT-ORC-INDEX.md -->

<!-- MRK:SKILL_NAV_TOC — Section index | nav,toc,index | L15-28 -->
<!-- - MRK:PT_VULN_RECEIVED  — Inputs and dispatch context          | vuln,received,input,dispatch | L29-50 -->
<!-- - MRK:PT_VULN_LOOKUP    — CVE and PoC lookup procedure         | vuln,lookup,nvd,edb,osv      | L51-105 -->
<!-- - MRK:PT_VULN_ASSESS    — Exploitation assessment              | vuln,assess,cvss,complexity  | L106-155 -->
<!-- - MRK:PT_VULN_XREF      — Engagement cross-reference           | vuln,xref,findings,chain     | L156-190 -->
<!-- - MRK:PT_VULN_OUTPUT    — Output format                        | vuln,output,format,block     | L191-235 -->
<!-- - MRK:PT_VULN_EXAMPLES  — Example analyses                     | vuln,examples,sample         | L236-270 -->
<!-- NAV-LEN: 6 entries | Integrity-hash: 0000000000000000 | Last-indexed: 2026-06-29T00:00:00Z -->

# pt-vuln — CVE Exploitation Path Advisor
*L2 — Loaded per vulnerability analysis objective. Drop after exploitation analysis produced.*

---

## MRK:PT_VULN_RECEIVED — Inputs and dispatch context | vuln,received,input,dispatch | L29-50

On dispatch, pt-orc (L1) passes one of:

| Input form | Example |
|---|---|
| CVE ID | `CVE-2024-6387` |
| Product + version | `"OpenSSH 8.9p1"` |
| Finding ID from engagement | `f-08-001` (pull product from JSONL) |

Also received:
- Engagement mode: `PTI` or `PTE`
- Working directory path (for JSONL findings access)
- Scope context: in-scope IPs, domains, services (from state snapshot)
- Optional: CVSS score already known (skip NVD lookup and go straight to assessment)

Dispatch protocol:
1. Acknowledge: *"pt-vuln loaded. Analysing [input] for [engagement]."*
2. Perform lookup (Section PT_VULN_LOOKUP).
3. Produce exploitation assessment (Section PT_VULN_ASSESS).
4. Cross-reference engagement findings (Section PT_VULN_XREF).
5. Return output block to L1 (Section PT_VULN_OUTPUT).

---

## MRK:PT_VULN_LOOKUP — CVE and PoC lookup procedure | vuln,lookup,nvd,edb,osv | L51-105

### Step 1 — NVD lookup

Run via orc-ai-lib.sh. The command depends on what was passed:

**CVE ID lookup:**
```bash
source ./orc-ai-lib.sh
nvd_cve_lookup_keyword "CVE-2024-6387" 5
```

**Product + version keyword lookup:**
```bash
source ./orc-ai-lib.sh
# Strip OS/distro suffix first: "OpenSSH 8.9p1 Ubuntu 3ubuntu0.10" → "OpenSSH 8.9p1"
nvd_cve_lookup_keyword "OpenSSH 8.9p1" 20
```

Each result line is JSON: `{"cve_id":"CVE-...","published":"...","description":"...","cvss_score":"...","severity":"...","references":[...]}`

Parse and record: cve_id, cvss_score, severity, description, references.

### Step 2 — ExploitDB / searchsploit lookup

```bash
source ./orc-ai-lib.sh
exploitdb_search "OpenSSH 8.9"
```

Each result line: `{"edb_id":"...","title":"...","date":"...","type":"...","path":"...","source":"exploitdb"}`

Note: `type` values: `webapps`, `remote`, `local`, `shellcode`. Prefer `remote` for PTE scope.

### Step 3 — OSV lookup (package vulnerabilities only)

Use only when the target is a known package ecosystem (npm, PyPI, Maven, etc.):

```bash
source ./orc-ai-lib.sh
osv_lookup "werkzeug" "PyPI"
osv_lookup "lodash" "npm"
```

Skip OSV for OS-level services (OpenSSH, Apache httpd, nginx) — use NVD instead.

### Lookup failure handling

If NVD is unreachable (`_nvd_reachable` returns 0): note the limitation and proceed
with ExploitDB only. If both fail: state "CVE data unavailable from offline vantage
point — manual NVD cross-reference required" and produce the assessment from the CVE
description if one was provided by L1.

---

## MRK:PT_VULN_ASSESS — Exploitation assessment | vuln,assess,cvss,complexity | L106-155

For each CVE retrieved, produce an exploitation assessment covering:

### CVSS vector decode

Read `cvss_score` (base score, 0.0–10.0) and decode the attack vector from the description
or NVD metric fields:

| Vector | Meaning | PTE relevance |
|---|---|---|
| AV:N (Network) | Exploitable remotely | High — directly relevant |
| AV:A (Adjacent) | Exploitable on adjacent network | Medium — LAN/VLAN only |
| AV:L (Local) | Requires local access | Low for external PTE |
| AV:P (Physical) | Requires physical presence | Out of PTE scope |

| Complexity | Meaning |
|---|---|
| AC:L | No special conditions needed — straightforward exploitation |
| AC:H | Race condition, specific config, or timing required |

| Privileges required | Meaning |
|---|---|
| PR:N | No authentication needed — most dangerous externally |
| PR:L | Low-privilege account needed |
| PR:H | Admin access needed |

### PoC availability rating

Based on ExploitDB results:

| Condition | PoC rating |
|---|---|
| EDB entry within 12 months with `remote` type | **Weaponized** — active exploit available |
| EDB entry older than 12 months | **Public PoC** — requires adaptation |
| No EDB entry; NVD refs include GitHub PoC link | **Proof of concept** — confirm at reference |
| No EDB; CVSS ≥7.5 and widely reported | **Likely weaponized** — check Metasploit modules |
| No PoC evidence | **Theoretical** — exploitation not publicly demonstrated |

### Weaponization likelihood

Combine CVSS vector and PoC rating into a single likelihood statement:

- **Immediate**: AV:N, AC:L, PR:N + Weaponized PoC
- **High**: AV:N, AC:L, any PR + Public PoC, or AV:N, AC:H + Weaponized PoC
- **Moderate**: AV:N, AC:H + Theoretical PoC, or AV:A + Public PoC
- **Low**: AV:L or AV:P, or CVSS < 4.0

---

## MRK:PT_VULN_XREF — Engagement cross-reference | vuln,xref,findings,chain | L156-190

After completing the CVE assessment, cross-reference against the engagement's findings:

### Load engagement findings

```bash
# Find all JSONL finding files in the working directory
find ./working -maxdepth 2 -name "*findings*.jsonl" -type f | sort
```

Read each JSONL line. Fields: `id`, `title`, `severity`, `phase`, `evidence_ids`, `description`.

### Cross-reference logic

For each engagement finding, check:

1. **Direct match** — finding description or title mentions the same product/version as the CVE.
   → Record as `chain_candidate: direct`

2. **Service match** — the CVE affects the same service type (e.g. CVE on Apache httpd, finding
   on web server config). → Record as `chain_candidate: service`

3. **Amplification** — the CVE finding, if exploited, would escalate an existing Medium finding
   to Critical (e.g. auth bypass CVE + exposed admin panel finding).
   → Record as `chain_candidate: amplifier`

4. **No match** — CVE is out of scope for current engagement targets.
   → State "No current engagement findings are amplified by this CVE."

### Chaining notation

When chain candidates are found, produce a chain note:
```
Chain: [finding-id] → [CVE-YYYY-NNNNN] → [escalation outcome]
Example: f-05-001 (OpenSSH exposed) → CVE-2024-6387 (regreSSHion) → Remote unauthenticated RCE
```

---

## MRK:PT_VULN_OUTPUT — Output format | vuln,output,format,block | L191-235

Return this block to pt-orc (L1) on completion:

```markdown
## pt-vuln Analysis — [CVE-ID or product] — [YYYYMMDD]

### CVE Summary
| Field         | Value |
|---|---|
| CVE ID        | CVE-YYYY-NNNNN |
| CVSS Score    | X.X ([severity]) |
| Attack Vector | AV:N / AV:A / AV:L / AV:P |
| Complexity    | AC:L / AC:H |
| Privileges    | PR:N / PR:L / PR:H |
| Published     | YYYY-MM-DD |

### Exploitation Assessment
**PoC availability:** [Weaponized / Public PoC / Theoretical]
**Weaponization likelihood:** [Immediate / High / Moderate / Low]

[2–4 sentences describing the attack vector, what an attacker achieves, and any
race conditions or prerequisites. No tool names. Evidence-based only.]

### PoC References
- ExploitDB [EDB-ID]: [title] ([date], type: [type])
- [Additional references from NVD]

### Engagement Cross-Reference
| Finding ID | Title | Chain type | Escalation outcome |
|---|---|---|---|
| f-XX-YYY | [title] | [direct/service/amplifier] | [description] |

[If no match:] No current engagement findings are amplified by this CVE.

### Recommended Actions
1. [Specific version-upgrade or patch action]
2. [Compensating control if patch not yet available]
3. [Verification step — confirm patch is applied to all in-scope instances]

### Confidence
[Certain / Firm / Tentative] — [basis: version confirmed / banner only / inference]
```

---

## MRK:PT_VULN_EXAMPLES — Example analyses | vuln,examples,sample | L236-270

### Example A — regreSSHion (CVE-2024-6387)

```
CVE ID: CVE-2024-6387 | CVSS: 8.1 (High) | AV:N, AC:H, PR:N
PoC: Public PoC (ExploitDB + GitHub); race condition required
Weaponization: High — race condition reduces exploitation window to minutes on modern
  hardware; Metasploit module available.
Engagement cross-ref: f-04-001 (SSH service exposed on 65.61.137.117:22, OpenSSH 8.9p1)
  → direct match → Remote unauthenticated RCE candidate
Chain: f-04-001 → CVE-2024-6387 → privilege escalation → full host compromise
Confidence: Firm — version confirmed via service banner; exploitation not attempted per RoE
```

### Example B — CVSS ≥ 9 but scoped out

```
CVE ID: CVE-2021-44228 (Log4Shell) | CVSS: 10.0 | AV:N, AC:L, PR:N
Engagement cross-ref: No Java application identified in scope. No engagement findings
  match. Log4Shell does not apply to assessed scope.
Outcome: Not applicable — note in limitations if client uses Java applications outside scope.
```

---
*pt-vuln SKILL.md v0.91 — L2 | dispatched by pt-orc*
*Phase 2: CVE exploitation path advisor — integrates orc-ai-lib.sh (nvd/exploitdb/osv lookups)*

<!-- L2 NAV:v1 → ../../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
