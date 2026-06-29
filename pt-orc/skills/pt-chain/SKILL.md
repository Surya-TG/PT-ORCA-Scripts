---
name: pt-chain
version: "0.91"
description: >
  [v0.91] L2 — Tactical attack chain builder. Loaded by pt-orc after findings are
  collected from one or more steps. Reads JSONL findings files from working/, detects
  multi-stage attack chain sequences (where one finding enables or amplifies another),
  builds ordered chain paths with escalation outcomes, and produces ASCII chain diagrams
  and a prioritised chain report. Output feeds pt-report for chain narrative sections
  and the executive summary. Works with PTE and PTI scope. Integrates with pt-vuln
  output (CVE-enriched findings). Do NOT load directly — pt-orc dispatches this.
---

<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../../AUDIT-ORC-INDEX.md -->

<!-- MRK:SKILL_NAV_TOC — Section index | nav,toc,index | L15-28 -->
<!-- - MRK:PT_CHAIN_RECEIVED — Inputs and dispatch context          | chain,received,input,dispatch | L29-52 -->
<!-- - MRK:PT_CHAIN_DETECT   — Chain detection logic                | chain,detect,link,pivot       | L53-110 -->
<!-- - MRK:PT_CHAIN_BUILD    — Chain construction and scoring       | chain,build,score,escalation  | L111-155 -->
<!-- - MRK:PT_CHAIN_DIAGRAM  — ASCII diagram format                 | chain,diagram,ascii,format    | L156-195 -->
<!-- - MRK:PT_CHAIN_OUTPUT   — Output format (chain report)         | chain,output,report,block     | L196-235 -->
<!-- - MRK:PT_CHAIN_EXAMPLES — Example chains                       | chain,examples,sample         | L236-275 -->
<!-- NAV-LEN: 6 entries | Integrity-hash: 0000000000000000 | Last-indexed: 2026-06-29T00:00:00Z -->

# pt-chain — Tactical Attack Chain Builder
*L2 — Loaded for chain analysis. Drop after chain report produced and handed back to L1.*

---

## MRK:PT_CHAIN_RECEIVED — Inputs and dispatch context | chain,received,input,dispatch | L29-52

On dispatch, pt-orc (L1) passes:
- Working directory path (contains JSONL findings from completed steps)
- Engagement mode: `PTI` or `PTE`
- Scope context: in-scope IPs, domains, key services
- Optional: pt-vuln output (CVE-enriched findings) for chain enrichment
- Optional: specific chain request — "build chain from f-08-001" or "all chains"

Dispatch protocol:
1. Acknowledge: *"pt-chain loaded. Building attack chains from [N] finding(s)."*
2. Load all JSONL findings (Section PT_CHAIN_DETECT, Step 1).
3. Detect chain opportunities (Section PT_CHAIN_DETECT, Steps 2–4).
4. Build and score chains (Section PT_CHAIN_BUILD).
5. Produce ASCII diagrams (Section PT_CHAIN_DIAGRAM).
6. Return chain report to L1 (Section PT_CHAIN_OUTPUT).

Minimum viable chain: 2 findings that logically chain. Single-finding "chains" are not
reported — they belong in the individual finding write-up. Maximum chain depth: 6 steps.

---

## MRK:PT_CHAIN_DETECT — Chain detection logic | chain,detect,link,pivot | L53-110

### Step 1 — Load findings

```bash
# Read all JSONL findings from working directory
find ./working -maxdepth 2 -name "*findings*.jsonl" -type f | sort | xargs cat 2>/dev/null
```

For each finding line, extract: `id`, `title`, `severity`, `phase`, `description`.

Build a findings table:
```
ID          | Severity | Phase              | Title
f-05-001    | high     | 05_web_enum        | Nikto: Outdated Apache 2.4.29
f-08-001    | high     | 08_app_api_review  | JWT alg:none accepted
f-08-003    | medium   | 08_app_api_review  | Unauthenticated user enumeration
f-25-001    | high     | 25_content_sec     | Missing CSP — unsafe-inline in script-src
```

### Step 2 — Apply chain detection rules

Check each finding pair for the link patterns below. A link exists when:

**Access enabler links** — one finding opens access that another exploits:
| Source finding type | Target finding type | Link type |
|---|---|---|
| Open port / service exposed | Auth bypass / CVE on that service | `expose → exploit` |
| User enumeration (IDOR / API) | Credential stuffing / brute force | `enumerate → attack` |
| Information disclosure | Authentication bypass | `leak → bypass` |
| Missing auth on admin endpoint | Account takeover | `unauth → takeover` |

**Escalation links** — one finding enables privilege escalation:
| Source | Target | Link type |
|---|---|---|
| XSS (stored/reflected) | Session hijack / CSRF | `xss → session` |
| SSRF | IMDS / internal service access | `ssrf → pivot` |
| Deserialization | RCE | `deser → rce` |
| JWT weakness | Auth bypass → privilege escalation | `jwt → privesc` |
| Open redirect | Phishing / token theft | `redirect → token` |

**Amplification links** — one finding makes another worse:
| Source | Target | Link type |
|---|---|---|
| Missing CSP | XSS exploitability increased | `csp-absent → xss-amplified` |
| Missing HSTS | MitM → credential intercept | `no-hsts → mitm` |
| Missing SameSite cookie | CSRF exploitability | `no-samesite → csrf` |
| Stack trace / debug info | Attack surface mapping | `disclosure → map` |

### Step 3 — Filter to in-scope chains only

For PTE: exclude chains that require local/adjacent network access (AV:A or AV:L only).
For PTI: include all chain types.

### Step 4 — Group by entry point

Sort chains by their first link (the initial finding an attacker would exploit). Each entry
point becomes the start of a chain. Multiple chains may share an entry point.

---

## MRK:PT_CHAIN_BUILD — Chain construction and scoring | chain,build,score,escalation | L111-155

### Chain construction

For each chain group, build an ordered sequence:
```
[Entry finding] → [Pivot finding(s)] → [Terminal outcome]
```

Terminal outcomes (highest severity in the chain determines chain risk):
- **Full compromise**: RCE, unauthenticated admin access, credential dump
- **Data exposure**: PII access, sensitive file read, database read
- **Lateral movement**: pivot to additional hosts, SSRF to internal services
- **Account takeover**: session hijack, auth bypass, privilege escalation
- **Persistent access**: backdoor, token theft, long-lived session

### Chain risk scoring

| Chain risk | Criteria |
|---|---|
| Critical | Terminal outcome is RCE or full system compromise; no auth required at entry |
| High | Terminal outcome is account takeover or data exposure; ≤1 auth step required |
| Medium | Terminal outcome is data exposure with auth; or escalation requires chaining ≥3 findings |
| Low | Chain is theoretical; individual findings are Low or Info only |

### Chain narrative (2–4 sentences per chain)

State:
1. The entry point — what the attacker accesses first and how (no tool names)
2. The pivot — what the entry point enables
3. The terminal outcome — what is achieved at chain end
4. Why this matters to the client (business risk, one sentence)

---

## MRK:PT_CHAIN_DIAGRAM — ASCII diagram format | chain,diagram,ascii,format | L156-195

Use this diagram format for each chain. Keep it within 70 characters wide.

### Standard chain (2–4 steps):
```
  ┌─────────────────────────────────────────────────┐
  │  ATTACK CHAIN [N] — [Risk: Critical/High/Medium] │
  └─────────────────────────────────────────────────┘

  [ENTRY]  f-XX-001 — [Short finding title]
      │    Severity: High | Phase: 05_web_enum
      │    What it gives: [access/disclosure/etc.]
      ▼
  [PIVOT]  f-XX-002 — [Short finding title]
      │    Severity: High | Phase: 08_app_api_review
      │    Pivot: [what this enables]
      ▼
  [TERMINAL] f-XX-003 — [Short finding title]
             Severity: Critical | Phase: 25_content_sec
             Outcome: [Full compromise / Data exposure / etc.]
```

### Simple chain (2 steps):
```
  f-XX-001 (High) ──expose──▶ f-XX-002 (Critical)
  [entry title]               [terminal title]
  Outcome: [one line]
```

### Rules for diagrams:
- Use box-drawing characters: `┌ ─ ┐ │ └ ┘ ▼ ▶`
- Do not exceed 70 chars per line
- Severity colour is described in the narrative (never in the diagram)
- If a chain has 5+ steps, use the compact arrow form between middle steps

---

## MRK:PT_CHAIN_OUTPUT — Output format (chain report) | chain,output,report,block | L196-235

Return this block to pt-orc (L1):

```markdown
## pt-chain Report — [OrgCode] — [YYYYMMDD]

### Findings Loaded
[N] findings from [M] phase(s): [phase list]

### Chain Summary
| Chain | Risk | Steps | Entry finding | Terminal outcome |
|---|---|---|---|---|
| Chain 1 | Critical | 3 | f-XX-001 (JWT bypass) | Account takeover → RCE |
| Chain 2 | High | 2 | f-YY-003 (User enum) | Credential stuffing |

### Chain 1 — [Short description] (Risk: Critical)

[ASCII diagram]

**Narrative:**
[2–4 sentences: entry, pivot, terminal, business risk]

**Chain findings:**
- f-XX-001: [title] — [severity] — already reported in Section 2.2.X
- f-XX-002: [title] — [severity] — already reported in Section 2.2.Y

**Report placement:** Include this chain in the Executive Summary (key risks) and as a
chain narrative callout in the finding body of [highest-severity finding in chain].

---

### Chain [N] — ...

[repeat for each chain]

---

### Quick-Win Remediations
| Priority | Finding | Fix complexity | Expected chain impact |
|---|---|---|---|
| 1 | f-XX-001 | Low (config change) | Breaks chains 1 and 3 |
| 2 | f-YY-002 | Medium (code change) | Breaks chain 2 |

### Risk Amplifiers
[Any finding that appears in 2+ chains. Note: fixing this one finding breaks
multiple chains — highest-leverage remediation.]
```

---

## MRK:PT_CHAIN_EXAMPLES — Example chains | chain,examples,sample | L236-275

### Example — JWT + User Enum chain (PTE, Web/API scope)

```
  ┌─────────────────────────────────────────────┐
  │  ATTACK CHAIN 1 — Risk: Critical             │
  └─────────────────────────────────────────────┘

  [ENTRY]  f-08-003 — Unauthenticated user enumeration
      │    Severity: Medium | Phase: 08_app_api_review
      │    What it gives: Valid username list for all registered accounts
      ▼
  [PIVOT]  f-08-001 — JWT algorithm:none accepted
      │    Severity: High | Phase: 08_app_api_review
      │    Pivot: Forge a valid JWT for any enumerated username
      ▼
  [TERMINAL] f-08-007 — Admin panel accessible with forged token
             Severity: Critical (escalated) | Phase: 08_app_api_review
             Outcome: Full account takeover for any user → admin panel access
```

Narrative: An attacker can retrieve valid usernames through the unauthenticated
REST enumeration endpoint, then forge a JWT token for any of those accounts by
exploiting the algorithm:none acceptance. The forged token grants access to the
admin panel, enabling full account management and data export. This requires no
authentication at any step and is achievable in a single automated sequence.

### Example — CSP amplifying stored XSS (PTE, Web scope)

```
  f-25-001 (High) ──amplifies──▶ f-09-002 (High)
  Missing CSP / unsafe-inline     Stored XSS in comment field
  Outcome: Reliable stored XSS execution → session hijack
```

---
*pt-chain SKILL.md v0.91 — L2 | dispatched by pt-orc*
*Phase 2: Tactical attack chain builder — reads JSONL findings, chains via link-type rules, produces ASCII diagrams*

<!-- L2 NAV:v1 → ../../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
