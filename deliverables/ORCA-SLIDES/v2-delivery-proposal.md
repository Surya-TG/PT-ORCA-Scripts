<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

<!-- NAV-LEN: 0 entries | UNMRKD -->

# ORCa — Delivery Proposal for TechGuard (v2)

**From**: ERA
**To**: TechGuard (attn: Hari — Technical Lead Manager, TechGuard India)
**Date**: 2026-04-27
**Status**: v2 — platform built; deployment + integration scope

---

## 1. Executive summary

ORCa — TechGuard's cyber-operations platform — is built and delivered. This proposal covers the deployment + Entra integration scope (M1 + M3, ~200–260h) to take the delivered platform from "skills in repo" to "TechGuard analysts independently operational."

The platform delivers three things:

- **nav-orc** (navigation + orchestration layer) — 7 skills, indexed file protocol, persistent project state, session warm-start, seat-controlled access. Any engagement resumes in two file reads across any session boundary.
- **pt-orc** (pentest execution suite) — 7-phase pipeline, 7 companion AI skills, evidence hash + chain of custody. Runs on the nav-orc platform.
- **Operator guides** — 5 documents covering install, indexed navigation, project workflow, task board, and README. All in `docs/`.

The access model is **Restricted Framed Seats** — three nested layers (org ceiling → seat frame → project perms) with five seat types (anonymous, analyst, senior, admin, restricted). No custom shared-AI broker required. Each analyst uses their own Claude seat; the seat frame governs access. Entra ID → seat auto-detection is M3.

**Two open items for Hari's decision**: repo ownership and first engagement scope (slide 20 of v7 deck).

---

## 2. What TechGuard receives

### 2.1 Platform (nav-tools + pt-orc)

- `audit-orc/` repo: tracked (private), containing nav-orc suite, pt-orc suite, shared docs
- **7 nav-orc skills**: nav_bare, nav_core, nav_project_proc, nav_action_plan_proc, nav_profile, nav_commit, nav_ext — full suite loads with `/nav_ext`
- **7 pt-orc skills**: pt-orc (orchestrator), pt-recon, pt-enum, pt-evidence, pt-report, pt-commands, pt-monitor
- **7 pt-orc phase scripts**: 00_bootstrap → 06_report; MSF-DB-backed; evidence pipeline end-to-end
- **orc-nav-reindex tool**: keeps indexes and integrity hashes current; run-on-commit via pre-commit hook
- **Seat wrapper scripts**: `orc-seat-start.ps1` / `.sh` — sets seat type at session start

### 2.2 Operator guides

All in `audit-orc/docs/`:

| Guide | Covers |
|---|---|
| `getting-started.md` | Install, first session, project creation |
| `nav-v1-user-guide.md` | Reading indexed files — TOC, anchors, precise range fetch |
| `nav-project-proc-guide.md` | Project lifecycle — create, log, offload, handover, close |
| `nav-action-plan-proc-guide.md` | Task board, session notes, reminders, custom shortcuts |
| `README.md` | Suite overview, install summary |

### 2.3 TechGuard methodology materials

- `docs/tg-unified-audit-methodology-v0.3.md` — 9-stage lifecycle with MethodologyPack architecture, EngagementCore integration points, TG-specific placeholders (`TG-CORE-CONTEXT`, `TG-ANL-CHAIN`)
- Aligned with DCPTCN_TG deliverables (commit 23e0f78): PHASE1–PHASE5 analysis, 6 MethodologyPack definitions, 5 architecture decision records

---

## 3. Scope — M1 + M3 (~200–260h)

Two milestones, gate-approved before proceeding:

| Milestone | Focus | Hours | Gate |
|-----------|-------|------:|------|
| M1 | Deployment + TG onboarding + first engagement | 100–120 | Analyst independent on ORCa |
| M2 | Additional shadowing (optional) | 40–60 | Second engagement complete |
| M3 | Entra group → seat auto-detection | 60–80 | Seat auto-assign live |

Full breakdown in `v2-scope-500h.md`.

---

## 4. Architecture

### 4.1 Repository structure

```
audit-orc/
├── nav-orc/
│   ├── skills/        7 AI skills (nav_bare, nav_core, nav_project_proc, ...)
│   ├── tools/         orc-nav-reindex — keeps file indexes current
│   └── spec/          nav-orc specification
├── pt-orc/
│   ├── scripts/       Phase scripts 00–07
│   ├── skills/        7 AI companion skills
│   └── spec/          PT-Orc methodology docs
└── docs/              Operator guides
```

### 4.2 nav-orc indexed file protocol

Every source file carries: L1 ORC-NAV header + L2 NAV:v1 domain index path + MRK:NAV_TOC block with sections and line ranges + integrity hash. AI reads the TOC (20–30 lines), gets the exact range it needs, fetches those lines — not the whole file. 10–15× context savings per session. Cold project resume in two reads: beacon (~30 lines) + NEXT document (full project state).

### 4.3 Restricted Framed Seats — access model

Three nested layers:

```
Org ceiling  (set by admin seat — maximum any seat can reach)
    │
    ▼
Seat frame   (set by seat type: anonymous / analyst / senior / admin / restricted)
    │
    ▼
Project perms (set per project — engagement-scoped restrictions)
```

Seat type is set at session start by `orc-seat-start.ps1` / `.sh`. M3 replaces this with Entra group → seat type auto-detection (M365-native, no new infrastructure).

### 4.4 TechGuard platform vision (DCPTCN_TG alignment)

```
tg-audit-orchestrator [planned — DCPTCN_TG]
├── EngagementCore         shared planning kernel (all MethodologyPacks)
└── MethodologyPacks (6)
    ├── PentestPack         adversarial engagements — powered by PT-Orc
    ├── ISO27001Pack        standards consulting
    ├── GapAnalysisPack
    ├── SecurityAssessPack
    ├── RiskAssessPack
    └── RemediationPack

ORCa (delivered today)
├── nav-tools              protocol + session layer for all MethodologyPacks
└── PT-Orc                 execution layer for PentestPack
```

ORCa is the execution and methodology layer. tg-audit-orchestrator is the planned orchestration layer above it (DCPTCN_TG scope, Phase A migration from current Decepticon architecture).

---

## 5. What's built vs. what this scope adds

| Delivered (in repo) | This scope adds |
|---|---|
| 7 nav-orc skills | Skills installed + configured on TG analyst machines |
| 7 pt-orc skills + 7 phase scripts | First engagement run together; TG-specific config applied |
| Restricted Framed Seats architecture | Seat wrapper scripts configured + Entra auto-detection (M3) |
| 5 operator guides | Guide calibration + TG-specific additions from M1 feedback |
| TG Unified Methodology v0.3 | — (already produced; M3 roadmap alignment with DCPTCN_TG) |
| orc-nav-reindex tool | Pre-commit hook installed in TG's workflow |

---

## 6. Open architecture decisions (for Hari)

Both from slide 20 of the v7 deck:

**A. Repo ownership**
1. TechGuard-owned GitHub org — cleanest Entra integration path; TG controls admin seat
2. Joint (co-admin) — ERA maintains upstream; TG has full access
3. Personal (ggerait/audit-orc) with TG admin access granted — current state; lowest friction

ERA recommendation: option 1 or 2, depending on TG's GitHub/DevOps setup. Option 1 is simplest for M3 Entra alignment.

**B. First engagement scope**
- Hari nominates a real or lab engagement for M1.3 (first engagement together)
- ERA and one TG analyst run it on ORCa; ERA co-pilots
- This shapes guide calibration, seat assignments, and org ceiling settings

No other open architecture decisions. Shared-AI-broker decision is resolved (removed in favor of framed seats).

---

## 7. Governance

### 7.1 IP

- **nav-tools**: ERA-authored; delivered to TechGuard (licensed)
- **pt-orc**: ERA-authored; delivered to TechGuard (licensed)
- **TG Unified Methodology v0.3**: collaborative (ERA produced from DCPTCN_TG delta + ERA architecture); TG owns the methodology content
- **Engagement data**: TechGuard ownership entirely; ERA delivers tooling, not data
- **EngagementCore / MethodologyPacks**: DCPTCN_TG authorship; ERA aligns nav-tools integration

### 7.2 Data handling

- Engagement data stays in TG's repo (M1.2 confirms infra placement)
- ERA has no production access beyond delivery scope
- Seat audit log stays in TG's environment

### 7.3 Post-handover support

Separate continuous consulting track covers:
- nav-tools version updates + nav_core v2 features
- Additional MethodologyPack development
- tg-audit-orchestrator integration as DCPTCN_TG delivers
- Entra Key Vault per-section encryption (planned post-M3)

---

## 8. Risks

| Risk | Likelihood | Impact | Mitigation |
|---|:---:|:---:|---|
| Entra group setup takes longer than expected (M3) | M | M | Start M3.1 group structure discussion in M1 window; don't wait |
| First engagement scope too complex for M1 calibration | M | L | ERA proposes a constrained lab scope if Hari's first pick is full production |
| Analyst adoption slower than expected | L | M | First engagement shadowing is the mitigation; extend for free up to +20h if needed |
| DCPTCN_TG EngagementCore timeline slips | M | L | ORCa delivery is independent of DCPTCN_TG; alignment is advisory |
| Repo ownership decision delays M1 | M | M | M1 can start on current repo; transfer at any point without disrupting skills |

---

## 9. Next steps

1. Hari confirms repo ownership preference (or requests discussion)
2. Hari nominates first engagement scope for M1.3
3. ERA sends M1 kick-off plan within 2 business days of both decisions
4. M1 starts: skills install + TG configuration (M1.1–M1.2, ~1 week)
5. First engagement together (M1.3) within 2–3 weeks of M1 start
6. Gate 1: Hari reviews; M2 / M3 scoped based on M1 findings

---

## Appendices

- **A. Scope detail** — `v2-scope-500h.md`
- **B. Speaker notes** — `v2-speaker-notes.md` (per-slide deck companion)
- **C. Delivery deck** — `v7-deck.pptx` (20 slides)
- **D. Methodology** — `docs/tg-unified-audit-methodology-v0.3.md`

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
