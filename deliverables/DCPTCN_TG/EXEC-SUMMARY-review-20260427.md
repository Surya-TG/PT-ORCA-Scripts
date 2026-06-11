<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- MRK:EXEC_SUMMARY_REVIEW_20260427_NAV_TOC — Section index | nav,toc,index | L4-10 -->
<!-- - MRK:EXEC_VERDICT — Overall verdict + decision confirmation | exec,verdict,overall,decision,confirmation | L11-28 -->
<!-- - MRK:EXEC_FINDINGS — Key findings from external review | exec,findings,key,external,review | L29-52 -->
<!-- - MRK:EXEC_ACTIONS — Action items entering TG planning | exec,actions,action,items,entering | L53-63 -->
<!-- - MRK:EXEC_STATUS — Broadcast + reply status | exec,status,broadcast,reply,pending | L64-74 -->
<!-- NAV-LEN: 4 entries | Integrity-hash: f73a1f0bedfe21a6 | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:EXEC_VERDICT — Overall verdict + decision confirmation | exec,verdict,overall,decision,confirmation | L11-28

**DCPTCN_TG — External Review Executive Summary**
*2026-04-27 | Responses: ORCA_RELEASE (direct reply) + NAV_CORE (beacon intelligence)*

**Overall verdict: All 5 phases accepted. All 4 decisions confirmed closed. No blockers. Go signal.**

### Architecture decisions — external confirmation

| Decision | DCPTCN_TG position | External confirmation |
|----------|-------------------|----------------------|
| D-001: EngagementCore extraction | Extract; Decepticon = PentestPack | ✓ Accepted. Clean boundary confirmed: PT-Orc = execution engine; EngagementCore = planning kernel |
| D-002: Objective schema | 12 keep, 2 replace, 2 drop | ✓ Not contested |
| D-003: MVP ~16–26 days | EngagementCore + scaffolding + 2 packs | ✓ Credible. MVP = first 160–200h of 500h envelope; remaining 300h covers packs 3–6 + interfaces + hardening |
| D-004: Pack priority | Pentest → Gap → TSA → ISO27001 → Compliance → Remediation | ✓ Correct. Aligns with audit-orc v1 delivery timeline |

---

## MRK:EXEC_FINDINGS — Key findings from external review | exec,findings,key,external,review | L29-52

### 1 — Repo layout: submodule, not monorepo (upgrade to Phase 5 recommendation)

`EngagementCore` has three consumers from day one: `tg-audit-orchestrator`, Decepticon, and PT-Orc. ORCA_RELEASE recommends a standalone `engagement-core/` repo with git submodule refs in each consumer. Packs stay bundled in `tg-audit-orchestrator` for MVP. Avoids a restructuring step when Decepticon Phase A imports the shared kernel.

### 2 — Timeline is tighter than it appeared

NAV_CORE confirms the ORCA_RELEASE Phase 3 blocker (NAV v1 delivery) was cleared 2026-04-27 by FAST_SPLIT. audit-orc v1 is genuinely imminent — ERA branding sweep is the only remaining gate. Phase A migration can begin days after v1 ships.

### 3 — audit-evidence-processor interface: design with real data

PT-Orc already produces a structured evidence layer (`pt-evidence` skill + per-finding stubs). ORCA_RELEASE requests early loop-in when defining the `audit-evidence-processor` interface contract — design it against PT-Orc's real output schema, not a placeholder.

### 4 — FrameworkRegistry slug design: lock before GapAssessmentPack interface finalises

ISO27001AuditPack is pack 4, but its framework slugs interact with the shared `FrameworkRegistry`. Define all built-in slug names before GapAssessmentPack (pack 2) locks its interface. One-pass design prevents naming conflicts.

### 5 — Phase A discovery spike: one day, before sprint commit

Before scheduling Phase A (3–5d estimate) in a sprint: run a one-day spike — move `engagement_loop.py` imports into a stub `engagement_core/` and run the Decepticon test suite. If clean, estimate holds. If it surfaces circular imports or hidden shared state, replan. Not a blocker; a planning guard.

---

## MRK:EXEC_ACTIONS — Action items entering TG planning | exec,actions,action,items,entering | L53-63

| # | Action item | Signal |
|---|-------------|--------|
| A1 | Define `audit-evidence-processor` interface using PT-Orc evidence schema as baseline | Loop in ORCA_RELEASE early |
| A2 | Design `FrameworkRegistry` built-in slugs before GapAssessmentPack interface is locked | Pre-sprint design task |
| A3 | Run Phase A discovery spike (1 day) before committing Phase A to sprint | First engineering action post v1-ship |
| A4 | Stand up `engagement-core` as standalone repo; add submodule refs in `tg-audit-orchestrator` + Decepticon | Repo setup, Day 1 of Phase A |

---

## MRK:EXEC_STATUS — Broadcast + reply status | exec,status,broadcast,reply,pending | L64-74

| Project | Message sent | Reply received | Notes |
|---------|-------------|----------------|-------|
| ORCA_RELEASE | ✓ 2026-04-27T18:45Z | ✓ 2026-04-27T19:00Z | Full review, 3 questions answered, 1 planning flag added |
| NAV_CORE | — (not in broadcast) | — (beacon read) | Cross-project context confirmed v1 unblocked |
| ORCA_DOCS | ✓ 2026-04-27T18:45Z | ⏳ pending | v0.3 doc integration + new TG-* placeholder docs |
| ORCA-SLIDES | ✓ 2026-04-27T18:45Z | ⏳ pending | Decepticon narrative update, 6-pack taxonomy, engagement model for slides |

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
