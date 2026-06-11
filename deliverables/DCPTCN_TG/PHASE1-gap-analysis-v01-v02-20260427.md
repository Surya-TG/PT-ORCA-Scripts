<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- MRK:PHASE1_GAP_ANALYSIS_V01_V02_20260427_NAV_TOC — Section index | nav,toc,index | L4-14 -->
<!-- - MRK:GAP_SUMMARY — Executive summary | gap,summary,executive,overview | L15-32 -->
<!-- - MRK:GAP_STRUCTURE — Document structure comparison | gap,structure,document,comparison,sections | L33-66 -->
<!-- - MRK:GAP_TOOLING — Tooling changes: v0.1 → v0.2 | gap,tooling,changes,v0,placeholders | L67-110 -->
<!-- - MRK:GAP_LIFECYCLE — Lifecycle stage changes | gap,lifecycle,stage,changes,stages | L111-154 -->
<!-- - MRK:GAP_MODELS — Model changes: evidence, findings, artifacts | gap,models,model,changes,evidence | L155-176 -->
<!-- - MRK:GAP_DROPPED — What v0.1 had that v0.2 dropped or weakened | gap,dropped,what,v0,had | L177-191 -->
<!-- - MRK:GAP_BUILDORDER — Implementation order (v0.2 §18) | gap,buildorder,implementation,order,v0 | L192-216 -->
<!-- - MRK:GAP_VERDICT — Phase 1 verdict for DCPTCN_TG | gap,verdict,phase,dcptcn,tg | L217-241 -->
<!-- NAV-LEN: 8 entries | Integrity-hash: d1272cc3d34aad3c | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:GAP_SUMMARY — Executive summary | gap,summary,executive,overview | L15-32

**Produced:** 2026-04-27 | **Project:** DCPTCN_TG | **Phase:** 1 of 5

v0.2 is not a revision of v0.1 — it is a rewrite from a fundamentally different premise. v0.1 is a **manual-first methodology** that acknowledges tooling as a support layer. v0.2 is an **automation-first platform spec** that treats the methodology as the schema for a software system.

The structural skeleton (9 stages, 6 service modules, same workspace structure) is preserved. Everything else is transformed:

- Every lifecycle stage gains an explicit tool placeholder list and a human gate.
- A systematic tool placeholder namespace (`TG-*`) is introduced with 12 families and ~34 named tools.
- Existing repos (PT-Orc, nav-tools, audit-evidence-processor, Decepticon) are formally mapped to placeholders.
- A build order for `tg-audit-orchestrator` is specified (18 steps).
- Four open review questions are stated explicitly, including the Decepticon role question.

**For DCPTCN_TG:** the Decepticon generalization work directly addresses v0.2's unresolved items. v0.2 created the slots (`TG-PT-AUTO-OPS`, `TG-CORE-PLAN`, `TG-CORE-DISPATCH`); the DCPTCN_TG spec must fill them.

---

## MRK:GAP_STRUCTURE — Document structure comparison | gap,structure,document,comparison,sections | L33-66

| § | v0.1 section | v0.2 section | Change |
|---|-------------|-------------|--------|
| 1 | Purpose and Scope | Purpose and Intent | Reframed: v0.2 adds "automation-first" and "tooling placeholders" as explicit intent |
| 2 | Methodology Design Principles | Core Operating Principle | v0.2 collapses principles into one automation-first statement |
| 3 | Methodology Structure (3 layers) | Design Principles | Same 3 layers; v0.2 adds "dedicated tool pipelines" and "minimal duplicated analyst effort" |
| 4 | Engagement Types | Methodology Layers | v0.2 adds explicit Layer 3: Tooling and Pipeline Packs |
| 5 | — | **Tooling Placeholder Model** (NEW) | 12 TG-* families; status labels (Existing/Planned/Optional) |
| 6 | — | **Existing Tool Mapping** (NEW) | PT-Orc, nav-tools, audit-evidence-processor, Decepticon mapped |
| 7 | — | **Future Core Platform Placeholders** (NEW) | 16 planned TG-CORE-* and TG-EVID-* tools |
| 8 | — | **Human Interaction Model** (NEW) | Explicit automation/human boundary definition |
| 9 | Standard Engagement Lifecycle (9 stages) | Standard Lifecycle with Tool Placeholders | Same 9 stages; v0.2 adds tool list + human gate per stage |
| 10 | Standard Roles | Roles in Automation-First Model | v0.2 adds "Tool Owner" role; human accountability framing |
| 11 | Standard Project Artifacts | Standard Artifact Model | v0.2 adds: "generated and maintained primarily through tools" |
| 12 | — | Standard Evidence Model | v0.1 had this as §8; v0.2 condenses + adds `linked objective/control` + tool refs |
| 13 | — | Standard Finding Model | v0.1 had this as §9; v0.2 condenses + adds tool refs |
| 14 | Service-Type Overlay Model (narrative) | Service Module Placeholders (tool lists) | v0.2 replaces narrative descriptions with per-module tool placeholder lists |
| 15 | Standard Project Data Structure | Standard Project Workspace Placeholder | Same folder structure; v0.2 ties it to `TG-CORE-WORKSPACE` |
| 16 | Exceptions and Deviations | Exceptions and Deviations | v0.2 adds `TG-CORE-TRACKER` + `TG-CORE-GATE` references |
| 17 | Metrics and Management Oversight | Metrics and Management Oversight | v0.2 adds automation coverage rate + analyst intervention rate + `TG-OPS-METRICS` |
| 18 | Implementation Roadmap (generic) | **Implementation Order for tg-audit-orchestrator** (explicit) | v0.2 gives 18-step build order by tool name |
| 19 | Immediate Next Deliverables (docs) | Immediate Next Deliverables (specs) | v0.1: glossary, QA checklist, templates. v0.2: data model, schemas, gate matrix |
| 20 | Draft Approval Notes (6 review questions) | Draft Approval Notes (5 review questions) | v0.2 drops "which terms need tighter definitions?"; adds Decepticon question |

**Dropped as standalone sections in v0.2:**
- §9 Findings/Gaps/Observations/Risks definitions (Observation, Gap, Finding, Risk)
- §10 Quality Assurance Requirements (merged into §7 stage)
- §11 Standard Stage Gates table (replaced by per-stage human gates)
- §12 Methodology Use of Tools, Automation, and AI (merged into framing)
- §17 Continuous Improvement Model (absorbed into §9 Closure)

---

## MRK:GAP_TOOLING — Tooling changes: v0.1 → v0.2 | gap,tooling,changes,v0,placeholders | L67-110

### TG-* Placeholder Namespace (v0.2 only)

v0.1 had no named tool references — only descriptions like "core engagement orchestration layer."
v0.2 introduces a systematic namespace:

| Family | Tools | Status |
|--------|-------|--------|
| `TG-CORE-*` | INTAKE, SCOPE, PLAN, WORKSPACE, DISPATCH, GATE, TRACKER, DOC-NAV | Planned (DOC-NAV = Existing) |
| `TG-EVID-*` | REQUEST, INGEST, NORMALIZE, INDEX | Planned (NORMALIZE = Existing) |
| `TG-ANL-*` | MAP, FINDINGS | Planned |
| `TG-RPT-*` | BUILD, PUBLISH | Planned |
| `TG-QA-*` | CHECK | Planned |
| `TG-OPS-*` | METRICS, LESSONS | Planned |
| `TG-PT-*` | EXEC-PIPELINE, AUTO-OPS, FINDING-BUILDER, RETEST | Existing (EXEC-PIPELINE), Optional (AUTO-OPS), Planned (rest) |
| `TG-STD-*` | CONTROL-MAP, EVIDENCE-PLAN, READINESS-SCORE, ROADMAP | Planned |
| `TG-GAP-*` | MATRIX, PRIORITIZE, ROADMAP | Planned |
| `TG-ASM-*` | CHECKS, CONTROL-MAP, OBSERVATIONS | Planned |
| `TG-RISK-*` | REGISTER, SCORING, TREATMENT | Planned |
| `TG-VAL-*` | CHECKLIST, EVIDENCE-COMPARE, DECISION | Planned |

### Existing Tool Mappings (v0.2 §6)

| Placeholder | Status | Current Repo | Role |
|-------------|--------|-------------|------|
| `TG-PT-EXEC-PIPELINE` | Existing | PT-Orc | phase-based pentest execution pipeline |
| `TG-CORE-DOC-NAV` | Existing | nav-tools | structured document navigation and methodology content |
| `TG-EVID-NORMALIZE` | Existing | audit-evidence-processor | convert, OCR, translate, categorize evidence |
| `TG-PT-AUTO-OPS` | Optional | Decepticon | autonomous objective-driven offensive execution and planning concepts |

### Decepticon in v0.2 (4 references)

| Location | Context |
|----------|---------|
| §6 tool mapping table | `TG-PT-AUTO-OPS | Optional | Decepticon` |
| §9 Stage 2 tool list | optional source for RoE/ConOps/OPPLAN-style planning patterns |
| §14.2 PT Module tool stack | `TG-PT-AUTO-OPS` - optional Decepticon |
| §20 review question | "should Decepticon remain optional or become a controlled specialist module?" |

**Key observation:** Decepticon is classified as `Optional` throughout v0.2. The planning concepts (RoE/ConOps/OPPLAN) are referenced as a pattern source in Stage 2, not as a mandatory component. The open question in §20 is the only place where its future role is explicitly put up for decision.

---

## MRK:GAP_LIFECYCLE — Lifecycle stage changes | gap,lifecycle,stage,changes,stages | L111-154

Both versions have the same 9 stages with the same names. The structural content (activities, outputs, entry/exit criteria) is largely preserved. The key additions in v0.2:

### Tool placeholders per stage

| Stage | v0.2 primary tools |
|-------|-------------------|
| 1. Intake | TG-CORE-INTAKE, TG-CORE-TRACKER, TG-CORE-DOC-NAV |
| 2. Scope | TG-CORE-SCOPE, TG-CORE-GATE, TG-CORE-DOC-NAV, **TG-PT-AUTO-OPS** (optional) |
| 3. Planning | TG-CORE-PLAN, TG-CORE-WORKSPACE, TG-CORE-DISPATCH, TG-EVID-REQUEST, TG-CORE-DOC-NAV |
| 4. Evidence | TG-EVID-REQUEST, TG-EVID-INGEST, TG-EVID-NORMALIZE, TG-EVID-INDEX |
| 5. Analysis | TG-ANL-MAP, TG-CORE-DISPATCH, TG-PT-EXEC-PIPELINE, **TG-PT-AUTO-OPS** (optional), module-specific tools |
| 6. Synthesis | TG-ANL-FINDINGS, TG-RISK-SCORING, TG-GAP-MATRIX, TG-CORE-TRACKER |
| 7. QA | TG-QA-CHECK, TG-EVID-INDEX, TG-CORE-GATE, TG-CORE-DOC-NAV |
| 8. Reporting | TG-RPT-BUILD, TG-RPT-PUBLISH, TG-CORE-TRACKER, TG-CORE-DOC-NAV |
| 9. Closure | TG-OPS-LESSONS, TG-OPS-METRICS, TG-CORE-TRACKER |

### Human gates per stage (v0.2 only)

| Stage | Human gate |
|-------|-----------|
| 1 | approve intake classification |
| 2 | approve scope and authorization before execution planning |
| 3 | approve plan |
| 4 | review material evidence gaps if automation cannot resolve them |
| 5 | analyst confirms conclusions where automated assessment is ambiguous or high-impact |
| 6 | lead analyst confirms severity and issue framing |
| 7 | reviewer signs off release readiness |
| 8 | final delivery approval |
| 9 | close project formally |

v0.1 had a standalone stage-gates table (§11) with the same 9 gates — v0.2 embeds them directly in each stage definition.

### Automation intent shift

v0.2 §8 explicitly states what should be automated vs. kept manual:

**Automate:** project setup, evidence request generation, evidence ingestion/normalization, objective/task generation, execution dispatch, evidence-to-control mapping, report assembly, QA pre-checking

**Keep manual:** service classification (ambiguous cases), scope/authorization approval, exceptions and deviations, expert judgment in analysis, severity confirmation, QA review, final delivery approval

---

## MRK:GAP_MODELS — Model changes: evidence, findings, artifacts | gap,models,model,changes,evidence | L155-176

### Evidence model

v0.1 §8 had detailed evidence principles (attributability, dating, storage, traceability, sensitivity). These are dropped in v0.2 in favor of machine-trackability framing.

v0.2 adds one field not in v0.1: `linked objective / requirement / control` — this is significant for the generalization work; it's the explicit bridge between evidence and the requirement model.

Both versions have the same recommended folder structure (01_intake through 11_closure).

### Finding model

v0.1 §9 had dedicated definitions for Observation / Gap / Finding / Risk — these are dropped as standalone definitions in v0.2. This is a **gap**: without these definitions, the finding model lacks the taxonomy foundation.

v0.2 condenses the finding schema and adds tool refs (`TG-ANL-FINDINGS`, `TG-RISK-SCORING`). Field-level diff: v0.2 drops "status" and "affected area/asset/process" from the finding schema. Both are in v0.1 and should be retained.

### Artifact model

v0.1 §7 listed 9 artifact families. v0.2 §11 lists the same 9 but adds: "generated and maintained primarily through tools, not manual folder handling." This is the key framing shift.

---

## MRK:GAP_DROPPED — What v0.1 had that v0.2 dropped or weakened | gap,dropped,what,v0,had | L177-191

| Item | v0.1 location | Status in v0.2 | Risk |
|------|--------------|---------------|------|
| Observation/Gap/Finding/Risk definitions | §9 | Dropped entirely | High — terminology gaps will create inconsistency across service modules |
| Detailed evidence principles | §8.1–8.3 (sufficiency states: sufficient/partial/insufficient/unavailable/client-declared) | Condensed; sufficiency states dropped | Medium — evidence quality judgment needs these |
| Methodology Use of AI (detailed) | §12.3 (uses + explicit prohibitions) | Absorbed into general automation-first framing | Low — implicit in human gate model, but less explicit |
| Continuous Improvement standalone section | §17 | Absorbed into §9 Closure and §19 | Low — content preserved, just less prominent |
| Standard QA checklist as next deliverable | §19 | Replaced by technical specs | Medium — QA checklist is operationally needed |
| Methodology glossary as next deliverable | §19 | Dropped | Medium — definitions section was also dropped |
| "affected area / asset / process" in finding schema | §9.5 | Not in v0.2 §13 | Low — should be in service module specs |
| "status" field in finding schema | §9.5 | Not in v0.2 §13 | Medium — required for tracker integration |

---

## MRK:GAP_BUILDORDER — Implementation order (v0.2 §18) | gap,buildorder,implementation,order,v0 | L192-216

v0.2 §18 specifies the explicit build order for `tg-audit-orchestrator`. This is entirely new — v0.1 had only a generic roadmap.

| Step | Tool | Notes |
|------|------|-------|
| 1 | TG-CORE-WORKSPACE | project structure initialization — first because everything else needs a workspace |
| 2 | TG-CORE-INTAKE | engagement registration |
| 3 | TG-CORE-SCOPE | scope pack generation |
| 4 | TG-CORE-PLAN | objective and task generation — **Decepticon OPPLAN generalization lands here** |
| 5 | TG-CORE-TRACKER | tracking across all stages |
| 6 | TG-EVID-INGEST | evidence intake |
| 7 | TG-EVID-INDEX | evidence manifest |
| 8 | TG-EVID-NORMALIZE | integration of existing audit-evidence-processor |
| 9 | TG-RPT-BUILD | report assembly |
| 10 | TG-QA-CHECK | QA rule engine |
| 11 | TG-CORE-DISPATCH | route work to service module pipelines — **OPPLAN execution loop lands here** |
| 12–18 | Service modules | PT first, then standards consulting, gap, assessment, risk, remediation validation |

**For DCPTCN_TG:** steps 4 and 11 are the primary landing zones for the Decepticon generalization:
- **Step 4 (TG-CORE-PLAN):** generalized OPPLAN creation — Soundwave interview → objective plan
- **Step 11 (TG-CORE-DISPATCH):** execution routing — equivalent to the EngagementLoop dispatching objectives to service agents

---

## MRK:GAP_VERDICT — Phase 1 verdict for DCPTCN_TG | gap,verdict,phase,dcptcn,tg | L217-241

### What Phase 1 establishes for the project

1. **v0.2 is the correct working draft.** It has the structure, the tool slots, and the open questions that DCPTCN_TG must close. v0.1 is useful as the conceptual baseline (definitions, principles) but v0.2 is the target.

2. **Primary landing zones for Decepticon generalization:**
   - `TG-CORE-PLAN` (build step 4) — generalized OPPLAN/objective state machine
   - `TG-CORE-DISPATCH` (build step 11) — execution routing to service module pipelines
   - Stage 2 tool list — Soundwave/intake pattern for RoE/ConOps-style scope packs

3. **v0.2 gaps to fix in DCPTCN_TG output (v0.3 direction):**
   - Restore Observation/Gap/Finding/Risk definitions (from v0.1 §9) — required for finding model consistency
   - Restore evidence sufficiency states (sufficient/partial/insufficient/unavailable/client-declared) — from v0.1 §8.3
   - Restore "status" and "affected area" fields to finding schema
   - Restore detailed AI use prohibitions — human gate model covers them but explicit is better
   - Add methodology glossary to next deliverables

4. **Decepticon role decision input (for Phase 3):**
   v0.2 never specifies HOW `TG-PT-AUTO-OPS` / Decepticon connects to the planning layer — it only names it as Optional. The exact interface (which fields map, how Soundwave is generalized, how OPPLAN phase model changes) is unspecified. That is DCPTCN_TG's core contribution.

5. **Phase 2 ready:** the Phase 2 Decepticon fit assessment can now map each Decepticon component directly to named v0.2 placeholders (`TG-CORE-PLAN`, `TG-CORE-DISPATCH`, `TG-CORE-SCOPE`, `TG-CORE-INTAKE`).

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
