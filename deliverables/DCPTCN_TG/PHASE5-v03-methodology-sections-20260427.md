<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- MRK:PHASE5_V03_METHODOLOGY_SECTIONS_20260427_NAV_TOC — Section index | nav,toc,index | L4-12 -->
<!-- - MRK:V03_OVERVIEW — v0.3 change log + structure guide | v03,overview,v0,change,log | L13-40 -->
<!-- - MRK:V03_ENGAGEMENT_MODEL — §NEW: Generic 10-entity engagement model | v03,engagement,model,new,generic | L41-100 -->
<!-- - MRK:V03_PACK_ARCH — §NEW: MethodologyPack architecture | v03,pack,arch,new,methodologypack | L101-170 -->
<!-- - MRK:V03_TOOLING_NEW — §UPDATED: New TG-* placeholders + build order | v03,tooling,new,updated,tg | L171-230 -->
<!-- - MRK:V03_DECEPTICON — §20 UPDATED: Decepticon role — open question CLOSED | v03,decepticon,updated,role,open | L231-295 -->
<!-- - MRK:V03_DELTA — Full v0.2 → v0.3 delta summary | v03,delta,full,v0,summary | L296-344 -->
<!-- NAV-LEN: 6 entries | Integrity-hash: 7b1a5fc9049a0bde | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:V03_OVERVIEW — v0.3 change log + structure guide | v03,overview,v0,change,log | L13-40

### Purpose

This document provides draft section text for **TG Unified Audit Methodology v0.3**. It does not replace v0.2 in full — it provides new sections to insert, updated sections to replace, and a delta guide for the editor. Each section is marked with its insertion instruction.

### v0.3 direction

v0.2 established the automation-first tooling model with TG-* placeholder namespace. v0.3 adds the **methodology architecture layer**: a formal multi-methodology framework that explains *how* the tooling model works across all six TechGuard service types, not just penetration testing.

The three additions in v0.3:
1. **Generic engagement model** — a methodology-neutral description of a TechGuard engagement; applicable to all service types
2. **MethodologyPack architecture** — the formal structure that connects the generic model to each service type
3. **Platform architecture update** — revised §20 that resolves the Decepticon open question and places all platform components in relation to each other

### v0.3 change summary

| Change type | Section | Status |
|-------------|---------|--------|
| NEW section | Generic Engagement Model (§EM) | Draft in V03_ENGAGEMENT_MODEL |
| NEW section | MethodologyPack Architecture (§MP) | Draft in V03_PACK_ARCH |
| UPDATED | TG-* placeholder list (add TG-CORE-CONTEXT, TG-ANL-CHAIN) | Draft in V03_TOOLING_NEW |
| UPDATED | Build order table (steps 4, 11 revised) | Draft in V03_TOOLING_NEW |
| REPLACED | §20 Decepticon (was: open question) | Draft in V03_DECEPTICON |
| RETAINED | All other v0.2 sections | No change needed |

---

## MRK:V03_ENGAGEMENT_MODEL — §NEW: Generic 10-entity engagement model | v03,engagement,model,new,generic | L41-100

> **Insert as:** new section immediately after the v0.2 "Engagement Types" section.

---

### The TechGuard Engagement Model

Every TechGuard engagement — regardless of service type — is described by ten entities. These entities are consistent across all service types; the *methodology pack* supplies the rules for how each entity is populated and used within a specific engagement type.

#### The ten entities

| # | Entity | Description |
|---|--------|-------------|
| 1 | **Client** | The organization being assessed. Identified by a short code (`client_short`) used to namespace all engagement artefacts. |
| 2 | **Engagement** | The top-level record for a body of work. Carries a stable `engagement_id` (format: `<PACK>-<CLIENT>-<YYYY>-<SEQ>`). One client may have multiple simultaneous or sequential engagements. |
| 3 | **Scope** | The defined boundary of the assessment: systems, networks, applications, processes, organizational units, or a combination. The scope is formally agreed before work begins and is immutable once the engagement enters the execution phase. |
| 4 | **Planning Bundle** | The set of planning documents that govern the engagement. The minimum required documents vary by service type; the planning bundle is always assembled before the execution phase begins. Typical documents: rules of engagement, concept of operations, assessment plan, control matrix. |
| 5 | **Objective** | A discrete, trackable unit of work within the engagement. Every objective has: a unique ID, a title, a service-type-specific type (e.g., `initial_access` for pentest; `annex_control` for ISO 27001 audit), a current status (`pending / in-progress / passed / blocked / out-of-scope`), and optional control references. The aggregate of all objectives is the OPPLAN (Operational Plan). |
| 6 | **Methodology Pack** | The service-type-specific rule set that governs how the engagement runs: the ordered list of phases, the permitted objective types, the control reference taxonomy, the required planning bundle documents, and the specialist agent roster. |
| 7 | **Execution State** | The live state of the engagement at any point in time: current phase, objective completion counts, active objectives, and the overall engagement lifecycle position. The execution state advances through the pack-defined phase sequence. |
| 8 | **Evidence** | Artifacts collected during the engagement: tool output, screenshots, configuration extracts, policy documents, interview notes, access review records. Evidence is referenced by objectives and cited in findings. |
| 9 | **Findings** | Observations, vulnerabilities, nonconformities, or gaps identified during the engagement. Findings are derived from completed objectives; each finding carries a severity or risk rating, a control reference, and a remediation recommendation. |
| 10 | **Report** | The formal deliverable. Structure varies by service type (pentest technical report vs. audit report vs. gap roadmap) but all reports include: an executive summary, a findings register, and remediation recommendations. The report is generated from the completed OPPLAN state. |

#### Entity relationships

```
Client
  └── Engagement (1..N per client)
        ├── Scope (1 per engagement)
        ├── Planning Bundle (1 per engagement)
        │     └── Documents (N; types defined by MethodologyPack)
        ├── MethodologyPack (1 per engagement)
        │     └── defines: Phases, ObjectiveTypes, ControlRefs
        ├── Execution State (1 per engagement; mutable)
        ├── Objectives / OPPLAN (N per engagement)
        │     └── references: Evidence (N per objective)
        ├── Findings (N; derived from Objectives)
        └── Report (1 per engagement; generated at completion)
```

#### What stays the same across service types

- The `Engagement` entity, `engagement_id` format, and lifecycle (planning → execution → reporting → complete) are identical for all service types.
- The `Objective` schema (fields, status FSM) is identical for all service types.
- Evidence collection and report generation use the same platform components regardless of service type.

#### What varies by service type

- The phase sequence within execution (e.g., pentest has `reconnaissance / exploitation / post-exploitation`; ISO 27001 audit has `document_review / controls_testing / nonconformity`).
- The permitted objective types and their control reference taxonomy.
- The required planning bundle documents.
- The specialist agents active during execution.
- The report structure and output sections.

All of this variation is encapsulated by the **MethodologyPack** (§MP below).

---

## MRK:V03_PACK_ARCH — §NEW: MethodologyPack architecture | v03,pack,arch,new,methodologypack | L101-170

> **Insert as:** new section immediately after §EM (Generic Engagement Model).

---

### MethodologyPack Architecture

#### What is a MethodologyPack?

A MethodologyPack is the service-type-specific configuration layer for a TechGuard engagement. It answers five questions for a given service type:

1. **What phases does the engagement progress through?** — ordered phase sequence
2. **What kinds of objectives are created?** — objective type taxonomy
3. **What control framework do findings reference?** — control reference taxonomy
4. **What planning documents are required?** — bundle document types
5. **Which specialist agents are active?** — agent roster per phase

TechGuard defines six standard packs, one per service category:

| Pack | Service type | Control anchor |
|------|-------------|----------------|
| `PentestPack` | Penetration test / red team | MITRE ATT&CK, CVE/CWE |
| `TechSecurityAssessmentPack` | Technical security assessment | CIS Benchmarks, NIST 800-53 |
| `ISO27001AuditPack` | ISO 27001 ISMS audit | ISO 27001:2022 Annex A |
| `ComplianceEvidencePack` | Compliance evidence review | SOC 2, PCI DSS, HIPAA, GDPR |
| `GapAssessmentPack` | Security gap assessment | NIST CSF, CIS Controls, custom |
| `RemediationVerificationPack` | Remediation verification | Prior engagement finding IDs |

#### How packs integrate with the platform

The `tg-audit-orchestrator` platform routes each new engagement to the correct pack at intake. The Soundwave intake agent presents a structured interview, collects engagement metadata, and produces a planning bundle seeded with the pack's required documents. From that point, all engagement work is executed within the pack's defined structure.

```
Operator / Client
  → Soundwave intake interview
       → identifies engagement_type
       → confirms scope, client_short, bundle documents
  → PackDispatcher loads MethodologyPack
  → EngagementLoop runs within pack's phase sequence
       → specialist agents execute objectives
  → Report generated via pack's report structure
  → Engagement closed; engagement_id archived
```

#### EngagementCore: the shared kernel

All six packs share a common infrastructure layer called `EngagementCore`:

- **OPPLAN** — the objective management engine (create, update, list, track status)
- **EngagementBundle** — planning document container
- **EngagementState** — phase tracking and lifecycle management
- **EngagementLoop** — the execution loop that iterates objectives and dispatches agents
- **Soundwave** — intake interview orchestrator
- **FrameworkRegistry** — central registry of control frameworks (MITRE ATT&CK, CIS, ISO 27001, etc.)

`EngagementCore` is methodology-agnostic. It knows nothing about reconnaissance, ISMS auditing, or compliance frameworks until a `MethodologyPack` is loaded. This is the deliberate separation that allows TechGuard to add new service types without modifying the platform core.

#### Adding a new service type

Adding a new service type to TechGuard's platform requires:
1. Defining a new `MethodologyPack` subclass (phases, objective types, control refs, bundle docs, agent roster).
2. Registering the pack slug in `PackDispatcher`.
3. Adding intake questions for the pack in Soundwave.
4. Implementing the pack's specialist agents (or reusing agents from existing packs).

No changes to `EngagementCore` are required. The platform's core stability is the foundation that allows the service portfolio to expand incrementally.

---

## MRK:V03_TOOLING_NEW — §UPDATED: New TG-* placeholders + build order | v03,tooling,new,updated,tg | L171-230

> **Insert as:** additions to the existing v0.2 TG-* placeholder table and build order table.

---

### New TG-* placeholders for v0.3

The following two placeholders are added to the TG-* namespace. They address gaps identified in the v0.2 → v0.3 analysis (Phase 1 of DCPTCN_TG review).

#### TG-CORE-CONTEXT

| Field | Value |
|-------|-------|
| **Placeholder** | `TG-CORE-CONTEXT` |
| **Family** | TG-CORE (planning layer) |
| **Status** | Planned |
| **Description** | Context and situational awareness document management. Stores the Concept of Operations (ConOps) and any background intelligence or client-environment context collected during intake. Provides a structured context object that is injected into specialist agent prompts throughout the engagement. |
| **Inputs** | Soundwave intake interview output; client-provided environment documentation |
| **Outputs** | `context_document` (ConOps narrative); `environment_profile` (key targets, technology stack, constraints); `opsec_requirements` (engagement-specific) |
| **v0.2 gap** | v0.2 had no explicit ConOps document concept; Decepticon carried ConOps informally inside `EngagementBundle`. v0.3 makes it a named, first-class document type with a formal placeholder. |
| **Landing zone** | Build step 4a (alongside `TG-CORE-PLAN`); prerequisite for step 11 dispatch |

#### TG-ANL-CHAIN

| Field | Value |
|-------|-------|
| **Placeholder** | `TG-ANL-CHAIN` |
| **Family** | TG-ANL (analysis layer) |
| **Status** | Planned |
| **Description** | Attack path / audit chain analysis. Builds and maintains a structured chain of steps linking objectives to findings. In adversarial engagements, this is the attack path narrative (initial access → lateral movement → objective). In audit engagements, this is the evidence chain (control → evidence → gap → finding). |
| **Inputs** | Completed objectives from `TG-CORE-PLAN` (OPPLAN); evidence artifacts |
| **Outputs** | `chain_document` (ordered steps with objective references); `finding_linkage_map` (objective → finding → remediation); used by `TG-CORE-REPORT` at report generation time |
| **v0.2 gap** | v0.2 had no chain-of-attack or evidence-chain concept. Findings were generated per-objective without a connective narrative. `TG-ANL-CHAIN` provides the structure for multi-step narratives in both adversarial and audit contexts. |
| **Landing zone** | Build step 9 (analysis layer, pre-reporting); feeds into `TG-CORE-REPORT` |

### Updated TG-* build order (v0.3 additions shown)

The following additions apply to the v0.2 build order table. Steps not shown are unchanged.

| Step | Placeholder | Change in v0.3 |
|------|-------------|----------------|
| 4 | `TG-CORE-PLAN` | **Sub-step 4a added:** `TG-CORE-CONTEXT` runs in parallel with OPPLAN initialization; ConOps document produced before first objective dispatch |
| 4a | `TG-CORE-CONTEXT` | **NEW in v0.3.** Context + ConOps document management. Feeds TG-CORE-PLAN (step 4) and TG-CORE-DISPATCH (step 11). |
| 9 | `TG-ANL-CHAIN` | **NEW in v0.3.** Analysis chain step inserted between objective completion and report generation. |
| 11 | `TG-CORE-DISPATCH` | **Updated label:** dispatch now routes to `MethodologyPack` specialist agents (not just Decepticon agents). The dispatch mechanism is pack-aware via `PackDispatcher`. |

### Updated complete TG-* tool family inventory (v0.3)

> Note: families below list only additions to v0.2. All v0.2 families and their members remain unchanged.

| Family | New member(s) | Status |
|--------|--------------|--------|
| TG-CORE | `TG-CORE-CONTEXT` | Planned (v0.3) |
| TG-ANL | `TG-ANL-CHAIN` | Planned (v0.3) |

Total TG-* placeholder count: v0.2 had ~34 named tools across 12 families. v0.3 adds 2, bringing the total to ~36.

---

## MRK:V03_DECEPTICON — §20 UPDATED: Decepticon role — open question CLOSED | v03,decepticon,updated,role,open | L231-295

> **Replace v0.2 §20 in full with this text.** The v0.2 open question ("should Decepticon remain optional or become a controlled specialist module?") is now closed.

---

### §20 — Decepticon and the tg-audit-orchestrator Platform

#### The open question, resolved

v0.2 §20 noted an open architectural question: *"Should Decepticon remain optional or become a controlled specialist module?"*

The answer is neither option as originally framed.

**Decepticon is refactored, not removed or constrained.** It is split along an architectural boundary that separates its generic planning infrastructure from its adversarial-specific logic:

- The **planning infrastructure** (OPPLAN, EngagementBundle, EngagementState, Soundwave intake) is extracted into `EngagementCore` — a shared library used by all service types. This layer is not optional; it is the foundation of every TechGuard engagement.
- The **adversarial-specific logic** (reconnaissance, exploitation, post-exploitation specialist agents; MITRE ATT&CK control references; red team phase taxonomy) becomes `PentestPack` — one of six `MethodologyPack` implementations. It is the pack selected when the engagement type is `pentest` or `red_team`.

Decepticon does not become "optional" — its core is mandatory for all engagements. It does not become a "specialist module" in the sense of a black-box called from outside — it becomes the first-party implementation of the `MethodologyPack` interface for adversarial service types.

#### Platform component map

The full `tg-audit-orchestrator` platform consists of:

| Component | Role | Relationship to Decepticon |
|-----------|------|--------------------------|
| `EngagementCore` | Shared planning kernel: OPPLAN, EngagementBundle, EngagementState, EngagementLoop, Soundwave | Extracted from Decepticon (Phase A migration) |
| `tg-audit-orchestrator` | Orchestration shell: session management, PackDispatcher, API | New component; wraps EngagementCore |
| `PentestPack` | Adversarial engagement logic: recon, exploit, post-exploit agents; MITRE ATT&CK | Decepticon specialist agent layer, renamed and adapted |
| `GapAssessmentPack` | Gap assessment logic | New; first non-adversarial pack |
| `TechSecurityAssessmentPack` | Technical security assessment logic | New |
| `ISO27001AuditPack` | ISO 27001 ISMS audit logic | New |
| `ComplianceEvidencePack` | Compliance evidence review logic | New |
| `RemediationVerificationPack` | Remediation verification logic | New |
| `audit-evidence-processor` | Evidence ingestion, normalization, storage | Separate component; interface with EngagementCore TBD |
| `nav-tools` | Navigation and session management tooling | Separate component; used by operators |

#### Decepticon migration path

Decepticon is not replaced in a single step. The migration preserves backward compatibility throughout:

**Phase A — Extract (no behavior change):**
Move `OPPLANMiddleware`, `EngagementBundle`, `EngagementState`, `EngagementLoop`, `Soundwave` into the `EngagementCore` library. Decepticon imports from `EngagementCore` instead of its own internal modules. All existing Decepticon functionality is identical; all tests pass unchanged.

**Phase B — Parameterize (no behavior change):**
Replace Decepticon's hardcoded `PHASES` list, `mitre[]` field, and `opsec_*` fields with pack-supplied values via the `MethodologyPack` interface. `PentestPack` supplies the same values that were previously hardcoded. All existing engagement behavior is preserved.

**Phase C — Scaffold (adds capability):**
Add the `tg-audit-orchestrator` T2 orchestration layer. Register `PentestPack` and `GapAssessmentPack` in `PackDispatcher`. Soundwave intake interview now selects the pack based on `engagement_type`. Pentest engagements continue to run exactly as before; gap assessment engagements are now available.

#### Decepticon in the context of v0.3 methodology

The v0.3 methodology treats Decepticon as the reference implementation of `PentestPack`, not as a standalone tool. When the methodology describes penetration test execution, the tooling references are:

- `TG-CORE-PLAN` → `EngagementCore / OPPLANMiddleware` (objective management)
- `TG-CORE-CONTEXT` → `EngagementCore / EngagementBundle / ConOps` (context + ConOps)
- `TG-CORE-DISPATCH` → `tg-audit-orchestrator / PackDispatcher` (routes to `PentestPack` specialist agents)
- `TG-ANL-CHAIN` → `PentestPack / attack chain analysis` (attack path narrative)
- `TG-CORE-REPORT` → `EngagementCore / BaseReportWriterAgent` + `PentestPack / PentestReportWriterAgent`

For non-pentest service types, the same methodology steps apply; only the pack-supplied content differs. The generic engagement model and the MethodologyPack architecture (§EM and §MP) describe this unification.

---

## MRK:V03_DELTA — Full v0.2 → v0.3 delta summary | v03,delta,full,v0,summary | L296-344

### Editor's guide: v0.2 → v0.3

This table is the complete set of changes for a document editor producing v0.3 from v0.2.

| # | Action | Location | Source material |
|---|--------|----------|-----------------|
| 1 | **INSERT** new §EM section (Generic Engagement Model) | After "Engagement Types" section | V03_ENGAGEMENT_MODEL (this file) |
| 2 | **INSERT** new §MP section (MethodologyPack Architecture) | After §EM | V03_PACK_ARCH (this file) |
| 3 | **ADD** two rows to TG-* placeholder table | TG-* namespace section | V03_TOOLING_NEW (this file) |
| 4 | **UPDATE** build order table: add steps 4a and 9; update step 11 note | Build order section | V03_TOOLING_NEW (this file) |
| 5 | **REPLACE** §20 in full | §20 — Decepticon | V03_DECEPTICON (this file) |
| 6 | **UPDATE** document version number and date | Cover / header | v0.3, 2026-Q2 |
| 7 | **UPDATE** platform architecture diagram | Architecture section | Three-tier model from ARCH_TIERS |

### What does NOT change in v0.3

- The 10-step TG engagement lifecycle (steps 1–14 in v0.2) — unchanged
- All existing TG-* placeholder definitions — unchanged (two new ones added; none modified)
- The tooling-driven philosophy and automation-first framing — retained and extended
- Evidence collection and chain-of-custody requirements — unchanged
- Client deliverable formats — unchanged (report structure varies by pack type, which is the new §MP, not a modification of existing deliverable specs)

### Version line recommendation

```
TG Unified Audit Methodology v0.3 — Tooling Driven + Multi-Methodology
Author: TechGuard
Status: Draft
Supersedes: v0.2 (Tooling Driven, 2026)
Changes: Generic engagement model, MethodologyPack architecture, §20 Decepticon resolution
```

### Decisions documented in this v0.3 direction

By incorporating the v0.3 sections above, the methodology document closes or documents the following:

| Question / gap | v0.2 status | v0.3 resolution |
|----------------|-------------|-----------------|
| Decepticon role (§20) | Open question | CLOSED: EngagementCore extraction + PentestPack |
| Multi-methodology support | Not described | ADDED: MethodologyPack architecture (§MP) |
| Generic engagement model | Not present | ADDED: 10-entity model (§EM) |
| ConOps document concept | Implicit in Decepticon | FORMALIZED: TG-CORE-CONTEXT placeholder |
| Attack/audit chain narrative | Absent | ADDED: TG-ANL-CHAIN placeholder |
| Platform component map | Partial (Decepticon only) | COMPLETE: 9-component map in §20 |

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
