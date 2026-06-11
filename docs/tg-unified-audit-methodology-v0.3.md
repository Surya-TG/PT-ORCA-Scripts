<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->

<!-- MRK:TG_UNIFIED_AUDIT_METHODOLOGY_V0_3_NAV_TOC — Section index | nav,toc,index | L4-21 -->
<!-- - MRK:TG_METH_HEADER — Version header | tg,meth,header,version | L22-34 -->
<!-- - MRK:TG_METH_PURPOSE — §1 Purpose and Intent | tg,meth,purpose,intent | L35-56 -->
<!-- - MRK:TG_METH_PRINCIPLE — §2–3 Core Principle + Design | tg,meth,principle,core,design | L57-94 -->
<!-- - MRK:TG_METH_LAYERS — §4 Methodology Layers + platform architecture | tg,meth,layers,methodology,platform | L95-193 -->
<!-- - MRK:TG_METH_TOOLING — §5–7 Tooling model + placeholder tables | tg,meth,tooling,model,placeholder | L194-261 -->
<!-- - MRK:TG_METH_LIFECYCLE — §8–9 Human model + lifecycle | tg,meth,lifecycle,human,model | L262-568 -->
<!-- - MRK:TG_METH_MODELS — §10–13 Roles, artifacts, evidence, findings | tg,meth,models,roles,artifacts | L569-651 -->
<!-- - MRK:TG_METH_SERVICES — §14 Service Module Placeholders | tg,meth,services,service,module | L652-734 -->
<!-- - MRK:TG_METH_EM — §EM Generic Engagement Model | tg,meth,em,generic,engagement | L735-790 -->
<!-- - MRK:TG_METH_MP — §MP MethodologyPack Architecture | tg,meth,mp,methodologypack,architecture | L791-857 -->
<!-- - MRK:TG_METH_WORKSPACE — §15 Project Workspace | tg,meth,workspace,project | L858-879 -->
<!-- - MRK:TG_METH_OPS — §16–17 Exceptions + Metrics | tg,meth,ops,exceptions,metrics | L880-930 -->
<!-- - MRK:TG_METH_BUILDORDER — §18 Implementation Order | tg,meth,buildorder,implementation,order | L931-959 -->
<!-- - MRK:TG_METH_NEXTDOCS — §19 Immediate Next Deliverables | tg,meth,nextdocs,immediate,next | L960-978 -->
<!-- - MRK:TG_METH_DECEPTICON — §20 Decepticon + platform architecture | tg,meth,decepticon,platform,architecture | L979-1039 -->
<!-- NAV-LEN: 15 entries | Integrity-hash: a9f1650a3affc2ec | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:TG_METH_HEADER — Version header | tg,meth,header,version | L22-34

# TG Unified Audit Methodology

Status: Draft v0.3 — Tooling Driven + Multi-Methodology
Owner: TechGuard
Audience: Internal employees, analysts, project leads, reviewers, delivery managers, and tool builders
Purpose: Define one automation-first methodology for all TechGuard cyber, security, audit, consulting, and assessment engagements
Supersedes: v0.2 (Tooling Driven, 2026)
Changes: Generic engagement model (§EM), MethodologyPack architecture (§MP), §20 Decepticon resolution, two new TG-* placeholders, build order updated

---

## MRK:TG_METH_PURPOSE — §1 Purpose and Intent | tg,meth,purpose,intent | L35-56

## 1. Purpose and Intent

This methodology defines the standard TechGuard operating model for all audit and security-related projects.

It is designed to support:

- one common lifecycle across all engagement types
- heavy use of automation, orchestration, and reusable pipelines
- minimal human interaction during routine execution
- explicit human control at approval, exception, judgment, and release points
- consistent integration between methodology, tools, templates, evidence handling, and reporting

This version is intentionally tooling-driven. It includes placeholders for:

- tools that already exist in current repositories
- tools that will be built later under the `tg-audit-orchestrator` project
- service-specific modules that will plug into the Core Method

---

## MRK:TG_METH_PRINCIPLE — §2–3 Core Principle + Design | tg,meth,principle,core,design | L57-94

## 2. Core Operating Principle

TechGuard will use one shared methodology for all engagement types.

The methodology is made of:

- a mandatory Core Method
- service-specific modules
- dedicated tool pipelines
- shared templates and markdown assets
- controlled human review points

The target operating model is:

1. client/project data is captured once
2. scope, plans, evidence requests, and work items are generated automatically where possible
3. execution is delegated to service-specific pipelines and tools
4. evidence is normalized and indexed automatically
5. findings and report drafts are assembled automatically
6. humans intervene mainly for approvals, exceptions, interpretation, and final sign-off

## 3. Design Principles

- one methodology, many service modules
- automation-first, not manual-first
- evidence-first conclusions
- explicit scope control
- repeatable execution
- strong traceability from source evidence to final finding
- modular tool integration
- minimal duplicated analyst effort
- controlled AI assistance
- mandatory QA before external delivery

---

## MRK:TG_METH_LAYERS — §4 Methodology Layers + platform architecture | tg,meth,layers,methodology,platform | L95-193

## 4. Methodology Layers

### 4.1 Layer 1: Core Method

The Core Method is mandatory for every engagement and defines:

- lifecycle stages
- stage gates
- approval points
- common artifact model
- common evidence model
- common finding model
- common QA model
- common reporting model

### 4.2 Layer 2: Service Modules

Each service type inherits the Core Method and adds:

- service-specific workflow logic
- service-specific toolchain
- service-specific evidence patterns
- service-specific analysis logic
- service-specific report sections

Initial service modules:

- standards consulting and preparation
- penetration testing
- gap analysis
- security assessments
- risk assessments
- remediation validation

### 4.3 Layer 3: Tooling and Pipeline Packs

Each methodology layer should be implemented in tooling through:

- core orchestration tools
- service pipelines
- evidence processing tools
- analysis support tools
- reporting tools
- QA and release tools

### 4.4 Platform Implementation Architecture (v0.3)

The `tg-audit-orchestrator` platform implements the three methodology layers as three software tiers:

```
┌─────────────────────────────────────────────────────────┐
│  TIER 1 — EngagementCore (shared library)               │
│                                                         │
│  engagement_core/                                       │
│  ├── models/                                            │
│  │   ├── objective.py      (Objective, ObjectiveStatus) │
│  │   ├── opplan.py         (OPPLANMiddleware, 5 tools)  │
│  │   ├── bundle.py         (EngagementBundle, ScopePack)│
│  │   ├── state.py          (EngagementState, phases)    │
│  │   └── pack.py           (MethodologyPack ABC)        │
│  ├── frameworks/                                        │
│  │   └── registry.py       (FrameworkRegistry)         │
│  ├── agents/                                            │
│  │   └── report_writer.py  (BaseReportWriterAgent)      │
│  ├── intake/                                            │
│  │   ├── soundwave.py      (IntakeInterview orchestrator)│
│  │   └── record.py         (IntakeRecord)               │
│  └── loop.py               (EngagementLoop)             │
│                                                         │
│  Dependencies: none (pure Python + LangChain primitives)│
└─────────────────────────────────────────────────────────┘
           ↑ imports                    ↑ imports
┌──────────────────────────┐   ┌────────────────────────────┐
│  TIER 2                  │   │  TIER 3                    │
│  tg-audit-orchestrator   │   │  Methodology Packs         │
│                          │   │                            │
│  orchestrator/           │   │  packs/                    │
│  ├── main.py             │   │  ├── pentest.py            │
│  ├── dispatcher.py       │   │  ├── tsa.py                │
│  ├── session.py          │   │  ├── iso27001.py           │
│  └── api/                │   │  ├── compliance.py         │
│      └── routes.py       │   │  ├── gap.py                │
│                          │   │  └── remediation.py        │
│  Dependencies:           │   │                            │
│  - EngagementCore (T1)   │   │  Dependencies:             │
│  - Packs (T3) via        │   │  - EngagementCore (T1)     │
│    PackDispatcher        │   │  - no T2 imports           │
└──────────────────────────┘   └────────────────────────────┘
```

**Dependency rules:**
- T1 → nothing — `EngagementCore` has no imports from T2 or T3
- T2 → T1, T3 — `tg-audit-orchestrator` imports T1 models and loads T3 packs via `PackDispatcher`
- T3 → T1 only — packs import `EngagementCore` models; they never import from T2

---

## MRK:TG_METH_TOOLING — §5–7 Tooling model + placeholder tables | tg,meth,tooling,model,placeholder | L194-261

## 5. Tooling Placeholder Model

This document uses placeholder identifiers so the methodology can later be bound directly to tools in `tg-audit-orchestrator`.

Placeholder naming approach:

- `TG-CORE-*` for shared core orchestration tools
- `TG-EVID-*` for evidence ingestion and processing tools
- `TG-ANL-*` for analysis and mapping tools
- `TG-RPT-*` for report generation and publishing tools
- `TG-QA-*` for quality and review tools
- `TG-OPS-*` for administration, metrics, and governance tools
- `TG-PT-*` for penetration testing tools and pipelines
- `TG-STD-*` for standards consulting and readiness tools
- `TG-GAP-*` for gap analysis tools
- `TG-ASM-*` for security assessment tools
- `TG-RISK-*` for risk assessment tools
- `TG-VAL-*` for remediation validation tools

Tool status labels:

- `Existing`: already available in a repository
- `Planned`: to be built in `tg-audit-orchestrator`
- `Optional`: may be integrated later or used selectively

## 6. Existing Tool Mapping

The following existing assets should be treated as the first implementation candidates behind methodology placeholders.

| Placeholder | Status | Current Source | Current Role |
|---|---|---|---|
| `TG-PT-EXEC-PIPELINE` | Existing | `PT-Orc` | phase-based pentest execution pipeline |
| `TG-CORE-DOC-NAV` | Existing | `nav-tools` | structured document navigation and methodology content discipline |
| `TG-EVID-NORMALIZE` | Existing | `audit-evidence-processor` | convert, OCR, translate, and categorize evidence |
| `TG-PT-AUTO-OPS` | Optional | `Decepticon / PentestPack` | adversarial execution; now implemented as PentestPack within EngagementCore |

## 7. Future Core Platform Placeholders

The `tg-audit-orchestrator` project should implement the following core capabilities.

| Placeholder | Status | Purpose |
|---|---|---|
| `TG-CORE-INTAKE` | Planned | create and manage intake records |
| `TG-CORE-SCOPE` | Planned | define scope, exclusions, approvals, and authorization pack |
| `TG-CORE-PLAN` | Planned | generate project plan, objectives, tasks, and dependencies |
| `TG-CORE-CONTEXT` | Planned | context and situational awareness; ConOps document management; environment profile |
| `TG-CORE-WORKSPACE` | Planned | create standard project structure and metadata |
| `TG-CORE-DISPATCH` | Planned | route objectives to the correct MethodologyPack specialist agents via PackDispatcher |
| `TG-CORE-GATE` | Planned | enforce stage gates and approval holds |
| `TG-CORE-TRACKER` | Planned | track tasks, evidence gaps, statuses, and exceptions |
| `TG-EVID-REQUEST` | Planned | generate and manage evidence requests |
| `TG-EVID-INGEST` | Planned | ingest files, exports, screenshots, logs, and raw evidence |
| `TG-EVID-INDEX` | Planned | maintain searchable evidence manifest and metadata |
| `TG-ANL-MAP` | Planned | map evidence to controls, objectives, risks, or findings |
| `TG-ANL-FINDINGS` | Planned | build draft findings from validated evidence and mappings |
| `TG-ANL-CHAIN` | Planned | attack path / audit chain analysis; links objectives to findings via structured chain |
| `TG-RPT-BUILD` | Planned | assemble draft reports from structured project data |
| `TG-QA-CHECK` | Planned | run structured QA checks before release |
| `TG-RPT-PUBLISH` | Planned | prepare final deliverables and release packages |
| `TG-OPS-METRICS` | Planned | collect operational and quality metrics |
| `TG-OPS-LESSONS` | Planned | capture lessons learned and improvement backlog items |

*(v0.3 additions: `TG-CORE-CONTEXT` and `TG-ANL-CHAIN`. Total TG-* placeholders: ~36 across 12 families.)*

---

## MRK:TG_METH_LIFECYCLE — §8–9 Human model + lifecycle | tg,meth,lifecycle,human,model | L262-568

## 8. Human Interaction Model

The methodology is intended to minimize manual handling, but not remove human accountability.

Human interaction should be concentrated in the following points:

- service classification where ambiguity exists
- scope and authorization approval
- exceptions and deviations
- expert judgment in analysis
- severity confirmation
- QA review
- final delivery approval

Routine work should be automated where possible:

- project setup
- evidence request generation
- evidence ingestion and normalization
- objective/task generation
- execution dispatch
- evidence-to-control mapping
- report assembly
- QA pre-checking

## 9. Standard Lifecycle with Tool Placeholders

All TechGuard engagements must follow the lifecycle below.

### Stage 1. Intake and Qualification

Objective: register the engagement and determine what service module applies.

Core activities:

- capture client, sponsor, project context, and expected outcome
- classify the engagement type
- record known scope, dependencies, and constraints
- identify required expertise and delivery conditions

Primary tools:

- `TG-CORE-INTAKE` - intake creation and project registration
- `TG-CORE-TRACKER` - open questions and qualification follow-up
- `TG-CORE-DOC-NAV` - methodology content guidance and template navigation

Outputs:

- intake record
- engagement classification
- preliminary scope note
- qualification question log

Human gate:

- approve intake classification

### Stage 2. Scope and Authorization

Objective: define exactly what is in scope, out of scope, and allowed.

Core activities:

- define scope boundaries
- record exclusions and prohibited actions
- record timing, communications, and escalation
- record legal and operating constraints

Primary tools:

- `TG-CORE-SCOPE` - scope pack generation and authorization management
- `TG-CORE-GATE` - stage gate enforcement
- `TG-CORE-DOC-NAV` - reuse of standard scope language and templates
- `TG-CORE-CONTEXT` - ConOps and environment profile initialization (v0.3)

Outputs:

- scope pack
- authorization pack
- exclusions list
- communication matrix

Human gate:

- approve scope and authorization before execution planning

### Stage 3. Planning and Work Design

Objective: convert the approved scope into an executable project workflow.

Core activities:

- generate objectives and workstreams
- assign service module pipeline
- create dependencies and milestones
- prepare evidence request plan
- prepare deliverable plan

Primary tools:

- `TG-CORE-PLAN` - plan, objective, and task generation
- `TG-CORE-CONTEXT` - ConOps document; context injected into specialist agent prompts (v0.3)
- `TG-CORE-WORKSPACE` - project structure initialization
- `TG-CORE-DISPATCH` - map project tasks to MethodologyPack specialist agents
- `TG-EVID-REQUEST` - generate evidence request lists
- `TG-CORE-DOC-NAV` - module and template guidance

Outputs:

- engagement plan
- objective/task plan
- evidence request list
- project workspace
- milestone plan

Human gate:

- approve plan

### Stage 4. Information and Evidence Acquisition

Objective: obtain all needed raw project inputs and normalize them for downstream use.

Core activities:

- request information and client evidence
- ingest raw technical and documentary evidence
- preserve source metadata
- identify missing evidence
- normalize evidence for search and analysis

Primary tools:

- `TG-EVID-REQUEST` - request generation and tracking
- `TG-EVID-INGEST` - raw evidence intake
- `TG-EVID-NORMALIZE` - conversion, OCR, translation, text extraction, and bundling
- `TG-EVID-INDEX` - evidence manifest and metadata indexing

Outputs:

- evidence request tracker
- evidence inventory
- normalized evidence corpus
- evidence sufficiency status
- evidence gap log

Human gate:

- review material evidence gaps if automation cannot resolve them

### Stage 5. Analysis and Assessment

Objective: evaluate collected evidence using the relevant service module logic.

Core activities:

- map evidence to controls, requirements, risks, or technical hypotheses
- run service-specific execution pipelines
- produce observations and intermediate conclusions
- identify missing support, contradictions, or uncertainty

Primary tools:

- `TG-ANL-MAP` - evidence-to-objective/control mapping
- `TG-CORE-DISPATCH` - route work to MethodologyPack specialist agents
- `TG-PT-EXEC-PIPELINE` - pentest execution where service type is penetration testing
- `TG-PT-AUTO-OPS` - optional autonomous objective execution where approved
- `TG-STD-CONTROL-MAP` - planned standards consulting mapping tool
- `TG-GAP-MATRIX` - planned gap comparison tool
- `TG-ASM-CHECKS` - planned security assessment checklist engine
- `TG-RISK-SCORING` - planned risk analysis engine

Outputs:

- analysis records
- mapped requirements / controls / objectives
- observations log
- preliminary finding candidates
- uncertainty / limitation notes

Human gate:

- analyst confirms conclusions where automated assessment is ambiguous or high-impact

### Stage 6. Synthesis and Finding Development

Objective: convert analysis outputs into defensible findings, gaps, and risks.

Core activities:

- deduplicate overlapping observations
- determine priority and severity
- add business or technical impact language
- bind findings to evidence references
- propose remediation or next actions

Primary tools:

- `TG-ANL-FINDINGS` - finding synthesis engine
- `TG-ANL-CHAIN` - attack path / audit chain; links objectives to findings (v0.3)
- `TG-RISK-SCORING` - risk and severity support
- `TG-GAP-MATRIX` - gap prioritization support
- `TG-CORE-TRACKER` - finding and remediation action tracking

Outputs:

- findings register
- gap matrix or risk register
- remediation recommendations
- severity rationale
- attack / audit chain document (v0.3)

Human gate:

- lead analyst confirms severity and issue framing

### Stage 7. Quality Assurance and Review

Objective: verify that outputs are accurate, traceable, complete, and aligned with scope.

Core activities:

- validate evidence traceability
- validate scope alignment
- validate severity consistency
- detect unsupported statements
- check report completeness and terminology

Primary tools:

- `TG-QA-CHECK` - QA rule engine
- `TG-EVID-INDEX` - evidence trace lookup
- `TG-CORE-GATE` - prevent release before required checks pass
- `TG-CORE-DOC-NAV` - reporting and wording standards guidance

Outputs:

- QA checklist results
- review comments
- approved draft deliverables

Human gate:

- reviewer signs off release readiness

### Stage 8. Reporting and Delivery

Objective: generate and deliver the final client-facing outputs.

Core activities:

- assemble technical and executive outputs
- produce action plans and trackers where required
- include limitations and confidence notes
- prepare final release package

Primary tools:

- `TG-RPT-BUILD` - report assembly engine
- `TG-RPT-PUBLISH` - release packaging and export
- `TG-CORE-TRACKER` - delivery status management
- `TG-CORE-DOC-NAV` - report structure and wording guidance

Outputs:

- executive summary
- technical report
- action tracker or remediation plan
- evidence index where required
- delivery package

Human gate:

- final delivery approval

### Stage 9. Closure and Continuous Improvement

Objective: close the engagement and feed improvements back into methodology and tooling.

Core activities:

- archive approved outputs
- record lessons learned
- capture reusable patterns
- register improvement items for methods, templates, and tools

Primary tools:

- `TG-OPS-LESSONS` - lessons learned and improvement capture
- `TG-OPS-METRICS` - project metrics and performance tracking
- `TG-CORE-TRACKER` - closure workflow management

Outputs:

- closure record
- lessons learned note
- improvement backlog entries
- metrics snapshot

Human gate:

- close project formally

---

## MRK:TG_METH_MODELS — §10–13 Roles, artifacts, evidence, findings | tg,meth,models,roles,artifacts | L569-651

## 10. Standard Roles in the Automation-First Model

| Role | Primary Responsibility in This Model |
|---|---|
| Engagement Lead | approve scope, exceptions, and final delivery |
| Delivery Manager / Coordinator | manage dependencies, communications, and stage movement |
| Lead Analyst | validate analysis, findings, and risk judgments |
| Analyst | review tool outputs, investigate exceptions, and refine conclusions |
| Reviewer / QA Reviewer | perform independent QA review |
| Tool Owner | maintain pipelines, templates, and automation quality |

Role rule:

- tools may execute process steps
- humans remain accountable for judgment and delivery

## 11. Standard Artifact Model

Each engagement should produce a structured project record with at least:

- intake record
- scope pack
- plan pack
- evidence request tracker
- evidence manifest
- analysis records
- findings register or risk register
- QA log
- report package
- closure record

These artifacts should be generated and maintained primarily through tools, not manual folder handling.

## 12. Standard Evidence Model

Evidence must be machine-trackable and human-reviewable.

Each evidence item should have:

- unique evidence ID
- project ID
- source
- collection method
- collection timestamp
- collector or collecting system
- classification or sensitivity
- linked scope item
- linked objective / requirement / control
- integrity or version reference where available

Primary evidence tooling placeholders:

- `TG-EVID-INGEST`
- `TG-EVID-NORMALIZE`
- `TG-EVID-INDEX`

## 13. Standard Finding Model

Each formal finding should contain:

- finding ID
- title
- affected scope area
- evidence references
- issue statement
- why it matters
- impact / risk statement
- severity / priority
- root cause or contributing factor
- recommendation
- status
- limitation or confidence note, if applicable

Primary finding tooling placeholders:

- `TG-ANL-FINDINGS`
- `TG-RISK-SCORING`
- `TG-CORE-TRACKER`

---

## MRK:TG_METH_SERVICES — §14 Service Module Placeholders | tg,meth,services,service,module | L652-734

## 14. Service Module Placeholders

The following modules should be built on top of the Core Method. Each module is implemented as a `MethodologyPack` — see §MP for the architecture.

### 14.1 Standards Consulting and Preparation Module

Purpose:

- help clients prepare for standards, certification, or audit readiness

Planned tools:

- `TG-STD-CONTROL-MAP`
- `TG-STD-EVIDENCE-PLAN`
- `TG-STD-READINESS-SCORE`
- `TG-STD-ROADMAP`

### 14.2 Penetration Testing Module

Purpose:

- execute authorized technical testing and validate exploitable weaknesses

Tool stack:

- `TG-PT-EXEC-PIPELINE` - existing `PT-Orc`
- `TG-PT-AUTO-OPS` - `PentestPack` specialist agents (formerly Decepticon; see §20)
- `TG-EVID-NORMALIZE` - existing evidence processor for collected artifacts
- `TG-PT-FINDING-BUILDER` - planned pentest finding assembly tool
- `TG-PT-RETEST` - planned remediation verification workflow

### 14.3 Gap Analysis Module

Purpose:

- compare current state to target requirements and identify missing implementation

Planned tools:

- `TG-GAP-MATRIX`
- `TG-GAP-PRIORITIZE`
- `TG-GAP-ROADMAP`

### 14.4 Security Assessment Module

Purpose:

- assess security controls, architecture, configurations, and operating effectiveness

Planned tools:

- `TG-ASM-CHECKS`
- `TG-ASM-CONTROL-MAP`
- `TG-ASM-OBSERVATIONS`

### 14.5 Risk Assessment Module

Purpose:

- identify, rate, and prioritize security risks

Planned tools:

- `TG-RISK-REGISTER`
- `TG-RISK-SCORING`
- `TG-RISK-TREATMENT`

### 14.6 Remediation Validation Module

Purpose:

- verify corrective actions and determine residual risk

Planned tools:

- `TG-VAL-CHECKLIST`
- `TG-VAL-EVIDENCE-COMPARE`
- `TG-VAL-DECISION`

---

## MRK:TG_METH_EM — §EM Generic Engagement Model | tg,meth,em,generic,engagement | L735-790

## EM. Generic Engagement Model

Every TechGuard engagement — regardless of service type — is described by ten entities. These entities are consistent across all service types; the *methodology pack* supplies the rules for how each entity is populated and used within a specific engagement type.

### The ten entities

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

### Entity relationships

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

### What stays the same across service types

- The `Engagement` entity, `engagement_id` format, and lifecycle (planning → execution → reporting → complete) are identical for all service types.
- The `Objective` schema (fields, status FSM) is identical for all service types.
- Evidence collection and report generation use the same platform components regardless of service type.

### What varies by service type

- The phase sequence within execution (e.g., pentest has `reconnaissance / exploitation / post-exploitation`; ISO 27001 audit has `document_review / controls_testing / nonconformity`).
- The permitted objective types and their control reference taxonomy.
- The required planning bundle documents.
- The specialist agents active during execution.
- The report structure and output sections.

All of this variation is encapsulated by the **MethodologyPack** (§MP below).

---

## MRK:TG_METH_MP — §MP MethodologyPack Architecture | tg,meth,mp,methodologypack,architecture | L791-857

## MP. MethodologyPack Architecture

### What is a MethodologyPack?

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

### How packs integrate with the platform

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

### EngagementCore: the shared kernel

All six packs share a common infrastructure layer called `EngagementCore`:

- **OPPLAN** — the objective management engine (create, update, list, track status)
- **EngagementBundle** — planning document container
- **EngagementState** — phase tracking and lifecycle management
- **EngagementLoop** — the execution loop that iterates objectives and dispatches agents
- **Soundwave** — intake interview orchestrator
- **FrameworkRegistry** — central registry of control frameworks (MITRE ATT&CK, CIS, ISO 27001, etc.)

`EngagementCore` is methodology-agnostic. It knows nothing about reconnaissance, ISMS auditing, or compliance frameworks until a `MethodologyPack` is loaded. This deliberate separation allows TechGuard to add new service types without modifying the platform core.

### Adding a new service type

Adding a new service type to TechGuard's platform requires:

1. Defining a new `MethodologyPack` subclass (phases, objective types, control refs, bundle docs, agent roster).
2. Registering the pack slug in `PackDispatcher`.
3. Adding intake questions for the pack in Soundwave.
4. Implementing the pack's specialist agents (or reusing agents from existing packs).

No changes to `EngagementCore` are required. The platform's core stability is the foundation that allows the service portfolio to expand incrementally.

---

## MRK:TG_METH_WORKSPACE — §15 Project Workspace | tg,meth,workspace,project | L858-879

## 15. Standard Project Workspace Placeholder

Each engagement should be created through `TG-CORE-WORKSPACE` and expose a standard logical structure such as:

- `01_intake`
- `02_scope`
- `03_plan`
- `04_evidence_requests`
- `05_evidence_raw`
- `06_evidence_processed`
- `07_analysis`
- `08_findings`
- `09_reports`
- `10_qa`
- `11_closure`

This may be implemented physically as folders, structured records, database entities, or a hybrid model, but the logical separation must remain.

---

## MRK:TG_METH_OPS — §16–17 Exceptions + Metrics | tg,meth,ops,exceptions,metrics | L880-930

## 16. Exceptions and Deviations

Automation does not eliminate the need to record deviations.

Exceptions include:

- incomplete scope authorization
- insufficient evidence
- tool failure or pipeline failure
- inability to execute a required module step
- limited client access
- accelerated release with reduced QA

Recommended tooling:

- `TG-CORE-TRACKER`
- `TG-CORE-GATE`

Every exception should capture:

- deviation description
- reason
- approver
- impact on delivery
- impact on confidence

## 17. Metrics and Management Oversight

The methodology should support operational metrics through tooling, not ad hoc manual counting.

Primary metrics areas:

- number of projects by type
- stage duration
- evidence sufficiency rate
- automation coverage rate
- analyst intervention rate
- QA failure / rework rate
- report cycle time
- recurring finding themes
- recurring evidence gaps
- recurring tool failures

Primary tooling:

- `TG-OPS-METRICS`

---

## MRK:TG_METH_BUILDORDER — §18 Implementation Order | tg,meth,buildorder,implementation,order | L931-959

## 18. Implementation Order for `tg-audit-orchestrator`

Recommended build order:

1. `TG-CORE-WORKSPACE`
2. `TG-CORE-INTAKE`
3. `TG-CORE-SCOPE`
4. `TG-CORE-PLAN`
4a. `TG-CORE-CONTEXT` *(v0.3 — runs in parallel with step 4; ConOps + environment profile before first objective dispatch)*
5. `TG-CORE-TRACKER`
6. `TG-EVID-INGEST`
7. `TG-EVID-INDEX`
8. integration of `TG-EVID-NORMALIZE`
9. `TG-ANL-CHAIN` *(v0.3 — analysis chain; inserted between objective completion and report generation)*
10. `TG-RPT-BUILD`
11. `TG-QA-CHECK`
12. `TG-CORE-DISPATCH` *(v0.3 — routes to MethodologyPack specialist agents via PackDispatcher)*
13. service modules in this order:
14. penetration testing (`PentestPack`)
15. standards consulting and preparation
16. gap analysis
17. security assessment
18. risk assessment
19. remediation validation

---

## MRK:TG_METH_NEXTDOCS — §19 Immediate Next Deliverables | tg,meth,nextdocs,immediate,next | L960-978

## 19. Immediate Next Deliverables

Recommended next documents after this draft:

- tooling placeholder register
- data model for project, evidence, finding, and report entities
- standard gate and approval matrix
- standard evidence metadata schema
- standard finding schema
- penetration testing service module draft
- standards consulting and preparation service module draft
- QA rule catalog
- report template pack
- MethodologyPack implementation guide (v0.3 addition)

---

## MRK:TG_METH_DECEPTICON — §20 Decepticon + platform architecture | tg,meth,decepticon,platform,architecture | L979-1039

## 20. Decepticon and the tg-audit-orchestrator Platform

### The open question, resolved

v0.2 §20 noted an open architectural question: *"Should Decepticon remain optional or become a controlled specialist module?"*

The answer is neither option as originally framed.

**Decepticon is refactored, not removed or constrained.** It is split along an architectural boundary that separates its generic planning infrastructure from its adversarial-specific logic:

- The **planning infrastructure** (OPPLAN, EngagementBundle, EngagementState, Soundwave intake) is extracted into `EngagementCore` — a shared library used by all service types. This layer is not optional; it is the foundation of every TechGuard engagement.
- The **adversarial-specific logic** (reconnaissance, exploitation, post-exploitation specialist agents; MITRE ATT&CK control references; red team phase taxonomy) becomes `PentestPack` — one of six `MethodologyPack` implementations. It is the pack selected when the engagement type is `pentest` or `red_team`.

Decepticon does not become "optional" — its core is mandatory for all engagements. It does not become a "specialist module" in the sense of a black-box called from outside — it becomes the first-party implementation of the `MethodologyPack` interface for adversarial service types.

### Platform component map

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

### Decepticon migration path

Decepticon is not replaced in a single step. The migration preserves backward compatibility throughout:

**Phase A — Extract (no behavior change):**
Move `OPPLANMiddleware`, `EngagementBundle`, `EngagementState`, `EngagementLoop`, `Soundwave` into the `EngagementCore` library. Decepticon imports from `EngagementCore` instead of its own internal modules. All existing Decepticon functionality is identical; all tests pass unchanged.

**Phase B — Parameterize (no behavior change):**
Replace Decepticon's hardcoded `PHASES` list, `mitre[]` field, and `opsec_*` fields with pack-supplied values via the `MethodologyPack` interface. `PentestPack` supplies the same values that were previously hardcoded. All existing engagement behavior is preserved.

**Phase C — Scaffold (adds capability):**
Add the `tg-audit-orchestrator` T2 orchestration layer. Register `PentestPack` and `GapAssessmentPack` in `PackDispatcher`. Soundwave intake interview now selects the pack based on `engagement_type`. Pentest engagements continue to run exactly as before; gap assessment engagements are now available.

### Decepticon in the context of v0.3 methodology

The v0.3 methodology treats Decepticon as the reference implementation of `PentestPack`, not as a standalone tool. When the methodology describes penetration test execution, the tooling references are:

- `TG-CORE-PLAN` → `EngagementCore / OPPLANMiddleware` (objective management)
- `TG-CORE-CONTEXT` → `EngagementCore / EngagementBundle / ConOps` (context + ConOps)
- `TG-CORE-DISPATCH` → `tg-audit-orchestrator / PackDispatcher` (routes to `PentestPack` specialist agents)
- `TG-ANL-CHAIN` → `PentestPack / attack chain analysis` (attack path narrative)
- `TG-CORE-REPORT` → `EngagementCore / BaseReportWriterAgent` + `PentestPack / PentestReportWriterAgent`

For non-pentest service types, the same methodology steps apply; only the pack-supplied content differs. The generic engagement model (§EM) and the MethodologyPack architecture (§MP) describe this unification.

<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
