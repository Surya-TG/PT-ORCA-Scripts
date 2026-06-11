<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->

<!-- MRK:SPEC_DCPTCN_TG_ORIENTATION_20260427_1325_NAV_TOC — Section index | nav,toc,index | L4-12 -->
<!-- - MRK:DCPTCN_SPEC_STATUS — Status & delivery target | dcptcn,spec,status,delivery,target | L13-21 -->
<!-- - MRK:DCPTCN_SPEC_ENGMODEL — Generic engagement model | dcptcn,spec,engmodel,generic,engagement | L22-40 -->
<!-- - MRK:DCPTCN_SPEC_METHODOLOGY — Unified methodology lifecycle | dcptcn,spec,methodology,unified,lifecycle | L41-82 -->
<!-- - MRK:DCPTCN_SPEC_DECEPTICON — Decepticon planner generalization | dcptcn,spec,decepticon,planner,generalization | L83-99 -->
<!-- - MRK:DCPTCN_SPEC_ARCH — Architecture bottom line | dcptcn,spec,arch,architecture,bottom | L100-113 -->
<!-- - MRK:DCPTCN_SPEC_REPO — Decepticon repo analysis | dcptcn,spec,repo,decepticon,analysis | L114-191 -->
<!-- NAV-LEN: 6 entries | Integrity-hash: ce4382f6aaebc86e | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:DCPTCN_SPEC_STATUS — Status & delivery target | dcptcn,spec,status,delivery,target | L13-21

**Project:** DCPTCN_TG — Review TG docs on Decepticon
**Domain:** audit-orc
**Status / Next:** plan / proposal for final delivery — ~500h from ERA
**Source:** David Belostotsky, 2026-04-27 (Slack/Teams messages)

---

## MRK:DCPTCN_SPEC_ENGMODEL — Generic engagement model | dcptcn,spec,engmodel,generic,engagement | L22-40

Manage one generic engagement model for all Tech Guard work:

| Entity | Description |
|--------|-------------|
| **Engagement** | Top-level container — client, framework, service type, constraints, risk, approvals |
| **Scope** | Inclusions, exclusions, contacts, timing, delivery plan |
| **Requirements** | Control framework or assessment model mapping (ISO 27001, SOC 2, pentest standard, etc.) |
| **Objectives** | Discrete work items — interview tasks, document review, config review, scanner runs, validation, evidence chase, report drafting |
| **Evidence Requests** | Formal evidence request list generated at scope stage |
| **Collected Evidence** | Raw evidence corpus collected during fieldwork |
| **Observations** | Thematic observations from evidence analysis |
| **Findings** | Drafted findings with severity, risk, remediation, reviewer sign-off |
| **Deliverables** | Technical report, executive summary, gap matrix, evidence index, remediation tracker |
| **Remediation Actions** | Tracked remediation items linked to findings |

---

## MRK:DCPTCN_SPEC_METHODOLOGY — Unified methodology lifecycle | dcptcn,spec,methodology,unified,lifecycle | L41-82

Use one Tech Guard lifecycle for every cyber/security audit or consulting engagement:

### 1. Intake and Qualification
Define client, framework, service type, constraints, risk, approvals.

### 2. Scope and Engagement Pack
Generate scope, exclusions, contacts, timing, evidence request list, delivery plan.
Reuse Decepticon's RoE/ConOps/OPPLAN discipline, but generalize it beyond red teaming.

### 3. Requirement Model
Map the engagement to a control framework or assessment model: ISO 27001, SOC 2, internal baseline, pentest standard, cloud review, gap assessment.

### 4. Fieldwork Planning
Break work into objectives and tasks.
Examples: interview tasks, document review, config review, scanner runs, validation, evidence chase, report drafting.

### 5. Execution
Route objectives to the right engine:
- **PT-Orc** — scoped scanning and technical verification
- **Decepticon** — advanced autonomous test objectives where explicitly approved
- **Manual analyst** — interviews, workshops, policy reviews, architecture review
- **Future connectors** — cloud/SaaS evidence pulls

### 6. Evidence Normalization
Everything collected gets converted into a normalized evidence corpus through **audit-evidence-processor**.

### 7. Evidence-to-Requirement Analysis
Map normalized evidence to controls, objectives, weaknesses, and missing proof.

### 8. Finding Generation and QA
Draft findings with evidence references, severity, risk, remediation, and reviewer sign-off.

### 9. Reporting
Generate technical report, executive summary, gap matrix, evidence index, and remediation tracker.

### 10. Closure and Reuse
Preserve sanitized playbooks, objective templates, evidence patterns, and report patterns for future jobs.

---

## MRK:DCPTCN_SPEC_DECEPTICON — Decepticon planner generalization | dcptcn,spec,decepticon,planner,generalization | L83-99

Reuse Decepticon's OPPLAN/objective state machine for all Tech Guard engagements — not just offensive ones.

Add methodology packs for:

| Pack | Description |
|------|-------------|
| **Pentest** | Scoped offensive testing lifecycle |
| **Technical Security Assessment** | Broad technical review without active exploitation |
| **ISO 27001 Support** | Gap analysis and evidence support for certification/surveillance |
| **Compliance Evidence Review** | Evidence mapping against a compliance framework |
| **Gap Assessment** | Baseline vs. target state analysis |
| **Remediation Verification** | Validate that remediation actions closed findings |

---

## MRK:DCPTCN_SPEC_ARCH — Architecture bottom line | dcptcn,spec,arch,architecture,bottom | L100-113

The cleanest platform shape:

| Component | Role |
|-----------|------|
| **tg-audit-orchestrator** | New Tech Guard platform core — drives the unified engagement lifecycle |
| **PT-Orc** | Pentest execution engine |
| **Decepticon** | Autonomous advanced objective engine (explicitly approved engagements) |
| **audit-evidence-processor** | Evidence normalization and thematic clustering |
| **nav-tools** | Shared methodology / document operating system |

---

## MRK:DCPTCN_SPEC_REPO — Decepticon repo analysis | dcptcn,spec,repo,decepticon,analysis | L114-191

**Repo:** https://github.com/PurpleAILAB/Decepticon.git
**Description:** Autonomous Hacking Agent for Red Team
**Stack:** Python · TypeScript · Go · LangGraph
**Agents:** 16 specialist agents organized by kill chain phase

### Planning System (Soundwave agent)

```
Operator defines target
→ Soundwave interview (threat profile, scope, exclusions, OPSEC)
→ generates: RoE + ConOps + Deconfliction Plan + OPPLAN
→ operator reviews and approves
→ autonomous execution loop
```

Source: `docs/engagement-workflow.md`, `docs/design/opplan-middleware.md`

### OPPLAN State Machine (OPPLANMiddleware)

**State transitions:**
```
pending → in-progress → passed
                      → blocked  → in-progress (retry)
                      → out-of-scope
```

**Tools:** `create_opplan` · `add_objective` · `get_objective` · `list_objectives` · `update_objective`

**Objective schema fields** (from `demo/plan/opplan.json` + `decepticon/core/schemas.py`):

| Field | Offensive use | Generalized use |
|-------|--------------|-----------------|
| `id` | OBJ-001 | unchanged |
| `phase` | recon/initial-access/c2/post-exploit/exfiltration | intake/scope/fieldwork/evidence/analysis/reporting |
| `title`, `description` | unchanged | unchanged |
| `acceptance_criteria[]` | pass criteria | unchanged |
| `priority`, `status` | unchanged | unchanged |
| `blocked_by[]` | dependency graph | unchanged |
| `concessions[]` | unchanged | unchanged |
| `mitre[]` | ATT&CK technique IDs | → `control_refs[]` (ISO clause, SOC 2 criterion, etc.) |
| `opsec`, `opsec_notes` | loud/standard/quiet | → drop / replace with `methodology_notes` |
| `c2_tier` | interactive/short-haul/long-haul | → drop |
| `owner`, `notes` | unchanged | unchanged |

### EngagementBundle (generalization target)

Current: RoE + ConOps + Deconfliction Plan + OPPLAN
Generalized: Scope Pack + Authorization Pack + Methodology Module + Objective Plan

### EngagementState phases (generalization target)

Current: `planning → attack → vaccine → complete`
Generalized: `planning → execution → analysis → reporting → complete`

### Key source files for review

| File | Purpose |
|------|---------|
| `demo/plan/roe.json` | Example RoE document (scope, prohibited/permitted actions, authorization) |
| `demo/plan/conops.json` | Example ConOps (threat profile, kill chain, methodology, success criteria) |
| `demo/plan/opplan.json` | Example OPPLAN (5 objectives, full state machine fields) |
| `docs/engagement-workflow.md` | Two-phase planning + execution workflow description |
| `docs/design/opplan-middleware.md` | State machine design: FSM, tools, state injection, validation |
| `decepticon/core/schemas.py` | Pydantic models: RoE, ConOps, Objective, OPPLAN, EngagementBundle, Finding, AttackPath |
| `decepticon/core/engagement.py` | EngagementState, EngagementConfig, EngagementPhase, IterationResult |
| `decepticon/core/engagement_loop.py` | Autonomous execution loop |
| `decepticon/orchestrator.py` | Main orchestrator — RoE enforcement, objective dispatch |

### Central question to close (v0.2 §20 open item)

> *"Should Decepticon remain Optional or become a controlled specialist module?"*

**Answer direction:** Extract the planning framework (Soundwave interview → OPPLAN state machine → EngagementBundle) as a shared methodology layer in `tg-audit-orchestrator`. Keep Decepticon as the offensive execution engine that plugs into that shared layer via the Pentest methodology pack.

<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
