<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- MRK:PHASE2_FIT_ASSESSMENT_20260427_NAV_TOC — Section index | nav,toc,index | L4-15 -->
<!-- - MRK:FIT_SUMMARY — Executive summary | fit,summary,executive,overview | L16-27 -->
<!-- - MRK:FIT_COMPONENTS — Decepticon component inventory | fit,components,decepticon,component,inventory | L28-67 -->
<!-- - MRK:FIT_MAP — Component → TG-CORE-* mapping | fit,map,component,tg,core | L68-100 -->
<!-- - MRK:FIT_REUSABLE — Reusable as-is | fit,reusable,unchanged,asis | L101-148 -->
<!-- - MRK:FIT_PARAMETERIZE — Needs parameterization | fit,parameterize,needs,parameterization,generalize | L149-204 -->
<!-- - MRK:FIT_DROP — Offensive-specific: drop | fit,drop,offensive,specific | L205-225 -->
<!-- - MRK:FIT_GAPS — Decepticon concepts not in v0.2 | fit,gaps,decepticon,concepts,v0 | L226-247 -->
<!-- - MRK:FIT_ARCHITECTURE — Extraction architecture | fit,architecture,extraction,engagementcore | L248-304 -->
<!-- - MRK:FIT_VERDICT — Phase 2 verdict for DCPTCN_TG | fit,verdict,phase,dcptcn,tg | L305-333 -->
<!-- NAV-LEN: 9 entries | Integrity-hash: f24356dbbe01480d | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:FIT_SUMMARY — Executive summary | fit,summary,executive,overview | L16-27

**Produced:** 2026-04-27 | **Project:** DCPTCN_TG | **Phase:** 2 of 5

Decepticon has a clean two-layer architecture: a **planning kernel** (Soundwave + EngagementBundle + OPPLANMiddleware) and an **offensive execution shell** (16 specialist agents + Vaccine loop + MITRE/OPSEC/C2 specifics). The planning kernel is almost entirely reusable. The offensive shell is entirely replaceable by methodology-pack-specific agent sets.

The correct generalization is not to modify Decepticon — it is to **extract the planning kernel** as a standalone library (`EngagementCore`) and have both `tg-audit-orchestrator` and Decepticon depend on it. Decepticon becomes the offensive methodology pack; audit orchestrator adds non-offensive packs.

Every v0.2 `TG-CORE-*` planned placeholder has a direct Decepticon implementation to draw from. The mapping is 1:1 for 9 of 11 core components. Two components have no Decepticon equivalent and must be designed new.

---

## MRK:FIT_COMPONENTS — Decepticon component inventory | fit,components,decepticon,component,inventory | L28-67

### Planning layer

| Component | File | Role |
|-----------|------|------|
| Soundwave agent | `decepticon/agents/` | Intake interview → generates all planning docs |
| RoE schema + generator | `decepticon/core/schemas.py` | Scope, authorization, prohibited/permitted actions |
| ConOps schema + generator | `decepticon/core/schemas.py` | Threat context, methodology, success criteria |
| DeconflictionPlan schema | `decepticon/core/schemas.py` | SOC coordination for real-time deconfliction |
| OPPLAN schema | `decepticon/core/schemas.py` | Objective collection + hierarchy |
| Objective schema | `decepticon/core/schemas.py` | Individual task with state machine fields |
| OPPLANMiddleware | `decepticon/middleware/` | 5 tools; state machine enforcement; state injection |
| EngagementBundle | `decepticon/core/schemas.py` | Container: RoE + ConOps + Deconfliction + OPPLAN |
| EngagementConfig | `decepticon/core/engagement.py` | Target scope, iteration limits, workspace, agent-phase map |
| EngagementState | `decepticon/core/engagement.py` | Persistent loop state: phase, completed/blocked objectives, findings |
| EngagementLoop | `decepticon/core/engagement_loop.py` | Iterates pending objectives; dispatches to specialist agents |

### Execution shell (offensive-specific)

| Component | Role |
|-----------|------|
| 16 specialist agents | recon, scanner, detector, verifier, exploiter, patcher, AD, cloud, reverser, reporter + orchestration |
| Decepticon main agent | orchestrator — owns OPPLAN access; enforces RoE per dispatch |
| VaccineOrchestrator | attack-defend-verify feedback loop (`decepticon/orchestrator.py`) |
| ObjectivePhase enum | recon/initial-access/post-exploit/c2/exfiltration |
| OpsecLevel enum | loud/standard/careful/quiet/silent |
| C2Tier enum | interactive/short-haul/long-haul |
| MITRE ATT&CK integration | `mitre[]` field per objective and finding |
| AttackPath schema | kill chain traversal connecting findings |
| FindingSeverity | critical/high/medium/low/informational (CVSS-aligned) |

### Middleware stack (orchestrator)

`SafeCommand → Skills → Filesystem → SubAgent → OPPLAN → ModelFallback → Summarization → PromptCaching → PatchToolCalls`

Key: **only the main orchestrator has OPPLAN middleware**. Specialist agents are tool-free and receive contextual information only. This enforces single-writer state management.

---

## MRK:FIT_MAP — Component → TG-CORE-* mapping | fit,map,component,tg,core | L68-100

| Decepticon component | v0.2 placeholder | Fit | Notes |
|---------------------|-----------------|-----|-------|
| Soundwave intake interview | `TG-CORE-INTAKE` | ✓ Direct | Generalize interview questions: threat profile → service type/framework/client/constraints |
| RoE generation | `TG-CORE-SCOPE` | ✓ Direct | in_scope/out_of_scope/prohibited_actions → scope statement/exclusions/authorization |
| ConOps generation | *(no v0.2 placeholder)* | ⚠ Gap | Engagement context document — v0.2 has no equivalent; needed in v0.3 |
| DeconflictionPlan | `TG-CORE-SCOPE` (partial) | ~ Partial | Coordination/escalation elements fold into scope pack; standalone doc is offensive-specific |
| `create_opplan` | `TG-CORE-PLAN` init | ✓ Direct | Creates the objective container for the engagement |
| `add_objective` | `TG-CORE-PLAN` objective create | ✓ Direct | Adds a work item with all state machine fields |
| `list_objectives` / `get_objective` | `TG-CORE-TRACKER` query | ✓ Direct | Progress queries and state reads |
| `update_objective` | `TG-CORE-TRACKER` update | ✓ Direct | State transitions: pending → in-progress → passed/blocked/out-of-scope |
| Objective dependency graph (`blocked_by[]`) | `TG-CORE-PLAN` + `TG-CORE-TRACKER` | ✓ Direct | Unchanged — dependency resolution is domain-agnostic |
| Objective acceptance criteria | `TG-CORE-PLAN` | ✓ Direct | Unchanged — pass/fail criteria per work item |
| EngagementBundle | `TG-CORE-WORKSPACE` (partial) + `TG-CORE-SCOPE` + `TG-CORE-PLAN` | ~ Distributed | Bundle pattern reusable; individual docs change per pack |
| EngagementConfig (target, workspace, agent map) | `TG-CORE-WORKSPACE` | ✓ Direct | Project structure initialization and configuration |
| EngagementState (phase, completed, findings) | `TG-CORE-TRACKER` | ✓ Direct | Persistent engagement state across sessions |
| EngagementLoop (iterate → dispatch) | `TG-CORE-DISPATCH` | ✓ Direct | Dispatch loop: pending objectives → route to service pipeline |
| RoE enforcement per dispatch | `TG-CORE-GATE` | ✓ Direct | Scope/authorization gate before each objective execution |
| Finding generation | `TG-ANL-FINDINGS` | ✓ Direct | Same model; MITRE[] → control_refs[], detection_gaps → compliance_gaps |
| State injection into every LLM call | `TG-CORE-DISPATCH` design | ✓ Carry over | Dynamic progress table injection is a key UX pattern to preserve |
| Single-writer OPPLAN (orchestrator only) | `TG-CORE-PLAN` architecture | ✓ Carry over | Preserve: only orchestrator writes plan; sub-agents are read-only |
| AttackPath (kill chain narrative) | *(no v0.2 placeholder)* | ⚠ Gap | Audit equivalent: ControlChain or FindingNarrative — not in v0.2 |
| ObjectivePhase (offensive phases) | `TG-CORE-PLAN` (methodology pack field) | ✓ Parameterize | Phase taxonomy is a methodology-pack parameter, not a fixed enum |
| OpsecLevel, C2Tier | *(drop)* | ✗ Drop | Offensive-only; no audit equivalent |
| MITRE ATT&CK (`mitre[]`) | `TG-ANL-MAP` (control_refs[]) | ✓ Replace | Replace with control reference: ISO clause, SOC 2 criterion, etc. |
| 16 specialist agents | Service module pipelines | ✓ Replace | Each methodology pack defines its own specialist agents |
| VaccineOrchestrator | *(drop)* | ✗ Drop | Offensive-specific attack-defend-verify loop |

**Summary:** 14 direct mappings, 3 carry-over patterns, 3 parameterizations, 2 gaps, 3 drops.

---

## MRK:FIT_REUSABLE — Reusable as-is | fit,reusable,unchanged,asis | L101-148

These elements transfer to `tg-audit-orchestrator` with zero or near-zero modification:

### Objective state machine

```
pending → in-progress → passed
                      → blocked  → in-progress (retry)
                      → out-of-scope
```

This FSM is domain-agnostic. Every engagement type has objectives that pass, block, or go out of scope. No change needed.

### Dependency graph

`blocked_by: [OBJ-001, OBJ-002]` — works identically for "interview task before config review" as for "recon before exploitation."

### Acceptance criteria

Per-objective `acceptance_criteria[]` list — unchanged. What changes is the content, not the structure.

### Hierarchical objectives (parent_id)

Parent-child objective relationships with cycle detection — directly useful for audit where a high-level objective (e.g., "assess identity controls") breaks into sub-objectives (review policy, interview IAM team, test MFA).

### Single-writer state architecture

Only the orchestrator has OPPLAN write access. Sub-agents receive context, not state. This prevents concurrent writes and is the right pattern for any multi-agent engagement system.

### State injection into every LLM call

OPPLANMiddleware dynamically injects the progress table (engagement status, objective table, next-recommended objective) into every orchestrator call. This keeps the orchestrator aware of overall progress without reading the OPPLAN explicitly. Carry this pattern directly.

### Finding severity model

`critical / high / medium / low / informational` aligned to CVSS — already standard in audit and compliance contexts. Unchanged.

### EngagementBundle pattern

Four planning documents in a container with workspace generation. The bundle pattern is right — only the document types change per methodology pack. RoE → scope pack; ConOps → context doc; OPPLAN → objective plan.

### EngagementState persistence

`save()` / `load()` pattern to `.engagement-state.json`. Audit engagements need the same session continuity.

---

## MRK:FIT_PARAMETERIZE — Needs parameterization | fit,parameterize,needs,parameterization,generalize | L149-204

These elements need to become methodology-pack parameters rather than fixed values:

### ObjectivePhase (most important)

Current fixed enum: `recon | initial-access | post-exploit | c2 | exfiltration`

Must become a pack-defined list. Each methodology pack supplies its own phase taxonomy:

| Pack | Phases |
|------|--------|
| Pentest (existing) | recon, initial-access, post-exploit, c2, exfiltration |
| Technical Security Assessment | scoping, config-review, interview, technical-test, analysis |
| ISO 27001 | intake, document-review, evidence-collection, control-mapping, gap-analysis, reporting |
| Gap Assessment | baseline-capture, target-mapping, gap-identification, prioritization |
| Compliance Evidence | intake, evidence-request, evidence-collection, mapping, sufficiency-check |
| Remediation Verification | baseline-finding-review, evidence-collection, retest, residual-risk-assessment |

### control_refs[] (replaces mitre[])

`mitre: ["T1595.001", "T1190"]` → `control_refs: ["ISO27001:A.8.8", "SOC2:CC6.1"]`

The field purpose is identical — map a work item to a taxonomy. The taxonomy changes per pack. Both should be strings. The finding schema should support both (pentest pack uses mitre[], audit packs use control_refs[]).

### Soundwave interview questions

Current questions: threat actor profile, methodology, authorized scope, exclusions, OPSEC requirements, testing window

Must become a pack-configurable question set:
- Pentest pack: current questions (unchanged)
- Audit packs: client, service type, framework, constraints, risk appetite, evidence access, timeline, stakeholders

### EngagementBundle document types

Current: RoE + ConOps + DeconflictionPlan + OPPLAN

Must become pack-configurable:
- Pentest: RoE + ConOps + Deconfliction + OPPLAN (unchanged)
- Audit: ScopePack + ContextDoc + ObjectivePlan (3 docs, no deconfliction)

### EngagementState phases

Current: `planning → attack → vaccine → complete`

Must become: `planning → execution → analysis → reporting → complete`
The `vaccine` phase is offensive-specific and should be removed from the core.

### Specialist agent roster

Current: 16 offensive agents hardwired to the kill chain.

Must become: pack-configurable agent set. The dispatch pattern (context injection, fresh context windows, tool-free sub-agents) stays; the agents change.

---

## MRK:FIT_DROP — Offensive-specific: drop | fit,drop,offensive,specific | L205-225

These elements have no audit equivalent and should not be in the generalized core:

| Element | Why drop |
|---------|---------|
| `OpsecLevel` (loud/standard/careful/quiet/silent) | Pertains to attack detection evasion — meaningless for audit |
| `C2Tier` (interactive/short-haul/long-haul) | Command-and-control timing — meaningless for audit |
| `opsec_notes` field on Objective | Replace with `methodology_notes` (free text) |
| `c2_tier` field on Objective | Remove entirely |
| VaccineOrchestrator | Attack-defend-verify loop — entirely offensive |
| DeconflictionPlan (as standalone doc) | Fold escalation/coordination elements into scope pack |
| `attack_narrative` on ConOps | Replace with `engagement_narrative` in context doc |
| `threat_actors[]` on ConOps | Keep structure, rename to `engagement_profile` |
| `kill_chain[]` on ConOps | Replace with `methodology_steps[]` in context doc |
| MITRE ATT&CK as primary taxonomy | Demote to pentest-pack-specific; core uses `control_refs[]` |

**Note:** none of these drops affect the Pentest methodology pack. The Pentest pack inherits all of Decepticon's current behaviour unchanged. The drops only apply to the generalized `EngagementCore` layer.

---

## MRK:FIT_GAPS — Decepticon concepts not in v0.2 | fit,gaps,decepticon,concepts,v0 | L226-247

Two Decepticon concepts that are genuinely valuable but have no v0.2 placeholder:

### ConOps / Context Document

Decepticon generates a ConOps: executive narrative, threat actor profile, attack methodology, success criteria. v0.2 has no equivalent — it goes from scope pack straight to objectives.

**Recommendation for v0.3:** add `TG-CORE-CONTEXT` — engagement context document generated after scope approval. For audit: engagement narrative, methodology pack selection rationale, service-specific execution strategy, success criteria. This fills the gap between "what we're authorized to do" (scope pack) and "how we will do it" (objective plan).

### AttackPath / ControlChain

Decepticon's `AttackPath` connects individual findings into a kill chain narrative showing how multiple weaknesses combine. v0.2 has no equivalent.

**Recommendation for v0.3:** add `TG-ANL-CHAIN` — finding chain / control failure narrative. For audit: connect related findings to show cumulative control failures (e.g., weak access controls + inadequate logging + no MFA = exploitable identity path). Maps to v0.2's `TG-ANL-FINDINGS` but adds a chaining layer.

### Dynamic state injection

OPPLANMiddleware injects a live progress table into every LLM call. v0.2's `TG-CORE-PLAN` and `TG-CORE-TRACKER` don't specify this behaviour. It should be a design requirement, not left implicit.

---

## MRK:FIT_ARCHITECTURE — Extraction architecture | fit,architecture,extraction,engagementcore | L248-304

### Proposed: EngagementCore library

Extract from Decepticon into a standalone, methodology-agnostic library:

```
EngagementCore/
  planning/
    intake.py          ← Soundwave interview (pack-configurable questions)
    scope.py           ← RoE/scope pack generation
    context.py         ← NEW: ConOps/context doc generation
    objective.py       ← Objective schema (parameterized phases, control_refs)
    opplan.py          ← OPPLAN schema + OPPLANMiddleware (5 tools)
    bundle.py          ← EngagementBundle (pack-configurable doc set)
  execution/
    state.py           ← EngagementState (phases: planning→execution→analysis→reporting→complete)
    loop.py            ← EngagementLoop (dispatch to pack-defined agent roster)
    gate.py            ← Scope/authorization gate (replaces RoE enforcement)
  findings/
    finding.py         ← Finding schema (control_refs[] primary; mitre[] optional)
    chain.py           ← NEW: ControlChain / finding narrative
  packs/
    base.py            ← MethodologyPack base class: phases, agents, bundle_docs, interview_qs
    pentest.py         ← Existing Decepticon behaviour (no changes)
    iso27001.py        ← NEW: ISO 27001 pack
    gap.py             ← NEW: Gap assessment pack
    ... (one file per methodology pack)
```

### Dependency relationship

```
tg-audit-orchestrator
    └── EngagementCore  ←──────────────────────────────┐
         └── packs/: iso27001, gap, assessment, ...    │
                                                        │
Decepticon                                              │
    └── EngagementCore  ───────────────────────────────┘
         └── packs/: pentest  (existing Decepticon = pentest pack)
```

Decepticon does not change its user-facing behaviour. It becomes a consumer of EngagementCore with the pentest pack loaded. All other methodology packs are new consumers.

### Single-writer rule (carry over)

`tg-audit-orchestrator` orchestrator agent: has OPPLANMiddleware in its stack.
Specialist agents (document reviewer, interviewer, control tester, etc.): tool-free, receive context only.

This is non-negotiable — it is the pattern that prevents concurrent state corruption and keeps sub-agent contexts clean.

### State injection (carry over)

`TG-CORE-DISPATCH` must inject a live progress table into every orchestrator LLM call. This is not an optional feature — it is what makes the orchestrator aware of engagement progress without requiring explicit state reads.

---

## MRK:FIT_VERDICT — Phase 2 verdict for DCPTCN_TG | fit,verdict,phase,dcptcn,tg | L305-333

### Decisions confirmed for Phase 3

**D-001 CLOSED:** Decepticon should neither remain Optional nor become a controlled specialist module. The correct answer is: **extract `EngagementCore` from Decepticon; Decepticon becomes the Pentest methodology pack**. This is a structural refactor, not a configuration choice.

**D-002 CLOSED:** Objective schema generalization is clear:
- Keep: `id`, `phase`, `title`, `description`, `acceptance_criteria[]`, `priority`, `status`, `blocked_by[]`, `concessions[]`, `owner`, `notes`, `parent_id`
- Replace: `mitre[]` → `control_refs[]`; `opsec_notes` → `methodology_notes`
- Drop: `opsec`, `c2_tier`
- Phase taxonomy: pack-defined list (not a fixed enum)

### Inputs for Phase 3 (generalization spec)

Phase 3 must produce:
1. Formal `EngagementCore` library spec (file-by-file interface definitions)
2. Generalized Objective schema (all fields with types, constraints, migration from Decepticon)
3. Generalized EngagementBundle structure per pack type
4. Generalized EngagementState phase model
5. MethodologyPack base class spec
6. Generalized Soundwave interview flow (pack-configurable question sets)
7. Two new v0.2 placeholder proposals: `TG-CORE-CONTEXT` and `TG-ANL-CHAIN`

### Inputs for Phase 4 (methodology packs)

Each pack must define: phase taxonomy, interview question set, bundle document types, specialist agent roles, control reference taxonomy, report sections.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
