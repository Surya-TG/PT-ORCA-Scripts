<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- MRK:PHASE3_GENERALIZATION_SPEC_20260427_NAV_TOC — Section index | nav,toc,index | L4-17 -->
<!-- - MRK:SPEC_OVERVIEW — Overview and design decisions | spec,overview,design,decisions | L18-40 -->
<!-- - MRK:SPEC_LIBRARY — EngagementCore library structure | spec,library,engagementcore,structure | L41-97 -->
<!-- - MRK:SPEC_OBJECTIVE — Generalized Objective schema | spec,objective,generalized,schema,fields | L98-185 -->
<!-- - MRK:SPEC_OPPLAN — Generalized OPPLAN + OPPLANMiddleware | spec,opplan,generalized,opplanmiddleware,middleware | L186-229 -->
<!-- - MRK:SPEC_BUNDLE — Generalized EngagementBundle | spec,bundle,generalized,engagementbundle,pack | L230-305 -->
<!-- - MRK:SPEC_STATE — Generalized EngagementState + phases | spec,state,generalized,engagementstate,phases | L306-391 -->
<!-- - MRK:SPEC_PACK — MethodologyPack base class | spec,pack,methodologypack,base,class | L392-486 -->
<!-- - MRK:SPEC_INTAKE — Generalized intake interview (Soundwave) | spec,intake,generalized,interview,soundwave | L487-562 -->
<!-- - MRK:SPEC_NEWPLACEHOLDERS — New v0.2 placeholder proposals | spec,newplaceholders,new,v0,placeholder | L563-616 -->
<!-- - MRK:SPEC_MIGRATION — Decepticon migration path | spec,migration,decepticon,path,pentest | L617-662 -->
<!-- - MRK:SPEC_VERDICT — Phase 3 verdict | spec,verdict,phase,phase3,decisions | L663-697 -->
<!-- NAV-LEN: 11 entries | Integrity-hash: 26d52b9ae5e58acf | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:SPEC_OVERVIEW — Overview and design decisions | spec,overview,design,decisions | L18-40

**Produced:** 2026-04-27 | **Project:** DCPTCN_TG | **Phase:** 3 of 5

This document is the formal generalization spec for `EngagementCore` — the shared planning kernel to be extracted from Decepticon and consumed by `tg-audit-orchestrator`.

### Design decisions carried in

From Phase 2:
- **D-001 CLOSED:** extract `EngagementCore`; Decepticon becomes the Pentest methodology pack
- **D-002 CLOSED:** Objective schema field map (keep 12, replace 2, drop 2, phase taxonomy = pack-defined)
- Planning kernel is the extraction target; offensive execution shell stays in Decepticon

### Core design principles

1. **EngagementCore is methodology-agnostic.** It knows nothing about pentesting, ISO 27001, or any specific engagement type. All domain-specific logic lives in methodology packs.
2. **Single-writer state.** Only the orchestrator agent has OPPLANMiddleware. Sub-agents are tool-free.
3. **State injection mandatory.** OPPLANMiddleware injects a live progress table into every orchestrator LLM call.
4. **Pack-first design.** A running engagement always has exactly one active MethodologyPack. The pack determines: phase taxonomy, interview questions, bundle document types, agent roster, control reference taxonomy, report sections.
5. **Backward compatibility.** Decepticon's existing behaviour must be 100% preserved by loading the Pentest pack.

---

## MRK:SPEC_LIBRARY — EngagementCore library structure | spec,library,engagementcore,structure | L41-97

```
engagement_core/
  __init__.py

  planning/
    intake.py          # IntakeInterview: pack-configurable interview → IntakeRecord
    scope.py           # ScopePack: generates scope + authorization document
    context.py         # ContextDoc: engagement narrative + methodology rationale (NEW — was ConOps)
    objective.py       # Objective, ObjectiveStatus, ObjectiveUpdate schemas
    opplan.py          # OPPLAN schema + OPPLANMiddleware (5 tools)
    bundle.py          # EngagementBundle: pack-configurable container for planning docs

  execution/
    state.py           # EngagementState, EngagementPhase enum, IterationResult
    loop.py            # EngagementLoop: iterates objectives, dispatches to pack agents
    gate.py            # EngagementGate: scope/authorization check before each dispatch

  findings/
    finding.py         # Finding, FindingSeverity, RemediationPriority
    chain.py           # ControlChain: connects findings into failure narratives (NEW — was AttackPath)

  packs/
    base.py            # MethodologyPack abstract base class
    pentest.py         # Pentest pack (= current Decepticon behaviour)
    iso27001.py        # ISO 27001 pack (Phase 4)
    gap.py             # Gap Assessment pack (Phase 4)
    assessment.py      # Technical Security Assessment pack (Phase 4)
    compliance.py      # Compliance Evidence Review pack (Phase 4)
    remediation.py     # Remediation Verification pack (Phase 4)

  middleware/
    opplan_middleware.py  # OPPLANMiddleware (extracted unchanged from Decepticon)
    base_middleware.py    # BaseMiddleware for sub-agent stack (no OPPLAN)
```

**Source mapping (extraction from Decepticon):**

| EngagementCore file | Decepticon source |
|--------------------|-------------------|
| `planning/objective.py` | `decepticon/core/schemas.py` (Objective, OPPLAN) |
| `planning/opplan.py` | `decepticon/core/schemas.py` + `decepticon/middleware/` |
| `planning/bundle.py` | `decepticon/core/schemas.py` (EngagementBundle) |
| `planning/intake.py` | `decepticon/agents/` (Soundwave) — generalize |
| `planning/scope.py` | `decepticon/core/schemas.py` (RoE) — generalize |
| `planning/context.py` | `decepticon/core/schemas.py` (CONOPS) — generalize |
| `execution/state.py` | `decepticon/core/engagement.py` |
| `execution/loop.py` | `decepticon/core/engagement_loop.py` — generalize |
| `execution/gate.py` | Decepticon main agent (RoE enforcement logic) |
| `findings/finding.py` | `decepticon/core/schemas.py` (Finding) — generalize |
| `findings/chain.py` | `decepticon/core/schemas.py` (AttackPath) — generalize |
| `middleware/opplan_middleware.py` | `decepticon/middleware/` — extract unchanged |
| `packs/pentest.py` | All offensive-specific enums + agent roster |

---

## MRK:SPEC_OBJECTIVE — Generalized Objective schema | spec,objective,generalized,schema,fields | L98-185

### ObjectiveStatus (unchanged FSM)

```python
class ObjectiveStatus(str, Enum):
    pending      = "pending"
    in_progress  = "in-progress"
    passed       = "passed"
    blocked      = "blocked"
    out_of_scope = "out-of-scope"
```

**Valid transitions:**
- `pending → in_progress`
- `in_progress → passed`
- `in_progress → blocked`
- `in_progress → out_of_scope`
- `blocked → in_progress`  # retry

### Objective schema

```python
class Objective(BaseModel):
    # Core identity — unchanged from Decepticon
    id:                   str                   # "OBJ-001", "OBJ-002", ...
    title:                str
    description:          str
    acceptance_criteria:  list[str]             # pass/fail criteria; unchanged
    priority:             int                   # execution order; unchanged
    status:               ObjectiveStatus       # state machine; unchanged
    blocked_by:           list[str] = []        # dependency graph (obj IDs); unchanged
    concessions:          list[str] = []        # approved deviations; unchanged
    owner:                str = ""              # analyst or agent assigned; unchanged
    notes:                str = ""              # free text; unchanged
    parent_id:            str | None = None     # hierarchical objectives; unchanged

    # Phase — CHANGED: was ObjectivePhase enum, now pack-defined string
    phase:                str                   # value validated against pack.phases at runtime

    # Control reference — CHANGED: replaces mitre[]
    control_refs:         list[str] = []        # ["ISO27001:A.8.8", "SOC2:CC6.1", "T1595.001"]
                                                # format: "<taxonomy>:<ref>" or plain string
                                                # pentest pack populates with ATT&CK IDs

    # Methodology notes — CHANGED: replaces opsec + opsec_notes
    methodology_notes:    str = ""              # free text; replaces opsec/opsec_notes

    # DROPPED: opsec (OpsecLevel enum)
    # DROPPED: c2_tier (C2Tier enum)
```

### Objective field migration table

| Decepticon field | EngagementCore field | Change |
|-----------------|---------------------|--------|
| `id` | `id` | unchanged |
| `phase` (ObjectivePhase enum) | `phase` (str, pack-validated) | parameterized |
| `title` | `title` | unchanged |
| `description` | `description` | unchanged |
| `acceptance_criteria` | `acceptance_criteria` | unchanged |
| `priority` | `priority` | unchanged |
| `status` | `status` | unchanged |
| `mitre` | `control_refs` | renamed + taxonomy-agnostic |
| `opsec` | — | dropped |
| `opsec_notes` | `methodology_notes` | merged + renamed |
| `c2_tier` | — | dropped |
| `concessions` | `concessions` | unchanged |
| `blocked_by` | `blocked_by` | unchanged |
| `owner` | `owner` | unchanged |
| `notes` | `notes` | unchanged |
| `parent_id` | `parent_id` | unchanged |

### Phase validation rule

```python
def validate_phase(obj: Objective, pack: MethodologyPack) -> None:
    if obj.phase not in pack.phases:
        raise ValueError(
            f"Phase '{obj.phase}' not valid for pack '{pack.name}'. "
            f"Valid phases: {pack.phases}"
        )
```

The Pentest pack sets `phases = ["recon", "initial-access", "post-exploit", "c2", "exfiltration"]` — identical to current Decepticon. No behaviour change.

---

## MRK:SPEC_OPPLAN — Generalized OPPLAN + OPPLANMiddleware | spec,opplan,generalized,opplanmiddleware,middleware | L186-229

### OPPLAN schema

```python
class OPPLAN(BaseModel):
    engagement_name: str
    pack_name:       str                 # which MethodologyPack is active
    objectives:      list[Objective] = []

    # Helper methods (unchanged from Decepticon)
    def children_of(self, parent_id: str) -> list[Objective]: ...
    def descendants_of(self, parent_id: str) -> list[Objective]: ...
    def root_objectives(self) -> list[Objective]: ...
    def tree(self) -> str: ...           # renders objective hierarchy as text
    def next_recommended(self) -> Objective | None: ...
```

### OPPLANMiddleware tools (5 tools — unchanged interface)

| Tool | Signature | Behaviour |
|------|-----------|-----------|
| `create_opplan` | `(engagement_name, pack_name)` | Initialize OPPLAN in LangGraph state; not intercepted |
| `add_objective` | `(id, title, description, phase, acceptance_criteria, priority, blocked_by?, control_refs?, methodology_notes?, parent_id?)` | Add objective; validate phase against active pack |
| `get_objective` | `(id)` | Read single objective with full fields + current state |
| `list_objectives` | `(phase?, status?)` | Returns progress table + filtered objective list |
| `update_objective` | `(id, status, notes?)` | Transition state with FSM validation; read-before-write |

**Intercepted tools** (middleware wraps these): `add_objective`, `get_objective`, `list_objectives`, `update_objective`

**State injection (unchanged):** middleware intercepts every LLM call to the orchestrator and prepends:
```
=== ENGAGEMENT STATUS ===
Pack: <pack_name>  Phase: <current_phase>  Iteration: <n>
Objectives: <N> total | <p> passed | <b> blocked | <pending> pending
Next recommended: <OBJ-NNN> — <title>

<objective table with id, phase, status, title>
```

**Parallel write guard (unchanged):** prohibit simultaneous `update_objective` calls to prevent state conflicts.

---

## MRK:SPEC_BUNDLE — Generalized EngagementBundle | spec,bundle,generalized,engagementbundle,pack | L230-305

### EngagementBundle schema

```python
class EngagementBundle(BaseModel):
    engagement_name: str
    pack_name:       str
    documents:       dict[str, BaseModel]    # keyed by document role
    opplan:          OPPLAN

    def workspace_dir(self) -> Path: ...     # compute workspace path
    def save(self, workspace: Path) -> None: # serialize all docs to disk
    def load(cls, workspace: Path) -> EngagementBundle: ...
```

### Pack-defined document roles

Each `MethodologyPack` specifies which document roles its bundle contains:

| Pack | Document roles | Decepticon equivalent |
|------|---------------|----------------------|
| Pentest | `roe`, `conops`, `deconfliction`, `opplan` | unchanged |
| All audit packs | `scope_pack`, `context_doc`, `opplan` | scope_pack ≈ RoE; context_doc ≈ ConOps |

**Document role schemas:**

```python
# Scope pack (generalizes RoE)
class ScopePack(BaseModel):
    engagement_name:     str
    client:              str
    engagement_type:     str              # from pack's engagement_types
    authorized_scope:    list[ScopeItem]  # replaces in_scope
    excluded_scope:      list[ScopeItem]  # replaces out_of_scope
    excluded_actions:    list[str]        # replaces prohibited_actions
    authorized_actions:  list[str]        # replaces permitted_actions
    timeline:            str
    contacts:            list[Contact]
    authorization_ref:   str
    version:             str

# Context doc (generalizes ConOps — NEW)
class ContextDoc(BaseModel):
    engagement_name:      str
    pack_name:            str
    engagement_narrative: str             # replaces executive_summary
    engagement_profile:   list[dict]      # replaces threat_actors (generalized)
    methodology_steps:    list[dict]      # replaces kill_chain (generalized)
    framework_or_standard: str | None     # e.g. "ISO 27001:2022", "SOC 2 Type II"
    success_criteria:     list[str]       # unchanged
```

### Workspace directory structure (from TG-CORE-WORKSPACE)

```
<engagement_name>/
  01_intake/
  02_scope/
  03_plan/
  04_evidence_requests/
  05_evidence_raw/
  06_evidence_processed/
  07_analysis/
  08_findings/
  09_reports/
  10_qa/
  11_closure/
  .engagement-state.json
  roe.json | scope_pack.json
  conops.json | context_doc.json
  opplan.json
```

---

## MRK:SPEC_STATE — Generalized EngagementState + phases | spec,state,generalized,engagementstate,phases | L306-391

### EngagementPhase (generalized)

```python
class EngagementPhase(str, Enum):
    planning   = "planning"     # intake → scope → context doc → OPPLAN generation
    execution  = "execution"    # objective dispatch loop (was "attack")
    analysis   = "analysis"     # evidence-to-requirement mapping, finding synthesis (NEW)
    reporting  = "reporting"    # report assembly, QA, delivery (was partially "vaccine")
    complete   = "complete"

# Pentest pack maps to the same phases:
# planning  → planning (unchanged)
# execution → attack (Decepticon name; internal only)
# vaccine   → moved to reporting (defensive loop is a reporting-phase activity for pentest)
# complete  → complete (unchanged)
```

### EngagementState schema

```python
class EngagementState(BaseModel):
    engagement_name:      str
    pack_name:            str
    current_phase:        EngagementPhase = EngagementPhase.planning
    iteration_count:      int = 0
    max_iterations:       int

    completed_objectives: list[str] = []   # objective IDs
    blocked_objectives:   list[str] = []
    findings:             list[str] = []   # finding IDs or paths

    history:              list[IterationResult] = []
    started_at:           datetime | None = None
    resumed_at:           datetime | None = None

    def save(self, workspace: Path) -> None: ...
    def load(cls, workspace: Path) -> EngagementState: ...

    @property
    def is_complete(self) -> bool:
        return (
            self.current_phase == EngagementPhase.complete
            or self.iteration_count >= self.max_iterations
        )

    @property
    def summary(self) -> dict: ...
```

### EngagementLoop (generalized)

```python
class EngagementLoop:
    def __init__(self, config: EngagementConfig, pack: MethodologyPack): ...

    def run(self, state: EngagementState, bundle: EngagementBundle) -> EngagementState:
        while not state.is_complete:
            obj = bundle.opplan.next_recommended()
            if obj is None:
                state.current_phase = self._advance_phase(state)
                continue

            # Gate check (replaces RoE enforcement)
            self.gate.check(obj, bundle.documents["scope_pack"])  # raises on violation

            # Dispatch to pack-defined specialist agent
            agent = self.pack.agent_for_phase(obj.phase)
            result = agent.execute(obj, context=self._build_context(state, bundle))

            # Update state
            state = self._apply_result(state, obj, result)
            state.iteration_count += 1

        return state
```

**Key carry-overs:**
- `next_recommended()` — same dependency-aware logic from OPPLANMiddleware
- `_build_context()` — injects progress table + relevant findings + scope constraints
- Fresh context window per objective — each specialist agent starts clean
- Gate check before every dispatch — scope/authorization enforcement is non-optional

---

## MRK:SPEC_PACK — MethodologyPack base class | spec,pack,methodologypack,base,class | L392-486

```python
from abc import ABC, abstractmethod

class MethodologyPack(ABC):
    # Identity
    name:              str                  # "pentest", "iso27001", "gap", etc.
    display_name:      str
    version:           str

    # Phase taxonomy — defines valid values for Objective.phase
    @property
    @abstractmethod
    def phases(self) -> list[str]: ...
    # e.g. pentest: ["recon", "initial-access", "post-exploit", "c2", "exfiltration"]
    # e.g. iso27001: ["intake", "document-review", "evidence-collection",
    #                 "control-mapping", "gap-analysis", "reporting"]

    # Bundle document types for this pack
    @property
    @abstractmethod
    def bundle_document_types(self) -> dict[str, type[BaseModel]]: ...
    # e.g. pentest: {"roe": RoE, "conops": ConOps, "deconfliction": DeconflictionPlan}
    # e.g. audit:   {"scope_pack": ScopePack, "context_doc": ContextDoc}

    # Intake interview question set
    @property
    @abstractmethod
    def intake_questions(self) -> list[IntakeQuestion]: ...
    # Each question: id, text, required, field_mapping

    # Agent roster — maps phases to specialist agent classes
    @abstractmethod
    def agent_for_phase(self, phase: str) -> BaseSpecialistAgent: ...

    # Control reference taxonomy label
    @property
    def control_ref_taxonomy(self) -> str:
        return "generic"
    # Override: pentest → "MITRE ATT&CK"; iso27001 → "ISO 27001:2022"; etc.

    # Report sections produced by this pack
    @property
    @abstractmethod
    def report_sections(self) -> list[str]: ...

    # Engagement type values valid for this pack
    @property
    @abstractmethod
    def engagement_types(self) -> list[str]: ...
```

### Pentest pack (preserves all Decepticon behaviour)

```python
class PentestPack(MethodologyPack):
    name         = "pentest"
    display_name = "Penetration Testing"
    version      = "1.0"

    phases = ["recon", "initial-access", "post-exploit", "c2", "exfiltration"]

    bundle_document_types = {
        "roe":           RoE,
        "conops":        ConOps,
        "deconfliction": DeconflictionPlan,
    }

    intake_questions = [
        IntakeQuestion("threat_profile", "Describe the threat actor profile and objectives"),
        IntakeQuestion("authorized_scope", "What systems are in scope?"),
        IntakeQuestion("excluded_scope",   "What is explicitly out of scope?"),
        IntakeQuestion("opsec_req",        "What OPSEC level is required?"),
        IntakeQuestion("testing_window",   "What is the authorized testing window?"),
    ]

    def agent_for_phase(self, phase: str) -> BaseSpecialistAgent:
        return PENTEST_AGENT_MAP[phase]   # existing 16-agent map

    control_ref_taxonomy = "MITRE ATT&CK"

    report_sections = [
        "executive_summary", "scope", "methodology", "findings",
        "attack_paths", "remediation", "evidence_index"
    ]

    engagement_types = ["external", "internal", "hybrid", "assumed-breach", "physical"]

    # Pentest pack also enables: OpsecLevel, C2Tier on Objective (as extra fields)
    # These are ignored by EngagementCore but used by pentest specialist agents
```

---

## MRK:SPEC_INTAKE — Generalized intake interview (Soundwave) | spec,intake,generalized,interview,soundwave | L487-562

### IntakeInterview class

```python
class IntakeInterview:
    def __init__(self, pack: MethodologyPack): ...

    async def conduct(self, operator_input: str) -> IntakeRecord:
        """
        Conduct a structured interview using pack.intake_questions.
        Returns a completed IntakeRecord with all required fields populated.
        Uses LLM to parse unstructured operator input into structured fields.
        Prompts for missing required fields interactively.
        """

class IntakeRecord(BaseModel):
    engagement_name:  str
    pack_name:        str
    client:           str
    responses:        dict[str, str]   # question_id → response
    raw_input:        str
    completed_at:     datetime
```

### Standard intake questions by pack

**Pentest pack** (existing Soundwave questions — unchanged):
1. Describe the threat actor profile and objectives
2. What systems and services are in scope?
3. What is explicitly out of scope?
4. What OPSEC level is required?
5. What is the authorized testing window?
6. Any escalation contacts or deconfliction requirements?

**ISO 27001 pack:**
1. Client name, organization type, and certification scope
2. Target standard (ISO 27001:2022 initial / surveillance / recertification)
3. In-scope business units, processes, and assets (ISMS boundary)
4. Known control gaps or previous audit findings
5. Evidence access: what systems, policies, and logs are available?
6. Timeline, key contacts, and delivery expectations
7. Any constraints (sensitivity, pending remediation, legal holds)?

**Gap Assessment pack:**
1. Client and engagement scope
2. Target framework or baseline (ISO 27001, NIST CSF, internal policy, etc.)
3. Current state: what documentation, policies, and controls exist?
4. Assessment depth: high-level gap matrix or detailed control-by-control?
5. Expected output format (gap matrix, roadmap, maturity score, or combination)
6. Timeline and key stakeholders

**Technical Security Assessment pack:**
1. Client and scope: which systems, services, or architecture domains?
2. Assessment objectives: controls effectiveness, architecture review, configuration audit, or combination?
3. Evidence access: configuration exports, architecture diagrams, logs, interviews?
4. Constraints: production system restrictions, change freeze, limited access windows?
5. Depth: findings-focused or maturity/posture-focused?
6. Timeline, delivery format, stakeholder expectations

**Compliance Evidence Review pack:**
1. Client, framework, and compliance obligation (SOC 2 Type II, PCI DSS, etc.)
2. Audit period and scope boundaries
3. Control list or control families in scope
4. Evidence package: what has the client prepared? What gaps exist?
5. Expected deliverable: evidence readiness assessment, gap list, or ready-to-submit package?

**Remediation Verification pack:**
1. Client and engagement context (which prior findings are being re-tested?)
2. Original finding references (IDs, descriptions, severity)
3. Client's claimed remediation actions and evidence
4. Scope: full retest, spot-check, or documentation review only?
5. Acceptance criteria: what constitutes a verified closed finding?

---

## MRK:SPEC_NEWPLACEHOLDERS — New v0.2 placeholder proposals | spec,newplaceholders,new,v0,placeholder | L563-616

These two placeholders were identified as gaps in v0.2 (present in Decepticon, missing from the v0.2 methodology). They should be added to v0.3.

### TG-CORE-CONTEXT (new)

**Proposed placeholder:** `TG-CORE-CONTEXT`
**Status:** Planned
**Maps from:** Decepticon ConOps generator
**Insert in v0.2 at:** §7 Future Core Platform Placeholders (after `TG-CORE-SCOPE`)

| Field | Value |
|-------|-------|
| Purpose | Generate and manage the engagement context document |
| Produces | `ContextDoc`: engagement narrative, pack selection rationale, methodology steps, framework/standard, success criteria |
| Triggered | After scope approval (Stage 2 → Stage 3 boundary) |
| Human gate | Operator reviews and approves context doc before objectives are generated |
| Pack behaviour | Pentest: generates ConOps (threat actor profile, kill chain, methodology); Audit: generates framework/methodology selection rationale and execution strategy |

**Why needed:** v0.2 jumps from scope approval (TG-CORE-SCOPE) directly to objective/plan generation (TG-CORE-PLAN). The ConOps layer fills a necessary conceptual gap: "how will we approach this engagement and what does success look like?" before "what specific work items will we execute?"

### TG-ANL-CHAIN (new)

**Proposed placeholder:** `TG-ANL-CHAIN`
**Status:** Planned
**Maps from:** Decepticon AttackPath
**Insert in v0.2 at:** §7 Future Core Platform Placeholders (after `TG-ANL-FINDINGS`)

| Field | Value |
|-------|-------|
| Purpose | Connect related findings into a control failure chain narrative |
| Produces | `ControlChain`: ordered list of findings, combined severity, failure narrative, chain impact statement |
| Triggered | After finding generation (TG-ANL-FINDINGS), before report assembly (TG-RPT-BUILD) |
| Pack behaviour | Pentest: generates AttackPath (kill chain traversal, combined CVSS, lateral movement path); Audit: generates ControlChain (e.g., "weak access controls + inadequate logging + no MFA = exploitable identity failure path") |

**Why needed:** individual findings often combine into more significant risk narratives. The chain layer elevates the deliverable from a flat findings list to a structured risk story. Essential for executive-level reporting.

### Updated v0.2 §6 tool mapping table (proposed additions)

| Placeholder | Status | Current Source | Role |
|-------------|--------|---------------|------|
| `TG-PT-EXEC-PIPELINE` | Existing | PT-Orc | pentest execution pipeline |
| `TG-CORE-DOC-NAV` | Existing | nav-tools | methodology document navigation |
| `TG-EVID-NORMALIZE` | Existing | audit-evidence-processor | evidence normalization |
| `TG-PT-AUTO-OPS` | Existing\* | Decepticon (pentest pack) | autonomous offensive objective execution |
| **`TG-CORE-INTAKE`** | **Existing\*** | **EngagementCore + Soundwave** | **intake interview and engagement registration** |
| **`TG-CORE-PLAN`** | **Existing\*** | **EngagementCore + OPPLANMiddleware** | **objective state machine and plan management** |
| **`TG-CORE-DISPATCH`** | **Existing\*** | **EngagementCore + EngagementLoop** | **objective dispatch to service pipelines** |
| **`TG-CORE-CONTEXT`** | **Existing\*** | **EngagementCore + ConOps/ContextDoc** | **engagement context document generation** |

\*Status changes from `Planned` to `Existing*` (exists in Decepticon; requires extraction to EngagementCore)

---

## MRK:SPEC_MIGRATION — Decepticon migration path | spec,migration,decepticon,path,pentest | L617-662

### Decepticon → EngagementCore migration (no user-facing change)

The migration is a refactoring, not a rewrite. Decepticon's behaviour is entirely preserved.

**Phase A — Extract (no behaviour change):**
1. Create `engagement_core/` package alongside `decepticon/`
2. Move `schemas.py` models → `engagement_core/planning/` and `engagement_core/findings/`
3. Move `engagement.py` → `engagement_core/execution/state.py`
4. Move `engagement_loop.py` → `engagement_core/execution/loop.py`
5. Move `middleware/opplan_middleware.py` → `engagement_core/middleware/`
6. Update `decepticon/` imports to reference `engagement_core`
7. All tests pass unchanged

**Phase B — Parameterize (pentest pack, no behaviour change):**
1. Create `engagement_core/packs/pentest.py` — copy all offensive-specific values
   - `phases = ["recon", "initial-access", "post-exploit", "c2", "exfiltration"]`
   - `bundle_document_types = {"roe": RoE, "conops": ConOps, "deconfliction": DeconflictionPlan}`
   - `intake_questions = [... existing Soundwave questions ...]`
   - `agent_for_phase = PENTEST_AGENT_MAP`
2. Replace `ObjectivePhase` enum usage in Decepticon with `PentestPack.phases` list
3. Objective schema: add `control_refs`, `methodology_notes`; keep `mitre`, `opsec`, `c2_tier` as pentest-pack extra fields
4. All tests pass unchanged

**Phase C — tg-audit-orchestrator scaffolding:**
1. Create `tg-audit-orchestrator/` repo
2. Import `engagement_core` as dependency
3. Implement `packs/iso27001.py`, `packs/gap.py`, etc. (Phase 4 deliverable)
4. Wire `TG-CORE-INTAKE` through `TG-CORE-DISPATCH` using EngagementCore

### Objective schema backward compatibility

```python
class Objective(BaseModel):
    # ... generalized fields ...
    control_refs:      list[str] = []      # new field; empty for existing Decepticon objectives
    methodology_notes: str = ""            # new field; empty for existing

    # Pentest-pack extra fields (preserved, not in base schema)
    model_config = ConfigDict(extra="allow")
    # This allows pentest pack to set mitre, opsec, c2_tier without schema collision
```

---

## MRK:SPEC_VERDICT — Phase 3 verdict | spec,verdict,phase,phase3,decisions | L663-697

### Summary

The generalization spec is complete. The `EngagementCore` library is fully specified:
- 13 source files with clear extraction mapping from Decepticon
- Generalized Objective schema (field-for-field migration table)
- MethodologyPack base class (6 abstract properties/methods)
- Pentest pack spec (100% backward compatible with current Decepticon)
- Two new v0.2 placeholder proposals (`TG-CORE-CONTEXT`, `TG-ANL-CHAIN`)
- Migration path: 3 phases, no user-facing behaviour change in Decepticon

### D-003 (tg-audit-orchestrator MVP) — input ready

The minimum viable `tg-audit-orchestrator` requires:
1. `EngagementCore` extracted (Phase A + B above)
2. `TG-CORE-WORKSPACE`, `TG-CORE-INTAKE`, `TG-CORE-SCOPE`, `TG-CORE-CONTEXT`, `TG-CORE-PLAN` (first 5 build steps from v0.2 §18, adjusted for new placeholders)
3. At least one non-pentest methodology pack (ISO 27001 or Gap recommended as first)

D-003 is now answerable: MVP = EngagementCore extraction + audit-orchestrator scaffolding + one audit pack.

### Inputs for Phase 4

Phase 4 must define each of the 6 methodology packs using the `MethodologyPack` base class:
- Phase taxonomy
- Intake questions (drafted in `MRK:SPEC_INTAKE`)
- Bundle document types
- Agent roles (names and responsibilities)
- Control reference taxonomy
- Report sections

Phase 4 also closes D-004: which pack is operationalized first after Pentest.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
