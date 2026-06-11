<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- MRK:PHASE5_ARCHITECTURE_DECISION_20260427_NAV_TOC — Section index | nav,toc,index | L4-14 -->
<!-- - MRK:ARCH_OVERVIEW — Summary + all decisions closed | arch,overview,summary,decisions,closed | L15-49 -->
<!-- - MRK:ARCH_TIERS — Three-tier component architecture | arch,tiers,three,tier,component | L50-117 -->
<!-- - MRK:ARCH_ENGCORE — ADR-001: EngagementCore extraction | arch,engcore,adr,engagementcore,extraction | L118-144 -->
<!-- - MRK:ARCH_FWREG — ADR-002: FrameworkRegistry in EngagementCore | arch,fwreg,adr,frameworkregistry,engagementcore | L145-205 -->
<!-- - MRK:ARCH_ENGID — ADR-003: EngagementID scheme | arch,engid,adr,engagementid,scheme | L206-262 -->
<!-- - MRK:ARCH_AGENT — ADR-004: Shared agent patterns | arch,agent,adr,shared,patterns | L263-326 -->
<!-- - MRK:ARCH_MVP — ADR-005: MVP delivery scope (D-003 closure) | arch,mvp,adr,delivery,scope | L327-377 -->
<!-- - MRK:ARCH_VERDICT — Phase 5 architecture summary | arch,verdict,phase,architecture,summary | L378-417 -->
<!-- NAV-LEN: 8 entries | Integrity-hash: c0d23de664317a31 | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:ARCH_OVERVIEW — Summary + all decisions closed | arch,overview,summary,decisions,closed | L15-49

### Purpose

This document formalizes the architecture decisions for `tg-audit-orchestrator` derived from Phases 1–4 of the DCPTCN_TG analysis. It closes the last open questions (D-003 formal) and presents five Architecture Decision Records (ADRs) covering the core structural choices.

### Decision register — final state

| ID | Decision | Status | Phase closed |
|----|----------|--------|-------------|
| D-001 | Extract `EngagementCore` from Decepticon; Decepticon becomes `PentestPack` | **CLOSED** | Phase 2 |
| D-002 | Generalized `Objective` schema: 12 fields kept, 2 replaced (`mitre[]` → `control_refs[]`; `opsec_notes` → `methodology_notes`), 2 dropped | **CLOSED** | Phase 2 |
| D-003 | MVP scope: `EngagementCore` extraction + `tg-audit-orchestrator` scaffolding + one audit pack (`GapAssessmentPack`) as proof-of-concept | **CLOSED** | Phase 5 (formal) |
| D-004 | Pack implementation priority: `PentestPack` → `GapAssessmentPack` → `TSA` → `ISO27001` → `Compliance` → `Remediation` | **CLOSED** | Phase 4 |

All four project decisions are now closed.

### ADR index

| ADR | Title | Decision |
|-----|-------|----------|
| ADR-001 | Three-Tier Architecture | `EngagementCore` / `tg-audit-orchestrator` / `packs` |
| ADR-002 | EngagementCore Extraction | Extract from Decepticon; backward-compatible; Decepticon = PentestPack |
| ADR-003 | FrameworkRegistry Placement | Factor into `EngagementCore` as shared utility |
| ADR-004 | EngagementID Scheme | `<pack-prefix>-YYYY-<seq>` stable format |
| ADR-005 | Shared Agent Patterns | `report_writer_agent` base in `EngagementCore`; pack-override optional |

### v0.2 §20 open question — CLOSED

> *"Should Decepticon remain optional or become a controlled specialist module?"*

**Answer:** Neither option as stated. The correct answer is: **Decepticon is refactored into two components.** Its methodology-agnostic kernel (`EngagementCore`) is extracted into a shared library; the adversarial-specific logic becomes `PentestPack`. This resolves the optionality debate by making the planning infrastructure mandatory (via `EngagementCore`) while the adversarial pack remains one choice among many — not "optional" (which implies degraded capability) but "one of six equally-valid packs."

---

## MRK:ARCH_TIERS — Three-tier component architecture | arch,tiers,three,tier,component | L50-117

### Three-tier model

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

### Dependency rules

1. **T1 → nothing** — `EngagementCore` has no imports from T2 or T3.
2. **T2 → T1, T3** — `tg-audit-orchestrator` imports T1 models and loads T3 packs via `PackDispatcher`.
3. **T3 → T1 only** — packs import `EngagementCore` models; they never import from T2.
4. **Decepticon** — becomes T3/pentest pack; imports T1; its existing orchestration stack (`EngagementLoop`) is replaced by T1's `EngagementLoop`.

### Repository layout recommendation

```
tg-audit-orchestrator/         ← Tier 2 repo
├── engagement_core/           ← Tier 1 (git submodule or pip package)
├── packs/                     ← Tier 3 (bundled in MVP; extractable later)
│   ├── pentest/               ← Decepticon specialist agents live here
│   └── ...
└── orchestrator/              ← Tier 2 entry point
```

**MVP option A (monorepo):** all three tiers in one repo; fastest to ship.
**MVP option B (submodule):** `engagement_core` as submodule; allows Decepticon to reference it directly. Recommended for D-001 migration path (Phase A of the 3-phase Decepticon refactor).

---

## MRK:ARCH_ENGCORE — ADR-001: EngagementCore extraction | arch,engcore,adr,engagementcore,extraction | L118-144

### ADR-001: EngagementCore as extracted shared library

**Status:** Accepted (closes D-001)

**Context:**
Decepticon contains a planning kernel (`OPPLANMiddleware`, `EngagementBundle`, `EngagementState`, `EngagementLoop`, `Soundwave`) that is methodology-agnostic except for the `PHASES` list, `CONTROL_REF_PREFIXES`, and `BUNDLE_DOCS`. Phase 2 established that 14 fields map directly to a generalized schema, 3 parameterize, and 3 drop.

**Decision:**
Extract the kernel into `engagement_core/` as a standalone library. Decepticon retains all specialist agent logic but its planning layer is replaced by `EngagementCore` imports. This makes `PentestPack` a thin adapter — it supplies `PHASES`, `CONTROL_REF_PREFIXES`, `BUNDLE_DOCS`, and the specialist agent registry; `EngagementCore` supplies everything else.

**Migration path (3 phases, from Phase 3 spec):**
- **Phase A** — Extract: move `OPPLANMiddleware`, `EngagementBundle`, `EngagementState`, `Soundwave`, `EngagementLoop` into `engagement_core/`. Decepticon imports from there. No behavior change. All existing Decepticon tests pass unchanged.
- **Phase B** — Parameterize: replace hardcoded `PHASES`, `mitre[]`, `opsec_*` fields with pack-supplied values. Add `MethodologyPack` ABC. `PentestPack` becomes the only pack. All existing behavior preserved via `PentestPack`.
- **Phase C** — Scaffold: add `tg-audit-orchestrator` T2 layer. Add `GapAssessmentPack`. `PackDispatcher` routes between packs. Intake interview now presented via Soundwave.

**Consequences:**
- (+) Decepticon remains fully functional through all three phases — no feature regression.
- (+) `tg-audit-orchestrator` has a clean import boundary; no circular deps.
- (+) Each methodology pack can be developed and tested independently against the `EngagementCore` interface.
- (-) Phase A requires a coordinated refactor of Decepticon's internal imports. Estimated effort: 2–3 days.

**Invariant:** `EngagementCore` version must be pinned in Decepticon's requirements to avoid cross-version schema drift.

---

## MRK:ARCH_FWREG — ADR-002: FrameworkRegistry in EngagementCore | arch,fwreg,adr,frameworkregistry,engagementcore | L145-205

### ADR-002: FrameworkRegistry as EngagementCore utility

**Status:** Accepted

**Context:**
Phase 4 identified that `ComplianceEvidencePack` and `GapAssessmentPack` share an identical `FRAMEWORK_REGISTRY` structure (framework slug → prefix + label + domain list). Without factoring this out, both packs duplicate the registry and any future pack that adds framework-configurable behavior adds a third copy.

**Decision:**
Add `engagement_core/frameworks/registry.py` containing `FrameworkRegistry` — a class-based registry that packs import to declare their supported frameworks and look up control ref prefixes.

```python
class FrameworkRegistry:
    """Central registry of compliance/security frameworks."""

    _registry: dict[str, FrameworkDefinition] = {}

    @classmethod
    def register(cls, slug: str, definition: FrameworkDefinition) -> None: ...

    @classmethod
    def get(cls, slug: str) -> FrameworkDefinition: ...

    @classmethod
    def list_slugs(cls) -> list[str]: ...

    @classmethod
    def prefix_for(cls, slug: str) -> str: ...


@dataclass
class FrameworkDefinition:
    slug: str
    label: str
    prefix: str          # e.g. "soc2:"
    domains: list[str]
    version: str = ""    # e.g. "2022" for ISO 27001:2022
```

**Built-in registrations (in `engagement_core/frameworks/builtins.py`):**
`soc2`, `pci_dss`, `hipaa`, `gdpr`, `nist_csf`, `cis_controls`, `iso27001`, `nist_800_53`, `mitre_attack` (minimal), `custom`.

**Pack usage:**
```python
class GapAssessmentPack(MethodologyPack):
    SUPPORTED_FRAMEWORKS = ["nist_csf", "cis_controls", "iso27001", "custom"]

    def supported_frameworks(self) -> list[str]:
        return self.SUPPORTED_FRAMEWORKS
```

**Consequences:**
- (+) Single source of truth for framework metadata; no duplication across packs.
- (+) New packs declare their frameworks by slug; built-in definitions are inherited.
- (+) Custom frameworks registered at engagement time via `FrameworkRegistry.register()` before `PackDispatcher.load()`.
- (-) Adds one module to `EngagementCore`; minor surface area increase.
- (-) Built-in slugs must be stable; changing a slug is a breaking change. Add deprecation aliases if needed.

---

## MRK:ARCH_ENGID — ADR-003: EngagementID scheme | arch,engid,adr,engagementid,scheme | L206-262

### ADR-003: EngagementID stable format

**Status:** Accepted

**Context:**
`RemediationVerificationPack` requires cross-referencing prior-engagement finding IDs. Without a stable `engagement_id` format, the `finding:` control ref prefix has no resolvable namespace.

**Decision:**
Define a canonical `EngagementID` format used by all packs:

```
Format:  <PACK-PREFIX>-<CLIENT-SHORT>-<YYYY>-<SEQ>
Example: PT-ACME-2026-001
         GAP-TECHCO-2026-001
         ISO-BANKCORP-2026-002

Components:
  PACK-PREFIX:    2–4 char code from pack registry
                  PT = PentestPack
                  TSA = TechSecurityAssessmentPack
                  ISO = ISO27001AuditPack
                  CER = ComplianceEvidencePack
                  GAP = GapAssessmentPack
                  RV = RemediationVerificationPack

  CLIENT-SHORT:   2–8 uppercase alphanumeric client identifier (no spaces)
                  Assigned at engagement creation; stored in EngagementBundle.client_short

  YYYY:           4-digit engagement year

  SEQ:            3-digit zero-padded sequential number per client per year
                  (client + year namespace; e.g., ACME's 3rd engagement of 2026 → 003)
```

**Finding ID sub-format:**
```
Format:  <ENGAGEMENT-ID>-F<NNN>
Example: PT-ACME-2026-001-F007
         GAP-TECHCO-2026-001-F023
```

**Implementation:**
- `EngagementBundle` gains a `client_short: str` field and `engagement_id: str` field (auto-generated by `tg-audit-orchestrator` at bundle creation; read-only after creation).
- `OPPLANMiddleware` prepends `engagement_id` to each objective ID for display but objectives remain internally referenced by their UUID.
- `RemediationVerificationPack` stores `prior_engagement_id: str` in `ScopePack.context_docs["prior_engagement_ref"]`.

**Consequences:**
- (+) Human-readable IDs in reports without relying on UUIDs.
- (+) `RemediationVerificationPack` cross-references are resolvable.
- (+) Sequential numbering is predictable for client record-keeping.
- (-) `client_short` must be enforced as alphanumeric at intake time; add `Soundwave` validation.
- (-) SEQ counter requires a per-client persistence store (simple JSON file per client is sufficient for MVP).

---

## MRK:ARCH_AGENT — ADR-004: Shared agent patterns | arch,agent,adr,shared,patterns | L263-326

### ADR-004: BaseReportWriterAgent in EngagementCore

**Status:** Accepted

**Context:**
All six packs define a `report_writer_agent` role. Without a common base, each pack implements its own report generation logic, leading to duplication of: OPPLAN-reading logic, finding-formatting logic, executive summary template, and severity/risk vocabulary.

**Decision:**
Add `engagement_core/agents/report_writer.py` defining `BaseReportWriterAgent` — a `MethodologyPack`-aware agent that:
1. Reads the completed `OPPLANMiddleware` state (all objectives + their status).
2. Reads the `EngagementBundle` for engagement metadata.
3. Calls pack-provided hooks for report section content.

```python
class BaseReportWriterAgent:
    """Pack-aware report writer. Packs override section_hooks()."""

    def __init__(self, pack: MethodologyPack, state: EngagementState):
        self.pack = pack
        self.state = state

    def generate(self) -> ReportDocument: ...

    def executive_summary(self) -> str:
        """Default: auto-generate from objective pass/block counts."""
        ...

    def section_hooks(self) -> dict[str, Callable[[], str]]:
        """Override in pack subclass to inject pack-specific sections."""
        return {}
```

**Pack override example (`PentestPack`):**
```python
class PentestReportWriterAgent(BaseReportWriterAgent):
    def section_hooks(self):
        return {
            "attack_narrative": self._build_attack_narrative,
            "mitre_mapping":    self._build_mitre_table,
        }
```

**BaseReportWriterAgent also provides:**
- Standard severity vocabulary: `critical / high / medium / low / informational`
- Finding table formatter (Finding ID, title, severity, control ref, status)
- Risk matrix builder (likelihood × impact grid from objective metadata)
- OPPLAN statistics block (total / passed / blocked / out-of-scope counts)

**Consequences:**
- (+) Consistent report structure across all pack types.
- (+) Pack report writers are thin overrides — only pack-specific narrative sections need implementing.
- (+) Severity vocabulary and risk matrix are standardized across all TechGuard engagements.
- (-) Requires `ReportDocument` schema in `EngagementCore`; adds one more model. Low complexity.

### Other shared agent patterns (non-ADR, recommendations)

- **`BaseScannerAgent`** — for TSA and Compliance packs: wraps scan tool invocation + result normalization. Post-MVP.
- **`BaseInterviewAgent`** — for ISO 27001 and Compliance packs: manages structured interview flows beyond Soundwave's intake scope. Post-MVP.
- **Agent registry** — `tg-audit-orchestrator` maintains a flat agent registry per pack instance; agents are instantiated at pack load time, not globally. Prevents agent state contamination across concurrent engagements.

---

## MRK:ARCH_MVP — ADR-005: MVP delivery scope (D-003 closure) | arch,mvp,adr,delivery,scope | L327-377

### ADR-005: tg-audit-orchestrator MVP scope

**Status:** Accepted (formally closes D-003)

**Context:**
D-003 was the open question: "what is the minimum viable tg-audit-orchestrator implementation?" Phase 3 provided a directional answer. This ADR formalizes the scope, exclusions, and delivery condition.

**MVP definition:**

The tg-audit-orchestrator MVP delivers the following, in this build order:

| Step | Deliverable | ADR/Phase ref |
|------|-------------|---------------|
| 1 | `engagement_core/` extracted from Decepticon (Phase A migration) | ADR-001 |
| 2 | `EngagementCore` unit test suite covering: `OPPLANMiddleware` FSM, `EngagementBundle` validation, `EngagementState` transitions | ADR-001 |
| 3 | `FrameworkRegistry` with built-in framework slugs | ADR-002 |
| 4 | `EngagementID` scheme + `client_short` intake field | ADR-003 |
| 5 | `PentestPack` (thin adapter over extracted `EngagementCore`) | Phase 4 |
| 6 | `GapAssessmentPack` (first non-adversarial pack; validates extension mechanism) | Phase 4 / D-004 |
| 7 | `PackDispatcher` with `PentestPack` + `GapAssessmentPack` registered | Phase 4 |
| 8 | `Soundwave` intake interview for both packs | Phase 3 |
| 9 | `BaseReportWriterAgent` + `PentestReportWriterAgent` | ADR-004 |
| 10 | `tg-audit-orchestrator` T2 entry point: session management, `PackDispatcher` routing, basic API routes | ADR-001 |

**MVP exclusions (post-v1):**
- `TechSecurityAssessmentPack`, `ISO27001AuditPack`, `ComplianceEvidencePack`, `RemediationVerificationPack` — build after MVP validation
- `BaseScannerAgent`, `BaseInterviewAgent` — post-MVP shared agent patterns
- Multi-pack composite engagements — no merged-pack concept in MVP
- Authentication / multi-tenant isolation — post-MVP (TechGuard Entra auth pending separately)
- `audit-evidence-processor` integration — external component; define interface contract in MVP but no implementation
- Web/API frontend — MVP is CLI-driven; `tg-audit-orchestrator` exposes a Python API; CLI wrapper is sufficient

**Delivery condition:**
MVP is complete when: (a) `PentestPack` runs a full engagement lifecycle (intake → OPPLAN → objectives → reporting) without regression against current Decepticon behavior; (b) `GapAssessmentPack` runs a full engagement lifecycle independently; (c) `PackDispatcher` correctly routes between the two packs based on `engagement_type`.

**Effort estimate:**
- Phase A migration (EngagementCore extraction): 3–5 days
- Phase B parameterize + PentestPack adapter: 2–3 days
- Phase C scaffolding + GapAssessmentPack: 5–8 days
- FrameworkRegistry + EngagementID: 1–2 days
- BaseReportWriterAgent: 2–3 days
- Integration + test suite: 3–5 days
- **Total MVP estimate:** ~16–26 days (senior engineer, full-time equivalent)

**Alignment with ~500h from ERA delivery target:**
At 8h/day, 20 days ≈ 160h. The MVP fits within the first 160–200h. Remaining capacity (300–340h) covers packs 3–6, `audit-evidence-processor` interface, and hardening.

---

## MRK:ARCH_VERDICT — Phase 5 architecture summary | arch,verdict,phase,architecture,summary | L378-417

### All decisions closed

| Decision | Closed at | Key outcome |
|----------|-----------|-------------|
| D-001 | Phase 2 + ADR-001 | Extract `EngagementCore`; Decepticon = `PentestPack` |
| D-002 | Phase 2 | Generalized Objective schema (14 keep, 2 replace, 2 drop) |
| D-003 | Phase 5 / ADR-005 | MVP = 10 steps; ~16–26 days engineering; fits within 500h target |
| D-004 | Phase 4 | Pentest → Gap → TSA → ISO27001 → Compliance → Remediation |

### Architecture summary

`tg-audit-orchestrator` is a three-tier system:

- **Tier 1 (`EngagementCore`)** — the extracted, methodology-agnostic planning kernel. The only tier that Decepticon will continue to depend on directly. Contains: `OPPLANMiddleware`, `EngagementBundle`, `EngagementState`, `EngagementLoop`, `Soundwave`, `FrameworkRegistry`, `BaseReportWriterAgent`.
- **Tier 2 (`tg-audit-orchestrator`)** — the orchestration shell. Loads packs via `PackDispatcher`, manages session lifecycle, exposes API routes.
- **Tier 3 (Packs)** — six `MethodologyPack` implementations. Each is independently testable and deployable. Decepticon's adversarial logic lives here as `PentestPack`.

### What this architecture resolves

- **v0.2 §20 open question** — CLOSED. Decepticon is neither optional nor a specialist module in the old sense; it is split into two components along a clean architectural boundary.
- **v0.2 content gap: ConOps** — CLOSED. `EngagementBundle` includes a `conops` doc type in `PentestPack`; `TG-CORE-CONTEXT` placeholder added for v0.3.
- **v0.2 content gap: AttackPath** — CLOSED. `TG-ANL-CHAIN` placeholder added for v0.3; maps to objective chain-of-steps narrative in `BaseReportWriterAgent`.
- **v0.2 content gap: multi-methodology** — CLOSED. `MethodologyPack` ABC + `PackDispatcher` is the answer.
- **v0.2 content gap: specialist agent roster** — CLOSED. Each pack defines its agent roster (Phase 4); `tg-audit-orchestrator` instantiates agents from the roster at engagement time.

### Deliverable status

| Phase | File | Anchors | Status |
|-------|------|---------|--------|
| Phase 1 | `PHASE1-gap-analysis-v01-v02-20260427.md` | 8 | DONE |
| Phase 2 | `PHASE2-fit-assessment-20260427.md` | 9 | DONE |
| Phase 3 | `PHASE3-generalization-spec-20260427.md` | 11 | DONE |
| Phase 4 | `PHASE4-methodology-packs-20260427.md` | 9 | DONE |
| Phase 5a | `PHASE5-architecture-decision-20260427.md` | 8 | DONE (this file) |
| Phase 5b | `PHASE5-v03-methodology-sections-20260427.md` | TBD | PENDING |

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
