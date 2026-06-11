<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- MRK:PHASE4_METHODOLOGY_PACKS_20260427_NAV_TOC — Section index | nav,toc,index | L4-15 -->
<!-- - MRK:PACK_OVERVIEW — All-pack summary + D-004 decision | pack,overview,summary,decision,d004 | L16-47 -->
<!-- - MRK:PACK_PENTEST — Pentest pack (PentestPack) | pack,pentest,pentestpack,red,team | L48-131 -->
<!-- - MRK:PACK_TSA — Tech Security Assessment pack | pack,tsa,tech,security,assessment | L132-215 -->
<!-- - MRK:PACK_ISO27001 — ISO 27001 Audit pack | pack,iso27001,iso,audit,isms | L216-308 -->
<!-- - MRK:PACK_COMPLIANCE — Compliance Evidence Review pack | pack,compliance,evidence,review,soc2 | L309-414 -->
<!-- - MRK:PACK_GAP — Gap Assessment pack | pack,gap,assessment,baseline,target | L415-511 -->
<!-- - MRK:PACK_REMEDIATION — Remediation Verification pack | pack,remediation,verification,retest,closure | L512-594 -->
<!-- - MRK:PACK_DISPATCHER — Pack selection + loading in tg-audit-orchestrator | pack,dispatcher,selection,loading,tg | L595-656 -->
<!-- - MRK:PACK_VERDICT — Phase 4 summary + D-004 closure | pack,verdict,phase,summary,closure | L657-699 -->
<!-- NAV-LEN: 9 entries | Integrity-hash: 9f7aa24af0f7f220 | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:PACK_OVERVIEW — All-pack summary + D-004 decision | pack,overview,summary,decision,d004 | L16-47

### Phase 4 scope

This document defines six `MethodologyPack` implementations for `tg-audit-orchestrator`. Each pack is self-contained: it specifies the phases, objective types, control reference taxonomy, `EngagementBundle` document types, specialist agent roster, and report structure for one service category. All six inherit from the `MethodologyPack` base class defined in Phase 3.

### Pack registry

| ID | Class | Service type | Control anchor | Status |
|----|-------|-------------|----------------|--------|
| 01 | `PentestPack` | Penetration test / red team | MITRE ATT&CK, CVE | Defined (Phase 3 + expanded here) |
| 02 | `TechSecurityAssessmentPack` | Technical security assessment | CIS Benchmarks, NIST 800-53, CVSS | Defined |
| 03 | `ISO27001AuditPack` | ISO 27001 ISMS audit | ISO 27001:2022 Annex A (93 controls) | Defined |
| 04 | `ComplianceEvidencePack` | Compliance evidence review | SOC 2 TSC, PCI DSS, HIPAA, GDPR | Defined |
| 05 | `GapAssessmentPack` | Security gap assessment | Configurable: NIST CSF, CIS Controls, ISO 27001, custom | Defined |
| 06 | `RemediationVerificationPack` | Remediation verification / re-test | Prior engagement finding IDs | Defined |

### D-004 decision — Implementation priority

**D-004 CLOSED.** Priority order for tg-audit-orchestrator integration:

1. **PentestPack** — already 100% backed by Decepticon; zero new tool work required; ships with EngagementCore extraction (Phase A migration)
2. **GapAssessmentPack** — most generic non-adversarial pack; validates the MethodologyPack extension mechanism without framework-specific complexity; ideal proof-of-concept for audit-type packs
3. **TechSecurityAssessmentPack** — nearest non-adversarial relative to Pentest; objective structure is similar; natural second technical pack
4. **ISO27001AuditPack** — well-bounded control set (93 Annex A controls); clean mapping from objective → control clause; high TechGuard demand signal
5. **ComplianceEvidencePack** — multi-framework; configurable framework parameter adds complexity; comes after single-framework ISO 27001
6. **RemediationVerificationPack** — depends on prior engagement output; implemented last once finding ID cross-referencing is stable

**Rationale:** ordering follows two axes — (a) implementation risk (low → high) and (b) dependency graph (self-contained → prior-engagement-dependent). Pentest + Gap together validate the dual-track (adversarial + audit) before committing to framework-specific logic.

---

## MRK:PACK_PENTEST — Pentest pack (PentestPack) | pack,pentest,pentestpack,red,team | L48-131

### Overview

`PentestPack` is the Decepticon-native pack. All existing Decepticon logic maps directly to this pack; no functional changes are made in Phase A migration. The pack encapsulates adversarial engagements: external/internal penetration tests, red team exercises, assumed-breach scenarios, and web application tests.

### Phase taxonomy

```python
PHASES = [
    EngagementPhase(id="planning",         label="Planning",          terminal=False),
    EngagementPhase(id="reconnaissance",   label="Reconnaissance",    terminal=False),
    EngagementPhase(id="exploitation",     label="Exploitation",      terminal=False),
    EngagementPhase(id="post_exploitation",label="Post-Exploitation", terminal=False),
    EngagementPhase(id="reporting",        label="Reporting",         terminal=False),
    EngagementPhase(id="complete",         label="Complete",          terminal=True),
]
```

### Objective types

| Type slug | Description | Typical status path |
|-----------|-------------|---------------------|
| `recon` | Passive/active reconnaissance target | pending → in-progress → passed/blocked |
| `initial_access` | Initial foothold objective | pending → in-progress → passed/blocked |
| `lateral_movement` | Pivot / lateral movement objective | pending → in-progress → passed/blocked/out-of-scope |
| `privilege_escalation` | Privilege escalation objective | pending → in-progress → passed/blocked/out-of-scope |
| `persistence` | Persistence / C2 establishment | pending → in-progress → passed/blocked/out-of-scope |
| `data_exfiltration` | Data access / exfiltration objective | pending → in-progress → passed/blocked/out-of-scope |
| `objective_flag` | Defined flag / proof-of-compromise | pending → in-progress → passed/blocked |

### Control reference taxonomy

```python
CONTROL_REF_PREFIXES = [
    "mitre:",       # e.g. "mitre:T1059.001" — MITRE ATT&CK technique
    "cve:",         # e.g. "cve:CVE-2024-1234"
    "cwe:",         # e.g. "cwe:CWE-89"
    "capec:",       # e.g. "capec:CAPEC-116"
]
```

### EngagementBundle document types

```python
BUNDLE_DOCS = [
    BundleDocType(key="roe",               label="Rules of Engagement",   required=True),
    BundleDocType(key="conops",            label="Concept of Operations",  required=True),
    BundleDocType(key="opplan",            label="OPPLAN",                required=True),
    BundleDocType(key="deconfliction",     label="Deconfliction Plan",    required=True),
    BundleDocType(key="technical_brief",   label="Technical Brief",       required=False),
    BundleDocType(key="assumed_breach",    label="Assumed Breach Setup",  required=False),  # scenario-conditional
]
```

### Specialist agent roster

| Agent slug | Role | Phase(s) active |
|------------|------|-----------------|
| `recon_agent` | Passive + active reconnaissance | reconnaissance |
| `web_app_agent` | Web application exploitation | exploitation |
| `network_agent` | Network exploitation + pivoting | exploitation, post_exploitation |
| `exploit_dev_agent` | Custom exploit development | exploitation |
| `post_exploit_agent` | Persistence, lateral movement, exfiltration | post_exploitation |
| `report_writer_agent` | Technical findings + executive narrative | reporting |

### Report structure

```
1. Executive Summary
2. Scope and Rules of Engagement
3. Attack Narrative (timeline)
4. Technical Findings (per objective)
   - Finding ID, title, severity, CVSS score
   - MITRE ATT&CK mapping
   - Evidence (screenshots, output)
   - Remediation recommendation
5. Risk Matrix
6. Remediation Roadmap (prioritized)
7. Appendices: tool output, methodology notes
```

---

## MRK:PACK_TSA — Tech Security Assessment pack | pack,tsa,tech,security,assessment | L132-215

### Overview

`TechSecurityAssessmentPack` covers non-adversarial technical reviews: vulnerability assessments, architecture reviews, configuration reviews, and hardening assessments. No exploitation; findings are discovery-and-analysis-only. The pack is the closest non-adversarial analogue to Pentest and shares similar objective granularity.

### Phase taxonomy

```python
PHASES = [
    EngagementPhase(id="planning",      label="Planning",           terminal=False),
    EngagementPhase(id="scoping",       label="Scoping",            terminal=False),
    EngagementPhase(id="discovery",     label="Discovery",          terminal=False),
    EngagementPhase(id="analysis",      label="Analysis",           terminal=False),
    EngagementPhase(id="reporting",     label="Reporting",          terminal=False),
    EngagementPhase(id="complete",      label="Complete",           terminal=True),
]
```

### Objective types

| Type slug | Description |
|-----------|-------------|
| `vuln_scan` | Automated vulnerability scan target (asset or subnet) |
| `config_review` | Configuration / hardening review for a component |
| `arch_review` | Architecture review for a system or integration |
| `patch_level` | Patch status assessment for OS / application |
| `network_segmentation` | Network segmentation and firewall rule review |
| `cloud_posture` | Cloud security posture review (IAM, storage, logging) |

### Control reference taxonomy

```python
CONTROL_REF_PREFIXES = [
    "cis:",         # e.g. "cis:CIS-L1-5.1.1" — CIS Benchmark control
    "nist:",        # e.g. "nist:SC-7" — NIST 800-53 control
    "cve:",         # e.g. "cve:CVE-2024-1234"
    "cvss:",        # e.g. "cvss:9.8" — CVSS base score annotation
    "ccm:",         # e.g. "ccm:IVS-06" — CSA Cloud Controls Matrix
]
```

### EngagementBundle document types

```python
BUNDLE_DOCS = [
    BundleDocType(key="scope_statement",   label="Scope Statement",        required=True),
    BundleDocType(key="technical_brief",   label="Technical Brief",        required=True),
    BundleDocType(key="assessment_plan",   label="Assessment Plan",        required=True),
    BundleDocType(key="asset_inventory",   label="Asset Inventory",        required=False),
    BundleDocType(key="scan_targets",      label="Scan Target List",       required=False),
]
```

### Specialist agent roster

| Agent slug | Role | Phase(s) active |
|------------|------|-----------------|
| `network_scanner_agent` | Network / host discovery, port scan, vuln scan | discovery |
| `vuln_analyzer_agent` | Vulnerability triage, CVSS scoring, deduplication | analysis |
| `config_reviewer_agent` | CIS Benchmark configuration review | discovery, analysis |
| `arch_reviewer_agent` | Architecture diagram review, trust boundary analysis | analysis |
| `cloud_posture_agent` | Cloud-specific posture review (AWS/Azure/GCP) | discovery, analysis |
| `report_writer_agent` | Findings narrative + executive summary | reporting |

### Report structure

```
1. Executive Summary
2. Assessment Scope and Methodology
3. Asset Overview
4. Findings by Severity
   - Finding ID, title, severity, CVSS score
   - Control reference (CIS / NIST)
   - Affected assets
   - Recommendation
5. Risk Heat Map
6. Patch Status Summary
7. Recommendations (prioritized by risk)
8. Appendices: scan output, raw evidence
```

---

## MRK:PACK_ISO27001 — ISO 27001 Audit pack | pack,iso27001,iso,audit,isms | L216-308

### Overview

`ISO27001AuditPack` conducts a formal ISMS audit against ISO 27001:2022. The pack maps every objective to one or more Annex A controls (or ISO 27001 clauses 4–10). The engagement yields a nonconformity log, an audit report, and a certification-readiness verdict. Applies to both initial certification audits and surveillance audits.

### Phase taxonomy

```python
PHASES = [
    EngagementPhase(id="planning",           label="Audit Planning",            terminal=False),
    EngagementPhase(id="document_review",    label="Document Review",           terminal=False),
    EngagementPhase(id="gap_analysis",       label="Gap Analysis",              terminal=False),
    EngagementPhase(id="controls_testing",   label="Controls Testing",          terminal=False),
    EngagementPhase(id="nonconformity",      label="Nonconformity Review",      terminal=False),
    EngagementPhase(id="reporting",          label="Reporting",                 terminal=False),
    EngagementPhase(id="complete",           label="Complete",                  terminal=True),
]
```

### Objective types

| Type slug | Description |
|-----------|-------------|
| `clause_review` | ISO 27001 clause (4–10) conformance review |
| `annex_control` | Annex A control review (A.5–A.8) |
| `doc_review` | ISMS document review (policy, procedure, record) |
| `interview` | Management / staff interview objective |
| `evidence_sample` | Evidence sampling objective (logs, access reviews) |
| `nonconformity` | Identified nonconformity requiring correction |

### Control reference taxonomy

```python
CONTROL_REF_PREFIXES = [
    "iso27001:",    # e.g. "iso27001:A.5.1" — Annex A control
    "iso27001:cl:", # e.g. "iso27001:cl:6.1.2" — ISO 27001 clause
    "iso27002:",    # e.g. "iso27002:5.1" — ISO 27002 implementation guidance
]

# Annex A domain index for 2022 edition
ANNEX_A_DOMAINS = {
    "A.5": "Organisational controls (37 controls)",
    "A.6": "People controls (8 controls)",
    "A.7": "Physical controls (14 controls)",
    "A.8": "Technological controls (34 controls)",
}
# Total: 93 controls across 4 domains
```

### EngagementBundle document types

```python
BUNDLE_DOCS = [
    BundleDocType(key="audit_scope",         label="Audit Scope Statement",      required=True),
    BundleDocType(key="audit_plan",          label="Audit Plan",                 required=True),
    BundleDocType(key="control_matrix",      label="Annex A Control Matrix",     required=True),
    BundleDocType(key="document_registry",   label="ISMS Document Registry",     required=True),
    BundleDocType(key="nonconformity_log",   label="Nonconformity Log",          required=False),  # populated during controls testing
    BundleDocType(key="statement_of_appl",   label="Statement of Applicability", required=False),  # client-provided
]
```

### Specialist agent roster

| Agent slug | Role | Phase(s) active |
|------------|------|-----------------|
| `doc_reviewer_agent` | ISMS policy and procedure document review | document_review |
| `clause_assessor_agent` | ISO 27001 clauses 4–10 conformance assessment | gap_analysis, controls_testing |
| `control_tester_agent` | Annex A control evidence review and testing | controls_testing |
| `nonconformity_analyst_agent` | NC classification, grading (major/minor/obs), root cause | nonconformity |
| `report_writer_agent` | Audit report, NC summary, certification readiness | reporting |

### Report structure

```
1. Audit Introduction (scope, objectives, standard version)
2. ISMS Overview and Context (organization summary)
3. Clause 4–10 Conformance Summary
4. Annex A Controls Assessment
   - Control ID, title, assessment result, evidence reference
   - Conformant / Nonconformant / Not Applicable
5. Nonconformity Register
   - Major NCs (certification-blocking)
   - Minor NCs
   - Observations (improvement opportunities)
6. Certification Readiness Verdict
7. Corrective Action Recommendations
8. Appendices: evidence index, interview notes, SoA cross-reference
```

---

## MRK:PACK_COMPLIANCE — Compliance Evidence Review pack | pack,compliance,evidence,review,soc2 | L309-414

### Overview

`ComplianceEvidencePack` supports periodic evidence collection and review for multiple compliance frameworks. Unlike ISO 27001 (single standard, fixed control set), this pack is framework-configurable — the `framework` field in the engagement bundle selects the active control taxonomy. Applies to SOC 2 Type II readiness, PCI DSS self-assessments, HIPAA Security Rule reviews, and GDPR Article 32 technical measures.

### Phase taxonomy

```python
PHASES = [
    EngagementPhase(id="planning",           label="Planning",                  terminal=False),
    EngagementPhase(id="evidence_request",   label="Evidence Request",          terminal=False),
    EngagementPhase(id="collection",         label="Evidence Collection",       terminal=False),
    EngagementPhase(id="review",             label="Evidence Review",           terminal=False),
    EngagementPhase(id="gap_identification", label="Gap Identification",        terminal=False),
    EngagementPhase(id="reporting",          label="Reporting",                 terminal=False),
    EngagementPhase(id="complete",           label="Complete",                  terminal=True),
]
```

### Objective types

| Type slug | Description |
|-----------|-------------|
| `control_test` | Evidence review for a single control / requirement |
| `policy_review` | Policy or procedure document review |
| `evidence_gap` | Missing or insufficient evidence for a control |
| `exception` | Control exception requiring compensating control |
| `access_review` | Periodic access review objective |
| `vendor_review` | Third-party / vendor control review |

### Control reference taxonomy (framework-configurable)

```python
# Framework registry — one selected per engagement via bundle.framework field
FRAMEWORK_REGISTRY = {
    "soc2": {
        "prefix": "soc2:",
        "label": "SOC 2 (AICPA Trust Services Criteria)",
        "domains": ["CC", "A", "PI", "C", "P"],  # Common Criteria + 4 additional
    },
    "pci_dss": {
        "prefix": "pci:",
        "label": "PCI DSS v4.0",
        "domains": ["R1-R12"],  # 12 requirements
    },
    "hipaa": {
        "prefix": "hipaa:",
        "label": "HIPAA Security Rule",
        "domains": ["admin_safe", "phys_safe", "tech_safe"],
    },
    "gdpr": {
        "prefix": "gdpr:",
        "label": "GDPR Article 32",
        "domains": ["technical_measures", "organisational_measures"],
    },
    "nist_csf": {
        "prefix": "csf:",
        "label": "NIST CSF 2.0",
        "domains": ["GV", "ID", "PR", "DE", "RS", "RC"],
    },
}

# Engagement-time selection:
#   bundle.scope.context_docs["framework_selection"] → keys into FRAMEWORK_REGISTRY
```

### EngagementBundle document types

```python
BUNDLE_DOCS = [
    BundleDocType(key="scope_statement",     label="Compliance Scope Statement", required=True),
    BundleDocType(key="control_matrix",      label="Control Matrix",             required=True),
    BundleDocType(key="evidence_request",    label="Evidence Request List",      required=True),
    BundleDocType(key="gap_log",             label="Gap and Exception Log",      required=False),
    BundleDocType(key="vendor_list",         label="In-Scope Vendor List",       required=False),
]
```

### Specialist agent roster

| Agent slug | Role | Phase(s) active |
|------------|------|-----------------|
| `evidence_collector_agent` | Evidence request tracking, completeness checking | evidence_request, collection |
| `control_mapper_agent` | Control-to-evidence mapping, framework taxonomy | review |
| `gap_analyst_agent` | Gap classification, exception identification, compensating controls | gap_identification |
| `vendor_review_agent` | Third-party questionnaire review | review |
| `report_writer_agent` | Management letter, control coverage report | reporting |

### Report structure

```
1. Executive Summary
2. Engagement Scope (framework, period, in-scope systems)
3. Control Coverage Summary (% covered by category)
4. Control-by-Control Assessment Table
   - Control ID, description, evidence provided, status (met / gap / exception)
5. Gap Register
   - Gap ID, control ref, description, risk rating, recommended remediation
6. Exception Register
7. Management Letter / Opinion
8. Appendices: evidence index, vendor assessments
```

---

## MRK:PACK_GAP — Gap Assessment pack | pack,gap,assessment,baseline,target | L415-511

### Overview

`GapAssessmentPack` is the most generic non-adversarial pack. It captures the delta between a client's current security posture and a target state defined by a chosen framework (or custom control set). The output is a prioritized remediation roadmap with effort estimates. Because it is the most framework-agnostic pack and the most versatile non-adversarial pattern, it is designated priority-2 in D-004 (first non-Pentest pack to implement).

### Phase taxonomy

```python
PHASES = [
    EngagementPhase(id="planning",          label="Planning",             terminal=False),
    EngagementPhase(id="baseline",          label="Baseline Assessment",  terminal=False),
    EngagementPhase(id="target_definition", label="Target Definition",    terminal=False),
    EngagementPhase(id="gap_analysis",      label="Gap Analysis",         terminal=False),
    EngagementPhase(id="prioritization",    label="Prioritization",       terminal=False),
    EngagementPhase(id="reporting",         label="Reporting",            terminal=False),
    EngagementPhase(id="complete",          label="Complete",             terminal=True),
]
```

### Objective types

| Type slug | Description |
|-----------|-------------|
| `baseline_domain` | Assess current state of a control domain |
| `target_control` | Define / confirm target state for a control |
| `gap_item` | Identified gap between current and target state |
| `quick_win` | Gap item scored as high-impact / low-effort |
| `strategic_item` | Gap item requiring long-term remediation |
| `dependency` | Gap item blocked by another gap item |

### Control reference taxonomy (configurable)

```python
# GapAssessmentPack uses the same FRAMEWORK_REGISTRY as ComplianceEvidencePack
# plus two additional options:

EXTRA_FRAMEWORKS = {
    "cis_controls": {
        "prefix": "cis:",
        "label": "CIS Controls v8",
        "domains": ["IG1", "IG2", "IG3"],  # Implementation Groups
    },
    "custom": {
        "prefix": "custom:",
        "label": "Custom control set",
        "domains": [],  # loaded from bundle.scope.context_docs["custom_controls"]
    },
}

# Maturity model: 0-Not Implemented → 1-Partial → 2-Defined → 3-Managed → 4-Optimizing
MATURITY_SCALE = [0, 1, 2, 3, 4]
```

### EngagementBundle document types

```python
BUNDLE_DOCS = [
    BundleDocType(key="scope_statement",       label="Gap Assessment Scope",       required=True),
    BundleDocType(key="current_state_profile", label="Current State Profile",      required=True),
    BundleDocType(key="target_state_profile",  label="Target State Profile",       required=True),
    BundleDocType(key="gap_register",          label="Gap Register",               required=False),  # produced during engagement
    BundleDocType(key="effort_estimates",      label="Effort Estimate Sheet",      required=False),
    BundleDocType(key="custom_controls",       label="Custom Control Set",         required=False),  # custom framework only
]
```

### Specialist agent roster

| Agent slug | Role | Phase(s) active |
|------------|------|-----------------|
| `baseline_analyst_agent` | Current state interviews, evidence review, maturity scoring | baseline |
| `target_definer_agent` | Target state mapping to chosen framework | target_definition |
| `gap_scorer_agent` | Gap delta calculation, maturity delta, risk scoring | gap_analysis |
| `prioritizer_agent` | Effort-impact scoring, quick win identification, roadmap sequencing | prioritization |
| `report_writer_agent` | Gap register narrative, roadmap report | reporting |

### Report structure

```
1. Executive Summary
2. Assessment Framework and Scope
3. Current State Summary (maturity scores by domain)
4. Target State Definition
5. Gap Register (sorted by risk / priority)
   - Gap ID, domain, control ref, current score, target score, delta, risk rating
6. Prioritized Remediation Roadmap
   - Phase 0 (Quick Wins — 0-30 days)
   - Phase 1 (Short Term — 30-90 days)
   - Phase 2 (Medium Term — 90-180 days)
   - Phase 3 (Strategic — 180+ days)
7. Effort Estimates (person-days by phase)
8. Appendices: evidence, interview notes, scoring methodology
```

---

## MRK:PACK_REMEDIATION — Remediation Verification pack | pack,remediation,verification,retest,closure | L512-594

### Overview

`RemediationVerificationPack` is the closure engagement type. It takes output from a prior engagement (any pack) — specifically its finding/gap register — and verifies that identified issues have been addressed. It introduces a `prior_engagement_ref` field in the bundle scope to link to the source engagement's finding IDs. This is the only pack with a direct inter-engagement dependency.

### Phase taxonomy

```python
PHASES = [
    EngagementPhase(id="planning",             label="Planning",                  terminal=False),
    EngagementPhase(id="evidence_collection",  label="Evidence Collection",       terminal=False),
    EngagementPhase(id="verification",         label="Verification",              terminal=False),
    EngagementPhase(id="regression_testing",   label="Regression Testing",        terminal=False),
    EngagementPhase(id="reporting",            label="Reporting",                 terminal=False),
    EngagementPhase(id="complete",             label="Complete",                  terminal=True),
]
```

### Objective types

| Type slug | Description |
|-----------|-------------|
| `finding_verify` | Verify remediation of a specific prior finding |
| `regression_test` | Regression test — confirm fix does not reintroduce issue |
| `partial_remediation` | Finding partially addressed; residual risk remains |
| `not_remediated` | Finding not addressed; original risk persists |
| `new_finding` | New issue discovered during verification (tracked separately) |

### Control reference taxonomy

```python
# Inherits control_refs from the prior engagement finding IDs
# Prefix convention: prior-engagement finding ID as the control reference

CONTROL_REF_PREFIXES = [
    "finding:",     # e.g. "finding:PT-2025-001-F07" — prior engagement finding
    "mitre:",       # inherited from pentest source if applicable
    "cve:",         # inherited from TSA/pentest if applicable
]

# Bundle field: prior_engagement_ref (required)
# Structure: { "engagement_id": str, "finding_count": int, "source_pack": str }
```

### EngagementBundle document types

```python
BUNDLE_DOCS = [
    BundleDocType(key="verification_scope",    label="Verification Scope Statement", required=True),
    BundleDocType(key="finding_list",          label="Finding List (from prior)",    required=True),
    BundleDocType(key="verification_matrix",   label="Verification Matrix",          required=True),
    BundleDocType(key="prior_report",          label="Prior Engagement Report Ref",  required=False),
    BundleDocType(key="new_findings_register", label="New Findings Register",        required=False),
]
```

### Specialist agent roster

| Agent slug | Role | Phase(s) active |
|------------|------|-----------------|
| `evidence_reviewer_agent` | Review remediation evidence submitted by client | evidence_collection |
| `finding_verifier_agent` | Technical verification — confirm fix is effective | verification |
| `regression_tester_agent` | Re-test original attack/probe to confirm closure | regression_testing |
| `status_tracker_agent` | Track finding status across verification run | verification, regression_testing |
| `report_writer_agent` | Verification summary, residual risk statement | reporting |

### Report structure

```
1. Executive Summary
2. Verification Scope (prior engagement reference, finding count)
3. Verification Summary Table
   - Finding ID, description, status (Closed / Partially Closed / Open), evidence ref
4. Regression Test Results
5. Residual Risk Statement
6. New Findings (if any)
7. Letter of Attestation (optional — if all critical findings closed)
8. Appendices: evidence index, test scripts used
```

---

## MRK:PACK_DISPATCHER — Pack selection + loading in tg-audit-orchestrator | pack,dispatcher,selection,loading,tg | L595-656

### PackDispatcher design

`tg-audit-orchestrator` requires a mechanism to select and instantiate the correct `MethodologyPack` at engagement start. The dispatcher is the single entry point and is invoked by Soundwave after the intake interview completes and `engagement_type` is confirmed.

```python
class PackDispatcher:
    """Registry and loader for MethodologyPack implementations."""

    REGISTRY: dict[str, type[MethodologyPack]] = {
        "pentest":               PentestPack,
        "tech_security_assessment": TechSecurityAssessmentPack,
        "iso27001":              ISO27001AuditPack,
        "compliance_evidence":   ComplianceEvidencePack,
        "gap_assessment":        GapAssessmentPack,
        "remediation_verification": RemediationVerificationPack,
    }

    @classmethod
    def load(cls, engagement_type: str, bundle: EngagementBundle) -> MethodologyPack:
        if engagement_type not in cls.REGISTRY:
            raise ValueError(f"Unknown engagement type: {engagement_type}")
        pack_class = cls.REGISTRY[engagement_type]
        return pack_class(bundle=bundle)

    @classmethod
    def list_types(cls) -> list[str]:
        return list(cls.REGISTRY.keys())
```

### Intake → dispatch flow

```
Soundwave intake interview
  → confirms engagement_type (from list_types())
  → builds EngagementBundle (with correct BUNDLE_DOCS for the pack)
  → calls PackDispatcher.load(engagement_type, bundle)
  → returns MethodologyPack instance to EngagementLoop

EngagementLoop.__init__(pack=dispatcher.load(...))
  → calls pack.initial_objectives() → seeds OPPLAN
  → calls pack.phase_sequence() → configures EngagementState phases
  → ready to execute
```

### Multi-pack note

A single engagement can reference multiple packs only via separate `EngagementBundle` instances (one per pack). Cross-pack objective references are handled through `control_refs` using `finding:` prefix (as in `RemediationVerificationPack`). There is no merged-pack or composite-pack concept in the MVP; if needed, it is a post-v1 extension.

### Adding a new pack

1. Subclass `MethodologyPack` — implement all abstract properties and methods.
2. Register in `PackDispatcher.REGISTRY` with a slug.
3. Define intake question set in `Soundwave.QUESTION_SETS[slug]`.
4. Add `BUNDLE_DOCS` list for the pack's `EngagementBundle`.
5. (Optional) Register specialist agents in the `tg-audit-orchestrator` agent registry.

No changes to `EngagementCore`, `OPPLANMiddleware`, or `EngagementState` — the pack extension point is intentionally additive.

---

## MRK:PACK_VERDICT — Phase 4 summary + D-004 closure | pack,verdict,phase,summary,closure | L657-699

### Phase 4 summary

Six `MethodologyPack` implementations are now fully specified. All inherit from the `MethodologyPack` base class (Phase 3). All are compatible with the `EngagementCore` extraction target.

| Pack | Key design choice | Most distinctive feature |
|------|-------------------|--------------------------|
| `PentestPack` | Decepticon-native; zero migration cost | Adversarial phase taxonomy + MITRE ATT&CK refs |
| `TechSecurityAssessmentPack` | Non-adversarial; CIS/NIST anchor | Architecture review objective type |
| `ISO27001AuditPack` | Fixed 93-control taxonomy | Nonconformity log + certification readiness verdict |
| `ComplianceEvidencePack` | Multi-framework configurable | Framework registry pattern (`bundle.framework`) |
| `GapAssessmentPack` | Most generic; maturity model | Current/target state delta + roadmap phases |
| `RemediationVerificationPack` | Inter-engagement dependency | `prior_engagement_ref` + regression testing phase |

### Cross-pack patterns

- **Framework configurability:** `ComplianceEvidencePack` and `GapAssessmentPack` share a `FRAMEWORK_REGISTRY` — factoring this into `EngagementCore` as `FrameworkRegistry` is a Phase 5 architecture recommendation.
- **Control ref inheritance:** `RemediationVerificationPack` references prior-engagement finding IDs — this implies the system needs a stable `engagement_id` scheme from day one; propose `<pack-prefix>-<YYYY>-<seq>` format.
- **Report writer agent:** All 6 packs include a `report_writer_agent` role — this agent can be implemented once in `EngagementCore` and overridden per-pack for template customization.

### D-004 closed

Implementation priority is locked:

```
1. PentestPack             → ships with Phase A migration (EngagementCore extraction)
2. GapAssessmentPack       → first non-adversarial pack; validates extension mechanism
3. TechSecurityAssessmentPack
4. ISO27001AuditPack
5. ComplianceEvidencePack
6. RemediationVerificationPack → last; requires stable engagement_id scheme
```

### Outstanding items entering Phase 5

- **FrameworkRegistry** — shared between `ComplianceEvidencePack` and `GapAssessmentPack`; propose factoring into `EngagementCore` in architecture decision
- **engagement_id scheme** — required for `RemediationVerificationPack` cross-referencing; define in architecture decision
- **report_writer_agent** — define once in `EngagementCore`; pack-level override optional
- **D-003 formal closure** — Phase 3 answered the MVP scope question; Phase 5 will write the formal architecture decision document

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
