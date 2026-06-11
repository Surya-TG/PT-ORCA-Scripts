<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# New Engagement Guide

## Overview

A new engagement creates the full directory structure for a client engagement and wires it into the Orca evidence lifecycle.

## Command

```
new engagement <engagement-id> type: <PT|audit|compliance>
```

**engagement-id**: a short identifier, e.g., `techguard-pt-2026-q2` or `client-iso27001-audit`.

## What gets created [BHV-2T6L]

```
engagements/<engagement-id>/
├── engagement-state.md       engagement state file
├── AGENTS.md                team registry (roles and assignments)
├── plans/                   active action plans
├── evidence/                evidence chain
│   ├── intake/              new items
│   ├── verified/
│   ├── classified/
│   ├── packaged/
│   └── delivered/
└── deliverables/            final outputs
```

## Engagement types

### PT engagement

Flow: `recon → enum → exploit → service-verify → report → wrap`

Evidence gates:
- HIGH severity: manual verification required before packaging
- CRITICAL severity: second-analyst sign-off required

Pack: PT pack (`../../pt-orc/`) handles the automated phase scripting.

### Audit engagement

Flow: `intake → control-testing → gap-analysis → management-response → final-report`

Evidence: each control maps to one or more evidence artifacts. Gap items map to framework requirements.

### Compliance engagement

Flow: `requirements-mapping → evidence-collection → gap-assessment → remediation-tracking → certification-readiness`

Evidence: gap items carry framework reference (ISO control / NIST function / CIS safeguard / PCI requirement).

## Post-creation

After the engagement is created:

1. Populate `AGENTS.md` with team member handles and roles
2. Configure sync connectors if this engagement crosses domains
3. Load the engagement: `load engagement <engagement-id>`
4. Switch to Manager frame for the initial orientation: `load frame Manager`

## Cross-domain engagements

If this engagement combines PT + compliance (common: PT findings feed compliance gaps):

After creation, declare a sync connector:
```
wire PT → compliance for <engagement-id>
```

The skill will surface classification suggestions in the compliance domain when PT findings are classified.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
