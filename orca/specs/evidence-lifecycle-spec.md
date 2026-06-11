<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Evidence Lifecycle Spec

**Platform**: Orca
**Governs**: evidence state chain [BHV-9F8R]

For the command reference and per-engagement-type variations, see `../tg-nav_hub/EVIDENCE-WORKFLOW.md`.
This spec covers the design rationale and enforcement rules.

**Maturity note**: Lifecycle chain enforcement runs today as skill-side discipline — transition commands check state before advancing. Runtime enforcement at the gate level (refusing transitions automatically when preconditions aren't met) is part of the **M3 deliverable**. Where this spec says "the chain enforces X," read as target behavior.

---

## Why a lifecycle chain

Traditional consulting evidence management loses traceability:
- A finding gets collected but never verified
- A control test result goes directly into a report without classification
- Deliverable contains evidence in unknown states

The Orca evidence lifecycle prevents this by making state explicit and enforcing the chain. Nothing can be packaged without being verified. Nothing can be delivered without being packaged. Every transition is logged.

---

## The chain

```
intake → verification → classification → packaging → delivery → archived
```

### State semantics

| State | Means | Who transitions |
|---|---|---|
| intake | collected, not yet assessed | automatic [DIR-V8BG] or analyst |
| verification | reviewed for accuracy and completeness | analyst (HIGH: manual; CRITICAL: second sign-off) |
| classification | type, severity, and framework mapping assigned | analyst |
| packaging | formatted for deliverable inclusion | analyst |
| delivery | included in issued deliverable | analyst or system |
| archived | closed; no further transitions | analyst |

### Supersession

An evidence item can be superseded by a newer item:

```
archive <item> superseded-by <newer-item>
```

The superseded item is archived; the chain records the supersession relationship.

---

## Enforcement rules

1. **Sequential only** — no skipping states
2. **HIGH-severity gate** (PT engagements) — manual verification required; skill blocks packaging until verified
3. **CRITICAL-severity gate** — second-analyst sign-off required; skill prompts for sign-off confirmation
4. **No delivery without packaging** — delivery transition requires packaging state
5. **Archived is terminal** — no transitions out of archived

---

## Provenance

Every evidence item carries:
- Source reference (tool run, session, analyst handle)
- State history with timestamps
- Classification (severity + type + framework mapping where applicable)
- Packaging reference (which deliverable section it appears in)
- Delivery timestamp (when it reached the client)

This makes the final deliverable audit-ready by construction.

---

## Cross-domain evidence [BHV-G3JC]

When sync connectors are active, an evidence item can appear in multiple domains:
- A PT finding → also a compliance gap
- A compliance gap → also a PT scope target

Cross-domain items share provenance but have independent states in each domain. Packaging in one domain does not package in another.

---

## Capture discipline [DIR-V8BG]

Capture at low threshold. Classification happens later. Do not delay intake because the item isn't fully understood yet — record it, then classify.

This prevents evidence loss during fast-moving phases (exploit, live testing).

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
