<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Orca Platform — Evidence Workflow

Evidence lifecycle managed by [BHV-9F8R]. Every piece of evidence — a finding, a control test result, a scan output, a document — follows this 6-state chain.

---

## The chain

```
intake → verification → classification → packaging → delivery → archived
```

No state may be skipped. The skill enforces the chain.

---

## States

### 1. intake

Evidence has been collected and recorded. Not yet assessed.

**Entry**: automatic on capture [DIR-V8BG] or manual `intake <item>`.
**Exit gate**: item has a source reference (tool, session, analyst).

### 2. verification

Evidence has been reviewed for accuracy and completeness.

**Entry**: `verify <item>`
**Exit gate**:
- Standard severity: analyst review
- HIGH severity: **manual verification required before proceeding** (PT engagements)
- CRITICAL severity: second-analyst sign-off required

### 3. classification

Evidence has been assigned its type, severity, and framework mapping.

**Entry**: `classify <item>`
**Exit gate**: severity assigned · framework reference attached (if compliance engagement) · finding type declared (PT: vuln/info/finding; audit: control/gap/observation).

### 4. packaging

Evidence has been formatted for inclusion in a deliverable.

**Entry**: `package <item>`
**Exit gate**: deliverable template section completed · evidence provenance recorded · cross-references wired (sync connectors, if applicable [BHV-G3JC]).

### 5. delivery

Evidence has been included in a client deliverable and delivered.

**Entry**: `deliver <item>`
**Exit gate**: deliverable issued to client · delivery timestamp recorded.

### 6. archived

Evidence is closed. No further state transitions.

**Entry**: `archive <item>` (after delivery) or `archive <item> superseded-by <newer-item>`.

---

## Engagement type variations

| Type | intake source | HIGH-severity gate | packaging format |
|---|---|---|---|
| PT | scan output / manual | manual verify required | finding-template + PoC reference |
| IT audit | control test / interview | analyst review | control-evidence matrix |
| Compliance | framework-mapping / gap | analyst review | gap-table + remediation-note |

---

## Evidence commands

| Command | Action |
|---|---|
| `intake <item>` | Register new evidence |
| `verify <item>` | Mark as verified |
| `classify <item>` | Assign type + severity + framework ref |
| `package <item>` | Format for deliverable |
| `deliver <item>` | Mark as delivered |
| `archive <item>` | Close |
| `status <item>` | Show current state + history |
| `list evidence [state]` | List all evidence at a given state (or all) |
| `chain <item>` | Show full state history for one item |

---

## Cross-domain sync

When sync connectors are active [BHV-G3JC], evidence transitions in one domain can trigger classification suggestions in another. Example:

- PT finding classified as HIGH → compliance gap-assessment frame surfaces the mapped control
- Compliance gap identified → PT scope suggestion for that system

Connectors are declared per engagement. The skill maintains them; no manual cross-referencing needed.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
