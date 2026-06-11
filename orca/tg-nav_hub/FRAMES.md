<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Orca Platform — Frames

A frame is your working perspective on an engagement. Switch frames as your focus shifts. Frames load only what you need — no context debt from switching.

**How to switch**: `load frame [name]` · `switch to [name] view` · `activate [frame-name]`

---

## Built-in frames

### Manager [FRM-X8Q2]

**When to use**: you need the full picture of an engagement or your portfolio.

**What loads**:
- All active engagements and their phase status
- What's in flight, what's blocked, who owns what
- Open evidence items above a threshold (HIGH and above by default)
- Upcoming milestones and delivery targets

**Best for**: status reviews · kick-off sessions · client updates · deciding where to focus next

---

### Worker [FRM-M5R7]

**When to use**: you're focused on a specific task or evidence item.

**What loads**:
- The current work item only (one finding, one control, one deliverable)
- Evidence needed for that item
- Relevant rules and gates for this item's engagement type
- Prior notes on this item from past sessions

**Best for**: running a PT phase · drafting a finding · verifying a control · composing a report section

---

### Role-define [FRM-K3PN]

**When to use**: defining a new role for a team member or customizing an existing role.

**What loads**:
- Current role registry
- Permission catalog
- Frame templates to fork

**Steps**:
1. Activate this frame
2. Describe the role (function, access, default frame preference)
3. The skill generates a `RLE-*` token and adds it to your profile

---

## Engagement frames

These frames are scoped to a specific engagement. Load an engagement first [BHV-W5HZ], then activate one of these frames.

### Current engagement [FRM-J7VC]

Full engagement state: plans, evidence status, AGENTS registry, all phases.

Use at session start to orient before switching to a focused frame.

---

### Deliverable compose [FRM-W2HG]

Evidence chain + report template for one deliverable.

Use when writing a specific report section or packaging evidence for delivery.

---

### Phase handover [FRM-T4YB]

Everything needed to transition between engagement phases: wrap-up checklist, evidence state at cutoff, what carries forward to the next phase.

Use at phase boundaries (e.g., enum → exploit, or gap-assessment → management-response).

---

### Final report [FRM-D9LF]

Full report assembly: all evidence chains + cross-references + engagement-state wrap + deliverable targets.

Use only when composing the final client deliverable. Loads broadly — confirm evidence is complete before activating.

---

### Gap assessment [FRM-Z6KX]

Compliance-specific: all gaps mapped to framework requirements (ISO 27001 · NIST CSF · CIS Controls · SOC2 · PCI-DSS).

Use during the gap-assessment phase of a compliance engagement.

---

## Custom frames [RLE-*]

Hari defines custom frames via `Role-define [FRM-K3PN]`. Each custom frame gets a `RLE-*` token and appears here after creation.

```
# Custom frames (added by Hari):
# (none yet)
```

---

## Frame discipline

- Frames are **additive at load, clean at unload** — switching frames never leaves residue
- The active frame is persisted at session end [BHV-K2NM] — next session resumes in the same frame
- Frames do not overlap — only one frame is active at any time
- debug logging [BHV-B1XK] records every frame switch when debug is on

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
