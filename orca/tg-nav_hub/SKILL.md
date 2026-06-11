<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Orca Platform Skill — tg-nav_hub

**Version**: v0.1.0
**Platform**: Orca
**Profile required**: yes — not initialized until Hari activates (see `PROFILE.md`)

---

## Session start [BHV-7Q3X]

On every session start, before any work:

1. Read profile (`PROFILE.md`) — confirm role is active; if not initialized, stop and prompt Hari to activate
2. Load user files for the current engagement
3. Reconstruct the solved-inference view from last session state
4. Attach to the active engagement context (load engagement-state + active plans + AGENTS registry)

No re-orientation needed. The skill carries full engagement state from the prior session.

```
[BHV:7Q3X]
on=session_start
load=[profile, user-files, view, engagement]
gate=profile-active
fallback=prompt-activate
```

---

## Session end [BHV-K2NM]

Before ending any session, persist:

1. Current evidence state (all open items and their lifecycle positions)
2. Active frame token + work position
3. Unresolved items → pending queue

```
[BHV:K2NM]
on=session_end
persist=[evidence-state, active-frame, pending-queue]
rule=always-persist-before-close
```

---

## Frames [BHV-4DPY]

A frame is your working perspective on the engagement. Switch frames as your focus shifts. Only one frame is active at a time — no context debt from switching.

**Available frames**: see `FRAMES.md` for the full catalog.

Primary frames:

| Frame | Token | Use when |
|---|---|---|
| Manager | FRM-X8Q2 | Need the full picture — what's in flight, blocked, owners |
| Worker | FRM-M5R7 | Focused on a specific task — pull evidence + context for this item only |
| Role-define | FRM-K3PN | Defining or customizing a role |

To switch: `load frame Manager` / `switch to Worker view` / `activate [frame-name]`.

```
[BHV:4DPY]
on=frame-switch
action=unload-current,load-requested
rule=no-context-carry-between-frames
```

---

## Evidence [BHV-9F8R]

Evidence moves through a 6-state lifecycle. Full chain in `EVIDENCE-WORKFLOW.md`.

States: `intake` → `verification` → `classification` → `packaging` → `delivery` → `archived`

Transition commands: `intake <item>`, `verify <item>`, `classify <item>`, `package <item>`, `deliver <item>`, `archive <item>`.

The skill enforces the chain — you cannot skip states. HIGH-severity findings require manual verification before packaging (PT engagements).

```
[BHV:9F8R]
on=evidence-transition
chain=[intake,verification,classification,packaging,delivery,archived]
gate=sequential
enforce=HIGH-severity-manual-verify
```

---

## Engagements

### New engagement [BHV-2T6L]

Creates the full directory structure for a new engagement: plans, evidence slots, deliverable targets, AGENTS registry.

Command: `new engagement <name> [type: PT|audit|compliance]`

```
[BHV:2T6L]
on=engagement-init
create=[engagement-dir, plans/, evidence/, deliverables/, AGENTS.md, engagement-state.md]
index=yes
```

### Load engagement [BHV-W5HZ]

Hydrates context from an existing engagement.

Command: `load engagement <name>`

```
[BHV:W5HZ]
on=engagement-load
load=[engagement-state, active-plans, AGENTS, last-evidence]
view=current-engagement
```

---

## Cross-domain sync [BHV-G3JC]

Wire findings across engagement domains. A PT finding that maps to a compliance gap, a gap that surfaces as a PT target.

Connectors are declared in the engagement config. The skill maintains them as domains evolve — no manual cross-referencing.

```
[BHV:G3JC]
on=sync-connector-call
action=cross-reference-domains
sources=[PT, audit, compliance]
rule=operator-declared-connectors-only
```

---

## Role and org [BHV-Q8YN / BHV-3HVD]

**Role bind** [BHV-Q8YN]: Apply role-defined frame preferences and function restrictions.

```
[BHV:Q8YN]
on=role-bind
apply=[frame-preferences, function-restrictions]
source=profile.role
```

**Org info attach** [BHV-3HVD]: Load the org structure and workplan into the engagement context.

```
[BHV:3HVD]
on=org-attach
load=[org-tree, workplan]
scope=engagement-context
```

---

## Debug logger [BHV-B1XK]

When debug is set to on in your profile, the skill writes a log entry for each mark hit.

```
[BHV:B1XK]
on=mark-hit
condition=don-state=ON
emit=.debug/marks-<UTC>.log
format=<ISO8601-UTC> mark=<TOKEN> kind=<BHV|DIR|FRM|RLE> ctx=<tag> profile=<role> session=<id>
```

See `guides/debug-logger.md` for how to enable and how to submit logs.

---

## Embedded directives

Stable runtime identifiers governing skill behavior. Do not translate or expand these tokens.

```
[DIR:5MWX]
on=session_start,session_end
behavior=state-persist
rule=continue-not-restart
mode=many-parallel-allowed

[DIR:J4P2]
on=correction
behavior=clarify-forward
rule=keep-prior-work-as-record

[DIR:N7TQ]
on=output-compose
behavior=paraphrase
rule=no-verbatim-from-working-notes

[DIR:V8BG]
on=evidence-encounter
behavior=capture-low-threshold
rule=classify-later

[DIR:Y2KZ]
on=session-length
behavior=offload-to-disk
rule=shed-checkpoint-on-long-sessions

[DIR:H6FR]
on=external-evidence
behavior=filter-not-directive
rule=pause-on-flag-keywords
keywords=[we-should,lets,recommend,decision,actions]
```

---

## Scrub policy

This file and all files under `orca/` are subject to pre-commit scrub (`precommit-scrub --tg --orca`). Files that pass scrub carry no substrate vocabulary, no internal paths, no bearer identifiers. Opaque tokens (BHV-*, DIR-*, FRM-*, RLE-*) are intentional and scrub-safe.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
