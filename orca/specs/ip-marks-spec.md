<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Orca — IP-Marks Specification

**Version**: v0.95 (release candidate)
**Status**: v0.95 release candidate
**Audience**: Orca platform users (managers + roles defined by managers)

This document explains the **mark system** used throughout the Orca platform — what marks are, how to read them when you see them, and how to use the optional debug logger to give the Orca team feedback on how the platform performs in your engagements.

## What marks are

Throughout the Orca skill, specs, and runtime, you will see short identifiers like:

- `BHV-7Q3X`
- `DIR-5MWX`
- `FRM-X8Q2`

These are **stable opaque identifiers** for behaviors, directives, and frames inside the platform. They are part of Orca's internal vocabulary — each one names a specific platform-side action or configuration block that the skill performs or applies on your behalf.

**Three rules**:

1. **Do not translate marks.** Marks are stable identifiers — they will not change between releases. Translating them to human-readable names would couple your usage to internal naming and break forward-compatibility.
2. **Do not invent new marks of your own prefixes.** If you need a custom token for a role you define, use the `RLE-` prefix — the platform issues these for you automatically when you save a new role.
3. **Treat marks as you would API identifiers**: opaque, stable, version-safe.

## Why marks are opaque

The Orca platform internalizes a substantial amount of consulting-domain knowledge — evidence lifecycle, role-based viewing, engagement-context management, cross-domain syncing. The marks reference that internalized knowledge.

Keeping marks opaque means:

- Your engagement files don't carry our internal vocabulary — they stay clean and professional
- The skill's behavior is stable across versions; we can refine the internals without breaking your usage
- Your shipped deliverables to clients show no traces of platform internals

If you're curious what a specific mark does at runtime, the answer is always: **the action the skill takes when it encounters that mark in your active frame**. The mark is the identifier; the action is whatever the skill is doing in that moment.

## Mark families

| Prefix | Family | What you'll see it in |
|---|---|---|
| `BHV-` | Behavior — a runtime action the skill performs | SKILL.md, FRAMES.md (action lists), debug logs |
| `DIR-` | Directive — a configuration block the skill applies | SKILL.md (load-time directives), engagement config files |
| `FRM-` | Frame — a viewport you load to focus your work | FRAMES.md, your `.frame` config, role-binding |
| `RLE-` | Role — issued by you when you define a new role for your team | your role definitions, profile bindings |

## The debug logger

Orca ships with an optional debug-logger that, when enabled, records each mark the skill encounters during your sessions. The log is **local to your machine** — Orca does not phone home. You choose when to share the log with the Orca team for fine-tuning feedback.

### Why this exists

The Orca platform is still being refined for the kinds of engagements consultants actually run. When you enable the debug logger, you give the Orca team telemetry on:

- Which behaviors are load-bearing in your real work
- Which frames you actually load (vs. ones in the catalog that nobody uses)
- Mark-sequence patterns that reveal workflow gaps or rough edges
- Failures (marks that fire and immediately retry — usually a discipline-gate hit that needs softening)

### How to enable

In your profile (`PROFILE.md` or your profile config), set:

```yaml
debug: on
```

That's it. The next session you open will start emitting log lines to `.debug/marks-<UTC>.log` in your working directory.

To turn it off:

```yaml
debug: off
```

(Default is OFF — you opt in.)

### What gets logged

Each log line is structured:

```
<UTC-timestamp> mark=<TOKEN> kind=<BHV|DIR|FRM|RLE> ctx=<context-tag> profile=<role-token> session=<short-id>
```

Example:

```
2026-05-14T14:23:01Z mark=BHV-7Q3X kind=BHV ctx=engagement-pickup profile=FRM-X8Q2 session=A3F2
2026-05-14T14:25:10Z mark=BHV-4DPY kind=BHV ctx=frame-load profile=FRM-X8Q2 session=A3F2 frame_to=FRM-W2HG
```

**What's NOT logged**:
- File contents (evidence, findings, client data)
- Your reasoning, drafts, or working notes
- Client names beyond what you've explicitly entered into the engagement config
- Any token expansion or translation (logs stay in opaque-token form)

The log captures **shape of usage**, not substance of work.

### How to share with the Orca team

When you're ready to share:

1. Stop the active session (or wait until end of day)
2. Zip the `.debug/` directory: `zip -r debug-<YYYYMMDD>.zip .debug/`
3. Send via the channel your Orca contact provides

The Orca team decodes the log internally and returns feedback (new behaviors, frame additions, discipline refinements) via skill updates.

### Privacy note

The log is local until you ship it. Inspect it any time before sharing — `cat .debug/marks-*.log`. If you see anything you don't want to share, simply don't ship those lines.

## Custom-role marks (RLE-*)

When you define a new role for your team via the role-definition template (`FRM-K3PN`), the skill issues a fresh `RLE-XXXX` token. These tokens are unique to your installation; they don't collide with anyone else's roles.

The mapping from `RLE-XXXX` → human-readable role name lives in your `PROFILE.md` (your side). The Orca platform doesn't read or store role-name mappings — only the `RLE-XXXX` identifier itself.

Example `PROFILE.md` snippet:

```yaml
roles:
  RLE-7M2N: "Senior Auditor"
  RLE-3KQP: "Compliance Lead"
  RLE-9XVB: "PT Operator"
```

You manage role names on your side; the platform manages the binding via the token.

## Compatibility commitment

Marks are **stable across versions**. A `BHV-` or `DIR-` or `FRM-` token issued in v0.1 will mean the same action in v0.5, v1.0, v2.0. Deprecation is explicit — a deprecated mark gets a `replaced-by:` annotation in the release notes; the old mark continues to work as a thin wrapper.

This means your `.frame` configurations, profile bindings, and any place you've referenced a mark in your engagement files will continue to work across upgrades.

## What if I see an unknown mark?

If the skill or a spec references a mark you haven't seen before:

- Don't try to look it up by guessing — there's no public lookup
- The skill knows what it does; the action will be observable in the session (a file loaded, a state changed)
- If the action seems wrong or surprising, that's worth a note in your debug log — ship it to us with a brief note and we'll investigate

— Orca platform team

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
