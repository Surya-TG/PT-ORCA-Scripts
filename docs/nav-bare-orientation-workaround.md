<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# nav_bare Orientation Gap — Workaround Guide

**Affects:** First message of any new Claude session using NAV v1
**Severity:** Medium — session starts are slower; no data is lost
**Resolved by:** NAV_CORE delivery (pending)

---

## What the gap is

When you start a fresh Claude session, `nav_bare` is supposed to automatically orient itself:
find the workspace root, read `MAIN-INDEX.md`, and build a domain map before any file
navigation begins. This "session-start orientation" step is currently unfinished — the
placement of the orientation logic (per-file loop vs. session-start) is an open design
question (C1-C6 thread, to be resolved in `nav_core`).

**Practical effect:** In a fresh session, Claude may not know:
- Where the workspace root is (`/c/ccrd/` or wherever your repo lives)
- Which domains/projects exist
- Which `*-INDEX.md` file to start from

This makes the first navigation step uncertain. Claude will attempt to walk the directory
tree and find index files, but it may start from the wrong directory or ask for
clarification that should be automatic.

---

## Workaround: manual orientation at session start

After loading your skills, add one of the following to your first message.

### Option A — Point to workspace root (recommended)

```
Workspace root is /c/ccrd/. MAIN-INDEX is at /c/ccrd/MAIN-INDEX.md.
```

Claude will read `MAIN-INDEX.md` and build the domain map from there. Takes one read
call; all subsequent navigation works normally.

### Option B — Point directly to the project

If you know which project you're resuming:

```
Workspace root is /c/ccrd/. Resume project ORCA_DOCS — beacon at
audit-orc/.in/ORCA_DOCS_beacon.md.
```

Claude skips the domain scan and goes directly to the project beacon. Fastest path for
single-project sessions.

### Option C — Full context block (for complex sessions)

For multi-domain sessions or when starting from a non-standard working directory:

```
Workspace root: /c/ccrd/
MAIN-INDEX: /c/ccrd/MAIN-INDEX.md
Active domains: nav-tools, audit-orc, PT-Orc, AssureIQ-AI-Audit
Working in: audit-orc
Active project: ORCA_DOCS
```

---

## At-a-glance: recommended session-start message

Copy and adapt this template for your sessions:

```
/nav open project <your-project-name>

Workspace root is /c/ccrd/. MAIN-INDEX at /c/ccrd/MAIN-INDEX.md.
```

The `/nav` invocation loads the skill family; the second line gives Claude its footing
immediately. No additional prompting required.

---

## Signs the gap has bitten you

- Claude asks "What directory are we working in?" at session start
- Navigation begins from `~/.claude/skills/` instead of your workspace
- `[oriented: 0 domains found]` appears in the status line
- Claude reads a stale or wrong `*-INDEX.md`

If any of these occur, paste Option A or B above and Claude will re-orient in one step.

---

## When this will be fixed

This workaround is temporary. When `nav_core` delivers the resolved orientation logic,
session-start orientation will be automatic — no manual context line needed. The
`ORCA_RELEASE` project tracks this under `AAP-ORCA-*`; TechGuard will be notified when
the fix ships and this guide can be retired.

Until then: one extra line at session start is all that is needed.

---

*See also: [System Assessment v1](system-assessment-v1-initial.md) — `MRK:ASSESS_GAPS §2` for the full technical description of this gap.*

<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
