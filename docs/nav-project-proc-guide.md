<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# NAV Project Workflow Guide

**Skill:** `/nav_project_proc` · **Version:** v1 · **Audience:** Operators using ORCa / PT-Orc-Suite

---

## What is a nav project?

A **nav project** is a named, persistent work surface that survives across sessions. It gives you:

- A **workspace directory** (`.work/<name>/`) for drafts, materials, and context
- A **NEXT document** — the single source of truth for the project's plan, log, and state
- A **beacon** (`.in/<name>_beacon.md`) — a lightweight git-tracked pointer that surfaces the project at every session start
- An **inbox** for receiving messages and materials from other projects
- **Automatic context reload** — warm-start every session exactly where you left off

Projects are designed for work that spans multiple sessions — an engagement, a spec, a delivery, a skill improvement stream.

---

## Quick start

```
nav project: my-engagement    # create project
nav project my-engagement     # check status
nav project log: started recon phase
nav project offload           # checkpoint before ending session
nav project close             # when done
```

---

## Creating a project

```
nav project: <name>
```

What gets created:

```
.work/<name>/
    <name>_NEXT.md        ← the project NEXT document (full state)
    readme.md             ← auto-generated project readme
    debug/                ← debug observations go here
    inbox/                ← incoming messages and file attachments
        .processed/       ← acknowledged items (permanent record)
    .nav-handover/        ← handover documents (populated by nav project handover:)
    ctx_notes.md          ← context snapshot (written on offload / NLC)

.in/<name>_beacon.md      ← beacon (git-tracked pointer)
```

Also: a `.gitignore` is created at the project root if absent, with standard nav entries (`.work/`, `.profile/`, `.backup/`, `.claude/`, etc.).

If `.work/<name>/` already exists, you get a choice: **(o) overwrite · (a) abort · (r) resume**.

---

## The NEXT document

The NEXT document is the heart of a nav project. It has 8 fixed sections:

| Section | What it contains |
|---------|-----------------|
| `STATUS_PROJECT` | Slug, goal, started date, auto-load setting, parent project |
| `STATUS_MATERIALS` | Source files, workspace contents, planned outputs |
| `STATUS_PLAN` | Execution phases — mark `[DONE]` / `[IN PROGRESS]` / `[PENDING]` |
| `STATUS_LOG` | Append-only progress log — one line per advance |
| `STATUS_AAP` | Action-plan items captured during this project (held until release) |
| `STATUS_NEXT` | Immediate next step + release condition |
| `STATUS_PERMS` | Bash allow-list and file edit scope for this project |
| `STATUS_LOAD` | Ordered pre-load list for the next session |

The NEXT doc is **gitignored** (lives in `.work/`). It never commits — the beacon and `.in/` artifacts are the committed trail.

---

## Commands reference

### Creating and inspecting

| Command | What it does |
|---------|-------------|
| `nav project: <name>` | Create project — workspace + NEXT + beacon + .gitignore |
| `nav project <name>` | Inspect — current phase + last 2 log entries + inbox count |
| `nav project list` | List all active projects from beacons in `.in/` |

### Logging and checkpointing

| Command | What it does |
|---------|-------------|
| `nav project log: <note>` | Append one entry to STATUS_LOG; flush NEXT to disk |
| `nav project offload` | Write ctx_notes + flush NEXT + clear session-lock; append log entry |

Use `offload` before ending a session — it writes the context snapshot so the next session can warm-start.

### Lifecycle

| Command | What it does |
|---------|-------------|
| `nav project release` | Publish deliverables + push AAP items to action-plan + commit |
| `nav project handover: <target>` | Write handover doc and deliver it to target project's inbox |
| `nav project close` | Commit sweep → archive NEXT + beacon → terminal operation |
| `nav project pause` | Set status paused; suppressed from active listing |
| `nav project resume` | Restore paused project to active |
| `nav project rename: <new>` | Rename workspace + beacon + all internal refs |

---

## Session lifecycle

### Starting a session

When you load `/nav_project_proc` at session start, it reads every `*_beacon.md` in `.in/` and:

1. Checks `session-lock:` — warns if another session has the project open
2. Surfaces unread inbox count
3. If `auto-load: true` — silently loads STATUS_LOG tail + ctx_notes + STATUS_LOAD entries
4. If `auto-load: false` — shows slug + last 2 log entries → `(r) resume | (s) skip | (l) list all`

You can toggle auto-load per project:

```
nav project autoload on    # silently warm-start next session
nav project autoload off   # prompt each time
```

### Ending a session

Session close (triggered by `wrap`, `nav close`, or `profile close`) runs:

1. **Checkpoint** — prompts if uncommitted work exists or open items are unresolved
2. **Session artifacts** — writes session notes, gap report, debug ledger to `.in/`
3. **Commit uncommitted work** — sweeps all uncommitted tracked changes in repo
4. **Clear session-lock** — releases the lock in the beacon

Always run `nav project offload` before closing if you want the next session to warm-start cleanly.

---

## The beacon

The beacon (`.in/<name>_beacon.md`) is the publicly visible project card. It's git-tracked so other projects and sessions can find it. Key fields:

```yaml
NEXT: .work/<name>/<name>_NEXT.md
STATUS: active | paused | released | closed
session-lock: 2026-04-27T10:00:00Z  (or —)
inbox: 0 unread
deliverables: (path when released)
parent: <parent-slug> | —
```

**Session-lock** prevents two sessions from writing to the same project simultaneously. If you see a lock warning, either the prior session didn't clean up or another session is genuinely active.

---

## Context snapshots (ctx_notes)

`ctx_notes.md` is your cross-session memory. It has 5 sections:

| Section | Contents |
|---------|----------|
| `CTX_STATE` | One-line summary of where you are |
| `CTX_DECISIONS` | Decisions locked this session |
| `CTX_QUESTIONS` | Unresolved questions to revisit |
| `CTX_FILES` | Files touched this session |
| `CTX_NEXT` | One-line action to resume from |

Written on: `nav project offload` (manual) or automatically when context is running low (NLC threshold).

Read on: session start when `auto-load: on`, or on `(r) resume`.

---

## Inbox and messages

Your project has an inbox for receiving files and messages from other projects:

```
inbox/                     ← all incoming land here
    .processed/            ← after you've read and acted on them
```

To send a message to another project:

```
nav msg <target>: <body>
```

This writes to `.work/<target>/inbox/` and sets an `[UNREAD]` marker in the target's beacon.

When you receive a message, it shows up as "N unread" in the beacon. Read it, then `ack` to move it to `.processed/`.

---

## Handover and close

### Handing off to another project

```
nav project handover: <target>
```

Writes a handover document (summary, deliverables, open items, recommendations) and delivers it to the target's inbox. The source project can continue, pause, or close after handover — it's a delivery event, not a terminal one.

### Closing a project

```
nav project close
```

Before closing, the skill:

1. **Commit sweep** — commits any uncommitted tracked work
2. Checks for unresolved traces and undelivered handovers
3. Archives NEXT → `.done/<name>_NEXT_<ts>.md` (git-tracked permanent record)
4. Archives beacon → `.done/<name>_beacon_<ts>.md`
5. Removes the live beacon from `.in/`
6. Updates NAV-MAIN-INDEX to `status: closed`
7. Final commit

The `.work/<name>/` directory remains locally (gitignored) — available for reference until you delete it manually.

---

## Project phases and plans

Structure your STATUS_PLAN with named phases:

```markdown
- [DONE] **Phase 1 — Recon**
  - [x] DNS enumeration
  - [x] Host discovery

- [IN PROGRESS] **Phase 2 — Enumeration**
  - [x] SMB shares
  - [ ] Web services
  - [ ] Database ports

- [PENDING] **Phase 3 — Reporting**
```

Mark phases done:

```
nav project plan: Phase 2 done
```

---

## Best practices

- **One project per engagement or stream** — don't create sub-projects for every task; use STATUS_PLAN phases instead
- **Log every meaningful advance** — `nav project log:` is your session memory
- **Offload before closing** — always run `offload` so ctx_notes is current
- **Use auto-load for long-running projects** — saves time on every session start
- **Route incoming materials to inbox** — never paste directly into NEXT; use inbox/ so there's a trail
- **Close cleanly** — don't just stop; `close` archives the record properly

<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
