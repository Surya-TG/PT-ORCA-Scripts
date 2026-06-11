<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# NAV Action Plan & Task Management Guide

**Skill:** `/nav_action_plan_proc` · **Version:** v1 · **Audience:** Operators using ORCa / PT-Orc-Suite

---

## What does nav_action_plan_proc do?

`/nav_action_plan_proc` is the persistent work-tracking layer. It manages:

- **TSK board** — structured task list (per-session and cross-session)
- **Session notes** — written at session close, archived in `.in/`
- **Reminders** — due-date and weekly recurring reminders
- **Custom commands** — user-defined shorthand commands
- **Shortcuts** — two/three-letter triggers that expand to full commands
- **AAP pipeline** — capturing → promoting → releasing action-plan items
- **Metrics** — session statistics (bytes read/written, misses, hits)
- **Status line** — the session header showing seat, project, and counters

Data lives in `.profile/` directories — not in NEXT docs. It persists across sessions and across projects.

---

## Data locations

| Scope | Path | Contents |
|-------|------|----------|
| User-global | `~/.claude/.profile/` | Cross-session metrics, global commands, global reminders, global shortcuts |
| Project-level | `<project>/.profile/` | Project tasks, project reminders, project shortcuts (override globals) |

Project-level overrides user-global for any overlapping key.

---

## TSK board — structured tasks

The TSK board is a lightweight task tracker. Unlike action-plan items (AP-N), TSK items are session-local or project-scoped — they don't go into the global action plan unless promoted.

### Creating and managing tasks

```
tsk add: <description>              # add a task
tsk add: <description> due:<date>   # with due date
tsk done: <N>                       # mark task N complete
tsk drop: <N>                       # drop task N
tsk list                            # show open tasks
tsk list all                        # show open + completed
```

### Task format

```
TSK-001  [ ] Set up recon environment          due:2026-05-01
TSK-002  [ ] DNS enumeration — TechGuard scope
TSK-003  [x] Install skills (completed)
```

Tasks live in `<project>/.profile/tasks.md`. The status line shows open task count.

### Promoting to action plan

When a TSK item reveals a systemic issue worth tracking globally:

```
tsk promote: <N>
```

This moves it into the AAP pipeline (see below) for eventual promotion to `planning/action-plan.md`.

---

## Session notes

Session notes capture what happened during a session — observations, ORC NAV leads, ABO blocks, and decisions.

### Written automatically

At session close, the skill writes `.in/SESSION-<project>_<ts>.md` with:
- ORC NAV: leads flagged during the session
- ABO blocks encountered
- Key decisions made
- Files touched

### Manual capture

```
note: <observation>     # capture an observation mid-session
```

Appears in the session notes at close.

---

## Reminders

Reminders fire at session start. Two types:

### Due-date reminders

```
remind: <text> due:<YYYY-MM-DD>
```

Fires on the due date and every session after until dismissed.

### Weekly recurring

```
remind: <text> weekly:<mon|tue|wed|thu|fri>
```

Fires every occurrence of that day.

### Managing reminders

```
remind list          # show all active reminders
remind done: <N>     # dismiss reminder N
remind drop: <N>     # delete reminder N permanently
```

Reminders live in `<project>/.profile/reminders.md` (project) or `~/.claude/.profile/orc-reminders.md` (global).

---

## Custom commands

Define your own commands that expand to full sequences:

```
cmd define: <name> → <expansion>
cmd list
cmd drop: <name>
```

**Example:**

```
cmd define: recon-start → nav project log: started recon; tsk add: DNS enum; tsk add: host discovery
```

Then just type `recon-start` to trigger the whole sequence.

Global commands live in `~/.claude/.profile/orc-commands.md`. Project commands in `<project>/.profile/`.

---

## Shortcuts

Shortcuts are two or three-letter triggers for frequently used commands. They expand silently.

### Built-in shortcuts

| Shortcut | Expands to |
|----------|-----------|
| `sas` | session start summary |
| `ps` | project status |
| `nl` | nav project log: |
| `no` | nav project offload |

### Defining your own

```
shortcut define: <trigger> → <expansion>
shortcut list
shortcut drop: <trigger>
```

**Example:**

```
shortcut define: rr → nav project release
```

Shortcuts live in `<project>/.profile/shortcuts.md` (project) or `~/.claude/.profile/shortcuts.md` (global). Project shortcuts override globals.

---

## AAP pipeline — action-plan items

The AAP (action-plan) pipeline is how you capture issues during a project and promote them to the global action plan at release time.

### The pipeline

```
Capture (AAP-<PREFIX>-NN)  →  Promote (AP-NN)  →  Release
       ↓                              ↓                 ↓
  STATUS_AAP in NEXT        planning/action-plan.md   on project release
```

### Capturing during a project

When you notice an issue worth tracking:

```
aap: <description>
```

This writes an `AAP-<PROJECT>-NN` item into `STATUS_AAP` in the NEXT doc. It stays there, held, until release.

**Example:**

```
aap: reindex tool doesn't preserve NAV-RULE lines — needs 3-line guard in migrate_file()
```

Creates: `AAP-MYPROJECT-1 — reindex tool NAV-RULE preservation`

### Reviewing before release

```
aap list          # show all captured items
aap drop: <N>     # discard if not worth promoting
aap edit: <N>     # refine before promotion
```

### Releasing — promotion to global action plan

On `nav project release`, all items in STATUS_AAP are:

1. Reviewed (you confirm each one)
2. Assigned a global `AP-NN` ID
3. Appended to `planning/action-plan.md:MRK:AP_INPROG` in the same commit as the deliverables

Items you drop at review time are discarded — they don't go to the action plan.

---

## Session metrics

The skill tracks per-session statistics:

| Metric | What it counts |
|--------|---------------|
| Bytes read | Total bytes read from files (R metric) |
| Bytes written | Total bytes written to files (W metric) |
| Lines saved | Lines not re-read due to cache hits (S metric) |
| Hits | Successful anchor lookups |
| Misses | Failed lookups (search-miss, anchor-miss, content-gap, cross-file-miss) |

Metrics append to `.profile/session-log.md` at session close. A rolling summary updates `~/.claude/.profile/orc-profile.md`.

---

## Status line

The status line appears at session start and on demand:

```
seat:anonymous · project:MY-PROJECT · tasks:3 open · reminders:1 due · AP:5 in-flight
```

Trigger manually:

```
profile status
```

When Entra auth is enabled, shows: `seat:analyst · user:g.gerait`.

---

## Command quick-reference

| Category | Command | Action |
|----------|---------|--------|
| Tasks | `tsk add: <text>` | Add task |
| | `tsk done: <N>` | Complete task |
| | `tsk list` | Show open tasks |
| | `tsk promote: <N>` | Send to AAP pipeline |
| Reminders | `remind: <text> due:<date>` | Due-date reminder |
| | `remind: <text> weekly:<day>` | Weekly reminder |
| | `remind list` | Show all |
| | `remind done: <N>` | Dismiss |
| Commands | `cmd define: <n> → <exp>` | Define command |
| | `cmd list` | Show all |
| Shortcuts | `shortcut define: <t> → <exp>` | Define shortcut |
| | `shortcut list` | Show all |
| AAP | `aap: <text>` | Capture item |
| | `aap list` | Review items |
| | `aap drop: <N>` | Discard item |
| Metrics | `profile status` | Show status line |
| Notes | `note: <text>` | Capture mid-session observation |

---

## Relationship with nav_project_proc

These two skills are paired and complementary:

| Concern | nav_project_proc | nav_action_plan_proc |
|---------|-----------------|---------------------|
| Project state (plan, log, ctx) | ✓ | — |
| Inbox / messages | ✓ | — |
| Session close (artifacts, commit) | ✓ | — |
| Tasks (TSK board) | — | ✓ |
| Reminders | — | ✓ |
| Shortcuts / commands | — | ✓ |
| AAP capture + release | Holds in STATUS_AAP | Promotes to action-plan |
| Metrics | — | ✓ |

They are loaded independently — `nav_project_proc` for project lifecycle, `nav_action_plan_proc` for task tracking. Often both are active in the same session.

<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
