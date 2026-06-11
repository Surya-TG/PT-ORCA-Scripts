<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Getting Started with ORCa / PT-Orc-Suite

**Skill:** First-session setup · **Version:** v1 · **Audience:** Operators new to ORCa / PT-Orc-Suite

---

## What is ORCa?

**ORCa** (Offensive Recon & Coordination assistant) is a suite of Claude skills for penetration testing and security assessments. It runs on the **NAV v1** system — a persistent, indexed session layer that keeps your work organized across multiple Claude sessions.

**PT-Orc-Suite** is the full package: ORCa skills + NAV system + project tracking + documentation templates.

---

## Prerequisites

Before your first session you need:

1. **Claude** — Claude.ai or Claude desktop with skills support enabled
2. **Skills installed** — the NAV v1 skill family (see below)
3. **A project repository** — a git repo for your engagement (can be an existing repo)

---

## Loading the skill

The v0.95 release consolidates the NAV skill family into a single hub skill.

1. Load `orca/tg-nav_hub/SKILL.md` as a system instruction in your Claude session — this is the engagement surface.
2. For navigating the platform specs section-by-section, also load `orca/tg-nav_hub/NAV-BARE.md` (the reading protocol).

Together these replace the older multi-skill `~/.claude/skills/` install. No copying into `~/.claude/skills/` is required.

---

## Starting your first session

### Step 1 — Load the skills

At the start of a Claude session, load the skills you need. For a typical engagement session:

```
/nav_project_proc
/nav_action_plan_proc
```

This activates project management and task tracking. The skills announce themselves with a status line.

For read-heavy work where you need full NAV navigation:

```
/nav_core
```

### Step 2 — Create your project

```
nav project: my-engagement
```

This creates:
- `.work/my-engagement/` — your project workspace (gitignored)
- `.work/my-engagement/my-engagement_NEXT.md` — the project's state document
- `.in/my-engagement_beacon.md` — a git-tracked pointer to your project
- `.gitignore` at project root — standard nav entries added automatically

See [NAV Project Workflow](nav-project-proc-guide.md) for the full guide.

### Step 3 — Log your first entry

```
nav project log: project created, starting recon phase
```

Every meaningful advance gets a log entry. This is your cross-session memory.

---

## Your second session

When you return to a project in a new session:

1. Load the same skills: `/nav_project_proc` `/nav_action_plan_proc`
2. The skill reads your beacons from `.in/` and surfaces your active projects
3. If auto-load is on, it warm-starts automatically; otherwise it prompts you to resume
4. You're back exactly where you left off

---

## Key concepts to know

### The NEXT document

Each project has a `_NEXT.md` file — the single source of truth for:
- What you're doing and why (STATUS_PROJECT)
- What phase you're in (STATUS_PLAN)
- What happened (STATUS_LOG)
- What to do next (STATUS_NEXT)

You never edit this directly — the skill manages it via `nav project log:`, `nav project offload`, etc.

### Session close

Before ending a session:

```
nav project offload     # write context snapshot
```

This ensures the next session can warm-start cleanly. See [NAV Project Workflow](nav-project-proc-guide.md#ending-a-session).

### TSK board

For tracking tactical tasks within a session:

```
tsk add: enumerate SMB shares
tsk list
tsk done: 1
```

See [Action Plan & Task Management](nav-action-plan-proc-guide.md) for the full guide.

---

## Quick-reference

| What you want to do | Command |
|---------------------|---------|
| Create a project | `nav project: <name>` |
| Check project status | `nav project <name>` |
| Log a progress note | `nav project log: <text>` |
| Add a task | `tsk add: <text>` |
| List tasks | `tsk list` |
| Checkpoint before exit | `nav project offload` |
| Finish a project | `nav project release` |
| Load full NAV navigation | `/nav_core` |

---

## Where to go next

- [NAV Project Workflow](nav-project-proc-guide.md) — full guide to project management
- [Action Plan & Task Management](nav-action-plan-proc-guide.md) — tasks, reminders, shortcuts
- [NAV v1 User Guide](nav-v1-user-guide.md) — reading NAV-indexed files
- [System Assessment v1](system-assessment-v1-initial.md) — AI operational review: strengths, gaps, and verdict for v1
- [nav_bare Orientation Workaround](nav-bare-orientation-workaround.md) — how to manually orient a fresh session (known v1 gap)

<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
