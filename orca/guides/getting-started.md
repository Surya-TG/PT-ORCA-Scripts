<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Getting Started with Orca

## Prerequisites

- Access to a Claude session
- The `tg-nav_hub` skill files (this `orca/` directory)

## Step 1 — Activate your profile

Open `tg-nav_hub/PROFILE.md`.

Set:
```yaml
active: true
role:
  token: "FRM-X8Q2"     # Manager frame (default for Hari)
  label: "Lead Consultant"
org:
  name: "TechGuard"
```

Save the file.

## Step 2 — Load the skill

In your Claude session, load `tg-nav_hub/SKILL.md`. You can paste the content or reference the file path depending on your Claude setup.

The skill will confirm your profile is active and wait for your first command.

## Step 3 — Start or load an engagement

**New engagement**:
```
new engagement <client-name> type: PT
```
(or `type: audit` / `type: compliance`)

**Existing engagement**:
```
load engagement <client-name>
```

## Step 4 — Pick a frame

You're now in `Manager` frame by default. To shift focus:
- `switch to Worker view` — when working on a specific task
- `load frame Gap assessment` — when doing a compliance pass

## Step 5 — Work

The platform tracks your evidence and session state automatically. At the end of each session, the skill persists your state — next session picks up here.

---

## Quick reference

| Want to | Command |
|---|---|
| Check engagement status | `load frame Manager` |
| Work on a specific finding | `switch to Worker view` then describe the item |
| Record new evidence | `intake <description>` |
| Move evidence forward | `verify <item>` / `classify <item>` / `package <item>` |
| Switch engagement | `load engagement <name>` |
| Create a new role | `activate Role-define` |
| Enable debug logging | Set `debug.state: on` in PROFILE.md |

## Next steps

- `new-engagement.md` — full engagement setup walkthrough
- `role-definition.md` — defining roles for your team
- `../specs/endless-session-spec.md` — how session continuity works

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
