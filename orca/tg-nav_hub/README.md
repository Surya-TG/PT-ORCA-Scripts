<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# tg-nav_hub

The Orca platform skill for TechGuard. Provides session continuity, evidence lifecycle management, frame-based navigation, and engagement configuration for security consulting work.

## Files

| File | Purpose |
|---|---|
| `SKILL.md` | Skill definition — load this with Claude to activate the Orca platform |
| `PROFILE.md` | Your profile — activate here before using the skill |
| `FRAMES.md` | Frame catalog — Manager · Worker · Role-define · engagement frames |
| `EVIDENCE-WORKFLOW.md` | 6-state evidence lifecycle — intake through archived |

## Quick start

1. Open `PROFILE.md` — set `active: true` and fill in your role and org fields
2. Load `SKILL.md` into your Claude session
3. Say `load engagement <name>` to resume an existing engagement, or `new engagement <name>` to start one
4. The skill handles session state — no re-orientation needed at the start of each session

## Specs

| Spec | What it covers |
|---|---|
| `../specs/orca-platform-spec.md` | Platform overview — what Orca is and how it's structured |
| `../specs/endless-session-spec.md` | How session continuity works across multiple sessions |
| `../specs/evidence-lifecycle-spec.md` | Evidence chain in depth |
| `../specs/role-frames-spec.md` | Frame catalog and customization guide |
| `../specs/ip-marks-spec.md` | About the stable token identifiers in this skill |

## Guides

| Guide | When to use |
|---|---|
| `../guides/getting-started.md` | First engagement setup |
| `../guides/new-engagement.md` | Starting a new client engagement |
| `../guides/role-definition.md` | Defining custom roles for your team |
| `../guides/debug-logger.md` | Enabling and submitting debug logs |
| `../guides/troubleshooting.md` | Common issues |

## Version

`v0.1.0` — initial release · Orca platform · PT pack is the first capability pack (`../../pt-orc/`)

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
