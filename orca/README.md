<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Orca Platform

Orca is a structured engagement management platform for security consulting. It provides persistent session state, evidence lifecycle tracking, role-based navigation, and a pack-based capability model.

## What Orca provides

- **Persistent sessions**: pick up any engagement exactly where the last session ended — no re-orientation
- **Evidence lifecycle**: every finding, control test result, and document tracked from intake through delivery
- **Role-based frames**: switch between Manager (full picture) and Worker (focused task) views in one command
- **Engagement configuration**: map, flows, rules, and domain wiring per engagement type
- **Pack extensibility**: add capability domains (PT, audit, compliance) as packs on a shared platform core

## Structure

```
orca/
├── README.md                  this file — platform overview
├── tg-nav_hub/                the Orca skill (load into Claude)
│   ├── SKILL.md
│   ├── FRAMES.md
│   ├── PROFILE.md
│   └── EVIDENCE-WORKFLOW.md
├── specs/                     platform specs (Hari-facing)
│   ├── orca-platform-spec.md
│   ├── endless-session-spec.md
│   ├── evidence-lifecycle-spec.md
│   ├── role-frames-spec.md
│   └── ip-marks-spec.md
├── guides/                    operational guides
│   ├── getting-started.md
│   ├── new-engagement.md
│   ├── role-definition.md
│   ├── debug-logger.md
│   └── troubleshooting.md
└── packs/                     pack catalog
    ├── README.md
    └── pt-pack/               penetration testing pack (wraps pt-orc/)
        └── manifest.md
```

## Packs

| Pack | Directory | What it does |
|---|---|---|
| **PT pack** | `../pt-orc/` | Penetration testing phase automation — recon · enum · exploit · service verification · reporting |

More packs are planned. Each pack inherits the platform core and adds a capability domain.

## Getting started

See `guides/getting-started.md`.

Load `tg-nav_hub/SKILL.md` into your Claude session. Activate your profile in `tg-nav_hub/PROFILE.md`. That's it — the platform manages session state from there.

<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
