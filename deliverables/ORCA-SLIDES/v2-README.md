<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

<!-- NAV-LEN: 0 entries | UNMRKD -->

# ORCa TechGuard Delivery Package — v2

> **SUPERSEDED 2026-05-14**: v0.95 release replaces these v2 slide artifacts. TG-facing surface is now `orca/tg-nav_hub/SKILL.md` + `orca/tg-nav_hub/NAV-BARE.md` (single skill + reading protocol). v2-* files retained as historical reference; install paths inside them refer to the old `nav-orc/skills/` layout which no longer exists.

**Author**: ERA
**Date**: 2026-04-27
**Status**: v2 — platform delivered; awaiting M1 kick-off

---

## What this package is

The v2 TechGuard delivery package covers:

1. The platform itself — nav-orc + pt-orc, installed and ready
2. The deployment + Entra integration scope (M1 + M3)
3. Supporting materials for Hari's review and approval

This is not a build-from-scratch proposal. The platform is built. This package is the delivery confirmation, architecture framing, and M1+M3 engagement scope.

---

## Package contents

### Primary deliverables

| File | Purpose |
|---|---|
| `v7-deck.pptx` | 20-slide delivery deck — send to Hari |
| `v2-email-hari.md` | Cover email — send with deck |
| `v2-delivery-proposal.md` | Full proposal for Hari + wider TG stakeholders |
| `v2-scope-500h.md` | M1 + M3 effort breakdown |
| `v2-speaker-notes.md` | Per-slide talking points + Q&A |
| `v2-dev-process.md` | Gated delivery process — how M1 + M3 run |
| `v2-docs-refresh-notes.md` | Post-M1 guide calibration notes |

### Platform (in `audit-orc/` repo)

- `nav-orc/skills/` — 7 nav-orc skills
- `pt-orc/skills/` — 7 pt-orc skills
- `pt-orc/scripts/` — 7 phase scripts (00_bootstrap → 06_report)
- `docs/` — 5 operator guides + README

### Methodology

- `docs/tg-unified-audit-methodology-v0.3.md` — 9-stage TG unified lifecycle + MethodologyPack architecture

---

## Key architecture points

**Restricted Framed Seats** replaces the v1 shared-AI-broker concept:
- Each analyst uses their own Claude seat
- `orc-seat-start.ps1` / `.sh` sets the seat frame at session start
- Three layers: org ceiling → seat frame → project perms
- Entra ID → seat auto-detection is M3

**nav-orc session continuity**:
- Cold project resumes in two file reads — beacon + NEXT document
- Warm-start under 10 seconds; works across sessions, weeks, team handovers

**DCPTCN_TG alignment**:
- EngagementCore + PentestPack (6 MethodologyPacks total) is the DCPTCN_TG planned architecture
- ORCa (nav-tools + PT-Orc) is the execution and methodology layer
- tg-audit-orchestrator is the planned orchestration layer above ORCa

---

## Two open decisions for Hari

1. **Repo ownership** — TechGuard org / joint / personal with TG admin access
2. **First engagement scope** — what does TG want to run first on ORCa?

Both are on slide 20 of `v7-deck.pptx`.

---

## Changelog from v1

| Item | v1 | v2 |
|---|---|---|
| Scope | 500h platform build | ~200–260h deploy + integrate |
| AI layer | Custom shared broker (P4, 100h) | Restricted Framed Seats (M3, 60–80h) |
| Access model | Sensitivity tags (public/sensitive/restricted) | Seat types (anonymous/analyst/senior/admin/restricted) |
| Platform state | To be built | Delivered |
| Methodology | TG methodology placeholder | v0.3 produced; MethodologyPack model aligned with DCPTCN_TG |
| Deck | v3 (22 slides) | v7 (20 slides) |
| Architecture decision | 4 options open | Framed seats primary; no open broker decision |

---

## How to send

1. `v7-deck.pptx` + `v2-email-hari.md` → send to Hari
2. `v2-delivery-proposal.md` → attach to email or send same day as "full proposal" follow-up
3. `v2-speaker-notes.md` → keep for the live walkthrough session
4. `v2-scope-500h.md` + `v2-dev-process.md` → send with proposal

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
