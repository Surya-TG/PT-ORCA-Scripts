<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

<!-- NAV-LEN: 0 entries | UNMRKD -->

# ORCa — TechGuard Delivery Scope (v2)

**Status**: nav-tools + PT-Orc suite delivered. This document covers the M1 deployment + M3 Entra integration scope.

**Not in scope**: Platform build (already complete). Custom shared-AI broker (architecture decision resolved — Restricted Framed Seats replaces broker).

---

## What changed from v1 scope

The v1 scope (500h) assumed building from scratch: platform packaging (200h), deployment (80h), sensitivity/access model (60h), shared-AI broker (100h), onboarding (60h).

The v2 scope is fundamentally different because the platform is **already built**:

| v1 assumption | v2 reality |
|---|---|
| Platform packaging needed (200h) | nav-tools + PT-Orc delivered, skills ready |
| Sensitivity-tag model needed (60h) | Restricted Framed Seats architecture implemented; seat wrapper scripts ship with skills |
| Custom shared-AI broker needed (100h) | **Removed** — framed seats + per-analyst Claude seats replaces broker; no custom infra |
| Onboarding from scratch (60h) | Operator guides written + in repo; M1 is deployment + first engagement, not fresh build |

**Net result**: v2 scope is ~200–260h (M1 + M3), not 500h. The platform build is complete; v2 is deployment, integration, and methodology calibration.

---

## Roll-up

| Milestone | Focus | Hours | Calendar |
|-----------|-------|------:|----------|
| M1 | Deployment + TG onboarding + first engagement | 100–120 | 3–4 wks |
| M2 | First engagement shadowing (optional — may fold into M1) | 40–60 | 1–2 wks |
| M3 | Entra group → seat auto-detection | 60–80 | 2–3 wks |
| **Total M1+M3** | | **200–260** | **~8 wks** |

Post M3: continuous consulting track (methodology, MethodologyPack development, tg-audit-orchestrator alignment).

---

## M1 — Deployment + TG onboarding + first engagement (100–120h)

**Goal**: TechGuard analysts running nav-orc + pt-orc on a real engagement. Skills installed, configured, seat wrapper scripts working, at least one analyst independently operational.

### M1.1 — Repo setup + skill install (15h)

- Repo ownership decision → set up TG-accessible branch or transfer as agreed
- Skills installed to TG analyst machines (nav-orc/skills/ + pt-orc/skills/)
- Seat wrapper script (`orc-seat-start.ps1` / `.sh`) configured for TG environment
- Smoke test: each analyst loads `/nav_ext`, creates a test project, verifies warm-start

### M1.2 — TG-specific configuration (15h)

- Seat assignment for each TG analyst (map analyst → seat type)
- Org ceiling configured for TG (what no seat can exceed)
- Project naming conventions adapted to TG engagement nomenclature
- `pt-orc.conf` scaffold with TG-specific defaults (report templates, evidence paths)

### M1.3 — First engagement together (40h)

- TG provides engagement scope; ERA and TG analyst run through it together on ORCa
- Full cycle: project create → recon → enum → evidence → report stub
- ERA observes, assists, captures friction points
- Same-session fixes where feasible; file-for-later on anything needing deeper work

### M1.4 — Calibration + guide updates (20h)

- Capture TG-specific workflow adjustments from M1.3
- Update/extend operator guides based on observed gaps (additions only — no overwrite of existing docs)
- Document TG engagement-naming convention, seat assignments, org ceiling
- Gate 1 brief: what was done, what was adjusted, what's open

### M1.5 — Buffer + Gate 1 (10h)

- Rework buffer
- Gate 1 review with Hari: walk through what's live

---

## M2 — Additional engagement shadowing (40–60h, optional)

**Goal**: second engagement run entirely by TG analyst; ERA shadows only.

May be folded into M1 if the first engagement is sufficient for analyst independence. Kept separate to allow scheduling flexibility.

- TG analyst self-selects a second engagement scope
- ERA monitors async (not live co-pilot)
- Final Q&A session after engagement closes
- Gate 2: analyst declares independent operational status

---

## M3 — Entra group → seat auto-detection (60–80h)

**Goal**: seat assignment derived automatically from M365 Entra group membership. Wrapper script no longer needed for seat setting; Entra group IS the seat frame.

### M3.1 — Entra group structure (10h)

- Define TG Entra group → seat type mapping (e.g. `tg-orca-analyst` → analyst seat, `tg-orca-senior` → senior seat)
- Confirm existing Entra group structure with TG IT; adjust if needed
- Design the lookup: session-start script reads Entra group membership → sets seat env var

### M3.2 — Session-start integration (25h)

- `orc-seat-entra.ps1` / `.sh` — wraps `az ad signed-in-user get-member-objects` or equivalent
- Maps Entra group GUIDs → seat type string
- Falls back to anonymous if group not found (safe default)
- Logs seat assignment to session audit entry
- Unit tests with mock group lookups

### M3.3 — Admin seat + org ceiling management (15h)

- Entra group for admin seat: who can assign/remove analysts from seat groups
- Org ceiling config: where it lives, how it's updated, who has write access
- Restricted seat ceiling: per-project override mechanism (for on-client-site deployments)

### M3.4 — Validation + rollout (10h)

- Integration test with TG analysts: each person logs in, seat is auto-detected correctly
- Verify org ceiling enforcement: senior seat can't exceed ceiling; restricted seat custom-ceiling works
- Audit log review: seat assignment entries visible + correct
- Gate 3: Hari reviews seat assignment table; sign-off that it matches team roles

---

## Effort flex

| Lever | Savings | Trade-off |
|---|---:|---|
| Skip M2 (analyst independent after M1.3) | 40–60h | Less shadowing buffer; acceptable if M1.3 is thorough |
| Skip M3.3 restricted-seat ceiling | ~10h | On-client-site deployments use manual wrapper; add later |
| TG IT handles Entra group setup (M3.1) | ~5h | Requires TG IT engagement early |
| **Minimum scope (M1 + M3 essentials)** | **~160h** | M2 skipped; M3.3 deferred |

---

## Payment + gate alignment

| Invoice | Trigger | % |
|---|---|---:|
| Mobilization | Repo + skills install confirmed | 20% |
| Gate 1 | First engagement complete; analyst operational | 40% |
| Gate 2 | Second engagement (if M2 in scope) | 15% |
| Gate 3 | Entra integration live; seat auto-detection verified | 25% |

Rates + terms per SOW. Hourly basis; over-gate work quoted separately.

---

## Post-M3: continuous consulting (separate track)

- Methodology evolution: additional MethodologyPacks (gap analysis, risk assessment, etc.)
- tg-audit-orchestrator alignment: as DCPTCN_TG builds EngagementCore, ERA aligns nav-tools integration
- Additional operator guides + training artefacts
- nav-tools version updates (nav_core → nav_core v2 features as they land)
- Entra Key Vault per-section encryption (parked; add when Entra integration is stable)

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
