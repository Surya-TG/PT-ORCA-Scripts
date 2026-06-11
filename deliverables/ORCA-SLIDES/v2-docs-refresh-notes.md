<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

<!-- NAV-LEN: 0 entries | UNMRKD -->

# docs/ Refresh Notes — v2 (current state → TG delivery)

**Purpose**: notes for the next dev session on what updates to the `audit-orc/docs/` operator guides are needed post-M1 calibration.

**Current state**: 5 guides written and in `docs/`. These notes cover additions and calibration items surfaced by the M1 engagement (to be filled in after M1.3). Pre-M1 items noted where known.

---

## 1. Principles

- **Additive only**. Existing guides are complete and correct. No overwrites. Add TG-specific sections, callout boxes, or appendices.
- **NAV-indexed additions only**. Any new MRK anchor added must follow NAV:v1 placement rules. Run reindex after each doc change.
- **Don't rebrand**. nav-orc/pt-orc names stay. "TechGuard" context is a framing layer, not a replacement.

---

## 2. Known pre-M1 items

### `docs/getting-started.md`

- Add a note on the Entra seat integration path: "If your organization uses Entra ID, seat type auto-detection is available (M3). Until then, use `orc-seat-start.ps1` / `.sh` to set your seat type at session start."
- Add TechGuard-specific install note if repo is moved to TG org (update clone URL reference).

### `docs/nav-v1-user-guide.md`

- No changes needed pre-M1. This is the reference guide; it's format-complete.
- Post-M1: add a section on TG-specific file naming conventions if calibration surfaces them.

### `docs/nav-project-proc-guide.md`

- Add a note on TG engagement naming convention (to be defined in M1.2): e.g. `tg-<clientcode>-<type>-<YYYY>-<QN>`.
- After M1: add a "TG engagement lifecycle" appendix mapping the 9-stage methodology stages to nav project commands (beacon create → project log → offload cadence).

### `docs/nav-action-plan-proc-guide.md`

- No changes needed pre-M1.
- Post-M1: add a "TG standard task tags" section if TG wants canonical TSK prefixes (e.g. `[RECON]`, `[EVIDENCE]`, `[FINDING-F01]`).

### `docs/README.md`

- Add a "TechGuard deployment" section pointing to:
  - `v2-delivery-proposal.md` — full proposal
  - `docs/tg-unified-audit-methodology-v0.3.md` — methodology reference
  - Seat wrapper scripts location
- Update contact / repo ownership line once Gate 1 repo ownership decision is finalized.

---

## 3. New docs to create (post-M1)

These are triggered by M1.3 calibration findings — create only if needed:

| Doc | Trigger |
|---|---|
| `docs/tg-engagement-quick-ref.md` | If TG analysts need a TechGuard-specific cheat sheet beyond the generic guides |
| `docs/tg-seat-assignment.md` | If seat assignment complexity warrants a standalone reference (vs. a README section) |
| `docs/tg-evidence-workflow.md` | If pt-evidence + chain-of-custody needs a TG-specific walkthrough |
| `docs/deployment-guide.md` | Installing nav on a TG project from scratch — planned Phase 2 ORCA_DOCS item |

---

## 4. New docs to create (ORCA_DOCS Phase 2 — separate project)

These are in the ORCA_DOCS project backlog, not this scope:

- `docs/nav-profile-guide.md` — identity, seats, domain access, Entra auth
- `docs/skills-reference.md` — all skills quick-reference card
- `docs/deployment-guide.md` — installing nav on a TG project from scratch
- `docs/nav-rule-reference.md` — all NAV-RULE tokens with examples

---

## 5. Methodology doc calibration

`docs/tg-unified-audit-methodology-v0.3.md` — post-M1 additions:

- Fill `TG-CORE-CONTEXT` placeholder (§7 table): TechGuard team structure, engagement types in scope, client context scope
- Fill `TG-ANL-CHAIN` placeholder (§7 table): TechGuard analysis chain — how findings flow from evidence to assessment to report
- Both placeholders are marked in the v0.3 doc. Content comes from Hari / TG team lead input.

---

## 6. What NOT to change

- nav-orc/pt-orc spec files — untouched
- NAV:v1 format, MRK placement rules — untouched
- Skill semantics — untouched
- Pre-existing MRK anchors in any doc — no renames, no moves

---

## 7. Priority order (post-M1.3)

1. `README.md` TechGuard deployment section — 20 min, add only
2. `getting-started.md` Entra/seat note — 10 min
3. `nav-project-proc-guide.md` engagement naming appendix — 30 min (requires M1.2 naming convention)
4. `tg-unified-audit-methodology-v0.3.md` placeholder fill — requires Hari / TG lead input; schedule as part of Gate 1 review

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
