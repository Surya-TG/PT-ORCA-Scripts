<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

<!-- NAV-LEN: 0 entries | UNMRKD -->

# Email to Hari — ORCa v1 delivery + deck

**To**: Hari [Technical Lead Manager, TechGuard India]
**From**: [sender]
**Subject**: ORCa — platform delivered, architecture confirmed, deck inside
**Date**: 2026-04-27

---

Hi Hari,

Following on from our conversations — ORCa v1 is delivered. I've put together a 20-slide deck that covers the platform, how nav-orc works, the access model, the PT-Orc suite, and where we go from here with TechGuard. I want to walk you through the key architecture decision before we start.

**What's live**

The delivery covers two suites:

- **nav-orc** (the platform layer) — 7 skills: navigation, project management, task tracking, session management, identity/access, commit pipeline, observability. Persistent projects across sessions and team members. Every indexed file navigable in two reads — the session model is proven.
- **pt-orc** (pentest execution) — 7 phases (bootstrap → recon → enum → scan → exploit → evidence → report), 7 companion AI skills, evidence hash + chain of custody. This is what your analysts run engagements with.
- **Operator guides** — getting started, nav-orc user guide, project workflow, task board, README. All in `docs/`.
- **TechGuard Unified Methodology** — I've produced the v0.3 draft of the 9-stage unified lifecycle, incorporating the EngagementCore and MethodologyPack architecture. More on that below.

Everything is in the `audit-orc` repo now. Skills install to `~/.claude/skills/` in one copy step.

**The access model — Restricted Framed Seats**

This is the architectural decision I want to confirm with you before we go further. Instead of a custom shared-AI broker (expensive, complex, fragile), the access model I'm proposing is what I'm calling **Restricted Framed Seats**:

- Each analyst uses their own Claude seat — no pooled broker, no VPN, no custom infra
- A seat frame is set at session start by a wrapper script (`orc-seat-start.ps1` / `.sh`) — this defines what the analyst can reach
- Three nested layers enforce access: **org ceiling** (what the org allows at all) → **seat frame** (what this seat type allows) → **project permissions** (what this engagement allows)
- Seat types: `anonymous` (local work, no client data) · `analyst` (standard engagement) · `senior` (evidence write + reporting) · `admin` (seat management + org config) · `restricted` (on-client-site with custom ceiling)
- **Entra ID integration** is the planned next step — auto-detect seat type from M365 group membership. No new infrastructure; it's your existing Entra. The wrapper script is the manual mechanism until then.

This is simpler, more reliable, and gives TechGuard better control than a custom broker. The wrapper script ships with the skills.

**Where the TechGuard methodology sits**

DCPTCN_TG (the architecture team) has finalized the expanded model:

- **EngagementCore** — shared planning kernel used by all engagement types (extracted from the red-team automation model we discussed)
- **PentestPack** — one of 6 **MethodologyPacks**, covering adversarial engagements (PT-Orc powers this)
- 6 MethodologyPacks total, one per TechGuard service type — standards/ISO 27001, PT, gap analysis, security assessment, risk assessment, remediation validation
- **tg-audit-orchestrator** — the planned orchestration layer that will tie all of this together

The v7 deck (slide 19) shows this architecture. The v0.3 methodology document covers the 9-stage lifecycle with the MethodologyPack layer.

**Two questions for you — slide 20 in the deck**

1. **Repo ownership**: currently in my personal GitHub (`ggerait/audit-orc`, private). Should this move to a TechGuard-owned org, a joint arrangement, or stay with ERA admin access granted to TG? This affects who controls the admin seat and the Entra integration path.

2. **First engagement scope**: what engagement do we run first together with ORCa on TG's side? Running the first session together is the fastest way to calibrate — real scope, real targets, real findings. This is the M1 deliverable that takes everything from "skills installed" to "team using it."

**Immediate scope — M1 and M3**

- **M1** (immediate): install, configure, first engagement together — analysts running nav-orc + pt-orc, first engagement on ORCa
- **M3**: Entra group → seat auto-detection — wraps your existing M365; no new infrastructure; delivery after M1 is stable

Deck is attached. 20 slides, ~25 min. Happy to walk through it live or answer on the deck directly.

What I need from you:
1. Repo ownership decision (or preferred model to discuss)
2. First engagement — tell me the scope and we start

Best,
[sender]

---

**Attachment**: `v7-deck.pptx` — ORCa platform · TechGuard delivery · 2026-04-27 (20 slides)

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
