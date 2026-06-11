<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ./AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Orca — getting started

---

## What this is

Orca is a platform that runs inside your AI session (Claude). It keeps track of where you are in long consulting engagements — instead of re-explaining context each session, Orca picks up exactly where the last session ended.

The **PT pack** wraps penetration testing work onto this platform: recon, enumeration, exploitation, service verification, and reporting — all logged with supporting evidence, tied to the engagement plan.

---

## The slides

You received two presentation decks separately (exec proposal + technical overview). Read those first — they frame what this package is for and what decisions are being asked.

---

## How to start

**1 — Load the skill**

Open `orca/tg-nav_hub/SKILL.md` and load it into your Claude session as a system instruction. The skill manages session state from that point forward.

**2 — Activate your profile**

Open `orca/tg-nav_hub/PROFILE.md` and follow the activation steps. This sets your role and default configuration.

**3 — Read the platform overview**

`orca/README.md` — platform shape and structure in two minutes.

**4 — Start an engagement**

Follow `orca/guides/new-engagement.md`. It walks through creating your first engagement, loading context, and attaching your org structure.

**5 — Navigate large files**

When working through a spec or guide, `orca/tg-nav_hub/NAV-BARE.md` helps you navigate to the section you need without reading the whole file.

<!-- L2 NAV:v1 → ./AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
