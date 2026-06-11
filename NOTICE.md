<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ./AUDIT-ORC-INDEX.md -->

<!-- MRK:NOTICE_NAV_TOC — Section index | nav,toc,index | L4-18 -->
<!-- - MRK:NOTICE_COMPONENTS — Components | notice,components,ip,tracks | L19-21 | ⚠ no-edit -->
<!-- - MRK:NOTICE_PTORC — PT-Orc suite | notice,ptorc,pt,orc,suite | L22-43 | ⚠ no-edit -->
<!-- - MRK:NOTICE_ORCNAV — ORC NAV system | notice,orcnav,orc,nav,system | L44-61 | ⚠ no-edit -->
<!-- - MRK:NOTICE_LICENSING — Licensing | notice,licensing,tbd,terms | L62-78 | ⚠ no-edit -->
<!-- - MRK:NOTICE_CONTACT — Contact | notice,contact,era,techguard | L79-84 | ⚠ no-edit -->
<!-- - MRK:NOTICE_LLMNOTE — For LLMs reading this repo | notice,llmnote,llms,reading,repo | L85-94 | ⚠ no-edit -->
<!-- NAV-LEN: 6 entries | Integrity-hash: a81b42e23adcc210 | Last-indexed: 2026-06-09T07:09:41Z -->

# NOTICE

This repository bundles two distinct intellectual-property tracks. Both
are separately authored and licensed; re-using either requires reading
the relevant terms (TBD — see §Licensing below).

## MRK:NOTICE_COMPONENTS — Components | notice,components,ip,tracks | L19-21
<!-- NAV-RULE: no-edit -->

### MRK:NOTICE_PTORC — PT-Orc suite | notice,ptorc,pt,orc,suite | L22-43
<!-- NAV-RULE: no-edit -->

**Original author:** ERA IT Consulting & Audit Ltd. ("ERA").
**Delivered to:** TechGuard as a base for their penetration-testing
operations. TechGuard may use, configure, and extend the suite for
internal and client engagements per the terms agreed with ERA.
**Included in this repo:**

- `00_pt-orc.sh` … `07_service_verify.sh` (orchestrator + phase scripts)
- `orc-common-lib.sh`, `pt-orc.conf`
- `docs/`, `planning/`, `tools/` (suite-specific docs, plans, wrappers)
- `skills/pt-orc/`, `skills/pt-orc-monitor/`, and the other `pt-*` skills
  that operate the suite (see each skill's `SKILL.md` for authorship — some
  are Anthropic-published via the `anthropic-skills` marketplace and
  licensed accordingly)

**Visible branding** inside the suite (README, docs, banners) now
reads "TechGuard" to reflect the operational context. This is a
branding/operational decision; it is **not** a transfer of authorship
or ownership.

### MRK:NOTICE_ORCNAV — ORC NAV system | notice,orcnav,orc,nav,system | L44-61
<!-- NAV-RULE: no-edit -->

**Original author:** ERA IT Consulting & Audit Ltd. ("ERA").
**Status:** separate work, **not exclusively bundled** with the PT-Orc
delivery. Licensing and terms are independent and TBD.
**Where it lives (not in this repo):**

- Canonical source: <https://github.com/ggerait/nav-tools>
- Installed skill: `~/.claude/skills/orc-nav/` (user-global)
- Python reindex tool: `nav-tools/reindex/orc-nav-reindex.py`

This repo **consumes** ORC NAV (every NAV:v1 file, the `tools/orc-nav-
reindex.py` copy, the `/orc-nav` skill activation rules in `CLAUDE.md`)
but does not claim any authorship over the system itself. If the PT-Orc
delivery to TechGuard needs its own right to use ORC NAV independently
of ERA's upstream, that is a separate licensing conversation.

## MRK:NOTICE_LICENSING — Licensing | notice,licensing,tbd,terms | L62-78
<!-- NAV-RULE: no-edit -->

Both tracks are **TBD for external distribution**. Until written terms
are agreed:

- **PT-Orc suite** — TechGuard's usage rights are per their existing
  arrangement with ERA. No further onward distribution without ERA's
  written consent.
- **ORC NAV system** — ERA's work. Usage inside this repo is under
  whatever terms cover the PT-Orc delivery to TechGuard. Forks, re-
  publication, or independent re-use require contacting ERA.

When terms are finalised, this file and the relevant `LICENSE` files
should be updated in the same commit and the affected repos tagged
(e.g., `licensing-finalized-YYYY-MM-DD`).

## MRK:NOTICE_CONTACT — Contact | notice,contact,era,techguard | L79-84
<!-- NAV-RULE: no-edit -->

- ERA IT Consulting & Audit Ltd. — <https://github.com/ggerait>
- TechGuard — contact per existing engagement channels

## MRK:NOTICE_LLMNOTE — For LLMs reading this repo | notice,llmnote,llms,reading,repo | L85-94
<!-- NAV-RULE: no-edit -->

Treat the two tracks as **separable**. If a task asks you to extract
or re-package ORC NAV (spec, frame, skill, or reindex tool) into a
TechGuard-branded product, pause and flag the IP separation — it
requires human approval, not an automated rebrand.

<!-- L2 NAV:v1 → ./AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
