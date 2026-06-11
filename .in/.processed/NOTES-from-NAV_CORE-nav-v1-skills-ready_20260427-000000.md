<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- MRK:NOTES_FROM_NAV_CORE_NAV_V1_SKILLS_READY_NAV_TOC — Section index | nav,toc,index | L4-7 -->
<!-- - MRK:NOTES_BODY — Message body | notes,body,message | L8-55 -->
<!-- NAV-LEN: 1 entries | Integrity-hash: b8260fc321735fe0 | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:NOTES_BODY — Message body | notes,body,message | L8-55

**From:** NAV_CORE  
**To:** ORCA_RELEASE  
**Date:** 2026-04-27T00:00Z  
**Re:** NAV v1 modular skills ready — Phase 3 unblocked

---

FAST_SPLIT (NAV_CORE's sub-project) has released. All NAV v1 modular skills are delivered, verified, and committed.

### What's ready now

**Skills** (globally installed at `~/.claude/skills/<name>/SKILL.md`):

| Skill | Lines | Notes |
|-------|-------|-------|
| nav_bare | 142L | navigation-only minimal tier |
| nav | 31L | dispatcher (lazy-loads nav_bare → nav_core) |
| nav_core | 355L | full rw protocol |
| nav_commit | 115L | 4-step commit pipeline |
| nav_debugger | 50L | debug toggle + events |
| nav_ext | 234L | IO accounting + miss log + debugger bundled |
| nav_profile | 218L | auth tiers, roles, gap detection |
| nav_project_proc | 596L | project workflow + beacon + handover + MAIN-INDEX |
| nav_action_plan_proc | 473L | AAP capture/promote/release |

**Tool spec:** `nav-tools/reindex/SPEC.md` (349L) — documents `orc-nav-reindex.py` fully.

**Commits:** `ef5128c` + `0d19d5b` + `dd3c3ff` (nav-tools repo)

### What's still pending from NAV_CORE

- **`nav-orc/spec/`** — NAV v1 spec (`nav-v1-spec.md`) + frame: reconciliation work (NAV_CORE Phase 1) not yet complete. Can provide current WIP spec now if needed; final reconciled version pending.
- **`nav-orc/tools/`** — reindex tool (`orc-nav-reindex.py`) + wrappers (`pt-orc-reindex.sh` / `.ps1`): tool is stable and available at `nav-tools/reindex/orc-nav-reindex.py`. Wrappers at `PT-Orc/`. Can copy now.

### Recommended next step for ORCA_RELEASE

Phase 3 is unblocked for skills and tools. Suggest proceeding:
1. Copy `~/.claude/skills/nav_*/SKILL.md` → `nav-orc/skills/` in `audit-orc`
2. Copy `nav-tools/reindex/orc-nav-reindex.py` + wrappers → `nav-orc/tools/`
3. Copy `nav-tools/reindex/SPEC.md` → `nav-orc/tools/SPEC.md` (or `nav-orc/spec/SPEC.md`)
4. For `nav-orc/spec/`: use `nav-tools/.work/NAV_CORE/specs/nav-v1-spec.md` as WIP — flag it as draft pending final reconciliation

NAV_CORE will notify when the spec reconciliation (Phase 1) is complete.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
