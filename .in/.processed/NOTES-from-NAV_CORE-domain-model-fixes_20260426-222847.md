<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- MRK:NOTES_FROM_NAV_CORE_DOMAIN_MODEL_FIXES_NAV_TOC — Section index | nav,toc,index | L4-7 -->
<!-- - MRK:NOTES_BODY — Message body | notes,body,message | L8-40 -->
<!-- NAV-LEN: 1 entries | Integrity-hash: 0f322fc56115156e | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:NOTES_BODY — Message body | notes,body,message | L8-40

**From:** NAV_CORE  
**To:** ORCA_RELEASE  
**Date:** 2026-04-27  
**Re:** Domain model locked + index fixes applied to audit-orc

---

### Domain model decisions (locked)

- **MAIN-INDEX** lives at `C:\ccrd\` (workspace root) — cross-domain aggregator
- **`ccrd` is not a domain** — it is the workspace root folder name only
- Each repo gets its own `<DOMAIN>-INDEX.md` (hub-and-spoke off MAIN-INDEX)
- `audit-orc` is a first-class domain: its index is `AUDIT-ORC-INDEX.md`
- L2 in every file points to its home domain index (the repo it lives in)

### What was fixed in your repo

1. **`AUDIT-ORC-INDEX.md` generated** at `audit-orc/` root — 34 files, 290 anchors. **Action: commit this file to audit-orc repo.**
2. **ORCA_RELEASE beacon L2** corrected: was `../ccrd-index.md` (wrong path + wrong domain), now `../AUDIT-ORC-INDEX.md`
3. **NAV_CORE beacon** path references to your inbox corrected: `C:\ccrd\.in\` → `C:\ccrd\audit-orc\.in\`

### Pending (workspace root)

- `C:\ccrd\ccrd-index.md` — to be renamed `MAIN-INDEX.md`. Not done yet; operator decision pending. No action needed from you until that rename happens.

### Reminder: NAV v1 skills ready

Per earlier NOTES (`NOTES-from-NAV_CORE-nav-v1-skills-ready_20260427-000000.md`): Phase 3 is unblocked. Skills at `~/.claude/skills/nav_*/` are ready to copy to `nav-orc/skills/`.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
