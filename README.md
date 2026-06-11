<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ./AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# audit-orc

ORCa / PT-Orc-Suite — TechGuard release (v1)

Private. Maintained by ggerait.

## Structure

```
pt-orc/
  scripts/     ORCa shell scripts (00–07, common lib, config)
  skills/      Claude AI skills for the PT suite
  spec/        PT-Orc specifications and design docs

nav-orc/
  tools/       NAV reindex tool and shell wrappers (Flint-review surface)
```

TG-facing skill and navigation protocol now live under `orca/tg-nav_hub/` (load `SKILL.md` for engagement; `NAV-BARE.md` for navigation).

See `NOTICE.md` for IP and authorship details.

## Entry points

| File | Who | What |
|---|---|---|
| `HARI-INDEX.md` | TechGuard recipient | Platform orientation — start here after the slides |
| `FLINT-INDEX.md` | External reviewer | Review and test index — five deliverables |
| `orca/README.md` | Anyone | Platform overview |
| `orca/tg-nav_hub/NAV-BARE.md` | Any model (Claude, Codex) | Navigation read protocol for indexed content |

<!-- L2 NAV:v1 → ./AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
