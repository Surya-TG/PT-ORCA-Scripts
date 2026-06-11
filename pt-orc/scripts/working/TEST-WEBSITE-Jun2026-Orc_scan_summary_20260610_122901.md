# Scan Summary  TEST-WEBSITE-Jun2026-Orc
*Generated: 2026-06-10 12:29:01 | Session: 20260610_122613*

## Engagement
- **Project:** TEST-WEBSITE-Jun2026-Orc
- **Mode:** pte
- **Subnets:** [none]
- **IPs:** 44.228.249.3
- **Global tier:** normal
- **Subnet map:** global=normal
- **Excluded IPs:** 10.0.2.15

## Host Inventory
- **Live hosts discovered:** 0

## Evidence Produced
### Sweep files (`evidence/_sweep/`)
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/masscan_fast_normal_44.228.249.3_20260610_122644.xml
- none

### Per-host enum files (`evidence/<IP>/`)


## MSF DB Exports (`evidence/_exports/`)


## TLS Targets (for 04_tls_scan.sh)
- none identified

## Manual Follow-up Required
See: `working/TEST-WEBSITE-Jun2026-Orc_manual_followup_20260610_122613.md`

## Next Steps
1. Review per-host enum output in `evidence/<IP>/`
2. Run `04_tls_scan.sh` against `working/tls_targets.txt`
3. Run `05_web_enum.sh` against confirmed web hosts
4. Process findings via pt-evidence workflow
5. Generate state snapshot

---
*03_comp_scan.sh v0.8 | TechGuard.*
