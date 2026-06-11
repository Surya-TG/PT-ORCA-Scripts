# Scan Summary  TEST-WEBSITE-Jun2026-Orc
*Generated: 2026-06-10 14:17:22 | Session: 20260610_133823*

## Engagement
- **Project:** TEST-WEBSITE-Jun2026-Orc
- **Mode:** pte
- **Subnets:** [none]
- **IPs:** 44.228.249.3
- **Global tier:** normal
- **Subnet map:** global=normal
- **Excluded IPs:** 10.0.2.15

## Host Inventory
- **Live hosts discovered:** 1

## Evidence Produced
### Sweep files (`evidence/_sweep/`)
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/masscan_fast_normal_44.228.249.3_20260610_122644.xml
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/masscan_fast_normal_44.228.249.3_20260610_133848.xml
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/nse_common_20260610_135910.nmap
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/nse_vapt_db_20260610_135926.nmap
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/nse_vapt_ftp_20260610_135926.nmap
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/nse_vapt_rdp_20260610_135926.nmap
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/nse_vapt_shellshock_20260610_135926.nmap
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/nse_vapt_smb_20260610_135926.nmap
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/nse_vapt_ssl_20260610_135926.nmap
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/os_detect_normal_20260610_140019.nmap
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/tcp_deep_normal_20260610_133914.nmap
- /home/kali/audit-orc-vapt/pt-orc/scripts/evidence/TEST-WEBSITE-Jun2026-Orc/_sweep/udp_fallback_20260610_140032.nmap

### Per-host enum files (`evidence/<IP>/`)


## MSF DB Exports (`evidence/_exports/`)
- hosts_enum_20260610_140218.csv
- hosts_tcp_20260610_140027.csv
- hosts_udp_20260610_140209.csv
- notes_enum_20260610_140218.csv
- notes_tcp_20260610_140027.csv
- notes_udp_20260610_140209.csv
- services_enum_20260610_140218.csv
- services_tcp_20260610_140027.csv
- services_udp_20260610_140209.csv

## TLS Targets (for 04_tls_scan.sh)
- none identified

## Manual Follow-up Required
See: `working/TEST-WEBSITE-Jun2026-Orc_manual_followup_20260610_133823.md`

## Next Steps
1. Review per-host enum output in `evidence/<IP>/`
2. Run `04_tls_scan.sh` against `working/tls_targets.txt`
3. Run `05_web_enum.sh` against confirmed web hosts
4. Process findings via pt-evidence workflow
5. Generate state snapshot

---
*03_comp_scan.sh v0.8 | TechGuard.*
