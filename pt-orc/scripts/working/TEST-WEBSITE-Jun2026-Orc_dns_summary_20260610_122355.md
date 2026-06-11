# DNS Recon Summary — TEST-WEBSITE-Jun2026-Orc
*Generated: 2026-06-10 12:25:57 | Session: 20260610_122355*

## Scope
- **Domains:** testphp.vulnweb.com
- **Seed IPs:** 44.228.249.3
- **Tester IP:** [not verified]

## Results
| Metric | Count |
|--------|-------|
| Unique in-scope IPs | 1 |
| Live HTTP/S hosts | 0 |
| Third-party/CDN IPs (flagged) | 0 |
| Takeover candidates | 0 |
| Total targets.txt | 1 |

## In-Scope IPs Discovered
| IP | Source |
|----|--------|
| 44.228.249.3 | a:testphp.vulnweb.com |

## Third-Party / CDN IPs (flagged — verify RoE before scanning)
| IP | Source |
|----|--------|

## CNAME Records
| Subdomain | CNAME |
|-----------|-------|

## Evidence Files
- evidence/_dns/all_subdomains_testphp.vulnweb.com_20260610_122355.txt
- evidence/_dns/all_targets_20260610_122355.txt
- evidence/_dns/axfr_testphp.vulnweb.com_20260610_122355.txt
- evidence/_dns/brute_testphp.vulnweb.com_20260610_122355.txt
- evidence/_dns/crt_testphp.vulnweb.com_20260610_122355.txt
- evidence/_dns/dns_recon_20260610_122355.log
- evidence/_dns/dnssec_testphp.vulnweb.com_20260610_122355.txt
- evidence/_dns/doh_testphp.vulnweb.com_20260610_122355.txt
- evidence/_dns/httpx_20260610_122355.txt

## Next Steps
1. Review takeover candidates manually (if any)
2. Review third-party IPs — confirm any in scope and add manually to `scripts/targets.txt`
3. Validate `scripts/targets.txt` — confirm all IPs are client-owned
4. Run: `sudo ./03_comp_scan.sh --mode pte`

---
*01_dns_recon.sh | TechGuard.*
