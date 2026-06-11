# DNS Recon Summary — Mithila-TEST-WEB-Jun2026-Orc
*Generated: 2026-06-10 16:31:26 | Session: 20260610_162904*

## Scope
- **Domains:** demo.testfire.net
- **Seed IPs:** 65.61.137.117
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
| 65.61.137.117 | a:demo.testfire.net |

## Third-Party / CDN IPs (flagged — verify RoE before scanning)
| IP | Source |
|----|--------|

## CNAME Records
| Subdomain | CNAME |
|-----------|-------|

## Evidence Files
- evidence/_dns/all_subdomains_demo.testfire.net_20260610_162904.txt
- evidence/_dns/all_targets_20260610_162904.txt
- evidence/_dns/axfr_demo.testfire.net_20260610_162735.txt
- evidence/_dns/axfr_demo.testfire.net_20260610_162904.txt
- evidence/_dns/brute_demo.testfire.net_20260610_162735.txt
- evidence/_dns/brute_demo.testfire.net_20260610_162904.txt
- evidence/_dns/crt_demo.testfire.net_20260610_162735.txt
- evidence/_dns/crt_demo.testfire.net_20260610_162904.txt
- evidence/_dns/dns_recon_20260610_162312.log
- evidence/_dns/dns_recon_20260610_162735.log
- evidence/_dns/dns_recon_20260610_162904.log
- evidence/_dns/dnssec_demo.testfire.net_20260610_162735.txt
- evidence/_dns/dnssec_demo.testfire.net_20260610_162904.txt
- evidence/_dns/doh_demo.testfire.net_20260610_162735.txt
- evidence/_dns/doh_demo.testfire.net_20260610_162904.txt
- evidence/_dns/httpx_20260610_162904.txt

## Next Steps
1. Review takeover candidates manually (if any)
2. Review third-party IPs — confirm any in scope and add manually to `scripts/targets.txt`
3. Validate `scripts/targets.txt` — confirm all IPs are client-owned
4. Run: `sudo ./03_comp_scan.sh --mode pte`

---
*01_dns_recon.sh | TechGuard.*
