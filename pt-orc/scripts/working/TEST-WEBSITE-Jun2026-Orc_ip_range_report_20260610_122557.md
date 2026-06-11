# IP Range & Ownership Report — TEST-WEBSITE-Jun2026-Orc
*Generated: 2026-06-10 12:26:13 | Session: 20260610_122557*

---

## Engagement Metadata
| Field        | Value |
|--------------|-------|
| Project      | TEST-WEBSITE-Jun2026-Orc |
| Date         | 2026-06-10 12:26:13 |
| Mode         | pte |
| Script       | 02_ip_analysis.sh |
| IP count     | 1 |
| Shodan       | not configured |

---

## Target IP Inventory
| IP | PTR | ASN | Org | Country | Cloud? |
|----|-----|-----|-----|---------|--------|
| 44.228.249.3 | ec2-44-228-249-3.us-west-2.compute.amazonaws.com | AS16509 | Amazon.com, Inc. | United States | **YES — PTR:ec2-44-228-249-3.us-west-2.compute.amazonaws.com;org:Amazon** |

---

## Cloud/CDN-Hosted IPs

- **44.228.249.3** — PTR:ec2-44-228-249-3.us-west-2.compute.amazonaws.com;org:Amazon
  > RoE Advisory: Confirm client owns or controls this IP before active scanning.
  > Cloud/CDN IPs may be shared infrastructure. Obtain written permission from
  > the cloud provider or verify the IP is dedicated to this client.


---

## ASN Grouping

### AS16509
  - 44.228.249.3 (Amazon.com, Inc.)

---

## BGP Prefix Coverage

| Prefix | IPs in scope |
|--------|-------------|
| 44.192.0.0 |  |
| - |  |
| 44.255.255.255 |  |

---

## Traceroute Summary

| IP | Hop Count |
|----|-----------|
| 44.228.249.3 | 0
0 |

---

## Recommendations

- **Cloud/CDN IPs (if any flagged above):** Do not begin active testing until written
  authorisation is obtained confirming the client owns/controls the IP, or until the
  cloud provider's own penetration testing policy is satisfied (e.g. AWS Penetration
  Testing Policy, Azure Penetration Testing T&Cs).

- **Shared hosting / CDN bypass:** If a target resolves to a CDN edge IP, confirm
  the origin IP with the client and add it to scope explicitly. CDN bypass testing
  (direct origin IP, Host header manipulation) should be included in scope.

- **IPs with no PTR record:** May indicate dynamically assigned addresses or
  infrastructure maintained with minimal DNS hygiene. Flag for manual scope
  confirmation with client before active scanning.

- **Multi-ASN scope:** Where IPs span multiple ASNs/orgs (see ASN Grouping above),
  confirm each netblock with the client. Third-party-managed IPs require separate
  written authorisation.

- **Traceroute topology:** Review per-IP traceroute files for shared intermediate
  hops — these can reveal upstream infrastructure and help detect filtering or WAF
  choke points between tester and target.

- **Shodan enrichment:** If Shodan data is available, cross-reference open port
  listings against 03_comp_scan.sh results to confirm scan coverage and
  identify any ports that may be filtered from the tester's source IP.

- **Threat intel (AbuseIPDB/VirusTotal):** IPs with high abuse confidence scores
  or positive VT detections may be sinkholes, honeypots, or adversary-controlled.
  Cross-reference before active scanning — a high-score IP may already be
  actively monitored. Set ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY in pt-orc.conf.

- **CDN bypass:** For CDN-fronted targets, request the client's origin IP(s)
  and add them to scope. Test direct origin access via: curl -H "Host: target.com"
  https://origin-ip/ — bypass may expose unpatched origin servers not behind WAF.

---
*02_ip_analysis.sh | TechGuard | TEST-WEBSITE-Jun2026-Orc*
