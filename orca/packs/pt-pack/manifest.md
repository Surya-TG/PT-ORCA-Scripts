<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# PT Pack — Manifest

**Pack name**: PT pack
**Version**: v0.95
**Location**: `../../pt-orc/`
**Status**: first shipped pack

---

## What this pack does

The PT pack provides penetration testing phase automation on top of the Orca platform core. It runs automated PT phases and feeds findings into the platform evidence chain.

## Capabilities

| Capability | Script | What it does |
|---|---|---|
| Reconnaissance | `pt-orc/scripts/01_recon.sh` | Host discovery, DNS, OSINT |
| Enumeration | `pt-orc/scripts/03_comp_scan.sh` | Service and port enumeration |
| Exploitation | `pt-orc/scripts/04_exploit.sh` | Controlled exploitation with scope gates |
| Service verification | `pt-orc/scripts/07_service_verify.sh` | 18+ probe types; RPORT-honoring |
| Reporting | `pt-orc/scripts/08_report.sh` | Report generation from evidence chain |
| Wrap | `pt-orc/scripts/09_wrap.sh` | Engagement close and archival |

Shared library: `pt-orc/scripts/orc-common-lib.sh`

## Evidence integration

PT pack outputs wire directly into the platform evidence lifecycle:

```
scan output → intake [BHV-9F8R]
                ↓
finding → verification (HIGH severity: manual required)
                ↓
finding → classification (severity + finding-type)
                ↓
finding → packaging (finding-template + PoC reference)
                ↓
packaged finding → delivery
```

## Engagement type

PT engagements use the `PT` type when initializing:

```
new engagement <name> type: PT
```

This configures:
- Flow: recon → enum → exploit → service-verify → report → wrap
- HIGH-severity gate: manual verification required before packaging
- Evidence states: finding / info / observation

## Configuration

PT pack reads scope and target configuration from the engagement config file. See `pt-orc/README.md` for configuration reference.

## Gates (ship-readiness)

| Gate | Status |
|---|---|
| BUG_GATE — no HIGH/CRITICAL open bugs | CLEAR (v0.95) |
| RPORT-honoring audit (18/18 MSF modules) | CLEAR (v0.95) |
| SUITE_VERSION in pt-orc.conf | pending U35 lane |

<!-- L2 NAV:v1 → ../../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
