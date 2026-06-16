<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Orca Packs

Packs extend the Orca platform with capability domains. Each pack runs on the platform core — session continuity, evidence lifecycle, and frame navigation are shared.

## Pack model

- Each pack adds one capability domain (PT, audit, compliance, reporting, etc.)
- Packs are composable — multiple packs can run on the same engagement
- Every pack uses the same evidence lifecycle and file shape as the platform core
- Packs are versioned independently

## Current packs

| Pack | Status | Location | What it does |
|---|---|---|---|
| PT pack | v0.95 (first ship) | `../../pt-orc/` | Penetration testing phase automation |

## PT pack

The PT pack wraps PT-Orc (`pt-orc/`) — the penetration testing automation suite. It provides:

- Phase scripting: recon · enum · exploit → service-verify → report → wrap
- Automated scan coordination
- Finding-to-evidence chain integration (scan output → intake [BHV-9F8R])
- MSF automation with RPORT-honoring audit gate

See `pt-pack/manifest.md` for the full pack description.

## Adding a pack

Each new pack:
1. Declares its capability domain
2. Inherits the platform L2 pattern (engagement + phase + deliverable per file)
3. Wires its output into the evidence lifecycle
4. Ships a manifest at `packs/<pack-name>/manifest.md`

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
