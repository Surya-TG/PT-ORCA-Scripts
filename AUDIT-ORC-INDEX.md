<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → [project root] -->

<!-- MRK:AUDIT_ORC_INDEX_NAV_TOC — Section index | nav,toc,index | L4-29 -->
<!-- - MRK:INDEX_PROTOCOL — Access protocol | index,protocol,access | L30-36 -->
<!-- - MRK:INDEX_RULES — Hard rules | index,rules,hard | L37-45 -->
<!-- - MRK:INDEX_TOOL — Reindex tool reference | index,tool,reindex,reference | L46-58 -->
<!-- - MRK:INDEX_FILES — Files by directory | index,directory | L59-535 -->
<!-- - MRK:INDEX_ALL — All anchors (flat, 466 entries) | index,anchors,flat,entries | L536-1008 -->
<!-- NAV-LEN: 5 entries | Integrity-hash: 27d194e5d25bab00 | Last-indexed: 2026-06-09T07:09:41Z -->

<!-- BEGIN USER-PROMPT (preserved across reindex — edit this block to add project context) -->
<!--
    PROJECT CONTEXT / OWNER GUIDELINES
    (Empty by default. Add engagement-specific or project-specific context
    here: target scope, goals, constraints, tester profile, anything that
    orients an LLM faster. Reindex PRESERVES this block — it's never
    overwritten by `orc-nav-reindex.py index`.)
-->
<!-- END USER-PROMPT -->

<!-- tool-sha: be6fd11ae8f4ef2d | orc-nav-reindex.py -->

# AUDIT-ORC-INDEX — audit-orc

ORCa / PT-Orc-Suite — TechGuard release (v1)

**Files indexed:** 105 &nbsp;·&nbsp; **Anchors:** 466 &nbsp;·&nbsp; **Last-indexed:** 2026-06-09T05:15:08Z

## MRK:INDEX_PROTOCOL — Access protocol | index,protocol,access | L30-36

1. **Read the file header first.** Every indexed file has L1 (rules) + L2 (`NAV:v1 → <path>`) on lines 1–2 (MD) or 2–3 (shebang script). `tail -2` gives the same orientation from the bottom (mirror).
2. **Use the per-file `MRK:NAV_TOC` block.** Each file carries a TOC listing entries with exact `L<start>-<end>` ranges. Match by keyword; fetch by range.
3. **Precise fetch only.** Use `L<start>-<end>` from the MRK line. No default line count. Range missing / stale → run `reindex` before reading.
4. **Miss? Log it.** When a TOC lookup didn't contain what you expected, record in `session_lessons_log.md` (see `/orc-nav` skill). No inference effort is wasted.

## MRK:INDEX_RULES — Hard rules | index,rules,hard | L37-45

- Never open a file without a stated purpose.
- Never bulk-read an indexed file — use the TOC.
- Never re-load a file already in context — recall from memory.
- Loading >200 lines without a target → state in one sentence what you're looking for first.
- After adding/renaming/removing any MRK anchor → run `reindex` before commit.
- Before every commit → run the composite `reindex + verify`.

## MRK:INDEX_TOOL — Reindex tool reference | index,tool,reindex,reference | L46-58

```
python tools/orc-nav-reindex.py reindex             # write pass — refresh ranges + hashes after edits
python tools/orc-nav-reindex.py verify              # read pass — integrity check (pre-commit)
python tools/orc-nav-reindex.py index               # regenerate this file
python tools/orc-nav-reindex.py append <file>       # add one NAV:v1 file's entry into this index
python tools/orc-nav-reindex.py append <file> --index <idx>  # target a specific index
./tools/pt-orc-reindex.sh --pre-commit              # composite: reindex + verify
```

Always run the pre-commit composite before `git commit`. Drift → fix source, retry.

## MRK:INDEX_FILES — Files by directory | index,directory | L59-535

### `.in/.in-index.md` — 1 anchors
- `MRK:IN_INDEX_FILES` — Files in this directory

### `.in/.processed/.processed-index.md` — 1 anchors
- `MRK:PROCESSED_INDEX_FILES` — Files in this directory

### `.in/.processed/NOTES-from-NAV_CORE-domain-model-fixes_20260426-222847.md` — 1 anchors
- `MRK:NOTES_BODY` — Message body

### `.in/.processed/NOTES-from-NAV_CORE-nav-v1-skills-ready_20260427-000000.md` — 1 anchors
- `MRK:NOTES_BODY` — Message body

### `.in/.processed/README.md` — 4 anchors
- `MRK:PROCESSED_README_PROTOCOL` — Access protocol (P1 v3)
- `MRK:PROCESSED_README_RULES` — Hard rules (P2 v2)
- `MRK:PROCESSED_README_CONFLICT` — Conflict-resolution
- `MRK:PROCESSED_README_CUSTOM` — Custom context (preserved)

### `.in/DCPTCN_TG_beacon.md` — 1 anchors
- `MRK:DCPTCN_TG_BEACON` — DCPTCN_TG project beacon

### `.in/ORCA-SLIDES_beacon.md` — 1 anchors
- `MRK:ORCA_SLIDES_BEACON` — ORCA-SLIDES project beacon

### `.in/ORCA_DOCS_beacon.md` — 1 anchors
- `MRK:ORCA_DOCS_BEACON` — ORCA_DOCS project beacon

### `.in/ORCA_RELEASE_beacon.md` — 1 anchors
- `MRK:ORCA_RELEASE_BEACON` — ORCA_RELEASE project beacon

### `.in/README.md` — 4 anchors
- `MRK:IN_README_PROTOCOL` — Access protocol (P1 v3)
- `MRK:IN_README_RULES` — Hard rules (P2 v2)
- `MRK:IN_README_CONFLICT` — Conflict-resolution
- `MRK:IN_README_CUSTOM` — Custom context (preserved)

### `.in/SPEC-DCPTCN_TG-orientation-20260427-132500.md` — 6 anchors
- `MRK:DCPTCN_SPEC_STATUS` — Status & delivery target
- `MRK:DCPTCN_SPEC_ENGMODEL` — Generic engagement model
- `MRK:DCPTCN_SPEC_METHODOLOGY` — Unified methodology lifecycle
- `MRK:DCPTCN_SPEC_DECEPTICON` — Decepticon planner generalization
- `MRK:DCPTCN_SPEC_ARCH` — Architecture bottom line
- …

### `AUDIT-ORC-INDEX.md` — 5 anchors
- `MRK:INDEX_PROTOCOL` — Access protocol
- `MRK:INDEX_RULES` — Hard rules
- `MRK:INDEX_TOOL` — Reindex tool reference
- `MRK:INDEX_FILES` — Files by directory
- `MRK:INDEX_ALL` — All anchors (flat, 450 entries)

### `CHANGELOG.md` — 2 anchors
- `MRK:RELEASE_V081` — v0.8.1 — 2026-04-21
- `MRK:RELEASE_V08` — v0.8 — 2026-04-20

### `FLINT-INDEX.md` — 0 anchors

### `HARI-INDEX.md` — 0 anchors

### `NAV-MAIN-INDEX.md` — 1 anchors
- `MRK:NAV_MAIN_PROJECTS` — Project registry

### `NOTICE.md` — 6 anchors
- `MRK:NOTICE_COMPONENTS` — Components
- `MRK:NOTICE_PTORC` — PT-Orc suite
- `MRK:NOTICE_ORCNAV` — ORC NAV system
- `MRK:NOTICE_LICENSING` — Licensing
- `MRK:NOTICE_CONTACT` — Contact
- …

### `README.md` — 0 anchors

### `deliverables/DCPTCN_TG/EXEC-SUMMARY-review-20260427.md` — 4 anchors
- `MRK:EXEC_VERDICT` — Overall verdict + decision confirmation
- `MRK:EXEC_FINDINGS` — Key findings from external review
- `MRK:EXEC_ACTIONS` — Action items entering TG planning
- `MRK:EXEC_STATUS` — Broadcast + reply status

### `deliverables/DCPTCN_TG/PHASE1-gap-analysis-v01-v02-20260427.md` — 8 anchors
- `MRK:GAP_SUMMARY` — Executive summary
- `MRK:GAP_STRUCTURE` — Document structure comparison
- `MRK:GAP_TOOLING` — Tooling changes: v0.1 → v0.2
- `MRK:GAP_LIFECYCLE` — Lifecycle stage changes
- `MRK:GAP_MODELS` — Model changes: evidence, findings, artifacts
- …

### `deliverables/DCPTCN_TG/PHASE2-fit-assessment-20260427.md` — 9 anchors
- `MRK:FIT_SUMMARY` — Executive summary
- `MRK:FIT_COMPONENTS` — Decepticon component inventory
- `MRK:FIT_MAP` — Component → TG-CORE-* mapping
- `MRK:FIT_REUSABLE` — Reusable as-is
- `MRK:FIT_PARAMETERIZE` — Needs parameterization
- …

### `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` — 11 anchors
- `MRK:SPEC_OVERVIEW` — Overview and design decisions
- `MRK:SPEC_LIBRARY` — EngagementCore library structure
- `MRK:SPEC_OBJECTIVE` — Generalized Objective schema
- `MRK:SPEC_OPPLAN` — Generalized OPPLAN + OPPLANMiddleware
- `MRK:SPEC_BUNDLE` — Generalized EngagementBundle
- …

### `deliverables/DCPTCN_TG/PHASE4-methodology-packs-20260427.md` — 9 anchors
- `MRK:PACK_OVERVIEW` — All-pack summary + D-004 decision
- `MRK:PACK_PENTEST` — Pentest pack (PentestPack)
- `MRK:PACK_TSA` — Tech Security Assessment pack
- `MRK:PACK_ISO27001` — ISO 27001 Audit pack
- `MRK:PACK_COMPLIANCE` — Compliance Evidence Review pack
- …

### `deliverables/DCPTCN_TG/PHASE5-architecture-decision-20260427.md` — 8 anchors
- `MRK:ARCH_OVERVIEW` — Summary + all decisions closed
- `MRK:ARCH_TIERS` — Three-tier component architecture
- `MRK:ARCH_ENGCORE` — ADR-001: EngagementCore extraction
- `MRK:ARCH_FWREG` — ADR-002: FrameworkRegistry in EngagementCore
- `MRK:ARCH_ENGID` — ADR-003: EngagementID scheme
- …

### `deliverables/DCPTCN_TG/PHASE5-v03-methodology-sections-20260427.md` — 6 anchors
- `MRK:V03_OVERVIEW` — v0.3 change log + structure guide
- `MRK:V03_ENGAGEMENT_MODEL` — §NEW: Generic 10-entity engagement model
- `MRK:V03_PACK_ARCH` — §NEW: MethodologyPack architecture
- `MRK:V03_TOOLING_NEW` — §UPDATED: New TG-* placeholders + build order
- `MRK:V03_DECEPTICON` — §20 UPDATED: Decepticon role — open question CLOSED
- …

### `deliverables/ORCA-SLIDES/v2-README.md` — 0 anchors

### `deliverables/ORCA-SLIDES/v2-delivery-proposal.md` — 0 anchors

### `deliverables/ORCA-SLIDES/v2-dev-process.md` — 0 anchors

### `deliverables/ORCA-SLIDES/v2-docs-refresh-notes.md` — 0 anchors

### `deliverables/ORCA-SLIDES/v2-email-hari.md` — 0 anchors

### `deliverables/ORCA-SLIDES/v2-scope-500h.md` — 0 anchors

### `deliverables/ORCA-SLIDES/v2-speaker-notes.md` — 0 anchors

### `docs/README.md` — 0 anchors

### `docs/docs-index.md` — 1 anchors
- `MRK:DOCS_INDEX_FILES` — Files in this directory

### `docs/getting-started.md` — 0 anchors

### `docs/nav-action-plan-proc-guide.md` — 0 anchors

### `docs/nav-bare-orientation-workaround.md` — 0 anchors

### `docs/nav-project-proc-guide.md` — 0 anchors

### `docs/nav-v1-user-guide.md` — 0 anchors

### `docs/system-assessment-v1-initial.md` — 6 anchors
- `MRK:ASSESS_OVERVIEW` — Assessment basis and scope
- `MRK:ASSESS_SYSTEM` — What the system is
- `MRK:ASSESS_STRENGTHS` — What works genuinely well
- `MRK:ASSESS_GAPS` — Where it is strained
- `MRK:ASSESS_VERDICT` — Overall verdict and recommendation
- …

### `docs/tg-unified-audit-methodology-v0.3.md` — 15 anchors
- `MRK:TG_METH_HEADER` — Version header
- `MRK:TG_METH_PURPOSE` — §1 Purpose and Intent
- `MRK:TG_METH_PRINCIPLE` — §2–3 Core Principle + Design
- `MRK:TG_METH_LAYERS` — §4 Methodology Layers + platform architecture
- `MRK:TG_METH_TOOLING` — §5–7 Tooling model + placeholder tables
- …

### `nav-orc/tools/README.md` — 4 anchors
- `MRK:TOOLS_README_PROTOCOL` — Access protocol (P1 v3)
- `MRK:TOOLS_README_RULES` — Hard rules (P2 v2)
- `MRK:TOOLS_README_CONFLICT` — Conflict-resolution
- `MRK:TOOLS_README_CUSTOM` — Custom context (preserved)

### `nav-orc/tools/orc-nav-reindex.py` — 13 anchors
- `MRK:REINDEX_CONSTANTS` — Module constants and configuration
- `MRK:REINDEX_DETECT` — File type detection
- `MRK:REINDEX_PARSE` — Anchor and TOC parsing
- `MRK:REINDEX_STRIP` — Legacy format stripping
- `MRK:REINDEX_EMIT` — Output generation helpers
- …

### `nav-orc/tools/pt-orc-reindex.ps1` — 2 anchors
- `MRK:REINDEX_PS1_SETUP` — Setup: find Python tool + resolver
- `MRK:REINDEX_PS1_DISPATCH` — Flag dispatch

### `nav-orc/tools/pt-orc-reindex.sh` — 2 anchors
- `MRK:REINDEX_SH_SETUP` — Setup: find Python tool + resolver
- `MRK:REINDEX_SH_DISPATCH` — Flag dispatch

### `nav-orc/tools/tools-index.md` — 1 anchors
- `MRK:TOOLS_INDEX_FILES` — Files in this directory

### `orca/README.md` — 0 anchors

### `orca/guides/debug-logger.md` — 0 anchors

### `orca/guides/getting-started.md` — 0 anchors

### `orca/guides/new-engagement.md` — 0 anchors

### `orca/guides/role-definition.md` — 0 anchors

### `orca/guides/troubleshooting.md` — 0 anchors

### `orca/packs/README.md` — 0 anchors

### `orca/packs/pt-pack/manifest.md` — 0 anchors

### `orca/specs/endless-session-spec.md` — 0 anchors

### `orca/specs/evidence-lifecycle-spec.md` — 0 anchors

### `orca/specs/ip-marks-spec.md` — 0 anchors

### `orca/specs/orca-platform-spec.md` — 0 anchors

### `orca/specs/role-frames-spec.md` — 0 anchors

### `orca/tg-nav_hub/EVIDENCE-WORKFLOW.md` — 0 anchors

### `orca/tg-nav_hub/FRAMES.md` — 0 anchors

### `orca/tg-nav_hub/NAV-BARE.md` — 0 anchors

### `orca/tg-nav_hub/PROFILE.md` — 0 anchors

### `orca/tg-nav_hub/README.md` — 0 anchors

### `orca/tg-nav_hub/SKILL.md` — 0 anchors

### `orca/tools/precommit-scrub.py` — 0 anchors

### `pt-orc/correlations/README.md` — 0 anchors

### `pt-orc/correlations/correlations-index.md` — 1 anchors
- `MRK:CORRELATIONS_INDEX_FILES` — Files in this directory

### `pt-orc/docs/README.md` — 4 anchors
- `MRK:DOCS_README_PROTOCOL` — Access protocol (P1 v3)
- `MRK:DOCS_README_RULES` — Hard rules (P2 v2)
- `MRK:DOCS_README_CONFLICT` — Conflict-resolution
- `MRK:DOCS_README_CUSTOM` — Custom context (preserved)

### `pt-orc/docs/design.md` — 4 anchors
- `MRK:PATTERNS` — Shared Patterns
- `MRK:GOTCHAS` — Key Design Decisions and Gotchas
- `MRK:D03` — 03_comp_scan.sh Architecture
- `MRK:TOOLS` — Tool Dependencies

### `pt-orc/docs/docs-index.md` — 1 anchors
- `MRK:DOCS_INDEX_FILES` — Files in this directory

### `pt-orc/docs/funcs.md` — 9 anchors
- `MRK:CTX` — §0. Context
- `MRK:S00` — 00_pt-orc.sh
- `MRK:S01` — 01_dns_recon.sh
- `MRK:S03` — 03_comp_scan.sh
- `MRK:S04` — 04_tls_scan.sh
- …

### `pt-orc/docs/ops.md` — 5 anchors
- `MRK:OPS_SCRIPTS` — Scripts at a Glance
- `MRK:OPS_PIPELINE` — Pipeline
- `MRK:OPS_FLAGS` — CLI Flags
- `MRK:OPS_OPERATIONS` — Common Operations
- `MRK:OPS_DIRS` — Directory Structure

### `pt-orc/docs/orientation.md` — 6 anchors
- `MRK:IDX_S0` — §0. MRK Naming Convention
- `MRK:IDX_S1` — §1. Suite Overview
- `MRK:IDX_S2` — §2. Data Flow
- `MRK:IDX_S3` — §3. Engagement Config
- `MRK:IDX_S4` — §4. Evidence Directory Layout
- …

### `pt-orc/docs/skill-brief.md` — 15 anchors
- `MRK:SKL_HOWTO` — How to Use This File
- `MRK:SKL_S0` — §0. Skill Navigation Protocol — how the skill reads suite files efficiently
- `MRK:SKL_S1` — §1. Skill Role
- `MRK:SKL_S2` — §2. Reference File Loading Strategy
- `MRK:SKL_S3` — §3. State Snapshot Schema
- …

### `pt-orc/modules/README.md` — 0 anchors

### `pt-orc/modules/modules-index.md` — 1 anchors
- `MRK:MODULES_INDEX_FILES` — Files in this directory

### `pt-orc/scripts/00_pt-orc.sh` — 11 anchors
- `MRK:00_ROOT` — ROOT CHECK
- `MRK:00_CONF` — ENGAGEMENT CONFIG
- `MRK:00_LOG` — COLOURS AND LOGGING + STEP BANNER
- `MRK:00_DEFAULTS` — DEFAULTS + STEP STATUS ACCUMULATORS
- `MRK:00_USAGE` — USAGE BANNER
- …

### `pt-orc/scripts/01_dns_recon.sh` — 14 anchors
- `MRK:01_ROOT` — ROOT CHECK
- `MRK:01_CONF` — ENGAGEMENT CONFIGURATION
- `MRK:01_LOG` — COLOURS AND LOGGING
- `MRK:01_ARGS` — ARGUMENT PARSING
- `MRK:01_SRCIP` — SOURCE IP VERIFICATION
- …

### `pt-orc/scripts/02_ip_analysis.sh` — 12 anchors
- `MRK:02_LOG` — COLOURS AND LOGGING
- `MRK:02_CONF` — ENGAGEMENT CONFIGURATION
- `MRK:02_USAGE` — USAGE
- `MRK:02_ARGS` — ARGUMENT PARSING
- `MRK:02_DEPS` — DEPENDENCY CHECK
- …

### `pt-orc/scripts/03_comp_scan.sh` — 26 anchors
- `MRK:03_ROOT` — ROOT CHECK
- `MRK:03_CONF` — ENGAGEMENT CONFIGURATION
- `MRK:03_TIER` — STEALTH TIER PARAMETERS
- `MRK:03_LOG` — COLOURS AND LOGGING
- `MRK:03_ARGS` — ARGUMENT PARSING
- …

### `pt-orc/scripts/04_tls_scan.sh` — 11 anchors
- `MRK:04_ROOT` — ROOT CHECK
- `MRK:04_CONF` — ENGAGEMENT CONFIGURATION
- `MRK:04_LOG` — COLOURS AND LOGGING
- `MRK:04_DB` — MSF DB CREDENTIALS
- `MRK:04_ARGS` — ARGUMENT PARSING
- …

### `pt-orc/scripts/05_web_enum.sh` — 11 anchors
- `MRK:05_ROOT` — ROOT CHECK
- `MRK:05_CONF` — ENGAGEMENT CONFIGURATION
- `MRK:05_LOG` — COLOURS AND LOGGING
- `MRK:05_ARGS` — ARGUMENT PARSING
- `MRK:05_DB` — MSF DB HELPERS
- …

### `pt-orc/scripts/06_wpscan.sh` — 13 anchors
- `MRK:06_LOG` — COLOURS AND LOGGING
- `MRK:06_CONF` — ENGAGEMENT CONFIGURATION
- `MRK:06_USAGE` — USAGE
- `MRK:06_ARGS` — ARGUMENT PARSING
- `MRK:06_DEPS` — DEPENDENCY CHECK
- …

### `pt-orc/scripts/07_service_verify.sh` — 34 anchors
- `MRK:07_ROOT` — ROOT CHECK
- `MRK:07_CONF` — ENGAGEMENT CONFIGURATION
- `MRK:07_LOG` — COLOURS AND LOGGING
- `MRK:07_ARGS` — ARGUMENT PARSING
- `MRK:07_DB` — MSF DB + MODULE RUNNER
- …

### `pt-orc/scripts/08_app_api_review.sh` — 32 anchors
- `MRK:08_ROOT` — ROOT CHECK
- `MRK:08_CONF` — ENGAGEMENT CONFIGURATION
- `MRK:08_LOG` — COLOURS AND LOGGING
- `MRK:08_ARGS` — ARGUMENT PARSING
- `MRK:08_DB` — MSF DB HELPERS
- …

### `pt-orc/scripts/09_ai_llm_review.sh` — 10 anchors
- `MRK:09_ROOT` — ROOT CHECK
- `MRK:09_CONF` — ENGAGEMENT CONFIGURATION
- `MRK:09_LOG` — COLOURS AND LOGGING
- `MRK:09_ARGS` — ARGUMENT PARSING
- `MRK:09_DB` — MSF DB HELPERS
- …

### `pt-orc/scripts/12_report_pack.sh` — 10 anchors
- `MRK:12_CONF` — ENGAGEMENT CONFIGURATION
- `MRK:12_LOG` — COLOURS AND LOGGING
- `MRK:12_ARGS` — ARGUMENT PARSING
- `MRK:12_VALIDATE` — VALIDATION
- `MRK:12_SCOPE` — BUILD SCOPE JSON
- …

### `pt-orc/scripts/README.md` — 4 anchors
- `MRK:SCRIPTS_README_PROTOCOL` — Access protocol (P1 v3)
- `MRK:SCRIPTS_README_RULES` — Hard rules (P2 v2)
- `MRK:SCRIPTS_README_CONFLICT` — Conflict-resolution
- `MRK:SCRIPTS_README_CUSTOM` — Custom context (preserved)

### `pt-orc/scripts/orc-common-lib.sh` — 4 anchors
- `MRK:COM_DB` — MSF / POSTGRES DIRECT ACCESS
- `MRK:COM_TRAIL` — MSF NOTES WRITER
- `MRK:COM_BANNER` — standalone banner
- `MRK:COM_SELFTEST` — reserved for future --test mode

### `pt-orc/scripts/scripts-index.md` — 1 anchors
- `MRK:SCRIPTS_INDEX_FILES` — Files in this directory

### `pt-orc/skills/pt-commands/SKILL.md` — 21 anchors
- `MRK:PT_CMDS_PASSIVE_CAPTURE` — GROUP: PASSIVE / CAPTURE
- `MRK:PT_CMDS_DNS_OSINT` — GROUP: DNS / OSINT
- `MRK:PT_CMDS_SWEEP` — GROUP: SWEEP
- `MRK:PT_CMDS_SMB` — GROUP: SMB
- `MRK:PT_CMDS_NFS` — GROUP: NFS
- …

### `pt-orc/skills/pt-enum/SKILL.md` — 7 anchors
- `MRK:PT_ENUM_RECEIVED` — Received from L1 (pt-orc)
- `MRK:PT_ENUM_EXIT` — Exit Criteria
- `MRK:PT_ENUM_DISPATCH` — L3 Dispatch Table
- `MRK:PT_ENUM_APPROACH` — Enumeration Approach by Stage
- `MRK:PT_ENUM_STUB_SCHEMA` — Finding Stub Schema
- …

### `pt-orc/skills/pt-evidence/SKILL.md` — 5 anchors
- `MRK:PT_EVIDENCE_RECEIVED` — Received from L1 (pt-orc)
- `MRK:PT_EVIDENCE_EXIT` — Exit Criteria
- `MRK:PT_EVIDENCE_PIPELINE` — Processing Pipeline
- `MRK:PT_EVIDENCE_TOOL_GUIDE` — Tool Output Interpretation Guide
- `MRK:PT_EVIDENCE_OUTPUT` — Output — Evidence Processing Block

### `pt-orc/skills/pt-monitor/SKILL.md` — 10 anchors
- `MRK:MON_ACTIVATE` — Activate when
- `MRK:MON_FIRSTREAD` — First read
- `MRK:MON_CORELOOP` — Core loop
- `MRK:MON_CADENCE` — /loop cadence
- `MRK:MON_ANOMALY` — Anomaly discipline
- …

### `pt-orc/skills/pt-monitor/monitor-frame.md` — 0 anchors

### `pt-orc/skills/pt-monitor/monitor-spec.md` — 0 anchors

### `pt-orc/skills/pt-orc/SKILL.md` — 12 anchors
- `MRK:PTORC_ROLE` — Role
- `MRK:PTORC_PRINCIPLES` — Core Principles (Immutable)
- `MRK:PTORC_NAMING` — Engagement Naming
- `MRK:PTORC_DIRS` — Directory Structure
- `MRK:PTORC_STAGES` — Stage Registry
- …

### `pt-orc/skills/pt-recon/SKILL.md` — 6 anchors
- `MRK:PT_RECON_RECEIVED` — Received from L1 (pt-orc)
- `MRK:PT_RECON_EXIT` — Exit Criteria
- `MRK:PT_RECON_S1` — S1 — Passive Reconnaissance
- `MRK:PT_RECON_S2` — S2 — Broad Sweep / Surface Mapping
- `MRK:PT_RECON_RETURN` — Return Pass Behaviour
- …

### `pt-orc/skills/pt-report/SKILL.md` — 20 anchors
- `MRK:PT_REPORT_RECEIVED` — Received from L1 (pt-orc)
- `MRK:PT_REPORT_INPUTS` — Input Sources
- `MRK:PT_REPORT_EXIT` — Exit Criteria
- `MRK:PT_REPORT_STRUCTURE` — Report Structure (PTI / PTE)
- `MRK:PT_REPORT_VERSIONING` — Document Versioning
- …

### `pt-orc/templates/README.md` — 0 anchors

### `pt-orc/templates/templates-index.md` — 1 anchors
- `MRK:TEMPLATES_INDEX_FILES` — Files in this directory

### `pt-orc/tools/README.md` — 4 anchors
- `MRK:TOOLS_README_PROTOCOL` — Access protocol (P1 v3)
- `MRK:TOOLS_README_RULES` — Hard rules (P2 v2)
- `MRK:TOOLS_README_CONFLICT` — Conflict-resolution
- `MRK:TOOLS_README_CUSTOM` — Custom context (preserved)

### `pt-orc/tools/install-skills.sh` — 5 anchors
- `MRK:INSTALL_SKILLS_SETUP` — Setup + arg parsing
- `MRK:INSTALL_SKILLS_SELECTION` — Skill selection (default vs all)
- `MRK:INSTALL_SKILLS_HELPERS` — Hash helpers + counters
- `MRK:INSTALL_SKILLS_MAIN_LOOP` — Main install loop with drift check
- `MRK:INSTALL_SKILLS_SUMMARY` — Summary output

### `pt-orc/tools/tools-index.md` — 1 anchors
- `MRK:TOOLS_INDEX_FILES` — Files in this directory

## MRK:INDEX_ALL — All anchors (flat, 466 entries) | index,anchors,flat,entries | L536-1008

| File | Line | Tag | Title |
|------|------|-----|-------|
| `.in/.in-index.md` | L8 | `MRK:IN_INDEX_FILES` | Files in this directory |
| `.in/.processed/.processed-index.md` | L8 | `MRK:PROCESSED_INDEX_FILES` | Files in this directory |
| `.in/.processed/NOTES-from-NAV_CORE-domain-model-fixes_20260426-222847.md` | L8 | `MRK:NOTES_BODY` | Message body |
| `.in/.processed/NOTES-from-NAV_CORE-nav-v1-skills-ready_20260427-000000.md` | L8 | `MRK:NOTES_BODY` | Message body |
| `.in/.processed/README.md` | L11 | `MRK:PROCESSED_README_PROTOCOL` | Access protocol (P1 v3) |
| `.in/.processed/README.md` | L18 | `MRK:PROCESSED_README_RULES` | Hard rules (P2 v2) |
| `.in/.processed/README.md` | L27 | `MRK:PROCESSED_README_CONFLICT` | Conflict-resolution |
| `.in/.processed/README.md` | L35 | `MRK:PROCESSED_README_CUSTOM` | Custom context (preserved) |
| `.in/DCPTCN_TG_beacon.md` | L8 | `MRK:DCPTCN_TG_BEACON` | DCPTCN_TG project beacon |
| `.in/ORCA-SLIDES_beacon.md` | L8 | `MRK:ORCA_SLIDES_BEACON` | ORCA-SLIDES project beacon |
| `.in/ORCA_DOCS_beacon.md` | L8 | `MRK:ORCA_DOCS_BEACON` | ORCA_DOCS project beacon |
| `.in/ORCA_RELEASE_beacon.md` | L8 | `MRK:ORCA_RELEASE_BEACON` | ORCA_RELEASE project beacon |
| `.in/README.md` | L11 | `MRK:IN_README_PROTOCOL` | Access protocol (P1 v3) |
| `.in/README.md` | L18 | `MRK:IN_README_RULES` | Hard rules (P2 v2) |
| `.in/README.md` | L27 | `MRK:IN_README_CONFLICT` | Conflict-resolution |
| `.in/README.md` | L35 | `MRK:IN_README_CUSTOM` | Custom context (preserved) |
| `.in/SPEC-DCPTCN_TG-orientation-20260427-132500.md` | L13 | `MRK:DCPTCN_SPEC_STATUS` | Status & delivery target |
| `.in/SPEC-DCPTCN_TG-orientation-20260427-132500.md` | L22 | `MRK:DCPTCN_SPEC_ENGMODEL` | Generic engagement model |
| `.in/SPEC-DCPTCN_TG-orientation-20260427-132500.md` | L41 | `MRK:DCPTCN_SPEC_METHODOLOGY` | Unified methodology lifecycle |
| `.in/SPEC-DCPTCN_TG-orientation-20260427-132500.md` | L83 | `MRK:DCPTCN_SPEC_DECEPTICON` | Decepticon planner generalization |
| `.in/SPEC-DCPTCN_TG-orientation-20260427-132500.md` | L100 | `MRK:DCPTCN_SPEC_ARCH` | Architecture bottom line |
| `.in/SPEC-DCPTCN_TG-orientation-20260427-132500.md` | L114 | `MRK:DCPTCN_SPEC_REPO` | Decepticon repo analysis |
| `AUDIT-ORC-INDEX.md` | L30 | `MRK:INDEX_PROTOCOL` | Access protocol |
| `AUDIT-ORC-INDEX.md` | L37 | `MRK:INDEX_RULES` | Hard rules |
| `AUDIT-ORC-INDEX.md` | L46 | `MRK:INDEX_TOOL` | Reindex tool reference |
| `AUDIT-ORC-INDEX.md` | L59 | `MRK:INDEX_FILES` | Files by directory |
| `AUDIT-ORC-INDEX.md` | L431 | `MRK:INDEX_ALL` | All anchors (flat, 450 entries) |
| `CHANGELOG.md` | L16 | `MRK:RELEASE_V081` | v0.8.1 — 2026-04-21 |
| `CHANGELOG.md` | L73 | `MRK:RELEASE_V08` | v0.8 — 2026-04-20 |
| `NAV-MAIN-INDEX.md` | L8 | `MRK:NAV_MAIN_PROJECTS` | Project registry |
| `NOTICE.md` | L19 | `MRK:NOTICE_COMPONENTS` | Components |
| `NOTICE.md` | L22 | `MRK:NOTICE_PTORC` | PT-Orc suite |
| `NOTICE.md` | L44 | `MRK:NOTICE_ORCNAV` | ORC NAV system |
| `NOTICE.md` | L62 | `MRK:NOTICE_LICENSING` | Licensing |
| `NOTICE.md` | L79 | `MRK:NOTICE_CONTACT` | Contact |
| `NOTICE.md` | L85 | `MRK:NOTICE_LLMNOTE` | For LLMs reading this repo |
| `deliverables/DCPTCN_TG/EXEC-SUMMARY-review-20260427.md` | L11 | `MRK:EXEC_VERDICT` | Overall verdict + decision confirmation |
| `deliverables/DCPTCN_TG/EXEC-SUMMARY-review-20260427.md` | L29 | `MRK:EXEC_FINDINGS` | Key findings from external review |
| `deliverables/DCPTCN_TG/EXEC-SUMMARY-review-20260427.md` | L53 | `MRK:EXEC_ACTIONS` | Action items entering TG planning |
| `deliverables/DCPTCN_TG/EXEC-SUMMARY-review-20260427.md` | L64 | `MRK:EXEC_STATUS` | Broadcast + reply status |
| `deliverables/DCPTCN_TG/PHASE1-gap-analysis-v01-v02-20260427.md` | L15 | `MRK:GAP_SUMMARY` | Executive summary |
| `deliverables/DCPTCN_TG/PHASE1-gap-analysis-v01-v02-20260427.md` | L33 | `MRK:GAP_STRUCTURE` | Document structure comparison |
| `deliverables/DCPTCN_TG/PHASE1-gap-analysis-v01-v02-20260427.md` | L67 | `MRK:GAP_TOOLING` | Tooling changes: v0.1 → v0.2 |
| `deliverables/DCPTCN_TG/PHASE1-gap-analysis-v01-v02-20260427.md` | L111 | `MRK:GAP_LIFECYCLE` | Lifecycle stage changes |
| `deliverables/DCPTCN_TG/PHASE1-gap-analysis-v01-v02-20260427.md` | L155 | `MRK:GAP_MODELS` | Model changes: evidence, findings, artifacts |
| `deliverables/DCPTCN_TG/PHASE1-gap-analysis-v01-v02-20260427.md` | L177 | `MRK:GAP_DROPPED` | What v0.1 had that v0.2 dropped or weakened |
| `deliverables/DCPTCN_TG/PHASE1-gap-analysis-v01-v02-20260427.md` | L192 | `MRK:GAP_BUILDORDER` | Implementation order (v0.2 §18) |
| `deliverables/DCPTCN_TG/PHASE1-gap-analysis-v01-v02-20260427.md` | L217 | `MRK:GAP_VERDICT` | Phase 1 verdict for DCPTCN_TG |
| `deliverables/DCPTCN_TG/PHASE2-fit-assessment-20260427.md` | L16 | `MRK:FIT_SUMMARY` | Executive summary |
| `deliverables/DCPTCN_TG/PHASE2-fit-assessment-20260427.md` | L28 | `MRK:FIT_COMPONENTS` | Decepticon component inventory |
| `deliverables/DCPTCN_TG/PHASE2-fit-assessment-20260427.md` | L68 | `MRK:FIT_MAP` | Component → TG-CORE-* mapping |
| `deliverables/DCPTCN_TG/PHASE2-fit-assessment-20260427.md` | L101 | `MRK:FIT_REUSABLE` | Reusable as-is |
| `deliverables/DCPTCN_TG/PHASE2-fit-assessment-20260427.md` | L149 | `MRK:FIT_PARAMETERIZE` | Needs parameterization |
| `deliverables/DCPTCN_TG/PHASE2-fit-assessment-20260427.md` | L205 | `MRK:FIT_DROP` | Offensive-specific: drop |
| `deliverables/DCPTCN_TG/PHASE2-fit-assessment-20260427.md` | L226 | `MRK:FIT_GAPS` | Decepticon concepts not in v0.2 |
| `deliverables/DCPTCN_TG/PHASE2-fit-assessment-20260427.md` | L248 | `MRK:FIT_ARCHITECTURE` | Extraction architecture |
| `deliverables/DCPTCN_TG/PHASE2-fit-assessment-20260427.md` | L305 | `MRK:FIT_VERDICT` | Phase 2 verdict for DCPTCN_TG |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L18 | `MRK:SPEC_OVERVIEW` | Overview and design decisions |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L41 | `MRK:SPEC_LIBRARY` | EngagementCore library structure |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L98 | `MRK:SPEC_OBJECTIVE` | Generalized Objective schema |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L186 | `MRK:SPEC_OPPLAN` | Generalized OPPLAN + OPPLANMiddleware |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L230 | `MRK:SPEC_BUNDLE` | Generalized EngagementBundle |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L306 | `MRK:SPEC_STATE` | Generalized EngagementState + phases |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L392 | `MRK:SPEC_PACK` | MethodologyPack base class |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L487 | `MRK:SPEC_INTAKE` | Generalized intake interview (Soundwave) |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L563 | `MRK:SPEC_NEWPLACEHOLDERS` | New v0.2 placeholder proposals |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L617 | `MRK:SPEC_MIGRATION` | Decepticon migration path |
| `deliverables/DCPTCN_TG/PHASE3-generalization-spec-20260427.md` | L663 | `MRK:SPEC_VERDICT` | Phase 3 verdict |
| `deliverables/DCPTCN_TG/PHASE4-methodology-packs-20260427.md` | L16 | `MRK:PACK_OVERVIEW` | All-pack summary + D-004 decision |
| `deliverables/DCPTCN_TG/PHASE4-methodology-packs-20260427.md` | L48 | `MRK:PACK_PENTEST` | Pentest pack (PentestPack) |
| `deliverables/DCPTCN_TG/PHASE4-methodology-packs-20260427.md` | L132 | `MRK:PACK_TSA` | Tech Security Assessment pack |
| `deliverables/DCPTCN_TG/PHASE4-methodology-packs-20260427.md` | L216 | `MRK:PACK_ISO27001` | ISO 27001 Audit pack |
| `deliverables/DCPTCN_TG/PHASE4-methodology-packs-20260427.md` | L309 | `MRK:PACK_COMPLIANCE` | Compliance Evidence Review pack |
| `deliverables/DCPTCN_TG/PHASE4-methodology-packs-20260427.md` | L415 | `MRK:PACK_GAP` | Gap Assessment pack |
| `deliverables/DCPTCN_TG/PHASE4-methodology-packs-20260427.md` | L512 | `MRK:PACK_REMEDIATION` | Remediation Verification pack |
| `deliverables/DCPTCN_TG/PHASE4-methodology-packs-20260427.md` | L595 | `MRK:PACK_DISPATCHER` | Pack selection + loading in tg-audit-orchestrator |
| `deliverables/DCPTCN_TG/PHASE4-methodology-packs-20260427.md` | L657 | `MRK:PACK_VERDICT` | Phase 4 summary + D-004 closure |
| `deliverables/DCPTCN_TG/PHASE5-architecture-decision-20260427.md` | L15 | `MRK:ARCH_OVERVIEW` | Summary + all decisions closed |
| `deliverables/DCPTCN_TG/PHASE5-architecture-decision-20260427.md` | L50 | `MRK:ARCH_TIERS` | Three-tier component architecture |
| `deliverables/DCPTCN_TG/PHASE5-architecture-decision-20260427.md` | L118 | `MRK:ARCH_ENGCORE` | ADR-001: EngagementCore extraction |
| `deliverables/DCPTCN_TG/PHASE5-architecture-decision-20260427.md` | L145 | `MRK:ARCH_FWREG` | ADR-002: FrameworkRegistry in EngagementCore |
| `deliverables/DCPTCN_TG/PHASE5-architecture-decision-20260427.md` | L206 | `MRK:ARCH_ENGID` | ADR-003: EngagementID scheme |
| `deliverables/DCPTCN_TG/PHASE5-architecture-decision-20260427.md` | L263 | `MRK:ARCH_AGENT` | ADR-004: Shared agent patterns |
| `deliverables/DCPTCN_TG/PHASE5-architecture-decision-20260427.md` | L327 | `MRK:ARCH_MVP` | ADR-005: MVP delivery scope (D-003 closure) |
| `deliverables/DCPTCN_TG/PHASE5-architecture-decision-20260427.md` | L378 | `MRK:ARCH_VERDICT` | Phase 5 architecture summary |
| `deliverables/DCPTCN_TG/PHASE5-v03-methodology-sections-20260427.md` | L13 | `MRK:V03_OVERVIEW` | v0.3 change log + structure guide |
| `deliverables/DCPTCN_TG/PHASE5-v03-methodology-sections-20260427.md` | L41 | `MRK:V03_ENGAGEMENT_MODEL` | §NEW: Generic 10-entity engagement model |
| `deliverables/DCPTCN_TG/PHASE5-v03-methodology-sections-20260427.md` | L101 | `MRK:V03_PACK_ARCH` | §NEW: MethodologyPack architecture |
| `deliverables/DCPTCN_TG/PHASE5-v03-methodology-sections-20260427.md` | L171 | `MRK:V03_TOOLING_NEW` | §UPDATED: New TG-* placeholders + build order |
| `deliverables/DCPTCN_TG/PHASE5-v03-methodology-sections-20260427.md` | L231 | `MRK:V03_DECEPTICON` | §20 UPDATED: Decepticon role — open question CLOSED |
| `deliverables/DCPTCN_TG/PHASE5-v03-methodology-sections-20260427.md` | L296 | `MRK:V03_DELTA` | Full v0.2 → v0.3 delta summary |
| `docs/docs-index.md` | L8 | `MRK:DOCS_INDEX_FILES` | Files in this directory |
| `docs/system-assessment-v1-initial.md` | L13 | `MRK:ASSESS_OVERVIEW` | Assessment basis and scope |
| `docs/system-assessment-v1-initial.md` | L36 | `MRK:ASSESS_SYSTEM` | What the system is |
| `docs/system-assessment-v1-initial.md` | L69 | `MRK:ASSESS_STRENGTHS` | What works genuinely well |
| `docs/system-assessment-v1-initial.md` | L108 | `MRK:ASSESS_GAPS` | Where it is strained |
| `docs/system-assessment-v1-initial.md` | L149 | `MRK:ASSESS_VERDICT` | Overall verdict and recommendation |
| `docs/system-assessment-v1-initial.md` | L178 | `MRK:ASSESS_META` | AI meta-observation |
| `docs/tg-unified-audit-methodology-v0.3.md` | L22 | `MRK:TG_METH_HEADER` | Version header |
| `docs/tg-unified-audit-methodology-v0.3.md` | L35 | `MRK:TG_METH_PURPOSE` | §1 Purpose and Intent |
| `docs/tg-unified-audit-methodology-v0.3.md` | L57 | `MRK:TG_METH_PRINCIPLE` | §2–3 Core Principle + Design |
| `docs/tg-unified-audit-methodology-v0.3.md` | L95 | `MRK:TG_METH_LAYERS` | §4 Methodology Layers + platform architecture |
| `docs/tg-unified-audit-methodology-v0.3.md` | L194 | `MRK:TG_METH_TOOLING` | §5–7 Tooling model + placeholder tables |
| `docs/tg-unified-audit-methodology-v0.3.md` | L262 | `MRK:TG_METH_LIFECYCLE` | §8–9 Human model + lifecycle |
| `docs/tg-unified-audit-methodology-v0.3.md` | L569 | `MRK:TG_METH_MODELS` | §10–13 Roles, artifacts, evidence, findings |
| `docs/tg-unified-audit-methodology-v0.3.md` | L652 | `MRK:TG_METH_SERVICES` | §14 Service Module Placeholders |
| `docs/tg-unified-audit-methodology-v0.3.md` | L735 | `MRK:TG_METH_EM` | §EM Generic Engagement Model |
| `docs/tg-unified-audit-methodology-v0.3.md` | L791 | `MRK:TG_METH_MP` | §MP MethodologyPack Architecture |
| `docs/tg-unified-audit-methodology-v0.3.md` | L858 | `MRK:TG_METH_WORKSPACE` | §15 Project Workspace |
| `docs/tg-unified-audit-methodology-v0.3.md` | L880 | `MRK:TG_METH_OPS` | §16–17 Exceptions + Metrics |
| `docs/tg-unified-audit-methodology-v0.3.md` | L931 | `MRK:TG_METH_BUILDORDER` | §18 Implementation Order |
| `docs/tg-unified-audit-methodology-v0.3.md` | L960 | `MRK:TG_METH_NEXTDOCS` | §19 Immediate Next Deliverables |
| `docs/tg-unified-audit-methodology-v0.3.md` | L979 | `MRK:TG_METH_DECEPTICON` | §20 Decepticon + platform architecture |
| `nav-orc/tools/README.md` | L11 | `MRK:TOOLS_README_PROTOCOL` | Access protocol (P1 v3) |
| `nav-orc/tools/README.md` | L18 | `MRK:TOOLS_README_RULES` | Hard rules (P2 v2) |
| `nav-orc/tools/README.md` | L27 | `MRK:TOOLS_README_CONFLICT` | Conflict-resolution |
| `nav-orc/tools/README.md` | L35 | `MRK:TOOLS_README_CUSTOM` | Custom context (preserved) |
| `nav-orc/tools/orc-nav-reindex.py` | L64 | `MRK:REINDEX_CONSTANTS` | Module constants and configuration |
| `nav-orc/tools/orc-nav-reindex.py` | L127 | `MRK:REINDEX_DETECT` | File type detection |
| `nav-orc/tools/orc-nav-reindex.py` | L143 | `MRK:REINDEX_PARSE` | Anchor and TOC parsing |
| `nav-orc/tools/orc-nav-reindex.py` | L243 | `MRK:REINDEX_STRIP` | Legacy format stripping |
| `nav-orc/tools/orc-nav-reindex.py` | L412 | `MRK:REINDEX_EMIT` | Output generation helpers |
| `nav-orc/tools/orc-nav-reindex.py` | L532 | `MRK:REINDEX_MIGRATE` | Core migration and reindex engine |
| `nav-orc/tools/orc-nav-reindex.py` | L810 | `MRK:REINDEX_CLI` | Scope configuration and file collection |
| `nav-orc/tools/orc-nav-reindex.py` | L908 | `MRK:REINDEX_CMDS` | Migrate, verify, reindex subcommands |
| `nav-orc/tools/orc-nav-reindex.py` | L1007 | `MRK:REINDEX_INDEX_HELPERS` | Index generation helpers |
| `nav-orc/tools/orc-nav-reindex.py` | L1327 | `MRK:REINDEX_CMD_INDEX` | Index subcommand |
| `nav-orc/tools/orc-nav-reindex.py` | L1473 | `MRK:REINDEX_CMD_APPEND` | Append subcommand |
| `nav-orc/tools/orc-nav-reindex.py` | L1598 | `MRK:REINDEX_CMD_MAIN_INDEX` | main-index subcommand: hierarchical MAIN-INDEX + dirname-indexes |
| `nav-orc/tools/orc-nav-reindex.py` | L1645 | `MRK:REINDEX_MAIN` | Entry point and subcommand dispatch |
| `nav-orc/tools/pt-orc-reindex.ps1` | L19 | `MRK:REINDEX_PS1_SETUP` | Setup: find Python tool + resolver |
| `nav-orc/tools/pt-orc-reindex.ps1` | L40 | `MRK:REINDEX_PS1_DISPATCH` | Flag dispatch |
| `nav-orc/tools/pt-orc-reindex.sh` | L19 | `MRK:REINDEX_SH_SETUP` | Setup: find Python tool + resolver |
| `nav-orc/tools/pt-orc-reindex.sh` | L40 | `MRK:REINDEX_SH_DISPATCH` | Flag dispatch |
| `nav-orc/tools/tools-index.md` | L8 | `MRK:TOOLS_INDEX_FILES` | Files in this directory |
| `pt-orc/correlations/correlations-index.md` | L8 | `MRK:CORRELATIONS_INDEX_FILES` | Files in this directory |
| `pt-orc/docs/README.md` | L11 | `MRK:DOCS_README_PROTOCOL` | Access protocol (P1 v3) |
| `pt-orc/docs/README.md` | L18 | `MRK:DOCS_README_RULES` | Hard rules (P2 v2) |
| `pt-orc/docs/README.md` | L27 | `MRK:DOCS_README_CONFLICT` | Conflict-resolution |
| `pt-orc/docs/README.md` | L35 | `MRK:DOCS_README_CUSTOM` | Custom context (preserved) |
| `pt-orc/docs/design.md` | L14 | `MRK:PATTERNS` | Shared Patterns |
| `pt-orc/docs/design.md` | L62 | `MRK:GOTCHAS` | Key Design Decisions and Gotchas |
| `pt-orc/docs/design.md` | L101 | `MRK:D03` | 03_comp_scan.sh Architecture |
| `pt-orc/docs/design.md` | L168 | `MRK:TOOLS` | Tool Dependencies |
| `pt-orc/docs/docs-index.md` | L8 | `MRK:DOCS_INDEX_FILES` | Files in this directory |
| `pt-orc/docs/funcs.md` | L16 | `MRK:CTX` | §0. Context |
| `pt-orc/docs/funcs.md` | L32 | `MRK:S00` | 00_pt-orc.sh |
| `pt-orc/docs/funcs.md` | L51 | `MRK:S01` | 01_dns_recon.sh |
| `pt-orc/docs/funcs.md` | L85 | `MRK:S03` | 03_comp_scan.sh |
| `pt-orc/docs/funcs.md` | L201 | `MRK:S04` | 04_tls_scan.sh |
| `pt-orc/docs/funcs.md` | L226 | `MRK:S05` | 05_web_enum.sh |
| `pt-orc/docs/funcs.md` | L260 | `MRK:S02` | 02_ip_analysis.sh |
| `pt-orc/docs/funcs.md` | L282 | `MRK:S06` | 06_wpscan.sh |
| `pt-orc/docs/funcs.md` | L307 | `MRK:S07` | 07_service_verify.sh |
| `pt-orc/docs/ops.md` | L17 | `MRK:OPS_SCRIPTS` | Scripts at a Glance |
| `pt-orc/docs/ops.md` | L47 | `MRK:OPS_PIPELINE` | Pipeline |
| `pt-orc/docs/ops.md` | L134 | `MRK:OPS_FLAGS` | CLI Flags |
| `pt-orc/docs/ops.md` | L222 | `MRK:OPS_OPERATIONS` | Common Operations |
| `pt-orc/docs/ops.md` | L287 | `MRK:OPS_DIRS` | Directory Structure |
| `pt-orc/docs/orientation.md` | L16 | `MRK:IDX_S0` | §0. MRK Naming Convention |
| `pt-orc/docs/orientation.md` | L44 | `MRK:IDX_S1` | §1. Suite Overview |
| `pt-orc/docs/orientation.md` | L64 | `MRK:IDX_S2` | §2. Data Flow |
| `pt-orc/docs/orientation.md` | L83 | `MRK:IDX_S3` | §3. Engagement Config |
| `pt-orc/docs/orientation.md` | L150 | `MRK:IDX_S4` | §4. Evidence Directory Layout |
| `pt-orc/docs/orientation.md` | L242 | `MRK:IDX_S5` | §5. Stealth Tier Reference |
| `pt-orc/docs/skill-brief.md` | L29 | `MRK:SKL_HOWTO` | How to Use This File |
| `pt-orc/docs/skill-brief.md` | L33 | `MRK:SKL_S0` | §0. Skill Navigation Protocol — how the skill reads suite files efficiently |
| `pt-orc/docs/skill-brief.md` | L115 | `MRK:SKL_S1` | §1. Skill Role |
| `pt-orc/docs/skill-brief.md` | L135 | `MRK:SKL_S2` | §2. Reference File Loading Strategy |
| `pt-orc/docs/skill-brief.md` | L148 | `MRK:SKL_S3` | §3. State Snapshot Schema |
| `pt-orc/docs/skill-brief.md` | L220 | `MRK:SKL_S4` | §4. Phase → Skill Dispatch |
| `pt-orc/docs/skill-brief.md` | L239 | `MRK:SKL_S5` | §5. Evidence Consumption Map |
| `pt-orc/docs/skill-brief.md` | L304 | `MRK:SKL_S6` | §6. Finding Severity Assignment |
| `pt-orc/docs/skill-brief.md` | L325 | `MRK:SKL_S7` | §7. Hard Limits |
| `pt-orc/docs/skill-brief.md` | L338 | `MRK:SKL_S8` | §8. Skill Version Tracking |
| `pt-orc/docs/skill-brief.md` | L354 | `MRK:SKL_S9` | §9. Session Start Checklist for Skill Builder |
| `pt-orc/docs/skill-brief.md` | L369 | `MRK:SKL_S10` | §10. Multi-analyst + shared-Claude broker awareness |
| `pt-orc/docs/skill-brief.md` | L403 | `MRK:SKL_S11` | §11. Cross-engagement correlation + finding-ID namespace |
| `pt-orc/docs/skill-brief.md` | L441 | `MRK:SKL_S12` | §12. NAV-RULE + Notes protocol integration |
| `pt-orc/docs/skill-brief.md` | L478 | `MRK:SKL_S13` | §13. Planning artefacts (`.in/`, `.deleted/`, `NEXT.md`, `techguard-workplan.md`) |
| `pt-orc/modules/modules-index.md` | L8 | `MRK:MODULES_INDEX_FILES` | Files in this directory |
| `pt-orc/scripts/00_pt-orc.sh` | L61 | `MRK:00_ROOT` | ROOT CHECK |
| `pt-orc/scripts/00_pt-orc.sh` | L71 | `MRK:00_CONF` | ENGAGEMENT CONFIG |
| `pt-orc/scripts/00_pt-orc.sh` | L79 | `MRK:00_LOG` | COLOURS AND LOGGING + STEP BANNER |
| `pt-orc/scripts/00_pt-orc.sh` | L109 | `MRK:00_DEFAULTS` | DEFAULTS + STEP STATUS ACCUMULATORS |
| `pt-orc/scripts/00_pt-orc.sh` | L144 | `MRK:00_USAGE` | USAGE BANNER |
| `pt-orc/scripts/00_pt-orc.sh` | L201 | `MRK:00_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/00_pt-orc.sh` | L234 | `MRK:00_DISCOVER` | SCRIPT DISCOVERY |
| `pt-orc/scripts/00_pt-orc.sh` | L266 | `MRK:00_CONTROL` | STEP CONTROL |
| `pt-orc/scripts/00_pt-orc.sh` | L286 | `MRK:00_RUNNER` | STEP RUNNER |
| `pt-orc/scripts/00_pt-orc.sh` | L329 | `MRK:00_SUMMARY` | SUMMARY TABLE |
| `pt-orc/scripts/00_pt-orc.sh` | L395 | `MRK:00_MAIN` | MAIN |
| `pt-orc/scripts/01_dns_recon.sh` | L50 | `MRK:01_ROOT` | ROOT CHECK |
| `pt-orc/scripts/01_dns_recon.sh` | L60 | `MRK:01_CONF` | ENGAGEMENT CONFIGURATION |
| `pt-orc/scripts/01_dns_recon.sh` | L242 | `MRK:01_LOG` | COLOURS AND LOGGING |
| `pt-orc/scripts/01_dns_recon.sh` | L269 | `MRK:01_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/01_dns_recon.sh` | L289 | `MRK:01_SRCIP` | SOURCE IP VERIFICATION |
| `pt-orc/scripts/01_dns_recon.sh` | L310 | `MRK:01_CONFIRM` | SCOPE CONFIRMATION |
| `pt-orc/scripts/01_dns_recon.sh` | L343 | `MRK:01_SCOPE` | THIRD-PARTY / PRIVATE IP BOUNDARY CHECKS + add_ip accumulator |
| `pt-orc/scripts/01_dns_recon.sh` | L381 | `MRK:01_TAKEOVER` | SUBDOMAIN TAKEOVER DETECTION |
| `pt-orc/scripts/01_dns_recon.sh` | L403 | `MRK:01_STATE` | TARGET ACCUMULATORS |
| `pt-orc/scripts/01_dns_recon.sh` | L429 | `MRK:01_PASSIVE` | PASSIVE RECON |
| `pt-orc/scripts/01_dns_recon.sh` | L655 | `MRK:01_ACTIVE` | ACTIVE DNS |
| `pt-orc/scripts/01_dns_recon.sh` | L708 | `MRK:01_RESOLVE` | RESOLUTION AND LIVE CHECK |
| `pt-orc/scripts/01_dns_recon.sh` | L772 | `MRK:01_OUTPUT` | TARGET LIST + SUMMARY |
| `pt-orc/scripts/01_dns_recon.sh` | L890 | `MRK:01_MAIN` | MAIN entry point |
| `pt-orc/scripts/02_ip_analysis.sh` | L44 | `MRK:02_LOG` | COLOURS AND LOGGING |
| `pt-orc/scripts/02_ip_analysis.sh` | L62 | `MRK:02_CONF` | ENGAGEMENT CONFIGURATION |
| `pt-orc/scripts/02_ip_analysis.sh` | L91 | `MRK:02_USAGE` | USAGE |
| `pt-orc/scripts/02_ip_analysis.sh` | L116 | `MRK:02_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/02_ip_analysis.sh` | L135 | `MRK:02_DEPS` | DEPENDENCY CHECK |
| `pt-orc/scripts/02_ip_analysis.sh` | L173 | `MRK:02_TARGETS` | TARGET LOADING |
| `pt-orc/scripts/02_ip_analysis.sh` | L226 | `MRK:02_CONFIRM` | SCOPE CONFIRMATION |
| `pt-orc/scripts/02_ip_analysis.sh` | L257 | `MRK:02_CMDWRAP` | DRY-RUN COMMAND WRAPPER |
| `pt-orc/scripts/02_ip_analysis.sh` | L274 | `MRK:02_STATE` | PER-IP ACCUMULATORS |
| `pt-orc/scripts/02_ip_analysis.sh` | L288 | `MRK:02_ANALYZE` | PER-IP ANALYSIS |
| `pt-orc/scripts/02_ip_analysis.sh` | L666 | `MRK:02_REPORT` | CONSOLIDATED REPORT |
| `pt-orc/scripts/02_ip_analysis.sh` | L845 | `MRK:02_MAIN` | MAIN entry point |
| `pt-orc/scripts/03_comp_scan.sh` | L71 | `MRK:03_ROOT` | ROOT CHECK |
| `pt-orc/scripts/03_comp_scan.sh` | L81 | `MRK:03_CONF` | ENGAGEMENT CONFIGURATION |
| `pt-orc/scripts/03_comp_scan.sh` | L168 | `MRK:03_TIER` | STEALTH TIER PARAMETERS |
| `pt-orc/scripts/03_comp_scan.sh` | L318 | `MRK:03_LOG` | COLOURS AND LOGGING |
| `pt-orc/scripts/03_comp_scan.sh` | L343 | `MRK:03_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/03_comp_scan.sh` | L385 | `MRK:03_DIRS` | DIRECTORY STRUCTURE SETUP |
| `pt-orc/scripts/03_comp_scan.sh` | L409 | `MRK:03_DB` | MSF / POSTGRES DB HELPERS |
| `pt-orc/scripts/03_comp_scan.sh` | L469 | `MRK:03_SCAN` | SCAN EXECUTION MODEL |
| `pt-orc/scripts/03_comp_scan.sh` | L711 | `MRK:03_CSV` | CSV FALLBACK HELPERS |
| `pt-orc/scripts/03_comp_scan.sh` | L768 | `MRK:03_GNMAP` | GNMAP FALLBACK |
| `pt-orc/scripts/03_comp_scan.sh` | L844 | `MRK:03_SCOPE` | TIER RESOLUTION |
| `pt-orc/scripts/03_comp_scan.sh` | L940 | `MRK:03_SRCIP` | SOURCE IP VERIFICATION (PTE) |
| `pt-orc/scripts/03_comp_scan.sh` | L962 | `MRK:03_CONFIRM` | SCOPE CONFIRMATION |
| `pt-orc/scripts/03_comp_scan.sh` | L996 | `MRK:03_RATE` | RATE SELF-TEST (PTE / evasion mode) |
| `pt-orc/scripts/03_comp_scan.sh` | L1030 | `MRK:03_WS` | MSF WORKSPACE SETUP |
| `pt-orc/scripts/03_comp_scan.sh` | L1118 | `MRK:03_EXCL` | TESTER EXCLUSION |
| `pt-orc/scripts/03_comp_scan.sh` | L1422 | `MRK:03_P1` | PHASE 1: DISCOVERY |
| `pt-orc/scripts/03_comp_scan.sh` | L1456 | `MRK:03_P2` | PHASE 2: TCP FULL SCAN |
| `pt-orc/scripts/03_comp_scan.sh` | L1804 | `MRK:03_NSE` | PHASE 2b: COMMON-PORT NSE SWEEP |
| `pt-orc/scripts/03_comp_scan.sh` | L2038 | `MRK:03_OS` | PHASE 2c: OS FINGERPRINTING |
| `pt-orc/scripts/03_comp_scan.sh` | L2173 | `MRK:03_P3` | PHASE 3: UDP CORRELATION SCAN |
| `pt-orc/scripts/03_comp_scan.sh` | L2269 | `MRK:03_P4` | PHASE 4: SERVICE ENUMERATION |
| `pt-orc/scripts/03_comp_scan.sh` | L2275 | `MRK:03_PROBES` | Active service probes |
| `pt-orc/scripts/03_comp_scan.sh` | L2610 | `MRK:03_P4B` | PHASE 4b: PTE SERVICE ENUMERATION |
| `pt-orc/scripts/03_comp_scan.sh` | L2776 | `MRK:03_P5` | PHASE 5: REPORT / SUMMARY |
| `pt-orc/scripts/03_comp_scan.sh` | L2847 | `MRK:03_MAIN` | MAIN |
| `pt-orc/scripts/04_tls_scan.sh` | L50 | `MRK:04_ROOT` | ROOT CHECK |
| `pt-orc/scripts/04_tls_scan.sh` | L60 | `MRK:04_CONF` | ENGAGEMENT CONFIGURATION |
| `pt-orc/scripts/04_tls_scan.sh` | L88 | `MRK:04_LOG` | COLOURS AND LOGGING |
| `pt-orc/scripts/04_tls_scan.sh` | L114 | `MRK:04_DB` | MSF DB CREDENTIALS |
| `pt-orc/scripts/04_tls_scan.sh` | L136 | `MRK:04_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/04_tls_scan.sh` | L155 | `MRK:04_SCAN` | SCAN EXECUTION MODEL |
| `pt-orc/scripts/04_tls_scan.sh` | L224 | `MRK:04_CONFIRM` | SCOPE CONFIRMATION |
| `pt-orc/scripts/04_tls_scan.sh` | L250 | `MRK:04_TARGETS` | TARGET LIST ASSEMBLY |
| `pt-orc/scripts/04_tls_scan.sh` | L283 | `MRK:04_ASSESS` | PER-HOST TLS ASSESSMENT |
| `pt-orc/scripts/04_tls_scan.sh` | L636 | `MRK:04_SCREENS` | SCREENSHOT CAPTURE |
| `pt-orc/scripts/04_tls_scan.sh` | L656 | `MRK:04_MAIN` | MAIN entry point |
| `pt-orc/scripts/05_web_enum.sh` | L55 | `MRK:05_ROOT` | ROOT CHECK |
| `pt-orc/scripts/05_web_enum.sh` | L65 | `MRK:05_CONF` | ENGAGEMENT CONFIGURATION |
| `pt-orc/scripts/05_web_enum.sh` | L110 | `MRK:05_LOG` | COLOURS AND LOGGING |
| `pt-orc/scripts/05_web_enum.sh` | L135 | `MRK:05_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/05_web_enum.sh` | L157 | `MRK:05_DB` | MSF DB HELPERS |
| `pt-orc/scripts/05_web_enum.sh` | L227 | `MRK:05_SCAN` | SCAN EXECUTION MODEL |
| `pt-orc/scripts/05_web_enum.sh` | L297 | `MRK:05_CONFIRM` | SCOPE CONFIRMATION |
| `pt-orc/scripts/05_web_enum.sh` | L324 | `MRK:05_TARGETS` | TARGET ASSEMBLY |
| `pt-orc/scripts/05_web_enum.sh` | L364 | `MRK:05_TLS` | TLS DETECTION |
| `pt-orc/scripts/05_web_enum.sh` | L382 | `MRK:05_ENUM` | PER-HOST WEB ENUMERATION |
| `pt-orc/scripts/05_web_enum.sh` | L773 | `MRK:05_MAIN` | MAIN entry point |
| `pt-orc/scripts/06_wpscan.sh` | L45 | `MRK:06_LOG` | COLOURS AND LOGGING |
| `pt-orc/scripts/06_wpscan.sh` | L63 | `MRK:06_CONF` | ENGAGEMENT CONFIGURATION |
| `pt-orc/scripts/06_wpscan.sh` | L110 | `MRK:06_USAGE` | USAGE |
| `pt-orc/scripts/06_wpscan.sh` | L141 | `MRK:06_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/06_wpscan.sh` | L164 | `MRK:06_DEPS` | DEPENDENCY CHECK |
| `pt-orc/scripts/06_wpscan.sh` | L196 | `MRK:06_DETECT` | PHASE 1 WP DETECTION SWEEP |
| `pt-orc/scripts/06_wpscan.sh` | L305 | `MRK:06_LOAD` | PHASE 2 TARGET LOADING |
| `pt-orc/scripts/06_wpscan.sh` | L335 | `MRK:06_CONFIRM` | SCOPE CONFIRMATION |
| `pt-orc/scripts/06_wpscan.sh` | L369 | `MRK:06_HELP` | HELPERS |
| `pt-orc/scripts/06_wpscan.sh` | L387 | `MRK:06_STATE` | PER-TARGET ACCUMULATORS |
| `pt-orc/scripts/06_wpscan.sh` | L403 | `MRK:06_ASSESS` | PER-TARGET ASSESSMENT |
| `pt-orc/scripts/06_wpscan.sh` | L895 | `MRK:06_REPORT` | CONSOLIDATED REPORT |
| `pt-orc/scripts/06_wpscan.sh` | L1063 | `MRK:06_MAIN` | MAIN entry point |
| `pt-orc/scripts/07_service_verify.sh` | L81 | `MRK:07_ROOT` | ROOT CHECK |
| `pt-orc/scripts/07_service_verify.sh` | L91 | `MRK:07_CONF` | ENGAGEMENT CONFIGURATION |
| `pt-orc/scripts/07_service_verify.sh` | L132 | `MRK:07_LOG` | COLOURS AND LOGGING |
| `pt-orc/scripts/07_service_verify.sh` | L154 | `MRK:07_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/07_service_verify.sh` | L179 | `MRK:07_DB` | MSF DB + MODULE RUNNER |
| `pt-orc/scripts/07_service_verify.sh` | L244 | `MRK:07_RESULTS` | RESULT TRACKING  "STATUS |
| `pt-orc/scripts/07_service_verify.sh` | L262 | `MRK:07_PARSE` | INPUT PARSING |
| `pt-orc/scripts/07_service_verify.sh` | L579 | `MRK:07_TOOLS` | TOOL AVAILABILITY |
| `pt-orc/scripts/07_service_verify.sh` | L604 | `MRK:07_DIR` | EVIDENCE DIR HELPER |
| `pt-orc/scripts/07_service_verify.sh` | L616 | `MRK:07_P_REDIS` | PROBE: REDIS NOAUTH |
| `pt-orc/scripts/07_service_verify.sh` | L687 | `MRK:07_P_MYSQL` | PROBE: MYSQL NOAUTH / ANONYMOUS LOGIN |
| `pt-orc/scripts/07_service_verify.sh` | L748 | `MRK:07_P_PG` | PROBE: POSTGRESQL NOAUTH |
| `pt-orc/scripts/07_service_verify.sh` | L813 | `MRK:07_P_MONGO` | PROBE: MONGODB NOAUTH |
| `pt-orc/scripts/07_service_verify.sh` | L879 | `MRK:07_P_SSH` | PROBE: SSH VERSION |
| `pt-orc/scripts/07_service_verify.sh` | L1010 | `MRK:07_P_FTP` | PROBE: FTP ANONYMOUS LOGIN |
| `pt-orc/scripts/07_service_verify.sh` | L1082 | `MRK:07_P_SMB` | PROBE: SMB NULL SESSION (PTI) |
| `pt-orc/scripts/07_service_verify.sh` | L1154 | `MRK:07_P_SNMP` | PROBE: SNMP DEFAULT COMMUNITY |
| `pt-orc/scripts/07_service_verify.sh` | L1216 | `MRK:07_P_SMTP` | PROBE: SMTP OPEN RELAY |
| `pt-orc/scripts/07_service_verify.sh` | L1283 | `MRK:07_P_SSRF` | PROBE: SSRF → IMDS (PTE) |
| `pt-orc/scripts/07_service_verify.sh` | L1358 | `MRK:07_P_TLS` | PROBE: TLS CERT VALIDITY |
| `pt-orc/scripts/07_service_verify.sh` | L1424 | `MRK:07_P_WEBH` | PROBE: HTTP SECURITY HEADERS |
| `pt-orc/scripts/07_service_verify.sh` | L1472 | `MRK:07_ENUM` | POST-VULN ENUMERATION |
| `pt-orc/scripts/07_service_verify.sh` | L1644 | `MRK:07_P_MSSQL` | PROBE: MSSQL |
| `pt-orc/scripts/07_service_verify.sh` | L1691 | `MRK:07_P_NFS` | PROBE: NFS |
| `pt-orc/scripts/07_service_verify.sh` | L1730 | `MRK:07_P_TELNET` | PROBE: Telnet |
| `pt-orc/scripts/07_service_verify.sh` | L1767 | `MRK:07_P_IPMI` | PROBE: IPMI |
| `pt-orc/scripts/07_service_verify.sh` | L1822 | `MRK:07_P_RDP` | PROBE: RDP |
| `pt-orc/scripts/07_service_verify.sh` | L1866 | `MRK:07_P_WINRM` | PROBE: WinRM |
| `pt-orc/scripts/07_service_verify.sh` | L1917 | `MRK:07_P_WEBGEN` | PROBE: Web generic |
| `pt-orc/scripts/07_service_verify.sh` | L2433 | `MRK:07_INGEST` | PHASE 0 INGEST STUBS |
| `pt-orc/scripts/07_service_verify.sh` | L2514 | `MRK:07_DISPATCH` | PROBE DISPATCHER |
| `pt-orc/scripts/07_service_verify.sh` | L2616 | `MRK:07_REPORT` | REPORT WRITER |
| `pt-orc/scripts/07_service_verify.sh` | L2724 | `MRK:07_CONFIRM` | SCOPE CONFIRMATION |
| `pt-orc/scripts/07_service_verify.sh` | L2752 | `MRK:07_MAIN` | MAIN entry point |
| `pt-orc/scripts/08_app_api_review.sh` | L80 | `MRK:08_ROOT` | ROOT CHECK |
| `pt-orc/scripts/08_app_api_review.sh` | L90 | `MRK:08_CONF` | ENGAGEMENT CONFIGURATION |
| `pt-orc/scripts/08_app_api_review.sh` | L146 | `MRK:08_LOG` | COLOURS AND LOGGING |
| `pt-orc/scripts/08_app_api_review.sh` | L169 | `MRK:08_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/08_app_api_review.sh` | L199 | `MRK:08_DB` | MSF DB HELPERS |
| `pt-orc/scripts/08_app_api_review.sh` | L255 | `MRK:08_CONFIRM` | SCOPE CONFIRMATION |
| `pt-orc/scripts/08_app_api_review.sh` | L274 | `MRK:08_TARGETS` | TARGET ASSEMBLY |
| `pt-orc/scripts/08_app_api_review.sh` | L307 | `MRK:08_FIND` | FINDING WRITER |
| `pt-orc/scripts/08_app_api_review.sh` | L333 | `MRK:08_UTILS` | SHARED UTILITIES |
| `pt-orc/scripts/08_app_api_review.sh` | L398 | `MRK:08_PROF` | PROFILE SETUP |
| `pt-orc/scripts/08_app_api_review.sh` | L438 | `MRK:08_T01` | T01 HTTP METHOD ENUM |
| `pt-orc/scripts/08_app_api_review.sh` | L503 | `MRK:08_T02` | T02 SCHEMA DISCOVERY |
| `pt-orc/scripts/08_app_api_review.sh` | L555 | `MRK:08_T03` | T03 AUTHENTICATION |
| `pt-orc/scripts/08_app_api_review.sh` | L634 | `MRK:08_T04` | T04 RATE LIMITING |
| `pt-orc/scripts/08_app_api_review.sh` | L684 | `MRK:08_T05` | T05 CORS MISCONFIG |
| `pt-orc/scripts/08_app_api_review.sh` | L738 | `MRK:08_T06` | T06 BOLA/IDOR |
| `pt-orc/scripts/08_app_api_review.sh` | L783 | `MRK:08_T07` | T07 MASS ASSIGNMENT |
| `pt-orc/scripts/08_app_api_review.sh` | L837 | `MRK:08_T08` | T08 SECURITY HEADERS |
| `pt-orc/scripts/08_app_api_review.sh` | L905 | `MRK:08_T09` | T09 JWT ATTACKS |
| `pt-orc/scripts/08_app_api_review.sh` | L1005 | `MRK:08_T10` | T10 GRAPHQL |
| `pt-orc/scripts/08_app_api_review.sh` | L1078 | `MRK:08_T11` | T11 SSRF |
| `pt-orc/scripts/08_app_api_review.sh` | L1161 | `MRK:08_T12` | T12 XXE |
| `pt-orc/scripts/08_app_api_review.sh` | L1215 | `MRK:08_T13` | T13 SSTI |
| `pt-orc/scripts/08_app_api_review.sh` | L1270 | `MRK:08_T14` | T14 HTTP SMUGGLING |
| `pt-orc/scripts/08_app_api_review.sh` | L1323 | `MRK:08_T15` | T15 HOST HEADER INJECTION |
| `pt-orc/scripts/08_app_api_review.sh` | L1373 | `MRK:08_T16` | T16 API VERSIONING |
| `pt-orc/scripts/08_app_api_review.sh` | L1414 | `MRK:08_T17` | T17 SENSITIVE DATA EXPOSURE |
| `pt-orc/scripts/08_app_api_review.sh` | L1475 | `MRK:08_T18` | T18 BUSINESS LOGIC |
| `pt-orc/scripts/08_app_api_review.sh` | L1528 | `MRK:08_T19` | T19 WEBSOCKET DETECTION |
| `pt-orc/scripts/08_app_api_review.sh` | L1563 | `MRK:08_T20` | T20 TLS & TRANSPORT CHECKS |
| `pt-orc/scripts/08_app_api_review.sh` | L1634 | `MRK:08_TRUN` | PER-TARGET DISPATCHER |
| `pt-orc/scripts/08_app_api_review.sh` | L1707 | `MRK:08_MAIN` | MAIN ENTRY POINT |
| `pt-orc/scripts/09_ai_llm_review.sh` | L47 | `MRK:09_ROOT` | ROOT CHECK |
| `pt-orc/scripts/09_ai_llm_review.sh` | L57 | `MRK:09_CONF` | ENGAGEMENT CONFIGURATION |
| `pt-orc/scripts/09_ai_llm_review.sh` | L99 | `MRK:09_LOG` | COLOURS AND LOGGING |
| `pt-orc/scripts/09_ai_llm_review.sh` | L122 | `MRK:09_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/09_ai_llm_review.sh` | L140 | `MRK:09_DB` | MSF DB HELPERS |
| `pt-orc/scripts/09_ai_llm_review.sh` | L204 | `MRK:09_CONFIRM` | SCOPE CONFIRMATION |
| `pt-orc/scripts/09_ai_llm_review.sh` | L230 | `MRK:09_TARGETS` | TARGET ASSEMBLY |
| `pt-orc/scripts/09_ai_llm_review.sh` | L270 | `MRK:09_FINDING` | FINDING WRITER |
| `pt-orc/scripts/09_ai_llm_review.sh` | L299 | `MRK:09_TEST` | PER-TARGET LLM TESTING |
| `pt-orc/scripts/09_ai_llm_review.sh` | L763 | `MRK:09_MAIN` | MAIN entry point |
| `pt-orc/scripts/12_report_pack.sh` | L44 | `MRK:12_CONF` | ENGAGEMENT CONFIGURATION |
| `pt-orc/scripts/12_report_pack.sh` | L77 | `MRK:12_LOG` | COLOURS AND LOGGING |
| `pt-orc/scripts/12_report_pack.sh` | L100 | `MRK:12_ARGS` | ARGUMENT PARSING |
| `pt-orc/scripts/12_report_pack.sh` | L127 | `MRK:12_VALIDATE` | VALIDATION |
| `pt-orc/scripts/12_report_pack.sh` | L156 | `MRK:12_SCOPE` | BUILD SCOPE JSON |
| `pt-orc/scripts/12_report_pack.sh` | L237 | `MRK:12_EVIDENCE` | BUILD EVIDENCE MANIFEST |
| `pt-orc/scripts/12_report_pack.sh` | L336 | `MRK:12_FINDINGS` | COLLECT FINDINGS |
| `pt-orc/scripts/12_report_pack.sh` | L591 | `MRK:12_BUNDLE` | BUILD REPORT BUNDLE |
| `pt-orc/scripts/12_report_pack.sh` | L650 | `MRK:12_WRITE` | WRITE OUTPUT FILES |
| `pt-orc/scripts/12_report_pack.sh` | L714 | `MRK:12_MAIN` | MAIN entry point |
| `pt-orc/scripts/README.md` | L11 | `MRK:SCRIPTS_README_PROTOCOL` | Access protocol (P1 v3) |
| `pt-orc/scripts/README.md` | L18 | `MRK:SCRIPTS_README_RULES` | Hard rules (P2 v2) |
| `pt-orc/scripts/README.md` | L27 | `MRK:SCRIPTS_README_CONFLICT` | Conflict-resolution |
| `pt-orc/scripts/README.md` | L35 | `MRK:SCRIPTS_README_CUSTOM` | Custom context (preserved) |
| `pt-orc/scripts/orc-common-lib.sh` | L54 | `MRK:COM_DB` | MSF / POSTGRES DIRECT ACCESS |
| `pt-orc/scripts/orc-common-lib.sh` | L180 | `MRK:COM_TRAIL` | MSF NOTES WRITER |
| `pt-orc/scripts/orc-common-lib.sh` | L436 | `MRK:COM_BANNER` | standalone banner |
| `pt-orc/scripts/orc-common-lib.sh` | L503 | `MRK:COM_SELFTEST` | reserved for future --test mode |
| `pt-orc/scripts/scripts-index.md` | L8 | `MRK:SCRIPTS_INDEX_FILES` | Files in this directory |
| `pt-orc/skills/pt-commands/SKILL.md` | L43 | `MRK:PT_CMDS_PASSIVE_CAPTURE` | GROUP: PASSIVE / CAPTURE |
| `pt-orc/skills/pt-commands/SKILL.md` | L69 | `MRK:PT_CMDS_DNS_OSINT` | GROUP: DNS / OSINT |
| `pt-orc/skills/pt-commands/SKILL.md` | L140 | `MRK:PT_CMDS_SWEEP` | GROUP: SWEEP |
| `pt-orc/skills/pt-commands/SKILL.md` | L199 | `MRK:PT_CMDS_SMB` | GROUP: SMB |
| `pt-orc/skills/pt-commands/SKILL.md` | L229 | `MRK:PT_CMDS_NFS` | GROUP: NFS |
| `pt-orc/skills/pt-commands/SKILL.md` | L257 | `MRK:PT_CMDS_SNMP` | GROUP: SNMP |
| `pt-orc/skills/pt-commands/SKILL.md` | L287 | `MRK:PT_CMDS_FTP` | GROUP: FTP |
| `pt-orc/skills/pt-commands/SKILL.md` | L323 | `MRK:PT_CMDS_TLS` | GROUP: TLS |
| `pt-orc/skills/pt-commands/SKILL.md` | L357 | `MRK:PT_CMDS_HTTP` | GROUP: HTTP |
| `pt-orc/skills/pt-commands/SKILL.md` | L402 | `MRK:PT_CMDS_WP` | GROUP: WP |
| `pt-orc/skills/pt-commands/SKILL.md` | L459 | `MRK:PT_CMDS_SSH` | GROUP: SSH |
| `pt-orc/skills/pt-commands/SKILL.md` | L481 | `MRK:PT_CMDS_RDP` | GROUP: RDP |
| `pt-orc/skills/pt-commands/SKILL.md` | L500 | `MRK:PT_CMDS_TELNET` | GROUP: TELNET |
| `pt-orc/skills/pt-commands/SKILL.md` | L516 | `MRK:PT_CMDS_OOB` | GROUP: OOB (IPMI / iLO / iDRAC) |
| `pt-orc/skills/pt-commands/SKILL.md` | L539 | `MRK:PT_CMDS_LDAP` | GROUP: LDAP |
| `pt-orc/skills/pt-commands/SKILL.md` | L563 | `MRK:PT_CMDS_DB` | GROUP: DB (databases) |
| `pt-orc/skills/pt-commands/SKILL.md` | L591 | `MRK:PT_CMDS_VPN` | GROUP: VPN |
| `pt-orc/skills/pt-commands/SKILL.md` | L623 | `MRK:PT_CMDS_NETDEV` | GROUP: NETDEV |
| `pt-orc/skills/pt-commands/SKILL.md` | L646 | `MRK:PT_CMDS_MQTT` | GROUP: MQTT |
| `pt-orc/skills/pt-commands/SKILL.md` | L670 | `MRK:PT_CMDS_MSF_REFERENCE` | MSF Quick Reference |
| `pt-orc/skills/pt-commands/SKILL.md` | L700 | `MRK:PT_CMDS_MANUAL_LOG` | Manual Session Log Header |
| `pt-orc/skills/pt-enum/SKILL.md` | L30 | `MRK:PT_ENUM_RECEIVED` | Received from L1 (pt-orc) |
| `pt-orc/skills/pt-enum/SKILL.md` | L43 | `MRK:PT_ENUM_EXIT` | Exit Criteria |
| `pt-orc/skills/pt-enum/SKILL.md` | L55 | `MRK:PT_ENUM_DISPATCH` | L3 Dispatch Table |
| `pt-orc/skills/pt-enum/SKILL.md` | L105 | `MRK:PT_ENUM_APPROACH` | Enumeration Approach by Stage |
| `pt-orc/skills/pt-enum/SKILL.md` | L166 | `MRK:PT_ENUM_STUB_SCHEMA` | Finding Stub Schema |
| `pt-orc/skills/pt-enum/SKILL.md` | L205 | `MRK:PT_ENUM_RETURN` | Return Pass Behaviour |
| `pt-orc/skills/pt-enum/SKILL.md` | L216 | `MRK:PT_ENUM_OUTPUT` | Output — Enum Summary Block |
| `pt-orc/skills/pt-evidence/SKILL.md` | L27 | `MRK:PT_EVIDENCE_RECEIVED` | Received from L1 (pt-orc) |
| `pt-orc/skills/pt-evidence/SKILL.md` | L38 | `MRK:PT_EVIDENCE_EXIT` | Exit Criteria |
| `pt-orc/skills/pt-evidence/SKILL.md` | L48 | `MRK:PT_EVIDENCE_PIPELINE` | Processing Pipeline |
| `pt-orc/skills/pt-evidence/SKILL.md` | L155 | `MRK:PT_EVIDENCE_TOOL_GUIDE` | Tool Output Interpretation Guide |
| `pt-orc/skills/pt-evidence/SKILL.md` | L226 | `MRK:PT_EVIDENCE_OUTPUT` | Output — Evidence Processing Block |
| `pt-orc/skills/pt-monitor/SKILL.md` | L26 | `MRK:MON_ACTIVATE` | Activate when |
| `pt-orc/skills/pt-monitor/SKILL.md` | L34 | `MRK:MON_FIRSTREAD` | First read |
| `pt-orc/skills/pt-monitor/SKILL.md` | L46 | `MRK:MON_CORELOOP` | Core loop |
| `pt-orc/skills/pt-monitor/SKILL.md` | L54 | `MRK:MON_CADENCE` | /loop cadence |
| `pt-orc/skills/pt-monitor/SKILL.md` | L62 | `MRK:MON_ANOMALY` | Anomaly discipline |
| `pt-orc/skills/pt-monitor/SKILL.md` | L73 | `MRK:MON_DEBRIEF` | Debrief protocol |
| `pt-orc/skills/pt-monitor/SKILL.md` | L87 | `MRK:MON_ORCNAV` | Integration with /orc-nav |
| `pt-orc/skills/pt-monitor/SKILL.md` | L116 | `MRK:MON_DONT` | Don't |
| `pt-orc/skills/pt-monitor/SKILL.md` | L127 | `MRK:MON_PERMS` | Permissions |
| `pt-orc/skills/pt-monitor/SKILL.md` | L149 | `MRK:MON_INSTALL` | Install as user-global skill (optional) |
| `pt-orc/skills/pt-orc/SKILL.md` | L38 | `MRK:PTORC_ROLE` | Role |
| `pt-orc/skills/pt-orc/SKILL.md` | L49 | `MRK:PTORC_PRINCIPLES` | Core Principles (Immutable) |
| `pt-orc/skills/pt-orc/SKILL.md` | L62 | `MRK:PTORC_NAMING` | Engagement Naming |
| `pt-orc/skills/pt-orc/SKILL.md` | L73 | `MRK:PTORC_DIRS` | Directory Structure |
| `pt-orc/skills/pt-orc/SKILL.md` | L137 | `MRK:PTORC_STAGES` | Stage Registry |
| `pt-orc/skills/pt-orc/SKILL.md` | L157 | `MRK:PTORC_DISPATCH` | Dispatch Table — L2 Skills |
| `pt-orc/skills/pt-orc/SKILL.md` | L179 | `MRK:PTORC_RETURNPASS` | Return Pass Protocol |
| `pt-orc/skills/pt-orc/SKILL.md` | L197 | `MRK:PTORC_STATE` | State Snapshot — Schema |
| `pt-orc/skills/pt-orc/SKILL.md` | L421 | `MRK:PTORC_SESSIONSTART` | Session Start Protocol |
| `pt-orc/skills/pt-orc/SKILL.md` | L428 | `MRK:PTORC_SESSIONEND` | Session End Protocol |
| `pt-orc/skills/pt-orc/SKILL.md` | L437 | `MRK:PTORC_CHECKLISTS` | Checklists |
| `pt-orc/skills/pt-orc/SKILL.md` | L478 | `MRK:PTORC_PITFALLS` | Common Pitfalls |
| `pt-orc/skills/pt-recon/SKILL.md` | L28 | `MRK:PT_RECON_RECEIVED` | Received from L1 (pt-orc) |
| `pt-orc/skills/pt-recon/SKILL.md` | L39 | `MRK:PT_RECON_EXIT` | Exit Criteria |
| `pt-orc/skills/pt-recon/SKILL.md` | L49 | `MRK:PT_RECON_S1` | S1 — Passive Reconnaissance |
| `pt-orc/skills/pt-recon/SKILL.md` | L114 | `MRK:PT_RECON_S2` | S2 — Broad Sweep / Surface Mapping |
| `pt-orc/skills/pt-recon/SKILL.md` | L164 | `MRK:PT_RECON_RETURN` | Return Pass Behaviour |
| `pt-orc/skills/pt-recon/SKILL.md` | L176 | `MRK:PT_RECON_OUTPUT` | Output — Recon Summary Block |
| `pt-orc/skills/pt-report/SKILL.md` | L43 | `MRK:PT_REPORT_RECEIVED` | Received from L1 (pt-orc) |
| `pt-orc/skills/pt-report/SKILL.md` | L55 | `MRK:PT_REPORT_INPUTS` | Input Sources |
| `pt-orc/skills/pt-report/SKILL.md` | L95 | `MRK:PT_REPORT_EXIT` | Exit Criteria |
| `pt-orc/skills/pt-report/SKILL.md` | L104 | `MRK:PT_REPORT_STRUCTURE` | Report Structure (PTI / PTE) |
| `pt-orc/skills/pt-report/SKILL.md` | L151 | `MRK:PT_REPORT_VERSIONING` | Document Versioning |
| `pt-orc/skills/pt-report/SKILL.md` | L167 | `MRK:PT_REPORT_HEADINGS` | PTI Heading Structure |
| `pt-orc/skills/pt-report/SKILL.md` | L187 | `MRK:PT_REPORT_EXEC_SUMMARY` | Executive Summary |
| `pt-orc/skills/pt-report/SKILL.md` | L226 | `MRK:PT_REPORT_BODY_RULES` | Finding Body Writing Rules |
| `pt-orc/skills/pt-report/SKILL.md` | L272 | `MRK:PT_REPORT_OBSERVATIONS` | Observations Writing Rules |
| `pt-orc/skills/pt-report/SKILL.md` | L284 | `MRK:PT_REPORT_IDENTITY` | Device Identity Verification Rule |
| `pt-orc/skills/pt-report/SKILL.md` | L305 | `MRK:PT_REPORT_PENDING` | Pending Actions Pre-Delivery Checklist |
| `pt-orc/skills/pt-report/SKILL.md` | L330 | `MRK:PT_REPORT_SUMMARY_TABLE` | Findings Summary Table |
| `pt-orc/skills/pt-report/SKILL.md` | L345 | `MRK:PT_REPORT_SEVERITY` | Severity Classification |
| `pt-orc/skills/pt-report/SKILL.md` | L367 | `MRK:PT_REPORT_FINDING_TEMPLATE` | Finding Body Template |
| `pt-orc/skills/pt-report/SKILL.md` | L400 | `MRK:PT_REPORT_OBS_TEMPLATE` | Observation Body Template |
| `pt-orc/skills/pt-report/SKILL.md` | L417 | `MRK:PT_REPORT_RETEST` | Re-test Documentation (S8) |
| `pt-orc/skills/pt-report/SKILL.md` | L441 | `MRK:PT_REPORT_SEC1` | Section 1 Introduction Templates |
| `pt-orc/skills/pt-report/SKILL.md` | L487 | `MRK:PT_REPORT_EVIDENCE_INDEX` | Appendix C Evidence Index Template |
| `pt-orc/skills/pt-report/SKILL.md` | L503 | `MRK:PT_REPORT_STYLE` | Style Rules Summary |
| `pt-orc/skills/pt-report/SKILL.md` | L519 | `MRK:PT_REPORT_PITFALLS` | Common Pitfalls |
| `pt-orc/templates/templates-index.md` | L8 | `MRK:TEMPLATES_INDEX_FILES` | Files in this directory |
| `pt-orc/tools/README.md` | L11 | `MRK:TOOLS_README_PROTOCOL` | Access protocol (P1 v3) |
| `pt-orc/tools/README.md` | L18 | `MRK:TOOLS_README_RULES` | Hard rules (P2 v2) |
| `pt-orc/tools/README.md` | L27 | `MRK:TOOLS_README_CONFLICT` | Conflict-resolution |
| `pt-orc/tools/README.md` | L35 | `MRK:TOOLS_README_CUSTOM` | Custom context (preserved) |
| `pt-orc/tools/install-skills.sh` | L28 | `MRK:INSTALL_SKILLS_SETUP` | Setup + arg parsing |
| `pt-orc/tools/install-skills.sh` | L60 | `MRK:INSTALL_SKILLS_SELECTION` | Skill selection (default vs all) |
| `pt-orc/tools/install-skills.sh` | L70 | `MRK:INSTALL_SKILLS_HELPERS` | Hash helpers + counters |
| `pt-orc/tools/install-skills.sh` | L85 | `MRK:INSTALL_SKILLS_MAIN_LOOP` | Main install loop with drift check |
| `pt-orc/tools/install-skills.sh` | L143 | `MRK:INSTALL_SKILLS_SUMMARY` | Summary output |
| `pt-orc/tools/tools-index.md` | L8 | `MRK:TOOLS_INDEX_FILES` | Files in this directory |

<!-- L2 NAV:v1 → [project root] -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
