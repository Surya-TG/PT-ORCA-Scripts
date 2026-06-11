<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ./AUDIT-ORC-INDEX.md -->

<!-- MRK:CHANGELOG_NAV_TOC — Section index | nav,toc,index | L4-15 -->
<!-- - MRK:RELEASE_V081 — v0.8.1 — 2026-04-21 | release,v081,v0 | L16-72 -->
<!-- - MRK:RELEASE_V08 — v0.8 — 2026-04-20 | release,v08,v0 | L73-135 -->
<!-- NAV-LEN: 2 entries | Integrity-hash: e03b6d958047941b | Last-indexed: 2026-06-09T07:09:41Z -->


**ERA IT Consulting & Audit Ltd.**

Append-only, newest first. Each entry: version tag, date, headline, bullet list of user-facing changes. Never edit past entries.

---

## MRK:RELEASE_V081 — v0.8.1 — 2026-04-21 | release,v081,v0 | L16-72
**Runtime bug fixes + resumability + trail/notes library v1**

### 03 runtime bug fixes (what now works that didn't)
- **ARP discovery `-Pn` removed** — `03_comp_scan.sh:1403` had `run_rc_scan "arp_discovery" -PR -sn -Pn ...` which made nmap assume every host up (false-positive everything). Comment two lines above already said "`-Pn` not used here" — drift between comment and code. ARP sweep now genuinely probes L2 and reports real live-host counts.
- **01/02 graceful no-op in PTI mode** — both scripts previously `exit 1` when `TARGET_DOMAINS` / `TARGET_IPS` were empty (legitimate PTI state). Orchestrator treated rc=1 as fatal, aborted the whole suite at step 1. Fixed: PTI + empty inputs now `exit 0` with `log_ok "PTI mode + no TARGET_DOMAINS/TARGET_IPS  nothing to enumerate, skipping"` — suite proceeds to step 3.

### 03 new features — Pass 1 target narrowing via ARP
- **On-link subnets now narrowed to ARP-live hosts** — `phase_tcp` builds per-subnet target lists: if subnet is L2-adjacent (ip route has no "via") AND ARP discovered ≥1 live host → replace CIDR with live-host list (union with any operator-listed `TARGET_IPS` in range, deduped). Routed subnets keep full CIDR (ARP can't cross gateway). Result on a /24 with ~30% occupancy: Pass 1 target count drops ~70%, wall-clock roughly proportional.
- **Per-subnet scope log line** before Pass 1 kicks off:
  ```
  TCP scope [ghost]   192.168.10.0/24  -> on-link, 60 live (ARP)
  TCP scope [normal]  192.168.1.0/24   -> on-link, 92 live (ARP) + 2 listed
  TCP scope [normal]  192.168.100.0/24 -> routed, full CIDR
  ```
- **New conf knobs** (`pt-orc.conf`):
  - `RUN_DISCOVERY=1` — enable/disable ARP phase independent of MODE (was hard-coded to run in PTI mode)
  - `USE_DISCOVERY_FOR_TCP=1` — toggle narrowing; `=0` reverts to full-CIDR legacy behaviour (escape hatch)
- **New helper primitives** in 03 (self-contained, will migrate to lib in next commit): `is_subnet_onlink`, `_filter_hosts_in_cidr` (python3 for arbitrary prefix; /24 bash fallback when python3 missing), `live_hosts_in_subnet`, `list_target_ips_in_subnet`.

### 03 + 00 — resumability flags
- **`--reuse-workspace`** (03 + forwarded via 00) — skip the default `ensure_workspace` rename-to-archive behaviour; reuse the existing `PROJECT_NAME` workspace in place. Lets operators restart mid-engagement after config tweaks (e.g. switching `FAST_TCP_SCANNER` backend) without losing prior ARP-discovered hosts.
- **`--continue`** (03's 03-native flag, now forwarded by 00) — 00 previously knew `--phase` but dropped `--continue`; 03 fell through to single-phase mode. Now `sudo ./00_pt-orc.sh --yes --from 3 --phase tcp --continue --reuse-workspace` resumes cleanly from phase_tcp onwards with prior workspace data.

### New file: `orc-common-lib.sh` (v1)
- **Shared helper library** — 480 lines, sourced by scripts with graceful fallback. Standalone execution prints a self-documenting banner.
- **Sections (MRK-anchored):** `COM_LOG` (colour + log_* + _ts + _now + new `_alert()` for loud-red class-invariant failures), `COM_DB` (`parse_db_conf`, `db_query`, `db_exec`, `_db_get_workspace_id`, `_db_get_host_id` with session caching), `COM_TRAIL` (JSON `orc.*` notes writer with 25 event-type wrappers).
- **Trail event types:** `orc.session.{start|end|scope}`, `orc.step.{start|end}`, `orc.phase.{start|end}`, `orc.discovery.summary`, `orc.tcp.{pass1|pass2|nse}`, `orc.udp.summary`, `orc.host.{tcp|udp}.complete`, `orc.svc.{tls.testssl|tls.headers|tls.screens|web.scan|web.headers|wp.detect|wp.scan|<probe>.complete}`, `orc.msf.module`, `orc.error`, `orc.export.csv`. All write JSON-encoded data via direct psql INSERT (no msfconsole startup overhead — sub-second per note).
- **Design calls** (confirmed 2026-04-21): one psql INSERT per call (no batching); on DB failure, emit bright-red `_alert` and continue (never abort caller); on `host_id` miss, insert note with NULL `host_id` (session-scope fallback, data never lost); workspace_id + host_id resolved once and cached.
- **Integration in 04/05/06/07** — each sources the lib, calls `parse_db_conf`, emits `trail_phase_start` / `trail_phase_end` around `main()`. Per-probe / per-target emissions deferred (separate pass).

### Deferred / not in this commit
- `00 + 03` trail-integration — both were running during this session; editing a live bash script corrupts execution. Next commit with suite idle.
- Per-probe emissions in 04/05/06 (`trail_svc_*` at existing tool-invocation points).
- `07` per-probe emissions — tied to 07 plugin refactor (`07-probes/` directory design, captured in action-plan).
- Full helper migration (move `parse_db_conf`, `db_query`, `log_*`, `ensure_workspace`, `run_rc_scan`, tier_*, CIDR helpers) out of 03/07 into the lib. Lib currently duplicates 03's copies; migration removes duplicates once 03 is idle.

### Action-plan expanded with design capture
- `[!] Incremental scanning — skip-known provenance via MSF DB` — 3-level check (port state / version / scripts-run), use native `nmap.nse.*` notes as NSE sentinels (no synthetic `orc.scripts.sC_complete` needed for -sC), synthetic `orc.<tool>.complete` sentinels only for non-nmap tools (testssl/gobuster/nikto/wpscan). Cross-workspace preload via `PRELOAD_WORKSPACES` conf. UDP always re-tests (unreliable state). 2-phase implementation plan. Refined after analysis of a real v0.76 engagement notes dump (83 unique types, 1269 notes, ~100 hosts).
- `[!] MSF DB as canonical run-trace` — structured progress notes taxonomy (session / phase / per-host / per-(host,port) / meta), JSON data format, integrates with MSF-native notes from `run_msf_module`, reconstruction guarantee from DB alone.
- `[ ] lib/ shared-helpers directory` — incremental migration plan with fallback-safe sourcing. Includes **designed 07 plugin layout** — `07-probes/` + `07-rules/` + `07-plugins/` + `07-custom-modules/`, plugin interface contract, TechGuard-contributable surface.
- `[~] Trail / notes integration completion roadmap` — 5 sub-items: 00+03 integration, per-probe for 04/05/06, 07 per-probe (ties to plugin work), helper migration, jq install.
- `[!] 03 bug: `db_query` shell-escape in `phase_sweep_nse`` — observed in live run: `psql error: ERROR: syntax error at or near "$"`. Silent degradation: Pass 2b NSE falls back to BASELINE_PORTS. HIGH priority fix.
- `[ ] 05 WordPress detection — multi-probe` — stronger than current single whatweb grep; 8-probe detection table (readme.html / wp-login / meta-gen / wp-json / xmlrpc / ajax / ...).
- `[~] 03 discovery + Pass 1 narrowing — production-ready pass` — `-Pn` removal landed, conf knobs landed, narrowing landed. Remaining: ghost-tier `-p-` host-timeout tuning (proven too tight at 2m, operator adjusted to 3m mid-session; proper fix is `GHOST_SKIP_FULL_PORT=1` or scale timeout to port count).

### Hygiene
- `PT-Orc-Slides.md` + `07_fixes_map.md` — pulled into repo from prior engagement scratch dir; engagement-unique content that belongs with the suite.
- Memory rule added: **MRK gap-fill discipline** — when `grep MRK:` misses or forces re-grep, add new anchors at the found location; 6 candidate gaps in 03 pre-captured for next edit.

### Phase-1 verification
- `./pt-orc-reindex.sh --pre-commit` → PASS — 8 scripts, 9 MDs verified, `orc-common-lib.sh` standalone banner verified, NAV ↔ section anchors ↔ NAV-LEN consistent.
- All scripts `bash -n` clean.
- Live Kali verification of `orc-common-lib.sh`: DB connect green, workspace_id lookup = 67, host_id lookup (192.168.10.160) = 4568, JSON builder returns valid output, `_alert` fires correctly when jq is missing.

---

## MRK:RELEASE_V08 — v0.8 — 2026-04-20 | release,v08,v0 | L73-135
**Suite normalisation + runnable bug fixes + access-protocol formalisation**

### Suite normalisation (breaking conventions — all forward-compatible)
- Filenames de-versioned across the repo. New canonical names: `00_pt-orc.sh`, `01_dns_recon.sh`, `02_ip_analysis.sh`, `03_comp_scan.sh`, `04_tls_scan.sh`, `05_web_enum.sh`, `06_wpscan.sh`, `07_service_verify.sh`. Previous `_v0.76.sh`/`_v0.770.sh` suffixes dropped — internal `Version:` banners also removed (version lives in release.md + git tags only).
- Doc renames: `PT-Orc-llm.md` → `PT-Orc-funcs.md` (function reference, clearer name), `PT-Orc-deep.md` → `PT-Orc-design.md` (design rationale + gotchas).
- Every file carries a standardised 2-line (MDs) / 3-line (scripts) orientation header with imperative NAV guidance: `read MRK:xx_NAV + <N> lines (= section index), then grep "MRK:TAG" to jump`.
- New unambiguous references: all suite docs in-body and in navigation use full `PT-Orc-*` prefix (e.g. `PT-Orc-funcs.md`, never bare `funcs.md`). README + core docs cross-referenced consistently.

### MRK anchor system — integrity-checked end-to-end
- Every script + MD carries a `MRK:xx_NAV` section-index block listing its anchors. Per-file body: every major section prefixed `# MRK:TAG -- DESCRIPTION`.
- **NAV-LEN integrity field** declared in every file's L2/L1: `read MRK:xx_NAV + <N> lines`. The number `<N>` is machine-checked against the actual section-header count. Drift → `--verify` exits 1.
- **New flat global index**: `ORC-INDEX.md` (renamed from `MRK-INDEX.md`). Auto-generated, always source-of-truth. 189 anchors. Header carries the full 4-step access protocol + hard rules + access cheatsheet.

### Tooling — pt-orc-reindex.sh + .ps1
- `--verify` — per-file NAV ↔ section-anchor ↔ NAV-LEN consistency check. Exit 1 on any drift. CI-friendly.
- `--mrk` — regenerates `ORC-INDEX.md` from live anchors.
- `--fix-nav` — auto-rebuilds per-file `MRK:xx_NAV` blocks from section anchors (sections = truth).
- **NEW `--pre-commit`** — composite: `fix-nav` + `verify` + `mrk` in one go, one-line status summary. Must PASS before `git commit`.
- `--diff` — script function line numbers vs `PT-Orc-funcs.md` table.
- Windows PowerShell counterpart: `./pt-orc-reindex.ps1` — identical command surface, byte-identical output (UTF-8-BOM wrapper for PS 5.1 compat).

### Runtime bug fixes (what now works that didn't)
- **07 MSF RPORT guards** — `auxiliary/scanner/postgres/postgres_login`, `auxiliary/scanner/mssql/mssql_ping`, `auxiliary/scanner/mssql/mssql_login` all reject RPORT in MSF 6.4+ and silently probe the default port. These calls are now port-guarded: MSF invoked only when the probe port matches the module default (5432 / 1433); non-default ports route to MANUAL with operator guidance.
- **05 `export_db` workspace** — now uses `workspace -a` (idempotent create+switch, propagating the v0.75 fix from 04).
- **05 security headers** — COEP (Cross-Origin-Embedder-Policy) added to the check, parity with 04's 10-header set.
- **Stale filename references** cleaned up across 01/02/05/06 (`03_comprehensive_scan.sh` → `03_comp_scan.sh`, `07_wpscan.sh` → `06_wpscan.sh`, `grab_scores_v2.2.py` → `GrabScores-v2.5.py`).
- **Hardcoded engagement codes** (`WTech-PTE-Apr-2026` in 02/06, `WTech-PTI/PTE-Mar-2026` in 07 footer) replaced with dynamic `${PROJECT_NAME}`.

### Hygiene
- `.gitattributes` added: `text eol=lf` for `*.sh`/`*.md`/`*.conf`/`*.py`/`.gitignore`. Closes the `$'\r': command not found` class of bugs when Windows contributors forget `core.autocrlf=true`.
- `.gitignore` expanded: engagement output trees (`evidence/`, `working/`, `screens/`, `reports/`, `prj_status/`, `ACTUAL_RUN/`), archive formats, deliverables (`*.docx`/`*.xlsx`/`*.pdf`/`*.pptx`), IDE + Python artefacts, secrets by default, catch-alls for `=*/` and `.*/` directories.

### Skill / docs
- `PT-Orc-skill-brief.md §0` — new authoritative Skill Navigation Protocol (4-step access, session defaults, budget threshold, tool references, hard limits).
- `action-plan.md` expanded with: drift findings (per-line RPORT audit, ingest stubs, DRY_RUN partial, check_deps gate consistency, S07 function-list reconciliation), three-phase release order (scripts → skills → skill-brief), CRLF root-cause entry, 24-hour TCP scan data point, upstream push sweep checklist, over-read evidence log rule.
- `PT-Orc-index.md MRK:IDX_S0` — new prefix-convention map for MRK naming.

### Phase-1 verification
- `./pt-orc-reindex.sh --pre-commit` → PASS — 8 scripts, 9 MDs, 189 anchors, integrity OK.
- `./pt-orc-reindex.ps1 --pre-commit` → PASS — identical result.
- All scripts `bash -n` syntax clean.
- Zero CRLF contamination across tree.

### Post-commit addendum (same day)
- `README.md` restructured as an "arrival path" doorway for LLM + human onboarding. Explicit "if LLM → read ORC-INDEX.md next; if human → Quick Start below" protocol. Moves the full access protocol / cheatsheet to `ORC-INDEX.md` (single source of truth), keeping README minimal.
- **Commit routine narrowed to changed files.** `pt-orc-reindex.sh --pre-commit` default scope is now NARROW — only files reported by `git diff --name-only` (staged + unstaged). Use `--pre-commit --full` to force all-suite scope (required for release cuts). `README.md`, `ORC-INDEX.md`, and `pt-orc.conf` are explicitly NOT MRK-indexed (README = arrival doorway, ORC-INDEX = generated, pt-orc.conf = config not prose) — skipped by all verify/fix-nav operations. Memory rule updated to reflect narrow-scope routine.
- **NAV-LEN unit renamed "lines" → "entries"** for semantic precision. `# NAV: read MRK:xx_NAV + <N> entries (= section index)`. In scripts each entry IS one physical line (equivalent). In MDs with table-formatted NAV (PT-Orc-index / design / action-plan / features), N counts the *data rows* — NOT the physical lines, because markdown tables carry a header row + separator + blank that aren't anchors. Verify parser accepts both "lines" and "entries" for backward compat. Headers across all files updated via sed.

### What's next (tracked in action-plan.md)
- **PHASE 2**: L2 skills batch update (pt-recon, pt-enum, pt-evidence, pt-report, pt-commands) to v0.8 references. Separate commit.
- **PHASE 3**: `PT-Orc-skill-brief.md` deeper refresh after skills land.
- `--frame <engagement>` CLI option on reindex for dynamic engagement frame-of-activity in ORC-INDEX.md.
- `PT-Orc-ops.md` body refresh for v0.8 command surface (flags / pipeline changes).
- MSF RPORT audit completion: remaining modules (snmp_login, smtp_relay, ipmi_*, rdp_scanner, winrm_auth_methods, telnet_version, mysql_sql, mongodb_login) need verification.
- 07 `ingest_*` function stubs — implement the per-finding grep + `add_result` calls per TODO blocks already in-code.
- Fast TCP backend tuning (naabu performance in multi-interface envs) — real engagement benchmarking.

---
*Generated alongside commit `v0.8` | PT-Orc | ERA IT Consulting & Audit Ltd.*

<!-- L2 NAV:v1 → ./AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
