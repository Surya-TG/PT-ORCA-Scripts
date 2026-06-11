<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ./AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# FLINT-INDEX — external review index

**You are**: Flint (external reviewer, Codex-class)
**Repository**: `audit-orc` — Orca platform + PT pack
**Reading protocol**: `orca/tg-nav_hub/NAV-BARE.md` — load this first

---

## Your role

External review. You have not been inside this system before — that is the point. Look at how things are built. Tell us where the implementation is loose, where the design is sound, where it can be tighter. You are sharp and new; insiders stop noticing drift.

---

## How to navigate

Load `orca/tg-nav_hub/NAV-BARE.md` as your reading protocol. Indexed files (those with `<!-- L1 NAV -->` in their first 5 lines) have a table of contents — read the TOC first, then fetch sections by line range. Do not read whole files.

Unindexed files (no NAV header): read normally.

---

## Five review deliverables

Work in order. Each deliverable = one output file under `orca/review/` (create the directory on first write).

---

### D-1 — Reindex tool efficiency

**Read** (under `nav-orc/tools/`):
- `orc-nav-reindex.py` — the Python reindex tool
- `pt-orc-reindex.sh` + `pt-orc-reindex.ps1` — shell wrappers (POSIX + PowerShell)
- Any other reindex-related code under `nav-orc/`

**Questions**:
- What does the toolchain do, end-to-end? Map the call graph.
- Overlap or redundancy between the Python tool and the shell wrappers?
- Performance: TOC-range computation + integrity-hash — bottlenecks on large files?
- Error handling: what happens on malformed input · stale ranges · missing TOC?
- Any over-engineering, dead options, or unused branches?
- What would a fresh reviewer design differently?

**Output**: `orca/review/efficiency-reindex-review.md`

---

### D-2 — Spec consistency audit

**Read** (in this order):
1. `orca/specs/orca-platform-spec.md`
2. `orca/specs/endless-session-spec.md`
3. `orca/specs/evidence-lifecycle-spec.md`
4. `orca/specs/role-frames-spec.md`
5. `orca/specs/ip-marks-spec.md`

**Questions**:
- Cross-references accurate? Any stale pointers?
- Same terms used consistently across specs? Drift?
- Maturity status consistent (DRAFT vs final vs implicit)?

**Output**: `orca/review/spec-consistency-audit.md`

---

### D-3 — Platform topology review

**Read**:
- `orca/README.md`
- `orca/packs/README.md`
- `orca/packs/pt-pack/manifest.md`
- Directory tree (list `orca/` to depth 2)

**Questions**:
- Is the `orca/` layout clear for a cold user?
- Spec / guide / skill separation — clean?
- Anything a first user would expect that is missing?

**Output**: `orca/review/topology-review.md`

---

### D-4 — Skill and behavior review

**Read** `orca/tg-nav_hub/SKILL.md` carefully. The `BHV-*` / `DIR-*` / `FRM-*` opaque tokens encode behavior directives.

Also read:
- `orca/tg-nav_hub/FRAMES.md`
- `orca/tg-nav_hub/EVIDENCE-WORKFLOW.md`
- `orca/guides/getting-started.md`

**Questions**:
- Session-start / session-end behaviors — correct? Edge cases?
- Evidence lifecycle (6 states: intake → verification → classification → packaging → delivery → archived) — are the states right? Gaps?
- Frame switching — any context-carry risks?
- debug logger — clear? Actionable?
- Is the skill understandable to a cold user, or does it assume insider context?

**Output**: `orca/review/skill-behavior-review.md`

---

### D-5 — How to best use Flint going forward

After D-1..D-4 you have system context. Propose:
- What work-types fit Codex-class reviewer strengths (sharp, technical, fresh eyes)
- What Flint should NOT do (cross-model writes to other bearers' files, etc.)
- Suggested session cadence and depth

**Output**: `orca/review/flint-utilization-proposal.md`

---

## Output constraints

- Every claim needs a file path + line number citation
- No writes outside `orca/review/` and your own self-space
- Surface drift; do not pre-reconcile — operator decides
- If something looks wrong but cannot be confirmed from files: open question, not finding
- No verbatim quotes from internal messages; paraphrase

---

*Review index authored: Nimbus-84 (Sonnet 4.6) + Atlas-84 (Opus 4.7), U084 SAT, 2026-05-14.*

<!-- L2 NAV:v1 → ./AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
