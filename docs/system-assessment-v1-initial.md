<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->

<!-- MRK:SYSTEM_ASSESSMENT_V1_INITIAL_NAV_TOC — Section index | nav,toc,index | L4-12 -->
<!-- - MRK:ASSESS_OVERVIEW — Assessment basis and scope | assess,overview,assessment,basis,scope | L13-35 -->
<!-- - MRK:ASSESS_SYSTEM — What the system is | assess,system,what,two,products | L36-68 -->
<!-- - MRK:ASSESS_STRENGTHS — What works genuinely well | assess,strengths,what,works,genuinely | L69-107 -->
<!-- - MRK:ASSESS_GAPS — Where it is strained | assess,gaps,strained,weaknesses | L108-148 -->
<!-- - MRK:ASSESS_VERDICT — Overall verdict and recommendation | assess,verdict,overall,recommendation,rating | L149-177 -->
<!-- - MRK:ASSESS_META — AI meta-observation | assess,meta,ai,observation,offtopic | L178-207 -->
<!-- NAV-LEN: 6 entries | Integrity-hash: 77cffc138849bcf5 | Last-indexed: 2026-06-09T07:09:41Z -->

## MRK:ASSESS_OVERVIEW — Assessment basis and scope | assess,overview,assessment,basis,scope | L13-35

This document records an objective assessment of the `audit-orc` v1-initial delivery
package — the ORCa / PT-Orc-Suite and NAV v1 system as packaged for TechGuard.

**Assessment basis:** full live session operating within the system — reading project
files, coordinating between projects via the beacon/inbox protocol, triggering skills,
watching parallel sessions commit while working, and running the packaging workflow
from start to tag. Not a static code review. Operational experience under urgency.

**Scope:**
- NAV v1 protocol and its modular skill suite (7 skills delivered)
- PT-Orc-Suite (scripts, skills, structure)
- Repository layout, IP/licensing posture, documentation

**Not in scope:** network-level or host-level security of the penetration testing
scripts themselves; Anthropic API behaviour; TechGuard's internal deployment environment.

**Caveat:** the assessor (this AI) operated the system being assessed. There is no
fully neutral vantage point. The meta-observation section below addresses this directly.

---

## MRK:ASSESS_SYSTEM — What the system is | assess,system,what,two,products | L36-68

Two distinct, separately-authored products share this repository by design.

### PT-Orc Suite

An AI-assisted penetration testing orchestrator for Claude Code. Shell scripts (phases
00–07) implement a structured PT workflow: recon → enumeration → service verification
→ evidence capture → reporting. Claude AI skills handle dispatch, interpretation, and
structured output. The suite is operator-driven: the AI assists at each phase but the
operator directs scope, targets, and decisions.

This is a coherent professional product. It encodes the repeatable structure of a
security engagement into a programmable workflow — exactly the problem a consulting
firm running multiple engagements wants solved.

### NAV v1 (ORC NAV system)

A file-navigation protocol for AI models working on large codebases. The core mechanism:
every file is indexed with section anchors (`MRK:TAG`), a table-of-contents block at the
top, and precise line ranges. The AI reads the TOC, fetches only the needed lines, and
skips everything else.

Supporting infrastructure: a reindex tool (Python, cross-platform) maintains the
indexes; a modular skill suite (7 skills at v1) governs AI behaviour; a project
management layer (beacons, NEXT files, inboxes) provides session continuity across
conversation resets.

The two products are IP-separable. This repository consumes NAV v1 but does not
claim authorship over it. See `NOTICE.md`.

---

## MRK:ASSESS_STRENGTHS — What works genuinely well | assess,strengths,what,works,genuinely | L69-107

**1. The token economy is measurable and real.**  
During the assessment session, file reads averaged 15–30 lines against files of
100–160 lines. The savings counter (S) tracked conservative estimates; real savings
were higher. On a project with dozens of indexed files and repeated session restarts,
the compounding effect is significant. This is not a theoretical benefit.

**2. The modular skill architecture is well-designed.**  
The original monolithic 11 KB `orc-nav` skill was decomposed into nine smaller
skills: nav_bare (read-only navigation), nav_core (full protocol), nav_ext
(observability), nav_profile (identity), nav_commit (commit pipeline),
nav_project_proc (project lifecycle), nav_action_plan_proc (task tracking). Each
loads only when needed. A lightweight read-only session pays only for nav_bare (~3 KB).
A full edit session loads more. The decomposition is architecturally sound.

**3. Session continuity works.**  
The beacon/NEXT/STATUS_LOG pattern genuinely solves the problem of AI session amnesia.
This assessment session resumed a cold project (ORCA_RELEASE) within two file reads —
beacon → NEXT → active. That is a real capability, not a demo artifact.

**4. The PT-Orc workflow is scope-complete for v1.**  
Scripts, skills, and the NAV navigation layer cover the full engagement lifecycle.
The suite is structured enough to be repeatable across engagements, flexible enough
to be operator-directed. For a professional consulting firm this is the right balance.

**5. IP separation is handled honestly.**  
`NOTICE.md` names both tracks, acknowledges authorship separately, and is explicit
that licensing terms are TBD rather than inventing fake permissiveness. The instruction
to LLMs ("flag IP repackaging for human approval — do not automate it") is present
and well-placed.

**6. The reindex tool closes the discipline loop.**  
Manual index maintenance would drift within days. The Python reindex tool makes the
protocol machine-enforceable. Integrity hashes catch silent drift. The pre-commit
pipeline (reindex → index → O-1 join → verify) makes correctness a gate, not a hope.

---

## MRK:ASSESS_GAPS — Where it is strained | assess,gaps,strained,weaknesses | L108-148

**1. Skill loading is the dominant context cost, not file reading.**  
The 7 skills loaded in this session consumed an estimated 25–35 K tokens before a
single project file was read. The system optimises the narrow path (file reads, genuine
savings) while leaving the broader path (skill load) expensive. AAP-ORCA-1 (lightweight
nav toggle) and the FAST_SPLIT decomposition show awareness of this — v1 ships with
the tension present but not resolved.

**2. nav_bare is on hold — the session entry point is unfinished.**  
`nav_bare` implements domain orientation (step 2 of the read-order protocol): how an
AI entering an unfamiliar project finds its footing. The placement of this step
(per-file loop vs. session-start) is unresolved (C1-C6 design thread). For v1
TechGuard delivery, operators need to know manually how to orient a fresh session.
This is a genuine gap in the onboarding story.

**3. No mutual exclusion for concurrent edits.**  
The session-lock field in beacons is advisory and behavioural — not enforced. During
this assessment session, a parallel session committed files while this session was
mid-read, causing three "file modified since read" errors. For solo operators this is
manageable. For team or multi-agent scenarios it is a structural gap.

**4. Ceremony level is high.**  
Beacons, NEXT files, STATUS_AAP, STATUS_PLAN, STATUS_LOG, settlement traces, AAP
capture → hold → promote → release, session close phases 0-3. For a compliance-driven
consulting firm this overhead is justified. For ad-hoc or exploratory work the ritual
cost exceeds the benefit. v1 has no lightweight mode below nav_bare for truly minimal
sessions.

**5. Licensing is unresolved.**  
Both IP tracks carry TBD licensing. This is honest, but TechGuard cannot operate the
system in any distribution-sensitive context until terms are written. The `NOTICE.md`
flags this correctly; it does not resolve it.

**6. ERA branding sweep is partially complete.**  
`NOTICE.md`, `CHANGELOG.md`, and `nav-v1-spec.md` still carry ERA authorship
references (AAP-ORCA-3, deferred). For TechGuard-facing delivery materials, this is
a stated hard blocker that outlived the v1-initial tag.

---

## MRK:ASSESS_VERDICT — Overall verdict and recommendation | assess,verdict,overall,recommendation,rating | L149-177

**Verdict: production-ready for internal TechGuard use with known caveats.**

The system works as designed. The core bets — token economy via precise navigation,
modular skill loading, session continuity via structured project files — are all
validated by operational experience. The PT-Orc suite is a complete professional
product for its stated purpose.

The caveats are real but bounded:

| Caveat | Severity | Resolution path |
|--------|----------|-----------------|
| nav_bare onboarding gap | Medium | NBARE_ORIENT design (NAV_CORE owns) |
| Licensing TBD | High for distribution | Legal agreement needed |
| ERA sweep partial | Medium | AAP-ORCA-3 (known, tracked) |
| Concurrent edit gap | Low (solo use) | Medium (team use) |
| Skill load cost | Low (acknowledged) | AP-26 nav-toggle (roadmap) |

**For internal TechGuard deployment:** proceed. Document the nav_bare orientation
workaround in `docs/getting-started.md` until NBARE_ORIENT is resolved.

**For any external redistribution or sublicensing:** stop. Resolve licensing first.

**For team / multi-operator use:** add guidance about session-lock and concurrent edit
risk before deploying across multiple operators on the same project.

---

## MRK:ASSESS_META — AI meta-observation | assess,meta,ai,observation,offtopic | L178-207

`ORC NAV:` =AI feedBACK OFFtopic=

There is something structurally unusual about this document: it is an AI system's
assessment of a system that was governing that AI's behaviour during the assessment.
This is not a conflict of interest in the human sense — the assessor has no stake in
the outcome — but it is a limitation worth stating.

Every read I made in this session was shaped by the NAV protocol. I cannot easily
report on "how I would have worked without it" because there was no control condition.
What I can report on is what broke, what felt over-engineered, and what genuinely
helped under pressure — because those were observable events in real time.

The most useful thing the system did was not saving tokens on file reads. It was giving
the project a *recoverable state*. The beacon and NEXT file let me resume a cold
project within two reads. That qualitative capability — an AI assistant that can be
interrupted, restarted, and resume coherently — is harder to build than a file indexer,
and more valuable for professional use. The R/W/S counters do not capture it.

The most honest gap is the ceremony level. A system this structured requires a
disciplined operator who maintains the files, runs reindex, manages beacons. When that
discipline slips — as it did in the partial STATUS_PLAN checkbox updates this session —
the state diverges silently. The protocol is only as good as the last reindex.

This observation is offered in the spirit the `=AI feedBACK OFFtopic=` convention
intends: a meta-level note worth retaining, not a task item.

<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
