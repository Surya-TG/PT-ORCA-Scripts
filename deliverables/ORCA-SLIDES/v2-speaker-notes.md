<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

<!-- NAV-LEN: 0 entries | UNMRKD -->

# ORCa v7 Deck — Speaker Notes

Companion to `v7-generate_deck.py` / `v7-deck.pptx` (20 slides). Per-slide talking points for the TechGuard delivery briefing with Hari.

---

## Slide 1 — Title

- Pause and frame: "Hari, ORCa is built and delivered. This deck is the walkthrough — 20 slides, ~25 minutes. I want your thoughts on two decisions at the end."
- The deck title says "Technical Lead Briefing" — if there are others on the call, acknowledge and ask who's the decision-maker.
- Don't start selling yet. This is a delivery confirmation, not a pitch.

---

## Slide 2 — Agenda

- Four parts: platform, initial release, getting started, TechGuard methodology.
- "Part 4 is new — we've been working with the TechGuard architecture team (DCPTCN) on the unified methodology and the EngagementCore model. That's slides 17–19."
- "Questions welcome throughout — this isn't a lecture."

---

## Slide 3 — Divider: The Platform

- Transition: "Let's start with what ORCa actually is."

---

## Slide 4 — What ORCa Is

- Lead with the definition box: "A navigation and orchestration layer for knowledge-intensive AI work."
- Key distinction: "It's not a tool you use once per engagement. It's the layer that makes every session, every analyst, every engagement consistent — because the indexed file structure and project state don't disappear when the session ends."
- Two components: nav-orc (the platform layer) + pt-orc (the PT execution layer). PT-Orc runs *on* nav-orc.
- Don't oversell pt-orc here — it gets its own slide.

---

## Slide 5 — Why nav-orc

- This is the contrast slide. Left column is the pain (raw AI), right is the fix.
- Key line on the left: "Every session starts cold." That's the problem. An analyst comes back to an engagement after 3 days — raw AI has no idea what was done.
- Key line on the right: "Same workflow every session — methodology enforced by design." That's the TechGuard value prop.
- Don't read the bullets. Paraphrase: "Without nav-orc, you have capable AI with no memory and no discipline. With it, every session picks up exactly where the last one left off."

---

## Slide 6 — Platform Architecture

- Walk the diagram: "audit-orc repo, two suites, shared docs."
- nav-orc/skills/ — that's where the 7 AI skills live. nav-orc/tools/ — that's the reindex tool (keeps ranges and hashes current automatically). pt-orc/scripts/ — the 7 phase scripts. pt-orc/skills/ — companion AI skills.
- "Everything in docs/ is for operators — getting started, nav-orc user guide, project workflow, task board guide."
- Keep this brief — it's orientation, not deep dive.

---

## Slide 7 — nav-orc: Indexed File Protocol

- **This is the technical depth slide.** Hari is technical — spend time here.
- Walk the code block on the left: "Every file has a two-line header telling the AI what domain index to use. Then a table of contents — MRK anchors with line ranges. The AI reads the TOC (20 lines), gets the range it needs, fetches those lines — not the whole file."
- Bottom left: "Read(file, offset=46, limit=74) — 74 lines, not the full 175." That's the discipline.
- The callout box (bottom right, dark background): **read it verbatim** — "Cold projects resume coherently in two file reads — across sessions, weeks, and team handovers." That's the system-assessment finding. It's the strongest claim.
- Anticipated pushback: "How does it know what to search for?" → The MRK:NAV_TOC is the answer. Every indexed file tells the AI where to look. No guessing.

---

## Slide 8 — Session Model

- Walk the code block: "Two slash commands to load the suite. One command to resume the project. The project warm-starts in under 10 seconds — plan, last log entries, task board, context snapshot."
- "nav project offload writes the context snapshot before you leave. Next session picks it up. This is the mechanism that makes teams work — not just individuals."
- Right column: what persists. The beacon is git-tracked — that's the entry point. The NEXT doc is the full project state. ctx_notes is overwritten every offload — always current.
- Key line at the bottom: "Projects can be paused, handed over, or closed — state is always preserved." This is what makes TechGuard team onboarding work.

---

## Slide 9 — Seat Access Model

- "This is the access model I want your input on."
- Three nested layers: org ceiling → seat frame → project perms. "The org decides the maximum anyone can reach. The seat type frames what this role allows. The project sets what's in scope for this engagement."
- Seat types table: walk the 5 rows. "Analyst is your standard PT operator. Senior is the lead — evidence write access and reporting. Restricted is for on-client-site work — you can set a custom ceiling that's tighter than the org default."
- Bottom bar: "The wrapper script is the current mechanism — `orc-seat-start.ps1` or `.sh`. Ships with the skills. Entra group → seat auto-detection is the next step — that's M3. Uses your existing M365 identity, no new infrastructure."
- This replaces the shared-AI-broker concept from v1. Simpler, more reliable, TG-controlled.

---

## Slide 10 — Divider: Initial Release

- "Here's what's in the box right now."

---

## Slide 11 — nav-orc Skills

- Walk the table. Seven skills.
- "nav_bare is the lightweight boot loader — auto-escalates to nav_core on first write. You don't need to manage which skill to load. /nav_ext loads the full suite in one command."
- "nav_action_plan_proc is the task board — TSK commands, session notes, reminders, custom shortcuts. That's where analysts track what they've done and what's next."
- "nav_commit has the reindex gate — you can't commit without verifying that indexes are current. No drift."
- If Hari asks about skills not on the list: nav_core handles all indexed navigation — it's the engine under everything else.

---

## Slide 12 — pt-orc Suite

- "Seven phases, seven companion skills. PT-Orc runs on the nav-orc platform."
- Left table (phase scripts): walk the phases. "Phase 00 sets up the environment. Phases 01–04 are the execution pipeline. Phases 05–06 are evidence and report. Phase 07 is cleanup."
- Right table (skills): "pt-orc is the orchestrator — it gates phase transitions. pt-recon handles scope capture. pt-evidence handles hash and chain of custody. pt-report is the report generator."
- "This is what your analysts use for an engagement. The nav-orc layer keeps the session state; pt-orc drives the methodology."

---

## Slide 13 — Operator Guides + Repo

- "Five guides in docs/. The getting-started guide is the first thing a new analyst reads — install, first session, project creation. The nav-v1-user-guide covers how to read indexed files. The project guide covers the full project lifecycle."
- Right side code block: "Three commands. Clone the repo. Copy nav-orc skills. Copy pt-orc skills. That's the install. Skills persist across all future sessions."
- "Repo access: ggerait/audit-orc, private. Repo ownership is one of the two open questions at the end of this deck — slide 20."

---

## Slide 14 — Divider: Getting Started + Next Steps

- "Part 3 is practical — what the first session looks like and what we're building together."

---

## Slide 15 — Getting Started

- Walk the three steps.
- Step 1: one-time. "Clone the repo, copy skills to `~/.claude/skills/`. Done. You don't re-do this."
- Step 2: per session. "Two slash commands. The full suite is loaded. That's it."
- Step 3: "Create a project with a slug — `tg-infratest-q2`. Log your progress. Close out with `nav project offload`. Next session: same two commands, and you're back where you were."
- "The full walkthrough is in docs/getting-started.md. But honestly, the three steps on this slide are 90% of it."

---

## Slide 16 — Where We Are + Where We're Going

- Left: "This is what's delivered." Don't undersell it — 7 nav-orc skills, 7 pt-orc skills, 5 operator guides, seat wrapper scripts, reindex tool.
- Right: "This is what we build together." Key items: Entra auto-detection (M3 — your M365 identity feeds into seat assignment automatically), first engagement together, methodology evolution as we use it.
- Bottom bar: "This is an active start — not a finished product handed over. We use it, improve it, and shape it together." Mean it. If something doesn't work for TG's workflow, we fix it.

---

## Slide 17 — Divider: TechGuard Methodology

- "Part 4 is the bigger picture — where ORCa sits inside TechGuard's engagement model."

---

## Slide 18 — TechGuard Unified Methodology

- Left: "Nine stages, every engagement type. Intake through closure. The same discipline whether it's a PT, a gap analysis, or a risk assessment."
- Right: "Six MethodologyPacks — one per TechGuard service type. PT is one of them. Penetration testing runs on PT-Orc / PentestPack."
- Bottom right (Design principles): "Automation-first. Evidence-first. Human review at every stage gate. One Core Method, many service modules."
- "The v0.3 methodology document is already produced — it maps this 9-stage lifecycle to the MethodologyPack architecture. It's in the repo."

---

## Slide 19 — Platform Vision

- Walk top to bottom.
- tg-audit-orchestrator bar at the top: "This is the planned orchestration layer — intake, scope, dispatch, reporting, QA across all engagement types. It's not built yet; this is the roadmap."
- Left: "PT-Orc is existing. It's what your analysts use today."
- Right: "EngagementCore + PentestPack — this is what DCPTCN is building. EngagementCore is the shared planning kernel — it'll power all six MethodologyPacks. PentestPack is the adversarial specialist layer (that's where PT-Orc sits in the future model). Phase A is the migration from the current Decepticon architecture to EngagementCore."
- Bottom right: audit-evidence-processor + nav-tools (both existing). "nav-tools is ORCa — the platform layer."
- Bottom bar: "ORCa delivers nav-tools + PT-Orc today. EngagementCore + 6 MethodologyPacks bring the full TechGuard engagement model under tg-audit-orchestrator." This is the vision slide — don't over-commit on timelines. "DCPTCN owns the EngagementCore timeline; we're aligned on the architecture."

---

## Slide 20 — Two Open Questions

- Slow down. These are the action items.
- **Q1 — Repo ownership**: "Currently personal GitHub, private. Options: TechGuard-owned org (you control admin seat, Entra integration is cleaner), joint (co-admin), or personal with TG admin access. My preference is whatever gives TG the cleanest control path for Entra. But this is your call — it's your platform."
- **Q2 — First engagement**: "This is where everything comes to life. What's the first engagement we run together on ORCa? Give me a scope and we start. The first session together will surface anything that needs tuning faster than any amount of testing on our end."
- Bottom bar: "ORCa is live. Skills ready. Repo available. Your confirmation + first engagement → we start."
- Close: "Those are the two asks. Anything you can confirm today, we take as go. Anything that needs checking, set a return date."

---

## Anticipated Q&A

**Q: Why do analysts each need their own Claude seat? Isn't the whole point to pool?**
A: Pooling was the v1 approach (custom broker). The framed-seats model is simpler and more reliable — each analyst uses their own seat, the seat frame controls what they can reach. Entra group → seat type is the governance layer. For TechGuard's current team size, per-seat is cheaper than running a custom broker. If the team scales to 15+ analysts and pooling makes cost sense, we can revisit — the architecture supports it.

**Q: What does "two file reads" mean in practice?**
A: Any indexed project resumes by reading the beacon (entry point, ~30 lines) and the NEXT document (full state — plan, log, task board). Everything the AI needs to pick up where the session left off. On a real engagement that's been running for 2 weeks, that's still two reads.

**Q: Can a senior analyst promote another analyst's work to evidence without re-running?**
A: Yes — the senior seat has evidence-write access. The evidence structure, hash, and chain of custody are recorded by pt-evidence. The analyst captures; the senior reviews, signs, and commits. The workflow is in docs/nav-action-plan-proc-guide.md.

**Q: What's the relationship between ORCa and DCPTCN_TG (EngagementCore / PentestPack)?**
A: ORCa (nav-tools + PT-Orc) is the delivery layer — what's in your analysts' hands today. DCPTCN_TG is building the orchestration layer above that (tg-audit-orchestrator, EngagementCore, 6 MethodologyPacks). The two are aligned on architecture — ORCa is the execution platform; DCPTCN is the orchestration and planning kernel. Phase A is the integration timeline.

**Q: How does this compare to commercial tools (PlexTrac, Dradis, AttackIQ)?**
A: Those are reporting/workflow tools for PT specifically. ORCa is the methodology and session layer — evidence capture, indexed knowledge, session continuity, multi-engagement coordination. They're not competitors; ORCa can feed report outputs into those tools if TG uses them.

**Q: Who maintains ORCa after delivery?**
A: ERA maintains the nav-tools + pt-orc codebase. TG owns the repo and the engagement data. Methodology evolution (new MethodologyPacks, Entra integration, additional skills) is a continuous consulting track. Not in scope for M1.

**Q: Can we add custom engagement types beyond PT?**
A: Yes — that's the MethodologyPack model. The 9-stage lifecycle is the Core Method; each MethodologyPack adds the service-specific execution layer. Adding a new pack is a scoped development item, not a platform rebuild.

**Q: What if an analyst's Claude seat is compromised?**
A: Seat frames limit blast radius. An analyst seat can't reach restricted data by design — the org ceiling blocks it regardless of prompt. The admin seat is what you protect carefully; that's where seat assignments live.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
