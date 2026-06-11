<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Endless Session Spec

**Platform**: Orca
**Governs**: session continuity behavior [DIR-5MWX / BHV-7Q3X / BHV-K2NM]

**Maturity note**: Endless-session continuity is the **M3 keystone** — runtime profiler at session start + identity-provider integration. Today the skill loads engagement state via conventions at session start; M3 lifts loading to runtime enforcement.

---

## What this means for you

Every Claude session starts with full engagement state already loaded. There is no "where were we?" — the platform picks up exactly where the last session ended.

This applies across:
- Multiple sessions on the same day
- Sessions days apart
- Parallel sessions on different engagements

---

## How it works

### Session start [BHV-7Q3X]

1. Profile is read — role confirmed, not-initialized state blocked
2. User files for the active engagement are loaded
3. The prior session's solved-inference view is reconstructed (evidence states, active frame, pending items)
4. Engagement context is attached (plans, evidence chain, AGENTS registry)

The consultant does not need to re-orient. The first message can be substantive work.

### Session end [BHV-K2NM]

Before ending:
- Evidence state at each lifecycle position is written to the engagement substrate
- Active frame token is persisted
- Unresolved items go to the pending queue

The next session resumes from this persisted state.

---

## Multiple parallel sessions

The platform supports multiple parallel sessions — different engagements, different phases, different frames. Each session loads its own engagement context independently.

There is no conflict between parallel sessions on different engagements. Parallel sessions on the same engagement should use different frames to avoid state contention.

---

## The persistent view

The "solved-inference view" is the accumulated understanding of the engagement at the point of the last session end:

- Which evidence items are at which state
- Which findings are HIGH/CRITICAL
- What the next actions are
- Which connectors are live

This view is reconstructed at session start — not re-derived from scratch. It carries forward without decay.

---

## What this is not

- Not a transcript replay
- Not a per-session re-orient
- Not dependent on conversation history being visible

The platform state lives in the substrate (engagement files), not in the conversation. Conversation can be cleared; state persists.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
