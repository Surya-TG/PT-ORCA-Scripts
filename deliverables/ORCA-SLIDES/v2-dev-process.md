<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

<!-- NAV-LEN: 0 entries | UNMRKD -->

# ORCa — Dev Process Plan v2 (ERA ↔ TechGuard)

How we run M1 + M3 delivery. Adapted from the v1 gated process; scope and gates updated for v2.

---

## 1. Principles

- **Gated, not agile-in-name-only**. Three gates; no milestone starts without prior gate cleared. Payment tied to gates.
- **Evidence-first**. Every deliverable is traceable to a commit SHA. No floating docs.
- **Escalate within 48h**. Any blocker lasting >48h without clear path-forward is escalated to Hari. Silent stalls forbidden.
- **Session logs open**. ERA's NEXT.md handoffs and commit log are visible to TG on request (read-only). Full audit trail of what ERA did, when, and why.
- **NAV-indexed deliverables**. Every artifact — email, proposal, spec — carries NAV:v1 header so TG's ORCa instance can index it natively.

---

## 2. Phase structure

Each milestone follows: **Plan → Execute → Review → Gate**.

```
┌─────────────────────────────────────────────┐
│              Milestone N                     │
│                                              │
│  Plan (ERA)   → kickoff brief + checklist    │
│     │                                        │
│     ▼                                        │
│  Execute (ERA + TG)  → install, config, run  │
│     │                                        │
│     ▼                                        │
│  Review (ERA + TG)   → walkthrough / demo    │
│     │                                        │
│     ▼                                        │
│  Gate (Hari)  → accept / correct / hold      │
│     │                                        │
│     ▼                                        │
│  Next milestone unblocked                    │
└─────────────────────────────────────────────┘
```

- **Plan**: ERA sends a kick-off brief (<1 page). Hari reviews within 2 business days.
- **Execute**: Main work. ERA commits daily; TG-accessible branch updated.
- **Review**: Live session or async walkthrough. ERA prepares a brief (30–60 lines). TG asks questions.
- **Gate**: Hari (or delegate) says Go / Correct / Hold with specific reasoning.

---

## 3. Weekly cadence

- **Mon** — "week-plan" email from ERA to Hari. Format: what's planned, risks, asks. <200 words. Sent by 10am IST.
- **Wed** — 30-min sync, optional. If no agenda → skip and email instead.
- **Fri** — "status" email from ERA. Format: what shipped, what's blocked, demo link. Commit log for the week attached. Sent by 5pm IST.
- **Ad-hoc** — blocker escalation via email subject prefix `BLOCKER:`. Hari commits to <4h response during IST business hours.

---

## 4. Gates (3)

### Gate 1 — End of M1: Analyst independent on ORCa

- **Deliverable**: skills installed + configured on TG analyst machines; orc-seat-start wrapper working; first engagement run (M1.3 complete); guide calibration done
- **Acceptance**: Hari or delegate confirms at least one TG analyst can run a project start-to-finish on ORCa without ERA co-piloting; seat types assigned correctly; no P0/P1 issues
- **Out**: M1 complete; M2 optional scope decision; M3 unblocked
- **Typical effort**: ~100–120h

### Gate 2 — End of M2: Second engagement complete (optional)

- **Deliverable**: TG analyst runs second engagement independently; ERA shadows async only; final Q&A session done
- **Acceptance**: TG analyst declares operational independence; observed pain points addressed or filed
- **Out**: M2 complete; analyst declared independent; M3 unblocked
- **Typical effort**: ~40–60h

### Gate 3 — End of M3: Entra integration live

- **Deliverable**: `orc-seat-entra.ps1` / `.sh` working against TG's Entra; seat type auto-detected from M365 group membership; admin seat management confirmed; audit log showing seat assignments
- **Acceptance**: Hari reviews seat assignment table — each TG analyst shows the correct seat type on session start; org ceiling enforced correctly; Hari walks through adding/removing an analyst from a seat group
- **Out**: M3 complete; wrapper scripts deprecated in favor of Entra; handover to continuous consulting track

---

## 5. Artefacts per milestone

| Artefact | Owner | Milestone | NAV-indexed |
|---|---|---|---|
| Kick-off brief | ERA | start of each | yes |
| Gate acceptance record | TG (Hari) | end of each | captured by ERA |
| Mon week-plan / Fri status emails | ERA | weekly | archived |
| Session logs (NEXT.md) | ERA | each dev session | yes |
| Commit log | ERA | continuous | git |
| TG-specific config record | ERA | M1.2 | yes |
| Seat assignment table | ERA + TG | M1.2, updated M3 | yes |

---

## 6. Collaboration tooling

- **Repo**: `audit-orc` (current: `ggerait/audit-orc`; ownership per Hari's Gate 1 decision)
- **TG access**: read from M1 start; write access discussed at Gate 1
- **Chat**: Slack or Teams (ERA-TG-ORCa channel). Ephemeral discussion. Decisions go to email + repo.
- **Calendar**: shared calendar for gate dates. TG owns the invites.
- **Secrets/creds**: TG-managed. ERA has no production creds beyond delivery scope.

---

## 7. Quality gates (continuous)

Every commit that touches indexed files must:
1. Pass `python tools/orc-nav-reindex.py reindex && verify`. No drift accepted.
2. Include a topical commit message.
3. Update `NEXT.md` if material state changed.

---

## 8. Escalation ladder

1. **Blocker >24h (ERA)** — ERA re-scopes internally
2. **Blocker >48h (ERA)** — surface to Hari via `BLOCKER:` email + proposed mitigation
3. **Gate missed** — call within 48h to reset schedule; no phase blame
4. **Scope disagreement** — ERA+TG leads joint call; decision in email within 5 business days

---

## 9. Handover completeness

M3 exit (final handover) is only "done" when:

- [ ] Entra seat auto-detection confirmed working for all TG analysts
- [ ] Admin seat owner confirmed (TG-side) and knows how to add/remove analysts
- [ ] All known issues logged in TG's repo; no secret ERA list
- [ ] ERA has no production creds or runtime access to TG's ORCa instance
- [ ] Continuous consulting SOW or retainer agreed (or explicitly deferred)
- [ ] Final ERA commit: `session: end — M3 handover complete — Entra integration live`

---

## 10. Post-M3 (separate consulting track)

- nav-tools version updates as nav_core v2 features land
- Additional MethodologyPack development (gap analysis, risk assessment, etc.)
- tg-audit-orchestrator alignment as DCPTCN_TG delivers EngagementCore
- Entra Key Vault per-section encryption (planned post-M3)
- Quarterly methodology review + calibration

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
