<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Role Frames Spec

**Platform**: Orca
**Governs**: frames and role system [BHV-4DPY / FRM-* tokens]

For the frame catalog and switch commands, see `../tg-nav_hub/FRAMES.md`.
This spec covers the design and customization model.

**Maturity note**: Frame switching runs today as skill-side commands. Frame-state persistence across sessions and runtime-enforced role binding (profiler at boot + identity-provider integration) are part of the **M3 deliverable**. Where this spec describes lifecycle persistence, read as target behavior.

---

## Frames as perspective

A frame is a scoped perspective on engagement work. It loads only what is needed for a specific mode of work and nothing else. Switching frames is lightweight — no context debt.

Frames replace the problem of "loading everything and losing focus" with "loading exactly what this mode needs."

---

## Built-in frame roles

| Token | Name | Mode of work |
|---|---|---|
| FRM-X8Q2 | Manager | Status / oversight / decision |
| FRM-M5R7 | Worker | Task / evidence / composition |
| FRM-K3PN | Role-define | Role creation and customization |
| FRM-J7VC | Current engagement | Full engagement orientation |
| FRM-W2HG | Deliverable compose | Output assembly |
| FRM-T4YB | Phase handover | Phase transition |
| FRM-D9LF | Final report | Full report assembly |
| FRM-Z6KX | Gap assessment | Compliance gap mapping |

---

## Custom roles [RLE-*]

The manager defines roles for the team structure. Each role:
- Forks from a built-in frame as parent
- Restricts or extends the permission set
- Sets a preferred default frame for that role

Custom roles are assigned `RLE-*` tokens and registered in the profile.

### Defining a custom role

1. Activate `Role-define [FRM-K3PN]`
2. Describe: role label · parent frame · permission adjustments · default frame
3. Skill assigns `RLE-XXXX` and records it in `PROFILE.md` under `custom_roles`

### Permission model

Each role carries a permissions list. Built-in permissions:

| Permission | What it allows |
|---|---|
| engagement-init | Create new engagements |
| engagement-load | Load and attach to existing engagements |
| evidence-all | Full evidence lifecycle access (all states) |
| evidence-read | Read-only evidence access |
| frame-switch | Switch between frames |
| org-attach | Load org structure and workplan |
| sync-connectors | Wire and query cross-domain connectors |
| role-define | Create and edit roles |

A role can restrict permissions below its parent frame's default set. It cannot grant permissions the parent does not have.

---

## Frame lifecycle

**Load**: state from prior session (same frame) is restored. First load of a frame for this engagement starts fresh.

**Unload**: current work position is persisted to substrate. Nothing carries into the next frame.

**Persist at session end [BHV-K2NM]**: the active frame token is saved. Next session resumes in the same frame.

---

## Frame selection guidance

| When | Use |
|---|---|
| Starting a session, need orientation | FRM-J7VC (current-engagement), then switch |
| Client call, status update | FRM-X8Q2 (Manager) |
| Writing a finding | FRM-M5R7 (Worker) |
| Phase transition, close-out | FRM-T4YB (Phase handover) |
| Final report assembly | FRM-D9LF (Final report — load only when evidence is complete) |
| Compliance gap pass | FRM-Z6KX (Gap assessment) |
| Onboarding a team member | FRM-K3PN (Role-define) |

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
