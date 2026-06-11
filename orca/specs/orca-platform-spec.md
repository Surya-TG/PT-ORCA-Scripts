<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Orca Platform — Specification

**Version**: v0.95 (release candidate)
**Status**: v0.95 release candidate — multi-seat runtime enforcement deferred to M3
**Audience**: Managers and roles using Orca for consulting engagements

**Maturity note**: Multi-seat runtime enforcement — analyst profiler at session start, identity-provider integration, automated lifecycle gates — is the **M3 deliverable**. Today these run skill-side as conventions; M3 lifts them to runtime enforcement. Where this spec says "the platform enforces X," read it as target behavior.

This is the platform specification — what Orca is, what it does, how it's organized, and how to operate it. Pair with `tg-l2-spec.md` (file-layer details), `evidence-lifecycle-spec.md` (per-finding chain), `role-frames-spec.md` (viewport catalog), and `ip-marks-spec.md` (mark system).

## What Orca is

Orca is a configurable, persistent engagement-management platform for consulting work — IT audit, compliance (ISO 27001, NIST CSF, CIS Controls, SOC2, PCI-DSS), penetration testing, and any evidence-heavy delivery.

It is **not** a chat assistant, not a script runner, and not a document repository. It is a control plane: configuration of the engagement, navigation across the engagement state, and management of evidence through its lifecycle — all in one skill surface that loads into any compatible session and persists state across sessions.

## What makes Orca different

Most AI tools surface their reasoning in the session. Orca doesn't work that way.

All inference stays **inside**. The working environment — your analysis, intermediate reasoning, cross-domain wiring, draft notes — is internal to the platform. What reaches your client is only what you deliberately compose and package. This boundary is **structural**, not a convention: it is enforced by the platform's design, by the way evidence flows through the lifecycle, and by a pre-delivery hygiene pass that ensures internals never leak into client-facing outputs.

This matters for consulting:

- Client-confidential reasoning stays confidential
- Deliverables are professionally composed outputs — never leaked working notes
- The same engagement can run across multiple sessions, multiple consultants, and multiple weeks without losing context or leaking it

We call this **inference-inside discipline**. It is the core promise of the platform.

## Architecture — three layers

Orca has three layers working together:

### Layer 1 — Control plane

You configure the engagement once. The platform holds the configuration and enforces it across every session.

The control plane covers:

- **Map** — the topology of the engagement: which domains it covers, how they relate, which files live where
- **Flows** — how evidence moves from collection through to delivery (each engagement type has its own flow)
- **Rules** — engagement-specific gates (severity verification, control-evidence pairing, framework-mapping requirements)
- **Discipline** — operating mode within the engagement (what is automated, what requires sign-off)
- **Frames** — the viewports through which you and your team see the engagement
- **Sync connectors** — wiring between projects and domains within the engagement

New engagement type? Configure a new map, define its flow, set its rules. The platform absorbs the configuration; the skill enforces it.

### Layer 2 — Evidence lifecycle

Every piece of evidence moves through a tracked chain:

```
intake → verification → classification → packaging → delivery → archived
```

Six states. Each state has explicit gates that govern transition to the next. Nothing gets packaged before it's verified. Nothing gets delivered before it's complete. The chain is auditable by construction — every finding carries its full provenance through to the deliverable.

See `evidence-lifecycle-spec.md` for state definitions, transition gates, and the data model.

### Layer 3 — Endless-session continuity

Each session begins where the last ended.

When you open a new working session, the platform reads your profile, loads the engagement state, restores your last view, and brings forward the work-in-progress. No re-orientation. No "where were we." Full engagement state in seconds.

This is enforced through a runtime directive (`DIR-5MWX`) that fires at session start. You can observe its execution in the debug log if you want to verify the behavior (see `guides/debug-logger.md`).

## The pack model

Orca is a **platform that hosts packs**. A pack is a self-contained capability bundle — code, configuration, and behaviors — that plugs into the platform's control plane and contributes to the engagement.

The first pack delivered with the platform is the **PT pack** (penetration testing). It wraps the `pt-orc` toolkit — automated phase execution (recon · enumeration · exploitation · service verification · report generation) — and feeds evidence directly into the lifecycle.

Future packs (audit pack, compliance pack, custom packs for client-specific frameworks) plug into the same surface. They share the lifecycle, the frames, and the configuration; they differ in their evidence sources and their domain-specific behaviors.

From your perspective: load the platform, pick the pack(s) relevant to the engagement, configure, work.

## Configuration surface

### Map

The map declares the structure of the engagement:

```yaml
engagement:
  name: client-2026-q2
  type: PT
  domains:
    - recon
    - enum
    - exploit
    - service-verify
    - report
  deliverables:
    - final-report
    - executive-summary
```

A new engagement is created by editing the map. The platform validates it and produces the directory structure, the empty evidence chain, and the initial frame state.

### Flows

Each engagement type carries a flow definition — which states evidence moves through, what triggers each transition.

PT flow:
```
recon → enum → exploit → service-verify → report
```

IT audit flow:
```
intake → control-testing → gap-analysis → management-response → final-report
```

Compliance flow:
```
requirements-mapping → evidence-collection → gap-assessment → remediation-tracking → certification-readiness
```

You can edit the flow per engagement if your work calls for it. The platform enforces what you've defined.

### Rules

Rules are engagement-specific gates:

- "All HIGH severity findings require manual verification before packaging" (PT)
- "Each control must reference a specific evidence artifact" (IT audit)
- "Gap items must map to a specific framework requirement" (compliance)

Rules live in the engagement config. The platform applies them at transition points; violations surface as transition-blocked notifications.

### Discipline

Discipline defines the operating mode: how the skill handles autonomy. A compliance engagement may set stricter evidence-handling discipline; an internal PT may be looser.

Disciplines are referenced by directive marks (`DIR-*`). See `ip-marks-spec.md` for the mark system and `guides/role-definition.md` for which directives to attach to which roles.

### Frames

Frames are viewports — load a frame, work, unload. No context debt.

| Frame mark | Frame name | What it loads |
|---|---|---|
| `FRM-X8Q2` | Manager | Full engagement state — what's in flight, blocked, owners |
| `FRM-M5R7` | Worker | Current task — evidence and context needed right now |
| `FRM-K3PN` | Role-define | Template for defining new roles for your team |
| `FRM-J7VC` | current-engagement | Engagement state + active work + agents |
| `FRM-W2HG` | deliverable-compose | Just what's needed to produce a specific output |
| `FRM-T4YB` | phase-handover | What needs wrap-up before the next phase starts |
| `FRM-D9LF` | final-report | Everything needed for the report in one load |
| `FRM-Z6KX` | gap-assessment | All gaps mapped to framework requirements (compliance) |

You can define additional frames for your team. The role-definition template (`FRM-K3PN`) walks you through it. Custom roles are issued `RLE-*` tokens automatically.

See `role-frames-spec.md` for full frame catalog and custom-frame guide.

### Sync connectors

When you run multiple domains for the same client — say, ongoing PT plus a compliance gap assessment — sync connectors wire them:

- A PT finding surfaces automatically as a compliance control failure
- A compliance gap flags as a PT target (under-patched systems from gap analysis become scoped for testing)
- Deliverables from one domain reference evidence from another

Connectors are declared in the map; the platform maintains them as domains evolve.

## Manager and worker roles

Two root roles ship with the platform:

### Manager (`FRM-X8Q2`)

The manager view sees the full engagement. Status, ownership, blocked items, deliverable readiness, evidence-chain gaps, schedule.

A manager:

- Defines and edits engagements
- Defines and assigns roles to team members
- Reviews evidence at transition points (where the rules require it)
- Decides on package/delivery gates
- Signs off on deliverables

The manager is typically the engagement lead — the person accountable for the delivery.

### Worker (`FRM-M5R7`)

The worker view focuses on the current task. The evidence in front of you, the context relevant to that piece, the next state in the chain.

A worker:

- Collects, analyzes, and classifies evidence
- Updates state as findings move through the chain
- Surfaces gaps and blockers up to the manager
- Composes draft deliverable sections

### Custom roles

You define additional roles for your team. The role-definition frame (`FRM-K3PN`) walks you through it; the platform issues a fresh `RLE-*` token and you bind it to your team member in `PROFILE.md`.

Examples of roles you might define:

- Senior auditor (read+write evidence; cannot transition state)
- Quality reviewer (read evidence; can flag transitions for re-review)
- Junior analyst (write evidence to intake only; cannot self-classify)

See `guides/role-definition.md` for the workflow.

## Profile and organization

Your profile (`PROFILE.md`) carries:

- Your identity (name, contact, organization)
- Your active role and any role bindings you've created for your team
- Your organization structure (departments, reporting lines — used by the platform when assigning ownership)
- Your debug-logger setting (`debug: on/off`)
- Any per-engagement preferences (default frame to load, default flow for new engagements of a given type)

The platform reads the profile at session start (`BHV-7Q3X`). What you put in the profile determines what the platform restores when you sit down to work.

## Loading the platform — what happens at session start

When you open a new session and the skill loads:

1. The skill reads your profile (`PROFILE.md`)
2. It loads the active engagement(s) you have configured
3. It restores your last view (the frame you were in when you ended the previous session)
4. It brings work-in-progress forward — the evidence you were working on, the open findings, the last position in the lifecycle
5. It surfaces any items that need your attention since the last session (transition-blocked findings, sync-connector hits, deliverable-readiness changes)

You arrive at "where you were" within seconds.

## Operating discipline

The platform enforces a small set of operating disciplines at runtime. You don't manage them directly — they fire automatically — but understanding what they do helps interpret the platform's behavior.

| Directive mark | What it does |
|---|---|
| `DIR-5MWX` | Endless-session continuity: load full state at session start, persist at session end |
| `DIR-J4P2` | Correction-as-clarification: when something changes, clarify forward — don't wholesale reverse history |
| `DIR-N7TQ` | Paraphrase, never verbatim: deliverables are deliberately composed; working notes never leak as verbatim quotes |
| `DIR-V8BG` | Low-threshold capture: capture everything at intake; classification happens later |
| `DIR-Y2KZ` | Context-footprint management: long sessions self-manage memory; offload-to-disk by default |
| `DIR-H6FR` | Evidence as input filter: external evidence informs decisions; it doesn't directly drive actions |

These directives are stable across versions. They reflect operating principles built into the platform.

## Getting started

The minimum to get from zero to a working engagement:

1. **Load the skill** — drop the Orca skill into your Claude Code (or compatible) session. The skill auto-discovers your profile.

2. **Configure your profile** — edit `PROFILE.md` with your identity and at least one role binding. (`PROFILE.md` ships with a template.)

3. **Define your first engagement** — copy the engagement-template from `guides/new-engagement.md`. Edit the map, choose the flow, set initial rules. The platform creates the directory structure.

4. **Load a frame** — `FRM-X8Q2` (Manager) gives you the full engagement view. Work from there.

5. **Capture evidence** — as you collect findings, the platform absorbs them into the intake state. From there the lifecycle takes over.

A first walkthrough takes under thirty minutes. Subsequent engagements take a few minutes to bootstrap.

## What the platform doesn't do

To set expectations:

- **It doesn't replace tooling** — Nmap, Burp, Nessus, your audit-evidence-collection tools, your compliance framework checklists. Orca consumes the output of those tools; the tools themselves remain yours.
- **It doesn't write deliverables for you** — composition is your decision and your professional judgment. The platform organizes evidence; you shape the narrative.
- **It doesn't manage clients** — CRM, scheduling, invoicing, contracts. Those live in your existing business tools.
- **It doesn't run unattended** — Orca is an interactive platform; it doesn't background-process or run agents on its own.

The platform is a substrate for your work, not a substitute for it.

## Versioning and compatibility

- Mark identifiers (`BHV-*`, `DIR-*`, `FRM-*`) are stable across versions. A mark issued in v0.1 means the same thing in v1.0.
- Configuration files (map, flow, rules, profile) are backward-compatible across minor versions. Major-version upgrades may require a migration; we ship migration tools.
- Skill body may change between versions as we refine internals; behavior surfaced through marks remains stable.

## Cross-references

- `tg-l2-spec.md` — engagement-aware file shape and L2 navigation pattern
- `evidence-lifecycle-spec.md` — 6-state chain, transitions, data model
- `role-frames-spec.md` — frame catalog and custom-frame guide
- `ip-marks-spec.md` — mark system, opacity contract, debug logger
- `spatial-overview.md` — lighter spatial summary for managers who want the big picture
- `endless-session-spec.md` — session-continuity behavior in detail
- `guides/getting-started.md` — first-engagement walkthrough
- `guides/new-engagement.md` — engagement-bootstrap workflow
- `guides/role-definition.md` — defining roles for your team
- `guides/debug-logger.md` — debug logger operator guide
- `guides/troubleshooting.md` — common issues and resolutions
- `packs/README.md` — pack model overview
- `packs/pt-pack/manifest.md` — PT pack details

— Orca platform team

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
