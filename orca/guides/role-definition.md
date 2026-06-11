<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Role Definition Guide

## Overview

Hari defines roles for his team using the `Role-define` frame [FRM-K3PN]. Each role gets a stable `RLE-*` token and is registered in the profile.

## Steps

### 1. Activate Role-define

```
activate Role-define
```

or

```
load frame Role-define
```

### 2. Describe the new role

Provide:
- **Label**: what to call this role (e.g., "Senior Analyst", "Junior Analyst", "Report Writer")
- **Parent frame**: which built-in frame this role extends (Manager or Worker)
- **Permissions**: which functions this role may use (see list below)
- **Default frame**: what frame this role loads at session start

Example:
```
New role: Senior Analyst
Parent frame: Worker
Permissions: evidence-all, frame-switch, engagement-load
Default frame: Worker
```

### 3. Token assignment

The skill assigns a `RLE-*` token and records the role in `tg-nav_hub/PROFILE.md` under `custom_roles`.

### 4. Assign the role

Team members use their `RLE-*` token in their own profile (`role.token` field in `PROFILE.md`).

---

## Permission reference

| Permission | What it allows |
|---|---|
| `engagement-init` | Create new engagements |
| `engagement-load` | Load existing engagements |
| `evidence-all` | Full evidence lifecycle (all states) |
| `evidence-read` | Read-only evidence access |
| `frame-switch` | Switch between frames |
| `org-attach` | Load org structure and workplan |
| `sync-connectors` | Wire and query cross-domain connectors |
| `role-define` | Create and edit roles (restrict to leads) |

## Typical role configurations

| Role | Parent | Permissions |
|---|---|---|
| Lead Consultant | Manager | all |
| Senior Analyst | Worker | evidence-all, frame-switch, engagement-load |
| Junior Analyst | Worker | evidence-all (intake/verify only), evidence-read |
| Report Writer | Worker | evidence-read, frame-switch, engagement-load |

## Editing a role

To change a role's permissions or label, activate `Role-define` and reference the existing `RLE-*` token:

```
edit role RLE-XXXX
change permissions: [new permission list]
```

The token stays the same; the behavior updates.

## Deprecating a role

```
deprecate role RLE-XXXX
```

The token is marked deprecated in the profile. It remains stable (never re-mapped). Team members using it are prompted to switch.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
