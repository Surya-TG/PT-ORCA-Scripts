<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Orca Platform — Profile

**Default state**: NOT INITIALIZED — the skill does not operate until a profile is activated.

Hari activates the profile by setting `active: true` and filling in the required fields below.

---

## Profile fields

```yaml
# Orca Platform Profile
active: false          # Set to true to initialize the skill

role:
  token: ""            # Assigned role token (FRM-X8Q2 = Manager, or a custom RLE-* token)
  label: ""            # Human-readable label for this role (e.g., "Lead Consultant")
  permissions:         # Which functions this role may use
    - engagement-init
    - engagement-load
    - evidence-all
    - frame-switch
    - org-attach
    - sync-connectors

org:
  name: ""             # Hari's organization name
  workplan: ""         # Path to the workplan file (relative to engagement root)
  team: []             # Team member handles (no PII — use handles only)

debug:
  state: "off"         # debug logger — off by default; set to on to enable mark logging
  submit_channel: ""   # Where to send debug logs (e.g., "email", "upload-portal")

session:
  default_frame: "FRM-X8Q2"    # Frame to load at session start (default: Manager)
  persist_on_end: true          # Always persist state before session close
```

---

## Activation steps

1. Open this file.
2. Set `active: true`.
3. Fill in `role.token` — use `FRM-X8Q2` for Manager (default) or a custom role token you've defined.
4. Fill in `role.label`, `org.name`, and any team handles.
5. Save. The skill will initialize on next session start [BHV-7Q3X].

---

## Debug logger

When `debug.state` is set to `on`, each mark hit during a session is written to `.debug/marks-<UTC>.log` in your engagement directory. See `guides/debug-logger.md` for details.

If you want to report behavior to us, ZIP the `.debug/` directory and submit via the channel in `debug.submit_channel`.

---

## Custom roles

Hari can define roles beyond the built-in frames. Use the `Role-define` frame [FRM-K3PN] to create a new role:

1. Load frame: `activate Role-define`
2. Describe the role's function, access scope, and preferred default frame
3. The skill assigns a `RLE-*` token and records it here under `custom_roles`

```yaml
custom_roles:
  # Example:
  # - token: "RLE-XXXX"
  #   label: "Senior Analyst"
  #   parent_frame: "FRM-M5R7"
  #   permissions: [evidence-all, frame-switch]
```

---

## Fine-tuning surface

After a few engagements, Hari can tune the profile:

- Adjust `default_frame` to the view he starts each session in
- Add or restrict `role.permissions` based on actual workflow
- Enable debug logging for a session to observe which behaviors fire — submit logs for our analysis

The profile is the primary tuning knob. No internal specs are needed to tune it.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
