<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Troubleshooting

## Profile not initialized

**Symptom**: Skill says "profile not active" or refuses to load engagement.

**Fix**: Open `tg-nav_hub/PROFILE.md`. Confirm `active: true` is set and `role.token` is filled in. Save and reload the skill.

---

## Session doesn't pick up from where I left off

**Symptom**: Session starts without prior engagement context.

**Check**:
1. Was the skill loaded (`tg-nav_hub/SKILL.md` in the session)?
2. Was the session ended properly last time — did the skill confirm `[BHV-K2NM]` persist?
3. Is the engagement-state.md file present in `engagements/<name>/`?

If the state file is missing, the prior session may not have persisted. Re-load the engagement and reconstruct from evidence files.

---

## Evidence won't transition to the next state

**Symptom**: `package <item>` is blocked.

**Most likely cause**: item is at `verification` state but not yet verified (HIGH-severity gate).

**Fix**: `verify <item>` first. If the item is HIGH severity, confirm manual verification is done before calling verify.

---

## Frame switch seems slow or incomplete

**Symptom**: after `load frame Manager`, some evidence items aren't visible.

**Check**: are those items in the `archived` state? Archived items don't load into Manager frame by default.

To include archived: `load frame Manager include-archived`.

---

## Can't find an engagement

**Symptom**: `load engagement <name>` returns "not found".

**Check**: the engagement directory exists at `engagements/<name>/` and contains `engagement-state.md`.

List available engagements: `list engagements`.

---

## Debug logging not producing files

**Symptom**: debug is on in profile but `.debug/` directory is empty.

**Check**:
1. Is `debug.state: "on"` saved in `PROFILE.md`? (Not just in conversation — the file must be updated.)
2. Has any mark-generating action occurred? Session start and frame switches both generate marks.

See `debug-logger.md` for the full logging guide (Lane A, pending).

---

## Reporting issues

Contact the platform provider with:
- The symptom
- The engagement type (PT / audit / compliance)
- The frame you were in
- If debug logging is enabled: ZIP and submit your `.debug/` directory

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
