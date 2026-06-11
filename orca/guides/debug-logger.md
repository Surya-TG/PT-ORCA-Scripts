<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# Debug Logger — Operator Guide

**Audience**: Managers and roles using Orca
**Status**: stable
**See also**: `specs/ip-marks-spec.md`

The debug logger captures how you use the Orca platform during your sessions — without capturing what you're working on. When you share the log with the Orca team, we use it to refine the platform around your actual workflow.

This guide is the practical operator manual: how to turn it on, what to expect, how to share.

## TL;DR

```yaml
# in your profile
debug: on
```

Next session, Orca starts logging mark hits to `.debug/marks-<UTC>.log` in your working directory. When you're ready to share, zip the `.debug/` directory and send to your Orca contact.

To stop logging, set `debug: off`. Default is OFF.

## What this logger does

Orca operates by hitting specific platform-internal markers (behaviors, directives, frames) as you work. The debug logger records each mark hit, in time order, during your sessions.

Think of it as a usage-shape recorder: it captures **which platform actions fire and in what sequence** — not what you're doing, just which Orca-side machinery you're triggering.

## What gets recorded

Each line of the log looks like this:

```
2026-05-14T14:23:01Z mark=BHV-7Q3X kind=BHV ctx=engagement-pickup profile=FRM-X8Q2 session=A3F2
```

Breaking it down:

| Field | Meaning |
|---|---|
| Timestamp (UTC, ISO 8601) | When the mark fired |
| `mark=` | The opaque identifier of the action (e.g., `BHV-7Q3X`) |
| `kind=` | Family: `BHV` (behavior), `DIR` (directive), `FRM` (frame), `RLE` (custom role) |
| `ctx=` | A short tag for what triggered it (e.g., `engagement-pickup`, `frame-load`) |
| `profile=` | The frame/role you were in when the mark fired |
| `session=` | A short session ID (so we can tell which marks belong to the same session) |

Some lines have extra fields (e.g., `frame_to=FRM-W2HG` when a frame switch happens).

## What does NOT get recorded

The logger is shape-only. It does **not** record:

- File contents — no evidence, no findings, no client data
- Your reasoning, drafts, working notes, or session transcripts
- Client names, project names, or any free-text content
- Token expansions (the logger uses opaque marks; nothing reveals what they map to)
- External system credentials, paths, or other infrastructure

The log captures **how you use the platform**, not **what you do with it**.

## How to enable

Open your profile config. By default it's `PROFILE.md` in your Orca workspace, or wherever you've configured your profile.

Find or add:

```yaml
debug: off
```

Change it to:

```yaml
debug: on
```

Save. The next session will begin logging. (No restart needed for the skill itself; just open a fresh session and the logger picks up the new value.)

You can also enable per-session by setting an environment override (advanced; see your Orca contact for details).

## Where the log file lives

`.debug/marks-<UTC>.log` in the current working directory (where you launched the session).

Examples:
- `.debug/marks-2026-05-14T09-00Z.log`
- `.debug/marks-2026-05-14T13-30Z.log`

A new file per session. The directory `.debug/` is added to `.gitignore` automatically — the logs never accidentally end up in version control.

If you want to inspect a log:
```
cat .debug/marks-2026-05-14T09-00Z.log
```

It's plain text, one entry per line. Grep it as you would any log file.

## How to share with the Orca team

When you have a few sessions worth of logs (a day, a week — your call):

1. Stop logging if you want a clean cut: `debug: off` in your profile
2. Zip the directory:
   ```
   zip -r orca-debug-<YYYYMMDD>.zip .debug/
   ```
3. Send via the channel your Orca contact provides (typically a secure upload link or encrypted email)

You can re-enable `debug: on` after zipping — new logs start fresh.

## What you can review before sending

Before zipping, you can:

- `cat` any log file to see what's in it
- Delete log files you don't want to share (`rm .debug/marks-<specific>.log`)
- Trim individual log files line-by-line if needed

There's nothing in the logs that should be sensitive (it's all opaque marks), but you have full control.

## What we do with the logs

The Orca team decodes the logs internally and uses them to:

- Identify which behaviors and frames are load-bearing in real consulting work
- Spot dead code: frames or behaviors that never fire in practice
- Find rough edges: behaviors that fire then immediately retry (usually a discipline-gate that needs softening)
- Surface gaps: mark sequences that reveal workflow holes the platform should address
- Prioritize the roadmap based on actual usage rather than assumptions

The output is platform refinements — new frames, smoother behaviors, better defaults — delivered back to you as skill updates.

## When to enable

A few suggested moments:

- **First two weeks** of using Orca: gives us a baseline of how you actually work
- **When something feels rough**: turn on debug, work through the rough patch, send the log so we see what fired during the friction
- **Mid-engagement** during a representative engagement: gives us realistic load patterns
- **Before requesting a feature**: send a log alongside the request so we can see the workflow that motivates the ask

## When to leave it off

- When you're doing exploratory or one-off work (the noise isn't useful to us)
- When you're in a stable workflow with no surprises (no telemetry need)
- When you're handling unusually sensitive engagements (even though the log is shape-only, your operational discretion is final)

## Troubleshooting

**Log files aren't appearing.** Confirm `debug: on` is in the active profile (not just edited in a file the skill doesn't read). Open a fresh session.

**Logs are very large.** Long sessions generate many entries. If a single log exceeds 10 MB, it's likely you've been running with debug on for many hours — that's fine; ship it as is.

**A log line looks malformed.** Save it. Send to your contact with the line number — that's a logger bug we want to fix.

**I want to log only certain sessions.** Toggle `debug` between sessions. Each session reads the value at start.

---

For the broader platform context, see `specs/ip-marks-spec.md`.

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
