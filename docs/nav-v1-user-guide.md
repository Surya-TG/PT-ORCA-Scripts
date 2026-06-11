<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# NAV v1 User Guide — Reading Indexed Files

**Skill:** `/nav_core` · **Version:** v1 · **Audience:** Operators reading NAV-indexed project files

---

## What is a NAV-indexed file?

A NAV-indexed file has a structured table of contents built into it. Instead of reading the whole file, you read the TOC, find the section you need, and fetch only that section. This keeps context use low and navigation fast — even across large codebases.

You'll encounter NAV-indexed files whenever you work with:
- Skill source files (`SKILL.md`)
- Project indexes (`*-INDEX.md`)
- Engagement documents (scoping docs, plans, specs)
- Scripts with NAV headers

---

## Recognizing a NAV v1 file

A NAV file's first two lines look like this (for a Markdown file):

```
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../NAV-TOOLS-INDEX.md -->
```

The `L2` line tells you where the domain index is — the root map for the whole repository.

For scripts, the same appears as comment lines after the shebang:

```bash
#!/usr/bin/env bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ../../NAV-TOOLS-INDEX.md
```

If you see `NAV:v1` in the first three lines, you're in a NAV file. Use the navigation protocol below.

---

## The navigation protocol

**Always in this order — never skip steps.**

### Step 1 — Read the TOC

Every NAV file has a `MRK:NAV_TOC` block near the top. It lists every section with:
- An anchor tag (`MRK:TAG`)
- A title
- Keywords
- A line range (`L<start>-<end>`)

Example TOC entry:
```
<!-- - MRK:NAVSPEC_PROJECT_WORKFLOW — Project workflow | project,workflow,beacon,next | L145-210 -->
```

Read the TOC block first. Find the entry whose keywords match what you need.

### Step 2 — Fetch only the matching section

Use the line range from the TOC entry. Fetch exactly `L<start>` through `L<end>`:

```
Read(file, offset=<start>, limit=<end>-<start>+1)
```

Do not read the whole file. Do not use a default line count. The line range is precise.

### Step 3 — Check for NAV-RULE

When you navigate to a section anchor, the line immediately after the anchor heading may have a `NAV-RULE:` comment:

```markdown
## MRK:SOME_SECTION — Title | keywords | L50-80
<!-- NAV-RULE: propose-before-edit -->
```

If a NAV-RULE is present, read and follow it before doing anything with the section. See [NAV-RULE tokens](#nav-rule-tokens) below.

### Step 4 — No TOC match? Grep fallback

If no TOC entry matches your query keywords:
1. Note the miss (search-miss)
2. Grep the file for a literal term from your query
3. If found, read the surrounding section
4. If still not found, expand to a broader section read using the ORC-INDEX.md routing

Do not bulk-read the whole file at step 4.

---

## Understanding anchors

Every section in a NAV file starts with an anchor line:

**Markdown files:**
```markdown
## MRK:PREFIX_SECTION — Title | keywords | L<start>-<end>
```

**Script files:**
```bash
# MRK:PREFIX_SECTION — Title | keywords | L<start>-<end>
```

The anchor serves two purposes:
1. It's the TOC entry target — when you fetch `L<start>`, you land on or just above the anchor
2. It marks the section boundary — everything from this anchor to the next is this section's scope

### Anchor namespacing

Anchors are prefixed to stay unique across large projects:

| File type | Prefix convention | Example |
|-----------|------------------|---------|
| Scripts | File prefix (`03` for `03_scan.sh`) | `MRK:03_PASS1` |
| Docs | Doc slug | `MRK:README_QUICKSTART` |
| Skill files | Skill prefix | `MRK:NAVSKILL_EDITPROTO` |
| Tables | `TAB:N` | `MRK:TAB:1` |
| Figures | `FIG:N` | `MRK:FIG:1` |

---

## NAV-RULE tokens

NAV-RULE constraints protect sections from accidental edits. As an operator reading (not editing) files, you'll mostly encounter:

| Token | What it means for you |
|-------|----------------------|
| `read-toc-first` | Read the full `MRK:NAV_TOC` before this section. Already done in step 1 above. |
| `no-edit` | This section is locked — generated output or runtime data. Read-only. |
| `propose-before-edit` | Any change needs user confirmation before proceeding. |
| `insert-here` | If you're adding content of this section's type, this is the right place. |
| `same-commit:<file>` | Changes here must commit atomically with the named file. |
| `no-insert-before` | Nothing can be inserted above this anchor without displacing all TOC ranges. |
| `no-insert-after` | Nothing can be inserted after this section's last line (code boundary). |

---

## The integrity hash

The TOC header includes an integrity hash:

```
<!-- NAV-LEN: 12 entries | Integrity-hash: 6f2b13b4384bbe64 | Last-indexed: 2026-04-27 -->
```

This hash changes whenever anchors are added, removed, or renamed. If you see:
- `UNMRKD` — the file has no anchors yet; it has the NAV header but hasn't been marked up
- A stale hash — the reindex tool hasn't been run since the last edit; line ranges may be slightly off

If you see `[reindex]` in a TOC entry, the file needs reindexing before you can rely on its line ranges.

---

## The domain index

The `L2` line in every NAV file points to the **domain index** — the repository's top-level index (e.g., `NAV-TOOLS-INDEX.md`, `AUDIT-ORC-INDEX.md`).

The domain index lists:
- All NAV-indexed files in the repository
- Their top-level anchors
- The project context block

When starting work in an unfamiliar repository or after a gap, read the domain index first to orient yourself before navigating into individual files.

---

## Common patterns

### "I want to read a specific section of a skill file"

1. Open the skill's `SKILL.md`
2. Read lines 1–30 (the TOC block — always near the top)
3. Find the keyword match in the TOC
4. Fetch that L-range

### "I want to understand the structure of a repo"

1. Find the domain index (`*-INDEX.md` at the repo root)
2. Read its TOC — it lists all files and their top anchors
3. Navigate from there

### "I know what I'm looking for but don't know which file"

1. Check the domain index for file-level routing
2. If the domain index has an anchor for your topic, navigate to it
3. Otherwise, Grep across the repo for a literal term, find the file, then navigate within it

---

## What not to do

- **Don't bulk-read a NAV file.** It defeats the system and wastes context.
- **Don't ignore NAV-RULE.** It protects structural integrity — especially `propose-before-edit` and `no-insert-before`.
- **Don't edit without reindexing.** After any edit to a NAV file, run the reindex tool to keep line numbers accurate.
- **Don't guess line numbers.** Use the TOC. If the TOC is stale (after an edit), reindex first.

---

## Where to go next

- [NAV v1 Concepts](nav-v1-user-guide.md) — the model and vocabulary
- [NAV Project Workflow](nav-project-proc-guide.md) — project management on top of NAV
- [Getting Started](getting-started.md) — installation and first session

<!-- L2 NAV:v1 → ../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
