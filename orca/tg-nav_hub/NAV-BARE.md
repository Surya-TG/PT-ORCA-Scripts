<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->

<!-- NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z -->

# NAV-BARE — navigation read protocol

**Compatible with**: Claude Code (load as skill via `/nav_bare`) · Codex (read as instruction file) · any model (follow protocol directly)

---

## What this is

A precise reading protocol for indexed content. Instead of reading files top-to-bottom, you read the table of contents first, then fetch only the section you need. Reduces context cost; keeps navigation accurate.

---

## Recognizing indexed files

A file uses the NAV index format if its first 5 lines contain a header block:

```
<!-- L1 NAV — description -->
<!-- L2 NAV:v3 → path/to/parent-index -->
```

Files without this header are unindexed — read them normally with no NAV constraints.

---

## Read gate: TOC first

**Before reading any section of an indexed file**, read its table of contents (TOC) block. The TOC is usually near the top of the file, marked:

```
<!-- MRK:<NAME>_NAV_TOC — ... -->
```

The TOC lists every section with its name, description, and line range (`| L<start>-L<end>`).

1. Match your query against section descriptions
2. Pick the right section
3. Read only that section — start at `L_start`, end at `L_end`; count = `L_end − L_start + 1`

**Do not read the full file.** Do not guess line ranges. Derive all ranges from the TOC.

**If no TOC match**: surface to the operator. Do not search the file content.

---

## Read order (step by step)

1. **File header** (first 5 lines) — confirms NAV format; shows parent index path
2. **TOC block** — read the full table of contents near the file top
3. **Match query to TOC entries** — use keywords from section names and descriptions
4. **Size check before reading**:
   | Range | Action |
   |---|---|
   | ≤ 100 lines | read directly |
   | 101–300 lines | prompt operator: "heavy section — fetch?" |
   | 301–1000 lines | prompt + offer sub-section breakdown |
   | > 1000 lines | refuse full read; ask operator to pick a sub-section |
5. **Fetch the section** using the exact line range from the TOC
6. **No match?** → tell the operator; do not grep or scan

---

## Orientation on load

When this protocol activates, build a space map before navigating:

1. From the current working directory, walk up until you find a file matching `*-INDEX.md`
2. Read its TOC — this is the space map listing what exists here
3. Use the map for all further navigation

If no `*-INDEX.md` is found after walking up 4+ levels: operate on local files only; tell the operator.

---

## Rules

- Read TOC before any section — always
- Use line ranges from the TOC — never estimate
- Do not read a whole file when sections are available
- Do not search (grep/find) indexed file content — use the TOC
- If a TOC entry shows `[reindex]` in the range, the range is stale — tell the operator
- This protocol is **read-only** — it does not write, edit, or create files

---

*Spec source: nav_bare v2.0.0-DRAFT (NAV-TOOLS-v3 · ursul0/nav-tools-v3). This file is the TG-delivery / cross-model form — no Claude Code-specific syntax.*

<!-- L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md -->
<!-- L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count) -->
