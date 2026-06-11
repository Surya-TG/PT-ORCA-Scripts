#!/usr/bin/env python3
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md

# MRK:ORC_NAV_REINDEX_NAV_TOC — Section index | nav,toc,index | L5-63
# - MRK:REINDEX_CONSTANTS — Module constants and configuration | reindex,constants,module,configuration,config | L64-126
# - MRK:REINDEX_DETECT — File type detection | reindex,detect,type,detection,filetype | L127-142
# - MRK:REINDEX_PARSE — Anchor and TOC parsing | reindex,parse,anchor,toc,parsing | L143-242
# - MRK:REINDEX_STRIP — Legacy format stripping | reindex,strip,legacy,format,stripping | L243-411
# - MRK:REINDEX_EMIT — Output generation helpers | reindex,emit,output,generation,helpers | L412-531
# - MRK:REINDEX_MIGRATE — Core migration and reindex engine | reindex,migrate,core,migration,engine | L532-809 | ⚠ read-toc-first; propose-before-edit
# - MRK:REINDEX_CLI — Scope configuration and file collection | reindex,cli,scope,configuration,collection | L810-907
# - MRK:REINDEX_CMDS — Migrate, verify, reindex subcommands | reindex,cmds,migrate,verify,subcommands | L908-1006
# - MRK:REINDEX_INDEX_HELPERS — Index generation helpers | reindex,index,helpers,generation,user | L1007-1326
# - MRK:REINDEX_CMD_INDEX — Index subcommand | reindex,cmd,index,subcommand,orc | L1327-1472
# - MRK:REINDEX_CMD_APPEND — Append subcommand | reindex,cmd,append,subcommand,single | L1473-1597
# - MRK:REINDEX_CMD_MAIN_INDEX — main-index subcommand: hierarchical MAIN-INDEX + dirname-indexes | reindex,cmd,main,index,subcommand | L1598-1644
# - MRK:REINDEX_MAIN — Entry point and subcommand dispatch | reindex,main,entry,point,subcommand | L1645-1688
# NAV-LEN: 13 entries | Integrity-hash: 26c0d2177f2fdc9f | Last-indexed: 2026-06-09T07:09:41Z

"""
orc-nav-reindex.py — Migrate and maintain ORC NAV v1 format.

Reads files in the current directory (or explicit file args), detects whether they
use the legacy PT-Orc MRK format or the new ORC NAV v1 format, and emits the
new format: L1/L2 header (2 lines for non-shebang, 3 for shebang), MRK:NAV_TOC
block with line-ranges + integrity hash, MRK anchors in new `TAG — TITLE | kw | L-range`
form, and a domain index (<DOMAIN>-INDEX.md) for the project.

Subcommands:
    migrate  <file>...          Rewrite target files from legacy format to v1.
    verify   [<file>...]        Recompute hashes + ranges; report drift. Read-only.
    reindex  [<file>...]        Refresh ranges/hash/TOC in already-v1 files (idempotent).
    index                       Regenerate the domain index (<DOMAIN>-INDEX.md) from all indexed files in cwd.
    append   <file> [--index]   Add a single NAV:v1 file's entry into a target index,
                                then reindex the index. Default index: auto-detected domain index in cwd.

Notes:
    * Preserves file body content exactly (only headers + MRK anchors + NAV_TOC
      block are rewritten).
    * Keywords auto-generated from TITLE + description when migrating.
    * Out-of-scope files (no MRK anchors, binary, etc.) skipped.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Windows console default encoding (cp1252) cannot encode Unicode arrows
# and em-dashes used in v1 output and in this tool's own docstrings.
# Force UTF-8 on stdout/stderr so --help and progress output work.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass  # older Python or non-TTY streams

# MRK:REINDEX_CONSTANTS — Module constants and configuration | reindex,constants,module,configuration,config | L64-126
NAV_VERSION = "v1"
CAP_LINE_CHARS = 120
HASH_LEN = 16  # first 16 chars of SHA-256
LINE_SEP = "=" * 77  # existing PT-Orc convention

# Known NAV-RULE tokens — validated by verify pass
KNOWN_NAV_RULE_TOKENS = {
    "no-insert-before", "no-insert-after", "no-edit",
    "insert-here", "read-toc-first", "propose-before-edit",
}
# same-commit:<file> is parameterized — handled separately in validation

# Extracts NAV-RULE token string from a comment line
NAV_RULE_RE = re.compile(r"^\s*(?:<!--\s*|#\s*|//\s*)NAV-RULE:\s*(.+?)(?:\s*-->)?\s*$")

# Sentinel values written into the draft during Pass 1, then substituted in
# Pass 2 once real values are known.  Using named constants prevents the
# literal-coupling bug where edits to template strings break the Pass-2 match.
_HASH_SENTINEL      = "e3b0c44298fc1c14"   # SHA-256("") — valid stored value for UNMRKD files
_TIMESTAMP_SENTINEL = "0000-00-00T00:00:00Z"  # impossible real date, always replaced

# Self-integrity hash — embedded in tool, verified by zeroing field → hash → compare.
TOOL_INTEGRITY = "a5e88188be94922b"
_TOOL_INTEGRITY_RE = re.compile(r'(TOOL_INTEGRITY\s*=\s*")[0-9a-f]{16}(")')

# L1 canonical text — keep under 120 chars
L1_TEXT = "L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)"

# Comment style by extension
COMMENT_STYLES = {
    ".md": ("<!-- ", " -->"),
    ".sh": ("# ", ""),
    ".bash": ("# ", ""),
    ".py": ("# ", ""),
    ".ps1": ("# ", ""),
    ".yml": ("# ", ""),
    ".yaml": ("# ", ""),
    ".conf": ("# ", ""),
    ".toml": ("# ", ""),
    ".ini": ("# ", ""),
    ".js": ("// ", ""),
    ".ts": ("// ", ""),
    ".go": ("// ", ""),
    ".rs": ("// ", ""),
    ".c": ("// ", ""),
    ".cpp": ("// ", ""),
    ".h": ("// ", ""),
}

# Stopwords for keyword generation (lowercase)
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has",
    "have", "in", "into", "is", "it", "its", "of", "on", "or", "that", "the",
    "this", "to", "was", "were", "with", "when", "where", "which", "who",
    "not", "no", "all", "if", "else", "then", "also", "but", "per", "via",
    "each", "any", "some", "only", "own", "same", "so", "than", "too", "very",
    "will", "can", "just", "over", "under", "mode", "file", "files",
}

# --------------------------------------------------------------------- #
# File type detection                                                   #
# --------------------------------------------------------------------- #
# MRK:REINDEX_DETECT — File type detection | reindex,detect,type,detection,filetype | L127-142

def detect_filetype(path: Path, first_line: str) -> tuple[str, tuple[str, str]]:
    """
    Return (kind, (comment_open, comment_close)).
    kind is 'shebang' (line 1 = shebang) or 'non-shebang'.
    """
    ext = path.suffix.lower()
    style = COMMENT_STYLES.get(ext, ("# ", ""))
    if first_line.startswith("#!"):
        return ("shebang", style)
    return ("non-shebang", style)

# --------------------------------------------------------------------- #
# Parsing legacy + v1 formats                                            #
# --------------------------------------------------------------------- #
# MRK:REINDEX_PARSE — Anchor and TOC parsing | reindex,parse,anchor,toc,parsing | L143-242

# Matches an anchor with "-- " or "— " separator (both legacy and v1 forms).
ANCHOR_RE = re.compile(
    r"""^
    (?P<prefix>\s*(?:\#\s*|\#\#+\s*|<!--\s*|//\s*))    # comment prefix
    MRK:(?P<tag>[A-Z0-9_:]+)
    \s*(?:--|—)\s*
    (?P<rest>.+?)
    (?:\s*-->)?\s*$
    """,
    re.VERBOSE,
)

# MRK:NAV_TOC v1 line form: "- MRK:TAG — TITLE | kw1,kw2 | L<s>-<e>"
TOC_ENTRY_V1_RE = re.compile(
    r"""^\s*-\s*
    MRK:(?P<tag>[A-Z0-9_:]+)
    \s+—\s+
    (?P<title>[^|]+?)
    \s*\|\s*
    (?P<kw>[^|]*?)
    \s*\|\s*
    (?:L(?P<start>\d+)-(?P<end>\d+)|\[reindex\])
    \s*$
    """,
    re.VERBOSE,
)

def parse_anchor_line(line: str) -> tuple[str, str, str] | None:
    """Return (tag, title, desc_or_keywords) if the line is an MRK anchor header."""
    m = ANCHOR_RE.match(line)
    if not m:
        return None
    tag = m.group("tag")
    rest = m.group("rest").strip()
    # v1 form: TITLE | kw | L<range>
    if "|" in rest:
        parts = [p.strip() for p in rest.split("|")]
        if len(parts) >= 1:
            title = parts[0]
            return (tag, title, parts[1] if len(parts) > 1 else "")
    # legacy form: "TITLE  description" (2-space sep) or "TITLE description" or just "TITLE"
    if "  " in rest:
        title, _, desc = rest.partition("  ")
        return (tag, title.strip(), desc.strip())
    return (tag, rest, "")

def is_section_anchor_line(line: str) -> bool:
    """Anchor line that starts a section (has `-- TITLE` or `— TITLE`)."""
    return ANCHOR_RE.match(line) is not None

def find_anchors(lines: list[str]) -> list[tuple[int, str, str, str]]:
    """
    Return [(line_idx_0based, tag, title, desc_or_keywords), ...]
    Only section-anchor lines. Filters out TOC-entry lines (those don't match
    ANCHOR_RE because they don't have `-- ` separator).
    Skips lines inside markdown code fences (``` blocks) to prevent phantom anchors
    from MRK syntax examples in documentation files.
    """
    out = []
    in_fence = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        parsed = parse_anchor_line(line)
        if parsed:
            out.append((i, *parsed))
    return out


def parse_nav_rule(line: str) -> str | None:
    """Return the NAV-RULE token string if the line is a NAV-RULE comment, else None."""
    m = NAV_RULE_RE.match(line)
    if m:
        return m.group(1).strip()
    return None


def find_nav_rules(lines: list[str], anchors: list[tuple[int, str, str, str]]) -> dict[str, str]:
    """
    For each anchor, check if the immediately following line is a NAV-RULE comment.
    Returns {tag: token_string}. Only tags that have a NAV-RULE are included.
    """
    rules: dict[str, str] = {}
    for anchor_idx, tag, _title, _desc in anchors:
        next_idx = anchor_idx + 1
        if next_idx < len(lines):
            rule = parse_nav_rule(lines[next_idx])
            if rule:
                rules[tag] = rule
    return rules

# --------------------------------------------------------------------- #
# Legacy header + NAV-block stripping                                    #
# --------------------------------------------------------------------- #
# MRK:REINDEX_STRIP — Legacy format stripping | reindex,strip,legacy,format,stripping | L243-411

def find_legacy_nav_block(lines: list[str], filetype: str = "script") -> tuple[int, int] | None:
    """
    Return (start_idx, end_idx_exclusive) of a legacy (_NAV) or v1 (_NAV_TOC)
    NAV block, or None if not found. `filetype` is 'md' or 'script' — affects
    how we bound the legacy block (MDs allow prose; scripts end at first
    non-comment content).
    """
    # Find the NAV anchor line
    nav_idx = None
    nav_tag = None
    for i, line in enumerate(lines):
        parsed = parse_anchor_line(line)
        if not parsed:
            continue
        t = parsed[0]
        if t.endswith("_NAV_TOC") or t.endswith("_NAV") or t == "NAV_TOC":
            nav_idx = i
            nav_tag = t
            break
    if nav_idx is None:
        return None

    is_v1 = nav_tag.endswith("_NAV_TOC") or nav_tag == "NAV_TOC"
    # _NAV suffix alone is too broad — user tags can end in _NAV (e.g. NPS_P2_NAV).
    # Only treat _NAV anchors as legacy NAV blocks when found at the very start of
    # the provided lines (pos 0), indicating they precede any body content.
    # Deeper occurrences are user sections and must be left untouched.
    if not is_v1 and nav_tag.endswith("_NAV") and nav_idx > 0:
        return None

    # Block start: legacy format may have a "====" separator immediately above
    start = nav_idx
    if not is_v1 and start > 0:
        prev = lines[start - 1].strip()
        if prev.startswith("#") and "=" * 20 in prev:
            start -= 1

    # Block end
    if is_v1:
        # V1: block runs until the NAV-LEN/Integrity-hash stats line (inclusive)
        end = nav_idx + 1
        found_stats = False
        for e in range(nav_idx + 1, len(lines)):
            if "NAV-LEN:" in lines[e] and ("Integrity-hash:" in lines[e] or "integrity" in lines[e].lower()):
                end = e + 1
                found_stats = True
                break
            # Safety: stop at next non-NAV section anchor
            parsed = parse_anchor_line(lines[e])
            if parsed and not (parsed[0].endswith("_NAV_TOC") or parsed[0].endswith("_NAV") or parsed[0] == "NAV_TOC"):
                end = e
                break
        if not found_stats:
            # Fallback: block ran to first non-NAV anchor (end already set)
            pass
    elif filetype == "md":
        # Legacy MD: NAV header + prose + table/bullets. Ends at the next
        # `## MRK:TAG -- TITLE` section anchor, or at a horizontal rule `---`.
        end = nav_idx + 1
        while end < len(lines):
            line = lines[end]
            stripped = line.strip()
            parsed = parse_anchor_line(line)
            if parsed:
                tag = parsed[0]
                if not (tag.endswith("_NAV") or tag.endswith("_NAV_TOC") or tag == "NAV_TOC"):
                    break
            # Horizontal rule `---` on its own line = end of NAV block
            if stripped == "---":
                end += 1  # include the rule itself
                break
            end += 1
    else:
        # Legacy script: NAV block ends at first non-comment, non-blank line.
        # TOC entries (# MRK:TAG  TITLE, no `-- `), `===` banners, blank lines
        # are all considered NAV-block-interior.
        end = nav_idx + 1
        while end < len(lines):
            line = lines[end]
            stripped = line.strip()
            if not stripped:
                end += 1
                continue
            # Comment-prefixed lines: inside NAV
            if stripped.startswith(("#", "//", "<!--")):
                end += 1
                continue
            # Non-comment content = body = break
            break
        # Trim: if the last included line is a "===" banner that precedes
        # a section anchor (i.e., belongs to the next section's banner),
        # back off one line.
        while end > nav_idx + 1:
            prev = lines[end - 1].strip()
            if prev.startswith("#") and "=" * 20 in prev:
                # Check if what comes after `end` is a section anchor
                look = end
                while look < len(lines) and lines[look].strip() == "":
                    look += 1
                if look < len(lines):
                    next_parsed = parse_anchor_line(lines[look])
                    if next_parsed and not (
                        next_parsed[0].endswith("_NAV")
                        or next_parsed[0].endswith("_NAV_TOC")
                        or next_parsed[0] == "NAV_TOC"
                    ):
                        end -= 1
                        continue
            break

    # Consume a single trailing blank line after the block
    if end < len(lines) and lines[end].strip() == "":
        end += 1

    return (start, end)

def strip_legacy_header(lines: list[str], kind: str) -> tuple[list[str], list[str]]:
    """
    Strip the legacy 2-line (MD) or 2-line-after-shebang (script) header block
    plus any immediately-following "===" separators that belong to it.
    Returns (preserved_header_lines, remaining_lines).

    Logic: preserve shebang (if any), discard the next 1-2 lines if they look
    like legacy NAV/docs-map lines.
    """
    preserved = []
    i = 0
    if kind == "shebang":
        preserved.append(lines[0])
        i = 1
    # Legacy NAV line pattern — broad: any line in the first 3 with "NAV: "
    # followed by non-whitespace content (the strip loop caps at 3 iterations,
    # so content lines deeper in the file that happen to mention "NAV:" are
    # not at risk).
    nav_pat = re.compile(r"NAV:\s*\S", re.IGNORECASE)

    # Skip up to 3 legacy lines
    for _ in range(3):
        if i >= len(lines):
            break
        line = lines[i]
        if nav_pat.search(line):
            i += 1
            continue
        # New-format L1/L2 lines — skip these so we can rewrite
        if re.search(r"L[12]\s+ORC-NAV|NAV:v1\s*[→-]", line):
            i += 1
            continue
        break

    # Consume one trailing blank line between the (stripped) header and
    # whatever follows — prevents "+1 blank" drift on re-run of v1 files.
    if i < len(lines) and lines[i].strip() == "":
        i += 1

    # Also consume lone NAV-LEN stats lines (possibly multiple duplicates from
    # prior reindex passes) and trailing blanks.
    while i < len(lines) and "NAV-LEN:" in lines[i] and "Integrity-hash:" in lines[i]:
        i += 1
        if i < len(lines) and lines[i].strip() == "":
            i += 1

    return preserved, lines[i:]

# --------------------------------------------------------------------- #
# Emission helpers                                                       #
# --------------------------------------------------------------------- #
# MRK:REINDEX_EMIT — Output generation helpers | reindex,emit,output,generation,helpers | L412-531

def emit_comment_line(text: str, style: tuple[str, str]) -> str:
    """Format one-line comment with the given comment style."""
    open_, close = style
    return f"{open_}{text}{close}\n"

def strip_tail_mirror(lines: list[str]) -> list[str]:
    """
    Remove a trailing L2/L1 NAV mirror if present. The mirror is the last
    two non-blank lines (Ln-1 = L2, Ln = L1), with optional preceding blank.
    """
    if len(lines) < 2:
        return lines
    # Find last non-blank line
    i = len(lines) - 1
    while i >= 0 and lines[i].strip() == "":
        i -= 1
    if i < 1:
        return lines
    last = lines[i]
    prev = lines[i - 1]
    has_l1 = bool(re.search(r"L1\s+ORC-NAV", last))
    has_l2 = bool(re.search(r"L2\s+NAV:v1", prev))
    if not (has_l1 and has_l2):
        return lines
    # Cut at i-1, and also drop any preceding blank(s) that separated body
    # from the mirror
    cut = i - 1
    while cut > 0 and lines[cut - 1].strip() == "":
        cut -= 1
    return lines[:cut]

def emit_header(kind: str, style: tuple[str, str], next_jump: str) -> list[str]:
    """Return the 2-line (non-shebang) or 2-line-after-shebang (shebang) header."""
    l1 = emit_comment_line(L1_TEXT, style)
    l2 = emit_comment_line(f"L2 NAV:{NAV_VERSION} → {next_jump}", style)
    return [l1, l2]

def generate_keywords(tag: str, title: str, desc: str) -> list[str]:
    """
    Auto-generate 2–5 keyword tokens from the tag + title + description.
    Lowercase, alnum+underscore only, deduped, stopwords filtered.
    """
    source = f"{tag} {title} {desc}".lower()
    # Split on non-alnum
    tokens = re.split(r"[^a-z0-9]+", source)
    seen = set()
    kws = []
    for tok in tokens:
        if not tok or len(tok) < 2 or tok in STOPWORDS or tok.isdigit():
            continue
        if tok in seen:
            continue
        seen.add(tok)
        kws.append(tok)
        if len(kws) >= 5:
            break
    # Fallback: use tag stem if nothing survived
    if len(kws) < 2:
        stem = re.split(r"[^a-z0-9]+", tag.lower())
        for s in stem:
            if s and s not in seen and len(s) >= 2:
                kws.append(s)
                seen.add(s)
                if len(kws) >= 2:
                    break
    return kws[:5]

def emit_anchor_line(tag: str, title: str, keywords: list[str], line_range: str, style: tuple[str, str]) -> str:
    """Emit an MRK anchor comment line in v1 form."""
    kw = ",".join(keywords)
    text = f"MRK:{tag} — {title} | {kw} | {line_range}"
    return emit_comment_line(text, style)

def emit_toc_entry(tag: str, title: str, keywords: list[str], line_range: str) -> str:
    """Emit a NAV_TOC list entry."""
    kw = ",".join(keywords)
    return f"- MRK:{tag} — {title} | {kw} | {line_range}\n"

def compute_integrity_hash(
    anchors_with_ranges: list[tuple[str, str]],
    nav_rules: dict[str, str] | None = None,
) -> str:
    """First 16 chars of SHA-256 of sorted (TAG, L<s>-<e>[, rule]) triples joined by '\\n'."""
    nav_rules = nav_rules or {}
    parts = []
    for tag, rng in anchors_with_ranges:
        rule = nav_rules.get(tag, "")
        parts.append(f"{tag} {rng} {rule}".rstrip())
    blob = "\n".join(sorted(parts)).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:HASH_LEN]

def self_hash() -> str:
    """SHA-256 of this source file with TOOL_INTEGRITY zeroed to 16 zeroes."""
    src = Path(__file__).read_text(encoding="utf-8")
    zeroed = _TOOL_INTEGRITY_RE.sub(r'\g<1>' + "0" * HASH_LEN + r'\g<2>', src, count=1)
    return hashlib.sha256(zeroed.encode("utf-8")).hexdigest()[:HASH_LEN]

def stamp_self() -> None:
    """Compute self_hash() and write it back into TOOL_INTEGRITY in this source file."""
    h = self_hash()
    path = Path(__file__)
    src = path.read_text(encoding="utf-8")
    new_src = _TOOL_INTEGRITY_RE.sub(r'\g<1>' + h + r'\g<2>', src, count=1)
    if new_src != src:
        path.write_text(new_src, encoding="utf-8", newline="")

def _backup_index(index_path: Path) -> None:
    """Copy index → .backup/<stem>_<timestamp><ext> under project root."""
    backup_dir = index_path.parent / ".backup"
    backup_dir.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    dest = backup_dir / f"{index_path.stem}_{ts}{index_path.suffix}"
    dest.write_bytes(index_path.read_bytes())
    print(f"  Backup → .backup/{dest.name}")

# --------------------------------------------------------------------- #
# Migration / reindex main                                               #
# --------------------------------------------------------------------- #
# MRK:REINDEX_MIGRATE — Core migration and reindex engine | reindex,migrate,core,migration,engine | L532-809
# NAV-RULE: read-toc-first; propose-before-edit

def derive_file_prefix(path: Path) -> str:
    """Derive tag-prefix from the filename stem."""
    stem = path.stem
    # Numeric prefix pattern: 01_dns_recon.sh → '01'
    m = re.match(r"^(\d+)_", stem)
    if m:
        return m.group(1)
    # orc-common-lib.sh → 'COM' (from leading non-hyphen segment? no — use stem-based)
    # README.md → 'README'
    # PT-Orc-design.md → 'D' (legacy used MRK:D_, MRK:S01, etc.)
    # For migration we preserve existing anchor names, only synthesise prefix
    # when we need to name the NAV_TOC block itself.
    # Strip trailing timestamp suffix before slugifying to keep NAV_TOC anchor names
    # stable and readable: NOTES-foo_20260426-123000 → NOTES-foo
    stem = re.sub(r"_\d{8}(-\d{6})?$", "", stem)
    # Strategy: use upper-case, non-alnum → _, trimmed.
    slug = re.sub(r"[^A-Za-z0-9]+", "_", stem).strip("_").upper()
    # Cap prefix length so NAV_TOC anchor names stay bounded (~40 + "_NAV_TOC" = ~48)
    if len(slug) > 40:
        slug = slug[:40].rstrip("_")
    return slug

def migrate_file(path: Path) -> dict:
    """Migrate one file to v1. Returns a result dict."""
    result = {"path": str(path), "status": "skipped", "anchors": 0, "message": ""}
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except Exception as e:
        result["status"] = "error"
        result["message"] = f"read failed: {e}"
        return result

    # Preserve line-ending style
    uses_crlf = "\r\n" in raw
    lines = raw.splitlines(keepends=True)
    if not lines:
        return result

    first_line = lines[0]
    kind, style = detect_filetype(path, first_line)

    # All files get a v1 header (top + mirrored tail). Files with no MRK
    # anchors are flagged UNMRKD (header present, but no marked sections).
    all_anchors = find_anchors(lines)

    # Detect + isolate leading frontmatter (marp/YAML block bounded by `---`)
    frontmatter: list[str] = []
    body_lines = lines
    if kind == "non-shebang" and lines[0].strip() == "---":
        # Find closing `---`
        for idx in range(1, min(len(lines), 40)):
            if lines[idx].strip() == "---":
                frontmatter = lines[: idx + 1]
                # Consume one trailing blank line after frontmatter
                j = idx + 1
                if j < len(lines) and lines[j].strip() == "":
                    frontmatter.append(lines[j])
                    j += 1
                body_lines = lines[j:]
                break

    # Strip any existing tail mirror first so it doesn't confuse header logic
    body_lines = strip_tail_mirror(body_lines)

    # Strip legacy header (from body_lines — after frontmatter)
    preserved_hdr, remaining = strip_legacy_header(body_lines, kind)

    # Strip legacy NAV block from remaining (file-type-aware bounding).
    # Loop in case multiple NAV blocks accumulated from prior reindex passes.
    filetype_hint = "md" if path.suffix.lower() == ".md" else "script"
    for _ in range(5):  # bounded loop, defensive against infinite loops
        nav_block_range = find_legacy_nav_block(remaining, filetype_hint)
        if not nav_block_range:
            break
        start, end = nav_block_range
        remaining = remaining[:start] + remaining[end:]

    # Also strip stale lone stats lines anywhere in the first ~10 lines of
    # remaining (orphans left over from UNMRKD -> MRKD transitions).
    cleaned = []
    stripped = 0
    for idx, line in enumerate(remaining):
        if idx < 10 and "NAV-LEN:" in line and "Integrity-hash:" in line:
            stripped += 1
            # Also skip a trailing blank
            continue
        # Skip a blank line immediately after a stripped stats line
        if stripped > 0 and line.strip() == "" and len(cleaned) > 0 and cleaned[-1].strip() == "":
            stripped = 0  # consume one blank
            continue
        cleaned.append(line)
        if stripped > 0 and line.strip() != "":
            stripped = 0
    remaining = cleaned

    # Re-find anchors in `remaining` (the body). Exclude the NAV_TOC header
    # anchor itself — that's meta. Do NOT exclude _NAV-suffixed tags: user
    # sections can legitimately end in _NAV (e.g. MRK:NPS_P2_NAV). The
    # NAV_TOC block has already been stripped from `remaining` by this point.
    body_anchors = []
    for idx, tag, title, desc in find_anchors(remaining):
        if tag.endswith("_NAV_TOC") or tag == "NAV_TOC":
            continue
        body_anchors.append((idx, tag, title, desc))

    # Detect NAV-RULE tokens (line immediately after each anchor in `remaining`)
    body_anchor_rules = find_nav_rules(remaining, body_anchors)

    # Auto-generate keywords per anchor
    anchor_meta = []
    for idx, tag, title, desc in body_anchors:
        kws = generate_keywords(tag, title, desc)
        anchor_meta.append({
            "idx_in_remaining": idx, "tag": tag, "title": title,
            "keywords": kws, "nav_rule": body_anchor_rules.get(tag, ""),
        })

    # Compute next_jump for L2 — relative path from file's dir to domain index
    _domain_index = _detect_domain_index(Path.cwd())
    if path.name in (_domain_index, "index.md"):
        next_jump = "[project root]"
    else:
        try:
            rel = path.resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            rel = Path(path.name)
        depth = len(rel.parent.parts)
        if depth == 0:
            next_jump = f"./{_domain_index}"
        else:
            next_jump = "../" * depth + _domain_index

    # Rewrite each anchor's line in `remaining` to v1 form (with [reindex] placeholder)
    # Note: the anchor's original line has the section banner `#========` above+below
    # in scripts, and is an H2 heading in MDs. We rewrite only the anchor line itself.
    new_remaining = list(remaining)
    for meta in anchor_meta:
        i = meta["idx_in_remaining"]
        orig = new_remaining[i]
        # Determine anchor prefix from original line
        m = re.match(r"^(\s*(?:\#+|\#|<!--|//)\s*)", orig)
        anchor_prefix = m.group(1) if m else "# "
        # Preserve trailing close-comment for MDs
        trailing = " -->\n" if "<!--" in orig and "-->" in orig else "\n"
        new_line = f"{anchor_prefix}MRK:{meta['tag']} — {meta['title']} | {','.join(meta['keywords'])} | [reindex]{trailing.rstrip(chr(10))}\n"
        new_remaining[i] = new_line

    # Now build the NAV_TOC block as a comment-prefixed list.
    # Block tag: MRK:<prefix>_NAV_TOC (keeps unique per file).
    # If file has 0 anchors, skip the TOC block entirely (header-only file).
    prefix = derive_file_prefix(path)
    toc_tag = f"{prefix}_NAV_TOC" if prefix and not prefix.startswith("NAV_TOC") else "NAV_TOC"
    nav_len = len(anchor_meta)

    if nav_len == 0:
        # No section anchors — emit a minimal stats line with UNMRKD flag,
        # so the file is unambiguously v1-indexed but searchably-flagged as
        # lacking internal anchors. `grep UNMRKD` enumerates all such files.
        toc_tag = None  # sentinel: no TOC header anchor
        nav_toc_stats = emit_comment_line(
            f"NAV-LEN: 0 entries | UNMRKD | Integrity-hash: {_HASH_SENTINEL} | Last-indexed: {_TIMESTAMP_SENTINEL}",
            style,
        )
        nav_block = [nav_toc_stats, "\n"]
    else:
        nav_toc_header = emit_comment_line(f"MRK:{toc_tag} — Section index | nav,toc,index | [reindex]", style)
        nav_toc_body_lines = []
        for meta in anchor_meta:
            rule_suffix = f" | ⚠ {meta['nav_rule']}" if meta["nav_rule"] else ""
            nav_toc_body_lines.append(
                emit_comment_line(
                    f"- MRK:{meta['tag']} — {meta['title']} | {','.join(meta['keywords'])} | [reindex]{rule_suffix}",
                    style,
                )
            )
        nav_toc_stats = emit_comment_line(
            f"NAV-LEN: {nav_len} entries | Integrity-hash: {_HASH_SENTINEL} | Last-indexed: {_TIMESTAMP_SENTINEL}",
            style,
        )
        nav_block = [nav_toc_header] + nav_toc_body_lines + [nav_toc_stats, "\n"]

    # Assemble v1 file:
    #   frontmatter (if any) + preserved_hdr (shebang) + new 2-line header +
    #   blank + NAV_TOC block + remaining + tail mirror (L2, L1 at EOF)
    new_header = emit_header(kind, style, next_jump)
    tail_mirror = [
        "\n",  # blank separator before tail mirror
        emit_comment_line(f"L2 NAV:{NAV_VERSION} → {next_jump}", style),
        emit_comment_line(L1_TEXT, style),
    ]
    # Ensure remaining ends with a newline so tail mirror sits cleanly
    if new_remaining and not new_remaining[-1].endswith("\n"):
        new_remaining[-1] = new_remaining[-1] + "\n"
    draft = frontmatter + preserved_hdr + new_header + ["\n"] + nav_block + new_remaining + tail_mirror

    # --- Pass 2: populate [reindex] placeholders with real line numbers -----
    # Find each anchor's actual line in `draft`, compute [start, end].
    # Use 1-based line numbers.
    tag_to_start = {}
    draft_anchors = find_anchors(draft)
    # Filter out the NAV_TOC block's own anchor and its list-item "anchors"
    # (list entries look like "- MRK:... " and won't match ANCHOR_RE due to
    # leading "-" before MRK; but the NAV_TOC header itself does match).
    section_tags_ordered = [tag for _idx, tag, _t, _d in draft_anchors]
    for idx, tag, _title, _desc in draft_anchors:
        tag_to_start[tag] = idx + 1  # 1-based

    # Compute end lines: next anchor's start - 1, or EOF
    ends = {}
    ordered = sorted(
        [(idx, tag) for idx, tag, _t, _d in draft_anchors],
        key=lambda x: x[0],
    )
    for i, (idx, tag) in enumerate(ordered):
        if i + 1 < len(ordered):
            next_idx = ordered[i + 1][0]
            ends[tag] = next_idx  # end = next start - 1 (but we store exclusive)
        else:
            ends[tag] = len(draft)
    tag_to_range = {
        tag: (tag_to_start[tag], ends[tag])
        for tag in tag_to_start
    }

    # Build integrity hash from (TAG, L<s>-<e>[, rule]) triples for section anchors only
    # (exclude NAV_TOC header itself from hash input — it's meta)
    anchors_for_hash = [
        (tag, f"L{start}-{end}")
        for tag, (start, end) in tag_to_range.items()
        if (toc_tag is None or tag != toc_tag) and not tag.endswith("_NAV_TOC") and tag != "NAV_TOC"
    ]
    integrity = compute_integrity_hash(anchors_for_hash, body_anchor_rules)

    # Now substitute [reindex] placeholders with real values
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    final = []
    for line in draft:
        new_line = line
        # Replace anchor [reindex] with L<s>-<e>
        m = ANCHOR_RE.match(line)
        if m:
            tag = m.group("tag")
            if tag in tag_to_range:
                start, end = tag_to_range[tag]
                rng = f"L{start}-{end}"
                new_line = line.replace("[reindex]", rng, 1)
        # Replace TOC-entry [reindex] with L<s>-<e>
        else:
            # Look for TOC entry pattern: "- MRK:TAG — TITLE | kw | [reindex]"
            m2 = re.match(r"^(?P<prefix>.*?-\s*MRK:(?P<tag>[A-Z0-9_:]+)\s+—.*?\|.*?\|\s*)\[reindex\](?P<suffix>.*)$", line)
            if m2:
                tag = m2.group("tag")
                if tag in tag_to_range:
                    start, end = tag_to_range[tag]
                    rng = f"L{start}-{end}"
                    new_line = line.replace("[reindex]", rng, 1)
        # Replace NAV-LEN stats line
        if f"Integrity-hash: {_HASH_SENTINEL}" in new_line:
            new_line = new_line.replace(f"Integrity-hash: {_HASH_SENTINEL}", f"Integrity-hash: {integrity}")
        if f"Last-indexed: {_TIMESTAMP_SENTINEL}" in new_line:
            new_line = new_line.replace(f"Last-indexed: {_TIMESTAMP_SENTINEL}", f"Last-indexed: {timestamp}")
        final.append(new_line)

    out = "".join(final)
    if uses_crlf and "\r\n" not in out:
        out = out.replace("\n", "\r\n")

    path.write_text(out, encoding="utf-8", newline="")
    result["status"] = "migrated"
    result["anchors"] = nav_len
    return result

# --------------------------------------------------------------------- #
# CLI                                                                    #
# --------------------------------------------------------------------- #
# MRK:REINDEX_CLI — Scope configuration and file collection | reindex,cli,scope,configuration,collection | L810-907

DEFAULT_SCOPE_GLOB = [
    "**/*.sh", "**/*.py", "**/*.ps1", "**/*.md",
]
DEFAULT_SKIP_PATTERNS = [
    # Out-of-scope formats — Living Guide (not NAV v1 compatible)
    "pt-orc-monitor/monitor-spec.md",
    "pt-orc-monitor/monitor-frame.md",
    # User workspace (not project content)
    "memory/",
    "SNT/",
    "chat-starters/",
    # nav-tools may be cloned nested under this project for tool+skill
    # distribution; it has its own .git and its own reindex state.
    "nav-tools/",
    # Generated / ephemeral
    ".git/",
    "=OLD-RUN=/",
    "evidence/",
    "working/",
    "screens/",
    "reports/",
    "outputs/",          # future: correlations/outputs/
    "prj_status/",
    "ACTUAL_RUN/",
    "_nav-migration-test",
    # Regression test sandbox (never index test copies)
    ".regression_test/",
    # Personal working notes
    "gg_tbds_orc-nav_",
    # Nav system draft workspaces — working scratch, not project deliverables
    ".drafts/",
    ".draft/",
    # Project work surfaces — gitignored by default; not domain index content
    ".work/",
    # Profile skill workspace — personal session data (tasks, reminders, metrics)
    ".profile/",
]

def _skip_matches(skip: str, rel: str) -> bool:
    """Match a skip pattern against a relative path.
    Dir patterns (ending in '/') require a segment-boundary match so that
    e.g. 'evidence/' does not accidentally exclude 'skills/pt-evidence/'."""
    if skip.endswith("/"):
        seg = skip.rstrip("/")
        return rel.startswith(skip) or f"/{seg}/" in f"/{rel}"
    return skip in rel

def collect_files(explicit: list[str]) -> list[Path]:
    """Collect target files: explicit args, else default scope."""
    if explicit:
        return [Path(p).resolve() for p in explicit]
    root = Path.cwd()
    collected = []
    for pattern in DEFAULT_SCOPE_GLOB:
        for p in root.glob(pattern):
            if p.is_file():
                rel = p.relative_to(root).as_posix()
                if any(_skip_matches(skip, rel) for skip in DEFAULT_SKIP_PATTERNS):
                    continue
                collected.append(p)
    # Also pick up domain index / index.md
    for name in (_detect_domain_index(root), "index.md"):
        p = root / name
        if p.exists() and p not in collected:
            collected.append(p)
    return sorted(set(collected))

INDEXABLE_EXTS = {".md", ".sh", ".py", ".ps1", ".bash", ".yml", ".yaml", ".conf", ".js", ".ts"}

def collect_git_tracked_files(root: Path) -> list[Path]:
    """Return git-tracked files in root with indexable extensions.
    Uses `git ls-files --cached` so the domain index reflects exactly what is
    committed — gitignored workspace files (.work/, evidence/, etc.) are
    naturally excluded without any skip-pattern list.
    Falls back to collect_files([]) if git is unavailable or root is not a repo."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        files = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            p = root / line
            if p.is_file() and p.suffix.lower() in INDEXABLE_EXTS:
                files.append(p)
        return sorted(files)
    except (subprocess.CalledProcessError, FileNotFoundError):
        # Not a git repo or git not found — fall back to filesystem glob
        return collect_files([])

# MRK:REINDEX_CMDS — Migrate, verify, reindex subcommands | reindex,cmds,migrate,verify,subcommands | L908-1006
def cmd_migrate(args) -> int:
    files = collect_files(args.files)
    if not files:
        print("No files in scope.")
        return 0
    print(f"Migrating {len(files)} file(s)...")
    errors = 0
    root = Path.cwd()
    for p in files:
        res = migrate_file(p)
        status = res["status"]
        try:
            display = p.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            display = p.name
        if status == "migrated":
            print(f"  OK   {display:<44s} {res['anchors']} anchors")
        elif status == "skipped":
            print(f"  --   {display:<44s} {res['message']}")
        else:
            print(f"  FAIL {display:<44s} {status}: {res['message']}", file=sys.stderr)
            errors += 1
    # If the tool itself was in the reindex set, update self-hash
    self_path = Path(__file__).resolve()
    if any(p.resolve() == self_path for p in files):
        stamp_self()
        print("  [self-hash updated]")
    return 1 if errors else 0

def cmd_verify(args) -> int:
    files = collect_files(args.files)
    root = Path.cwd()
    print(f"Verifying {len(files)} file(s)...")
    drifts = 0
    for p in files:
        try:
            display = p.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            display = p.name
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            print(f"  FAIL {display}: read failed: {e}", file=sys.stderr)
            drifts += 1
            continue
        lines = raw.splitlines(keepends=True)
        # Check for v1 header — scan first 40 lines to account for frontmatter
        first_scan = "".join(lines[:40])
        if "NAV:v1" not in first_scan:
            print(f"  --   {display:<44s} not v1 (skipped)")
            continue
        # Recompute hash from existing anchors
        anchors = find_anchors(lines)
        tag_to_range = {}
        ordered = sorted(anchors)
        for i, (idx, tag, _t, _d) in enumerate(ordered):
            start = idx + 1
            end = ordered[i + 1][0] if i + 1 < len(ordered) else len(lines)
            tag_to_range[tag] = (start, end)
        # Identify TOC tag to exclude from hash
        toc_tags = [t for t in tag_to_range if t.endswith("_NAV_TOC") or t == "NAV_TOC"]
        # Detect NAV-RULEs and validate token set
        nav_rules = find_nav_rules(lines, anchors)
        for tag, rule_str in nav_rules.items():
            for token in rule_str.split(";"):
                token = token.strip()
                if not token or token.startswith("same-commit:"):
                    continue
                if token not in KNOWN_NAV_RULE_TOKENS:
                    print(f"  WARN {display:<44s} NAV-RULE MRK:{tag}: unknown token '{token}'")
        hash_input = [
            (tag, f"L{s}-{e}")
            for tag, (s, e) in tag_to_range.items()
            if tag not in toc_tags
        ]
        expected = compute_integrity_hash(hash_input, nav_rules)
        # Find stored hash
        stored = None
        for line in lines:
            m = re.search(r"Integrity-hash:\s*([0-9a-f]+)", line)
            if m:
                stored = m.group(1)
                break
        if stored is None:
            print(f"  ?    {display:<44s} no stored hash")
            drifts += 1
            continue
        if stored != expected:
            print(f"  FAIL {display:<44s} hash drift: stored={stored}  expected={expected}")
            drifts += 1
        else:
            print(f"  OK   {display:<44s} ok")
    return 1 if drifts else 0

def cmd_reindex(args) -> int:
    """Re-run migration logic — idempotent on v1 files (refreshes ranges + hash)."""
    return cmd_migrate(args)

# MRK:REINDEX_INDEX_HELPERS — Index generation helpers | reindex,index,helpers,generation,user | L1007-1326
USER_PROMPT_BEGIN = "<!-- BEGIN USER-PROMPT (preserved across reindex — edit this block to add project context) -->"
USER_PROMPT_END = "<!-- END USER-PROMPT -->"
USER_PROMPT_DEFAULT_BODY = """<!--
    PROJECT CONTEXT / OWNER GUIDELINES
    (Empty by default. Add engagement-specific or project-specific context
    here: target scope, goals, constraints, tester profile, anything that
    orients an LLM faster. Reindex PRESERVES this block — it's never
    overwritten by `orc-nav-reindex.py index`.)
-->"""

README_CUSTOM_BEGIN = "<!-- BEGIN README-CUSTOM (preserved across regen — edit to add project-local overrides) -->"
README_CUSTOM_END = "<!-- END README-CUSTOM -->"
README_CUSTOM_DEFAULT_BODY = """<!--
    CUSTOM CONTEXT / LOCAL OVERRIDES
    (Empty by default. Add directory-specific context, overrides, or
    constraints here. Reindex PRESERVES this block — it is never
    overwritten by `orc-nav-reindex.py main-index`.)
-->"""

def _extract_user_prompt(index_path: Path) -> str:
    """Extract existing USER-PROMPT block, or return empty default."""
    if not index_path.exists():
        return USER_PROMPT_DEFAULT_BODY
    try:
        text = index_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return USER_PROMPT_DEFAULT_BODY
    if USER_PROMPT_BEGIN in text and USER_PROMPT_END in text:
        start = text.index(USER_PROMPT_BEGIN) + len(USER_PROMPT_BEGIN)
        end = text.index(USER_PROMPT_END)
        body = text[start:end].strip("\n")
        return body
    return USER_PROMPT_DEFAULT_BODY

def _extract_project_desc(root: Path) -> tuple[str, str]:
    """
    Return (project_name, project_description).
    project_name: from root README.md H1 if present, else dir basename.
    project_description: first visible paragraph of root README.md.
    """
    readme = root / "README.md"
    name = root.resolve().name
    desc = f"NAV-indexed project at `{name}`."
    if not readme.exists():
        return (name, desc)
    try:
        lines = readme.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception:
        return (name, desc)
    # Walk past NAV header + NAV_TOC block + blank separators, find H1
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        # Skip HTML comments, blank lines, frontmatter separators
        if not line or line.startswith("<!--") or line == "---":
            i += 1
            continue
        # Treat heading
        if line.startswith("# "):
            name = line.lstrip("# ").strip()
            i += 1
            break
        # No H1 found — stop walking header
        break
    # Collect first visible paragraph (non-blank, non-comment, non-H)
    para = []
    while i < len(lines):
        line = lines[i].strip()
        if not line:
            if para:
                break
            i += 1
            continue
        if line.startswith("<!--") or line.startswith("#"):
            i += 1
            continue
        para.append(line)
        i += 1
    if para:
        desc = " ".join(para)
    return (name, desc)

def _detect_domain_index(root: Path, domain: str | None = None) -> str:
    """Return the domain index filename.
    If `domain` is given (e.g. 'nav-tools'), returns '<DOMAIN>-INDEX.md' directly.
    Otherwise auto-detects: looks for <DOMAIN>-INDEX.md (any *-INDEX.md except
    MAIN-INDEX.md) at root. Falls back to LOCAL-INDEX.md."""
    if domain:
        return f"{domain.upper()}-INDEX.md"
    for p in sorted(root.glob("*-INDEX.md")):
        if p.name.endswith("-INDEX.md") and p.name != "MAIN-INDEX.md":
            return p.name
    return "LOCAL-INDEX.md"

def _is_nav_root(dir_path: Path) -> bool:
    """Detect if dir is a nav-indexed project root (has any uppercase *-INDEX.md file)."""
    return any(p for p in dir_path.glob("*-INDEX.md") if p.name.endswith("-INDEX.md"))

def _walk_v1_files_minimal(root: Path) -> tuple[dict, list]:
    """Walk root recursively for NAV:v1 files. Skip .git/ and nested nav-roots.
    Returns (dir_to_files dict, nested_roots list)."""
    import os
    dir_to_files = {}
    nested_roots = []
    for dirpath, dirnames, filenames in os.walk(root):
        dp = Path(dirpath)
        # Skip .git always
        dirnames[:] = [d for d in dirnames if d != ".git"]
        # Detect nested nav-root (NOT root itself); stop recursion at boundary
        if dp != root and _is_nav_root(dp):
            nested_roots.append(dp)
            dirnames[:] = []
            continue
        v1_files = []
        for fn in filenames:
            if not fn.endswith((".md", ".sh", ".py", ".ps1")):
                continue
            # Don't list the dirname-index itself or any *-INDEX.md
            if fn.endswith("-INDEX.md"):
                continue
            if fn.endswith("-index.md"):
                continue
            fp = dp / fn
            try:
                head = "\n".join(fp.read_text(encoding="utf-8", errors="replace").splitlines()[:3])
                if "NAV:v1" in head:
                    v1_files.append(fp)
            except Exception:
                continue
        if v1_files:
            dir_to_files[dp] = sorted(v1_files)
    return dir_to_files, nested_roots

def _dirname_to_tag(dirname: str) -> str:
    """Convert dir name to MRK tag prefix (uppercase, hyphens/dots → underscores, leading dots stripped)."""
    normalized = dirname.lstrip(".").upper().replace("-", "_").replace(".", "_").replace(" ", "_")
    return normalized or "ROOT"

def _emit_dirname_index(dir_path: Path, files: list, root: Path, domain: str | None = None) -> Path:
    """Emit <dirname>-index.md inside dir_path. Returns the path written."""
    dirname = dir_path.name if dir_path != root else root.resolve().name
    index_filename = f"{dirname}-index.md"
    index_path = dir_path / index_filename
    domain_idx = _detect_domain_index(root, domain)
    if dir_path == root:
        rel_to_main = domain_idx
    else:
        depth = len(dir_path.relative_to(root).parts)
        rel_to_main = "../" * depth + domain_idx
    tag = _dirname_to_tag(dirname)
    rel_dir = dir_path.relative_to(root).as_posix() or "."
    style = ("<!-- ", " -->")
    out = []
    out.append(emit_comment_line(L1_TEXT, style))
    out.append(emit_comment_line(f"L2 NAV:{NAV_VERSION} → {rel_to_main}", style))
    out.append("\n")
    out.append(emit_comment_line(f"MRK:{tag}_INDEX_NAV_TOC — Section index | nav,toc,index", style))
    out.append(emit_comment_line("NAV-LEN: 0 entries | UNMRKD", style))
    out.append("\n")
    out.append(f"# {dirname} — Directory index\n\n")
    out.append(f"NAV:v1 files in `{rel_dir}/` (excluding nested nav-roots and index files).\n\n")
    out.append("---\n\n")
    out.append(f"## MRK:{tag}_INDEX_FILES — Files in this directory | dirname,files,{tag.lower()}\n\n")
    out.append("| File | Anchors | Top MRKs |\n")
    out.append("|------|---------|----------|\n")
    for fp in files:
        try:
            ftext = fp.read_text(encoding="utf-8", errors="replace")
            flines = ftext.splitlines(keepends=True)
            anchors = find_anchors(flines)
            body = [(t, ti) for _idx, t, ti, _d in anchors
                    if not (t.endswith("_NAV_TOC") or t == "NAV_TOC")]
            top = ", ".join(f"`{t}`" for t, _ in body[:3]) if body else "—"
            out.append(f"| `{fp.name}` | {len(body)} | {top} |\n")
        except Exception:
            out.append(f"| `{fp.name}` | ? | (read error) |\n")
    out.append("\n")
    out.append(emit_comment_line(f"L2 NAV:{NAV_VERSION} → {rel_to_main}", style))
    out.append(emit_comment_line(L1_TEXT, style))
    index_path.write_text("".join(out), encoding="utf-8", newline="")
    return index_path

def _emit_dir_index(dir_path: Path, root: Path, domain: str | None = None) -> Path:
    """Write INDEX.md in dir_path — minimal NAV:v1 single-entry → README.md.
    Always regenerated (no custom content)."""
    index_path = dir_path / "INDEX.md"
    dirname = dir_path.name if dir_path != root else root.resolve().name
    tag = _dirname_to_tag(dirname)
    depth = len(dir_path.relative_to(root).parts) if dir_path != root else 0
    domain_index = _detect_domain_index(root, domain)
    rel_to_orc = ("../" * depth) + domain_index
    style = ("<!-- ", " -->")
    out = []
    out.append(emit_comment_line(L1_TEXT, style))
    out.append(emit_comment_line(f"L2 NAV:{NAV_VERSION} → {rel_to_orc}", style))
    out.append("\n")
    out.append(emit_comment_line(f"MRK:{tag}_INDEX_NAV_TOC — Section index | nav,toc,index", style))
    out.append(emit_comment_line("NAV-LEN: 0 entries | UNMRKD", style))
    out.append("\n")
    out.append(f"## MRK:{tag}_INDEX_ENTRY — Directory nav entry | index,entry,{dirname.lower()},readme\n\n")
    out.append(f"→ **[README.md](./README.md)** — NAV:v1 protocol reference for `{dirname}/`.\n\n")
    out.append(emit_comment_line(f"L2 NAV:{NAV_VERSION} → {rel_to_orc}", style))
    out.append(emit_comment_line(L1_TEXT, style))
    index_path.write_text("".join(out), encoding="utf-8", newline="")
    return index_path


def _emit_dir_readme(dir_path: Path, root: Path, domain: str | None = None) -> tuple:
    """Write README.md with P1(v3)/P2(v2)/conflict-res/custom blocks.
    Skip-if-exists: returns (path, False) if already present, (path, True) if written."""
    readme_path = dir_path / "README.md"
    if readme_path.exists():
        return (readme_path, False)
    dirname = dir_path.name if dir_path != root else root.resolve().name
    tag = _dirname_to_tag(dirname)
    depth = len(dir_path.relative_to(root).parts) if dir_path != root else 0
    domain_index = _detect_domain_index(root, domain)
    rel_to_orc = ("../" * depth) + domain_index
    style = ("<!-- ", " -->")
    out = []
    out.append(emit_comment_line(L1_TEXT, style))
    out.append(emit_comment_line(f"L2 NAV:{NAV_VERSION} → {rel_to_orc}", style))
    out.append("\n")
    out.append(emit_comment_line(f"MRK:{tag}_README_NAV_TOC — Section index | nav,toc,index", style))
    out.append(emit_comment_line("NAV-LEN: 0 entries | UNMRKD", style))
    out.append("\n")
    out.append(f"# {dirname} — NAV:v1 protocol reference\n\n")
    # P1 v3 — Access protocol
    out.append(f"## MRK:{tag}_README_PROTOCOL — Access protocol (P1 v3) | readme,protocol,access\n\n")
    out.append(
        "1. **Read the file header first.** Every indexed file has L1 (rules) + L2 (`NAV:v1 → <path>`)"
        " on lines 1–2 (MD) or 2–3 (shebang script). `tail -2` gives the same orientation from the bottom (mirror).\n"
        "2. **Use the per-file `MRK:NAV_TOC` block.** Each file carries a TOC listing entries with exact"
        " `L<start>-<end>` ranges. Match by keyword; fetch by range.\n"
        "3. **Precise fetch only.** Use `L<start>-<end>` from the MRK line. No default line count."
        " Range missing / stale → run `reindex` before reading.\n"
        "4. **Miss? Log it.** When a TOC lookup didn't contain what you expected, record in"
        " `session_lessons_log.md` (see `/orc-nav` skill). No inference effort is wasted.\n\n"
    )
    # P2 v2 — Hard rules
    out.append(f"## MRK:{tag}_README_RULES — Hard rules (P2 v2) | readme,rules,hard\n\n")
    out.append(
        "- Never open a file without a stated purpose.\n"
        "- Never bulk-read an indexed file — use the TOC.\n"
        "- Never re-load a file already in context — recall from memory.\n"
        "- Loading >200 lines without a target → state in one sentence what you're looking for first.\n"
        "- After adding/renaming/removing any MRK anchor → run `reindex` before commit.\n"
        "- Before every commit → run the composite `reindex + verify`.\n\n"
    )
    # Conflict-resolution
    out.append(f"## MRK:{tag}_README_CONFLICT — Conflict-resolution | readme,conflict,resolution\n\n")
    out.append(
        "When the session skill (`/nav`, `/profile`) conflicts with this README:\n\n"
        "1. **README wins for project-local overrides** — if this README explicitly overrides a skill"
        " default, obey the README.\n"
        "2. **Skill wins for protocol mechanics** — read-order, anchor syntax, NAV-RULE enforcement,"
        " and reindex steps are governed by the skill.\n"
        "3. **In doubt** — ask the operator before proceeding.\n\n"
    )
    # Custom preserved block
    out.append(f"## MRK:{tag}_README_CUSTOM — Custom context (preserved) | readme,custom,preserved\n\n")
    out.append(README_CUSTOM_BEGIN + "\n")
    out.append(README_CUSTOM_DEFAULT_BODY + "\n")
    out.append(README_CUSTOM_END + "\n")
    out.append("\n")
    out.append(emit_comment_line(f"L2 NAV:{NAV_VERSION} → {rel_to_orc}", style))
    out.append(emit_comment_line(L1_TEXT, style))
    readme_path.write_text("".join(out), encoding="utf-8", newline="")
    return (readme_path, True)


def _emit_main_index(root: Path, dir_indexes: list, nested_roots: list) -> Path:
    """Emit MAIN-INDEX.md at root. dir_indexes: list of (dirname-index Path, file_count)."""
    main_path = root / "MAIN-INDEX.md"
    user_prompt_body = _extract_user_prompt(main_path)
    project_name, project_desc = _extract_project_desc(root)
    style = ("<!-- ", " -->")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = []
    out.append(emit_comment_line(L1_TEXT, style))
    out.append(emit_comment_line(f"L2 NAV:{NAV_VERSION} → [project root]", style))
    out.append("\n")
    out.append(emit_comment_line("MRK:MAIN_INDEX_NAV_TOC — Section index | nav,toc,index", style))
    out.append(emit_comment_line(f"NAV-LEN: 0 entries | UNMRKD", style))
    out.append("\n")
    out.append(USER_PROMPT_BEGIN + "\n")
    out.append(user_prompt_body + "\n")
    out.append(USER_PROMPT_END + "\n")
    out.append("\n")
    out.append(emit_comment_line(f"tool-sha: {self_hash()} | orc-nav-reindex.py", style))
    out.append("\n")
    out.append(f"# MAIN-INDEX — {project_name}\n\n")
    out.append(f"{project_desc}\n\n")
    out.append("Hierarchical index — index-of-indices. Each entry points to a `<dirname>-index.md` file (per nav-bearing dir) or a nested nav-root (opaque).\n\n")
    out.append(f"**Dirs indexed:** {len(dir_indexes)} &nbsp;·&nbsp; "
               f"**Nested roots:** {len(nested_roots)} &nbsp;·&nbsp; "
               f"**Last-indexed:** {timestamp}\n\n")
    out.append("## MRK:MAIN_INDEX_INDEXES — Dirname-indexes | main,indexes,dirname,hierarchy\n\n")
    if dir_indexes:
        for di_path, count in sorted(dir_indexes, key=lambda x: str(x[0])):
            rel = di_path.relative_to(root).as_posix()
            out.append(f"- `{rel}` — {count} files\n")
    else:
        out.append("(none)\n")
    out.append("\n")
    out.append("## MRK:MAIN_INDEX_NESTED — Nested nav-roots (opaque) | main,nested,roots,opaque\n\n")
    if nested_roots:
        for nr in sorted(nested_roots):
            rel = nr.relative_to(root).as_posix()
            kind = "MAIN-INDEX.md" if (nr / "MAIN-INDEX.md").exists() else _detect_domain_index(nr)
            out.append(f"- `{rel}/` — own {kind} (manages own hierarchy)\n")
    else:
        out.append("(none)\n")
    out.append("\n")
    out.append(emit_comment_line(f"L2 NAV:{NAV_VERSION} → [project root]", style))
    out.append(emit_comment_line(L1_TEXT, style))
    main_path.write_text("".join(out), encoding="utf-8", newline="")
    return main_path

# MRK:REINDEX_CMD_INDEX — Index subcommand | reindex,cmd,index,subcommand,orc | L1327-1472
def cmd_index(args) -> int:
    """Regenerate the domain index at project root with full structure:
    NAV header, preserved USER-PROMPT block, autogenerated description,
    access protocol + hard rules, reindex tool reference, files-by-dir,
    and a flat anchor table."""
    root = Path.cwd()
    files = collect_git_tracked_files(root)
    # Filter to v1 files + collect anchors
    entries = []
    all_anchors = []  # list of (path, line, tag, title) for flat table
    for p in files:
        try:
            raw = p.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        if "NAV:v1" not in "".join(raw.splitlines()[:40]):
            continue
        lines = raw.splitlines(keepends=True)
        anchors = find_anchors(lines)
        # Exclude the NAV_TOC header tags from display
        body_anchors = [
            (idx + 1, tag, title)
            for idx, tag, title, _desc in anchors
            if not (tag.endswith("_NAV_TOC") or tag == "NAV_TOC")
        ]
        top = [(tag, title) for _ln, tag, title in body_anchors][:5]
        nav_len = 0
        for line in lines:
            m = re.search(r"NAV-LEN:\s*(\d+)\s*(entries|files)", line)
            if m:
                nav_len = int(m.group(1))
                break
        rel = p.resolve().relative_to(root.resolve()).as_posix()
        entries.append({"path": rel, "nav_len": nav_len, "top": top, "all": body_anchors})
        for ln, tag, title in body_anchors:
            all_anchors.append((rel, ln, tag, title))

    # Preserve user-prompt block across regens
    domain_index_name = _detect_domain_index(root, getattr(args, "domain", None))
    user_prompt_body = _extract_user_prompt(root / domain_index_name)
    project_name, project_desc = _extract_project_desc(root)

    style = ("<!-- ", " -->")
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    index_hash = compute_integrity_hash([])  # matches verify's empty-set hash

    out = []
    # Header
    out.append(emit_comment_line(L1_TEXT, style))
    out.append(emit_comment_line(f"L2 NAV:{NAV_VERSION} → [project root]", style))
    out.append("\n")
    out.append(emit_comment_line(
        f"NAV-LEN: {len(entries)} files | Integrity-hash: {index_hash} | Last-indexed: {timestamp}",
        style,
    ))
    out.append("\n")

    # Preserved user-prompt block
    out.append(USER_PROMPT_BEGIN + "\n")
    out.append(user_prompt_body + "\n")
    out.append(USER_PROMPT_END + "\n")
    out.append("\n")

    # Tool SHA stamp
    out.append(emit_comment_line(f"tool-sha: {self_hash()} | orc-nav-reindex.py", style))
    out.append("\n")

    # Title + autogenerated description
    out.append(f"# {domain_index_name.removesuffix('.md')} — {project_name}\n\n")
    out.append(f"{project_desc}\n\n")
    out.append(f"**Files indexed:** {len(entries)} &nbsp;·&nbsp; "
               f"**Anchors:** {sum(e['nav_len'] for e in entries)} &nbsp;·&nbsp; "
               f"**Last-indexed:** {timestamp}\n\n")

    # Access protocol (generic ORC NAV — boilerplate)
    out.append("## MRK:INDEX_PROTOCOL — Access protocol\n\n")
    out.append(
        "1. **Read the file header first.** Every indexed file has L1 (rules) + L2 (`NAV:v1 → <path>`) on lines 1–2 (MD) or 2–3 (shebang script). `tail -2` gives the same orientation from the bottom (mirror).\n"
        "2. **Use the per-file `MRK:NAV_TOC` block.** Each file carries a TOC listing entries with exact `L<start>-<end>` ranges. Match by keyword; fetch by range.\n"
        "3. **Precise fetch only.** Use `L<start>-<end>` from the MRK line. No default line count. Range missing / stale → run `reindex` before reading.\n"
        "4. **Miss? Log it.** When a TOC lookup didn't contain what you expected, record in `session_lessons_log.md` (see `/orc-nav` skill). No inference effort is wasted.\n\n"
    )

    # Hard rules (boilerplate)
    out.append("## MRK:INDEX_RULES — Hard rules\n\n")
    out.append(
        "- Never open a file without a stated purpose.\n"
        "- Never bulk-read an indexed file — use the TOC.\n"
        "- Never re-load a file already in context — recall from memory.\n"
        "- Loading >200 lines without a target → state in one sentence what you're looking for first.\n"
        "- After adding/renaming/removing any MRK anchor → run `reindex` before commit.\n"
        "- Before every commit → run the composite `reindex + verify`.\n\n"
    )

    # Reindex tool reference
    out.append("## MRK:INDEX_TOOL — Reindex tool reference\n\n")
    out.append(
        "```\n"
        "python tools/orc-nav-reindex.py reindex             # write pass — refresh ranges + hashes after edits\n"
        "python tools/orc-nav-reindex.py verify              # read pass — integrity check (pre-commit)\n"
        "python tools/orc-nav-reindex.py index               # regenerate this file\n"
        "python tools/orc-nav-reindex.py append <file>       # add one NAV:v1 file's entry into this index\n"
        "python tools/orc-nav-reindex.py append <file> --index <idx>  # target a specific index\n"
        "./tools/pt-orc-reindex.sh --pre-commit              # composite: reindex + verify\n"
        "```\n\n"
        "Always run the pre-commit composite before `git commit`. Drift → fix source, retry.\n\n"
    )

    # Files by directory
    out.append("## MRK:INDEX_FILES — Files by directory\n\n")
    for e in sorted(entries, key=lambda x: x["path"]):
        out.append(f"### `{e['path']}` — {e['nav_len']} anchors\n")
        for tag, title in e["top"]:
            out.append(f"- `MRK:{tag}` — {title}\n")
        if e["nav_len"] > 5:
            out.append(f"- …\n")
        out.append("\n")

    # Flat anchor table (all anchors, for cross-file grep)
    out.append(f"## MRK:INDEX_ALL — All anchors (flat, {len(all_anchors)} entries)\n\n")
    out.append("| File | Line | Tag | Title |\n")
    out.append("|------|------|-----|-------|\n")
    for path, ln, tag, title in sorted(all_anchors):
        # Escape pipe characters in title for table
        safe_title = title.replace("|", "\\|")
        out.append(f"| `{path}` | L{ln} | `MRK:{tag}` | {safe_title} |\n")
    out.append("\n")

    # Tail mirror
    out.append("\n")
    out.append(emit_comment_line(f"L2 NAV:{NAV_VERSION} → [project root]", style))
    out.append(emit_comment_line(L1_TEXT, style))

    index_path = root / domain_index_name
    index_path.write_text("".join(out), encoding="utf-8", newline="")
    # Self-reindex: strip the placeholder stats line we just wrote and
    # re-emit with a real integrity hash over the index's own anchors
    # (MRK:INDEX_PROTOCOL, _RULES, _TOOL, _FILES, _ALL). Without this,
    # `verify` would immediately report drift after `index`.
    migrate_file(index_path)
    _backup_index(index_path)
    print(f"Generated {domain_index_name} — {len(entries)} indexed files, "
          f"{len(all_anchors)} anchors, user-prompt block preserved.")
    return 0

# MRK:REINDEX_CMD_APPEND — Append subcommand | reindex,cmd,append,subcommand,single | L1473-1597
def cmd_append(args) -> int:
    """Append a single NAV:v1 file's entry into a target index, then reindex the index.

    Inserts:
      - A file block (path + top-5 anchors) into the MRK:INDEX_FILES section.
      - Anchor table rows into the MRK:INDEX_ALL table.
    Then calls migrate_file() on the index to refresh its hash + NAV-LEN.

    Idempotent: if the file is already referenced in the index, exits cleanly.
    """
    target = Path(args.file)
    index_path = Path(args.index) if args.index else Path.cwd() / _detect_domain_index(Path.cwd())

    # --- validate target file ---
    if not target.exists():
        print(f"ERROR: {target} not found", file=sys.stderr)
        return 1
    raw = target.read_text(encoding="utf-8", errors="replace")
    if "NAV:v1" not in "\n".join(raw.splitlines()[:40]):
        print(f"ERROR: {target} is not a NAV:v1 file (no NAV:v1 token in first 40 lines)", file=sys.stderr)
        return 1

    lines = raw.splitlines(keepends=True)
    anchors = find_anchors(lines)
    body_anchors = [
        (idx + 1, tag, title)
        for idx, tag, title, _desc in anchors
        if not (tag.endswith("_NAV_TOC") or tag == "NAV_TOC")
    ]
    nav_len = 0
    for line in lines:
        m = re.search(r"NAV-LEN:\s*(\d+)\s*(entries|files)", line)
        if m:
            nav_len = int(m.group(1))
            break
    top5 = [(tag, title) for _ln, tag, title in body_anchors][:5]

    # path relative to the index file's parent directory
    try:
        rel = target.resolve().relative_to(index_path.parent.resolve()).as_posix()
    except ValueError:
        rel = target.resolve().as_posix()  # outside tree — use absolute path

    # --- validate index ---
    if not index_path.exists():
        print(f"ERROR: {index_path} not found. Run 'index' first to create it.", file=sys.stderr)
        return 1

    idx_raw = index_path.read_text(encoding="utf-8", errors="replace")
    if rel in idx_raw:
        print(f"INFO: {rel} already referenced in {index_path.name}. Nothing to do.")
        return 0

    idx_lines = idx_raw.splitlines(keepends=True)

    # Refuse if target is a dirname-index (per-dir block schema, not domain-index schema).
    # Dirname-indexes are identified by a NAV_TOC anchor ending in _INDEX_NAV_TOC.
    # They have no MRK:INDEX_FILES / MRK:INDEX_ALL sections — append would corrupt them.
    idx_anchors = find_anchors(idx_lines)
    if any(tag.endswith("_INDEX_NAV_TOC") for _idx, tag, _title, _desc in idx_anchors):
        print(
            f"ERROR: {index_path.name} is a dirname-index (per-dir block schema).\n"
            f"  'append' only works with domain indexes (NAV-TOOLS-INDEX.md, etc.).\n"
            f"  Use 'main-index' to regenerate dirname-indexes, or specify the\n"
            f"  domain index with --index <DOMAIN>-INDEX.md.",
            file=sys.stderr,
        )
        return 1

    # --- build content blocks ---
    file_block = [f"\n### `{rel}` — {nav_len} anchors\n"]
    for tag, title in top5:
        file_block.append(f"- `MRK:{tag}` — {title}\n")
    if nav_len > 5:
        file_block.append("- …\n")

    anchor_rows = []
    for ln, tag, title in body_anchors:
        safe_title = title.replace("|", "\\|")
        anchor_rows.append(f"| `{rel}` | L{ln} | `MRK:{tag}` | {safe_title} |\n")

    # --- locate insertion points ---
    # INDEX_FILES section: insert file_block before the MRK:INDEX_ALL heading.
    # INDEX_ALL table: append anchor_rows after the last | row in the table.
    idx_all_line = None   # line index of the MRK:INDEX_ALL ## heading
    last_pipe_line = None  # line index of the last | row found after idx_all_line

    for i, line in enumerate(idx_lines):
        if idx_all_line is None and "MRK:INDEX_ALL" in line and line.lstrip().startswith(("##", "<!--")):
            idx_all_line = i
        if idx_all_line is not None and line.startswith("|"):
            last_pipe_line = i

    new_lines = list(idx_lines)

    if idx_all_line is None:
        # No INDEX_ALL section — append everything before the tail mirror (last 2 lines)
        insert_at = max(0, len(new_lines) - 2)
        new_lines[insert_at:insert_at] = file_block + anchor_rows
    else:
        # 1. Insert file_block just before the INDEX_ALL heading
        new_lines[idx_all_line:idx_all_line] = file_block
        # 2. Anchor rows go after the last | row (adjusted for the insertion above)
        if last_pipe_line is not None:
            adj = last_pipe_line + len(file_block)
            new_lines[adj + 1:adj + 1] = anchor_rows
        else:
            # Table header present but no data rows yet — find the separator row
            for i in range(idx_all_line + len(file_block), len(new_lines)):
                if new_lines[i].startswith("|--") or new_lines[i].startswith("| --"):
                    new_lines[i + 1:i + 1] = anchor_rows
                    break

    # --- write + reindex ---
    index_path.write_text("".join(new_lines), encoding="utf-8", newline="")
    migrate_file(index_path)

    print(
        f"Appended: {rel} → {index_path.name}  "
        f"({nav_len} declared anchors, {len(body_anchors)} entries added to index)"
    )
    return 0


# MRK:REINDEX_CMD_MAIN_INDEX — main-index subcommand: hierarchical MAIN-INDEX + dirname-indexes | reindex,cmd,main,index,subcommand | L1598-1644

def cmd_main_index(args) -> int:
    """Build hierarchy: <dirname>-index.md per nav-bearing dir + MAIN-INDEX.md at root.
    Per-dir transactional: emit dirname-index, migrate (reindex), then update MAIN-INDEX
    and migrate it. Skip set: .git/ + nested nav-roots (own *-INDEX.md)."""
    root = Path.cwd()
    dir_files, nested_roots = _walk_v1_files_minimal(root)
    if not dir_files and not nested_roots:
        print("No NAV:v1 files / nested nav-roots; nothing to index.")
        return 0
    print(f"Found {len(dir_files)} dirs with NAV files + {len(nested_roots)} nested nav-roots.")
    domain = getattr(args, "domain", None)
    dir_indexes = []
    for dir_path, files in sorted(dir_files.items(), key=lambda x: str(x[0])):
        rel = dir_path.relative_to(root).as_posix() or "."
        try:
            di_path = _emit_dirname_index(dir_path, files, root, domain)
            migrate_file(di_path)
        except Exception as e:
            print(f"  FAIL emit/migrate dirname-index for {rel}: {e}")
            return 1
        try:
            idx_path = _emit_dir_index(dir_path, root, domain)
            migrate_file(idx_path)
            readme_path, wrote = _emit_dir_readme(dir_path, root, domain)
            if wrote:
                migrate_file(readme_path)
            readme_note = "README.md written" if wrote else "README.md skipped (exists)"
        except Exception as e:
            print(f"  FAIL emit INDEX.md/README.md for {rel}: {e}")
            return 1
        dir_indexes.append((di_path, len(files)))
        try:
            main_path = _emit_main_index(root, dir_indexes, nested_roots)
            migrate_file(main_path)
        except Exception as e:
            print(f"  FAIL emit/migrate MAIN-INDEX after {rel}: {e}")
            return 1
        print(f"  [{rel}] {di_path.name} ({len(files)} files) + INDEX.md + {readme_note} → MAIN-INDEX")
    if dir_indexes:
        _backup_index(root / "MAIN-INDEX.md")
    print(f"DONE — MAIN-INDEX.md + {len(dir_indexes)} dirname-indexes generated; "
          f"{len(nested_roots)} nested roots noted as opaque.")
    return 0


# MRK:REINDEX_MAIN — Entry point and subcommand dispatch | reindex,main,entry,point,subcommand | L1645-1688
def main():
    ap = argparse.ArgumentParser(description="ORC NAV v1 reindex tool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("migrate", help="Rewrite legacy files → v1")
    m.add_argument("files", nargs="*", help="Explicit files; default: scope glob")
    m.set_defaults(func=cmd_migrate)

    v = sub.add_parser("verify", help="Check integrity hash + NAV-LEN")
    v.add_argument("files", nargs="*")
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("reindex", help="Refresh ranges + hash (idempotent)")
    r.add_argument("files", nargs="*")
    r.set_defaults(func=cmd_reindex)

    i = sub.add_parser("index", help="Regenerate the domain index (<DOMAIN>-INDEX.md)")
    i.add_argument("--domain", default=None, metavar="NAME",
                   help="Domain name (e.g. 'nav-tools'). Writes <NAME>-INDEX.md. "
                        "Default: auto-detect from existing *-INDEX.md in cwd.")
    i.set_defaults(func=cmd_index)

    a = sub.add_parser("append", help="Add a single NAV:v1 file's entry into an index")
    a.add_argument("file", help="File to append (must be NAV:v1 indexed)")
    a.add_argument("--index", default=None,
                   help="Target index file (default: auto-detected domain index in cwd)")
    a.set_defaults(func=cmd_append)

    mi = sub.add_parser("main-index",
                        help="Build hierarchical MAIN-INDEX + <dirname>-index.md files")
    mi.add_argument("--domain", default=None, metavar="NAME",
                    help="Domain name override for L2 pointers in dirname-indexes and "
                         "INDEX.md/README.md files (e.g. 'nav-tools'). Default: auto-detect.")
    mi.set_defaults(func=cmd_main_index)

    args = ap.parse_args()
    return args.func(args)

if __name__ == "__main__":
    sys.exit(main())

# L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
