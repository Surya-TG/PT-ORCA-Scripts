#!/usr/bin/env python3
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md

# NAV-LEN: 0 entries | UNMRKD | Integrity-hash: e3b0c44298fc1c14 | Last-indexed: 2026-06-09T07:09:41Z

"""precommit-scrub.py · audit-orc Orca delivery content scrub

Extends the base precommit-scrub with TG-delivery and Orca-specific modes.

Modes
-----
FILE MODE  : python precommit-scrub.py [--tg] [--orca] [--root <root>] file1 file2 ...
DIFF MODE  : python precommit-scrub.py [--tg] [--orca] --from-diff [< diff.txt]
RETRO MODE : python precommit-scrub.py [--tg] [--orca] --retro <from-sha>..<to-sha>
ALL MODE   : python precommit-scrub.py [--tg] [--orca] --all [--root <root>]

Flags
-----
--tg    Enable TG-delivery substrate-leak checks (substrate vocab, bearer names,
        internal paths, NAV markers). Required before any TG-facing commit.
--orca  Enable Orca-delivery checks on top of --tg: ERA scrub, audit-orc-internal
        vocab that isn't part of the public Orca pack model.

Exit codes
----------
0 = PASS (no errors; warnings reported but do not block)
1 = FAIL (errors present; or any finding when --strict is set)
2 = usage / invocation error
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path


# ── BASE LINE-BY-LINE CHECKS ─────────────────────────────────────────────────

_BASE_LINE_CHECKS_RAW = [
    # API / credential leakage — ERROR
    ("E", "api-key", "API key (sk- prefix)",
     r"\bsk-[A-Za-z0-9]{20,}", 0),
    ("E", "api-key", "GitHub PAT (ghp_)",
     r"\bghp_[A-Za-z0-9]{36,}", 0),
    ("E", "api-key", "AWS access key (AKIA prefix)",
     r"\bAKIA[0-9A-Z]{16}\b", 0),
    ("E", "api-key", "Bearer token in content",
     r"Bearer\s+[A-Za-z0-9._\-]{20,}", re.IGNORECASE),

    # PII — WARNING
    ("W", "pii", "email address",
     r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", 0),
    ("W", "pii", "phone number (US / intl)",
     r"\b(?:\+?1[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b", 0),

    # Canary artifacts — WARNING
    ("W", "canary", "debug flag (DEBUG=True)",
     r"\bDEBUG\s*=\s*True\b", 0),
    ("W", "canary", "DRAFT watermark [DRAFT]",
     r"\[DRAFT\]", 0),
    ("W", "canary", "WIP marker",
     r"^WIP:", re.MULTILINE),
]

# ── TG-DELIVERY CHECKS (--tg) ────────────────────────────────────────────────
# Substrate vocabulary and marker leaks that must not appear in TG-facing files.

_TG_LINE_CHECKS_RAW = [
    # NAV marker leakage — ERROR
    ("E", "tg-nav-leak", "NAV marker (MRK: anchor)",
     r"<!--\s*MRK:", 0),
    ("E", "tg-nav-leak", "NAV:v envelope (L-tier)",
     r"<!--\s*L\d+\s+NAV", 0),
    ("E", "tg-nav-leak", "NAV-LEN integrity line",
     r"NAV-LEN:\s*\d+", 0),
    ("E", "tg-nav-leak", "Integrity-hash field",
     r"Integrity-hash:", 0),
    ("E", "tg-nav-leak", "REINDEX-GATE marker",
     r"REINDEX-GATE:", 0),

    # Bearer name leakage — ERROR
    ("E", "tg-bearer", "Bearer name: Atlas",
     r"\bAtlas(?:-\d+)?\b", 0),
    ("E", "tg-bearer", "Bearer name: Nimbus",
     r"\bNimbus(?:-\d+)?\b", 0),
    ("E", "tg-bearer", "Bearer name: Cairn",
     r"\bCairn\b", 0),
    ("E", "tg-bearer", "Bearer name: Flint",
     r"\bFlint\b", 0),
    ("E", "tg-bearer", "Bearer name: Iva",
     r"\bIva(?:-\d+)?\b", 0),
    ("E", "tg-bearer", "Bearer name: Comcon",
     r"\bComcon(?:-\d+)?\b", 0),
    ("E", "tg-bearer", "Bearer name: Cogitor",
     r"\bCogitor\b", 0),
    ("E", "tg-bearer", "Bearer name: Scribe",
     r"\bScribe\b", 0),
    ("E", "tg-bearer", "Bearer hat-handle",
     r"\[u0\d+-[a-z]+\d+\.\d+\]:", 0),

    # Substrate vocabulary — ERROR
    ("E", "tg-substrate", "V3G substrate reference",
     r"\bV3G\b", 0),
    ("E", "tg-substrate", "NOV system reference",
     r"\bNOV(?:-gate|-bound|-gated)?\b", 0),
    ("E", "tg-substrate", "Spatial mechanics leak",
     r"\bspatial.mechanics\b", re.IGNORECASE),
    ("E", "tg-substrate", "SAT-binding reference",
     r"\bSAT.binding\b", re.IGNORECASE),
    ("E", "tg-substrate", "MONO (continuity monolith)",
     r"\b(?:continuity.)?monolith\b", re.IGNORECASE),
    ("E", "tg-substrate", "Hyperspace reference",
     r"\bhyperspace\b", re.IGNORECASE),
    ("E", "tg-substrate", "aot-log reference",
     r"\baot.log\b", re.IGNORECASE),
    ("E", "tg-substrate", "focus-banner reference",
     r"\bfocus.banner\b", re.IGNORECASE),
    ("E", "tg-substrate", "FORUM2 reference",
     r"\bFORUM2\b", 0),
    ("E", "tg-substrate", "Beacon (nav beacon)",
     r"\bbeacon(?:s|.drop)?\b", re.IGNORECASE),

    # Internal path leakage — ERROR
    ("E", "tg-path", "Box path (E:\\WBL0)",
     r"E:\\WBL0", re.IGNORECASE),
    ("E", "tg-path", "Box path (E:/WBL0)",
     r"E:/WBL0", re.IGNORECASE),
    ("E", "tg-path", "SAT path variable",
     r"\$\{u0\d+-sat\}", 0),
    ("E", "tg-path", "Box path variable",
     r"\$\{box\}", 0),
    ("E", "tg-path", "nav-tools-v3 reference",
     r"nav-tools-v3", re.IGNORECASE),
    ("E", "tg-path", "NAV-TOOLS-v3 path",
     r"NAV-TOOLS-v3", 0),

    # Sensitive engagement names — ERROR
    ("E", "tg-client", "AssureIQ / DSG client reference",
     r"\bAssureIQ\b", 0),
    ("E", "tg-client", "DSG.AI client reference",
     r"\bDSG\.AI\b", 0),
    ("E", "tg-client", "DCPTCN engagement reference",
     r"\bDCPTCN\b", 0),
]

_TG_TEXT_CHECKS_RAW = [
    # UNKIN markers — ERROR (incomplete) or WARNING (pending)
    ("E", "unkin-incomplete", "UNKIN marker missing gate attribute",
     r"<!--\s*UNKIN\b(?![\s\S]*?gate=)[\s\S]*?-->", re.DOTALL),
    ("W", "unkin-pending", "UNKIN gate not yet approved",
     r'<!--\s*UNKIN\b[\s\S]*?gate=["\'](?!approved)[^"\']*["\'][\s\S]*?-->', re.DOTALL),
]

# ── ORCA DELIVERY CHECKS (--orca, extends --tg) ───────────────────────────────
# Additional rules for audit-orc Orca-pack delivery.

_ORCA_LINE_CHECKS_RAW = [
    # ERA must not appear in TG-facing materials — ERROR
    ("E", "orca-era", "ERA in TG-facing content (internal name only)",
     r"\bERA\b", 0),

    # audit-orc internal references not in public Orca model — WARNING
    ("W", "orca-internal", "audit-orc internal work area (.work/)",
     r"\.work/", 0),
    ("W", "orca-internal", "OPUS-SLIDES / ORCA_RELEASE internal area",
     r"\b(?:OPUS.SLIDES|ORCA_RELEASE)\b", re.IGNORECASE),
    ("W", "orca-internal", "nav-orc v1 reference (deprecated in Orca model)",
     r"\bnav-orc\b", re.IGNORECASE),
]

# ── ORCA ALLOWLIST: patterns that are intentional in orca/ files ─────────────
# If a line matches an allowlist pattern, tg/orca checks are skipped for that line.

_ORCA_ALLOWLIST_RAW = [
    r"BHV-[A-Z0-9]{4}",           # opaque behavior tokens
    r"DIR-[A-Z0-9]{4}",           # opaque directive tokens
    r"FRM-[A-Z0-9]{4}",           # opaque frame tokens
    r"RLE-[A-Z0-9]{4}",           # opaque custom-role tokens
    r"\[BHV:[A-Z0-9]{4}\]",       # token directive block header
    r"\[DIR:[A-Z0-9]{4}\]",       # token directive block header
]

ORCA_ALLOWLIST = [re.compile(p) for p in _ORCA_ALLOWLIST_RAW]

# ── COMPILED CHECKS ───────────────────────────────────────────────────────────

_SKIP_SUFFIXES = {".bak", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf",
                  ".zip", ".tar", ".gz", ".log"}
_DOC_SUFFIXES  = {".md", ".txt", ".rst"}


class Finding:
    __slots__ = ("severity", "category", "description", "filepath", "lineno", "snippet")

    def __init__(self, severity, category, description, filepath, lineno, snippet=""):
        self.severity  = severity
        self.category  = category
        self.description = description
        self.filepath  = str(filepath)
        self.lineno    = lineno
        self.snippet   = snippet.rstrip()[:120]

    def __str__(self):
        tag = "[ERROR]" if self.severity == "E" else "[ WARN]"
        loc = f"{self.filepath}:{self.lineno}" if self.lineno else self.filepath
        return f"  {tag} [{self.category}] {self.description}\n         -> {loc}: {self.snippet}"


def _line_number_of_offset(text, offset):
    return text[:offset].count("\n") + 1


def _allowlist_hit(line):
    """Return True if line matches any Orca allowlist pattern (intentional token)."""
    return any(rx.search(line) for rx in ORCA_ALLOWLIST)


def scan_text(text, filepath, mode_tg=False, mode_orca=False):
    """Scan file text; return list of Finding."""
    findings = []
    lines = text.splitlines()
    suffix = Path(filepath).suffix.lower()

    # Build active line-check set
    line_checks_raw = list(_BASE_LINE_CHECKS_RAW)
    if mode_tg:
        line_checks_raw.extend(_TG_LINE_CHECKS_RAW)
    if mode_orca:
        line_checks_raw.extend(_ORCA_LINE_CHECKS_RAW)
    line_checks = [(s, c, d, re.compile(p, f)) for s, c, d, p, f in line_checks_raw]

    # Build active text-check set
    text_checks_raw = []
    if mode_tg:
        text_checks_raw.extend(_TG_TEXT_CHECKS_RAW)
    text_checks = [(s, c, d, re.compile(p, f)) for s, c, d, p, f in text_checks_raw]

    # Line-by-line
    for lineno, line in enumerate(lines, 1):
        skip_tg_orca = (mode_tg or mode_orca) and _allowlist_hit(line)
        for sev, cat, desc, rx in line_checks:
            # Skip tg/orca checks for allowlisted lines
            if skip_tg_orca and (cat.startswith("tg-") or cat.startswith("orca-")):
                continue
            if rx.search(line):
                findings.append(Finding(sev, cat, desc, filepath, lineno, line))

    # Full-text
    for sev, cat, desc, rx in text_checks:
        for m in rx.finditer(text):
            lineno = _line_number_of_offset(text, m.start())
            snippet = m.group(0).replace("\n", " ")
            findings.append(Finding(sev, cat, desc, filepath, lineno, snippet))

    return findings


def scan_file(fp, root=None, mode_tg=False, mode_orca=False):
    fp = Path(fp)
    if not fp.is_absolute() and root:
        fp = Path(root) / fp
    if fp.suffix.lower() in _SKIP_SUFFIXES:
        return []
    try:
        text = fp.read_text(encoding="utf-8", errors="ignore")
    except OSError as e:
        return [Finding("W", "io-error", f"could not read: {e}", fp, None, "")]
    return scan_text(text, fp, mode_tg=mode_tg, mode_orca=mode_orca)


def scan_all_files(root, mode_tg=False, mode_orca=False, exclude_dirs=None):
    """Scan all non-skipped files under root."""
    exclude_dirs = exclude_dirs or {".git", ".backup", ".bak", "node_modules"}
    findings = []
    file_count = 0
    for fp in Path(root).rglob("*"):
        if fp.is_file():
            if any(part in exclude_dirs for part in fp.parts):
                continue
            if fp.suffix.lower() in _SKIP_SUFFIXES:
                continue
            file_count += 1
            findings.extend(scan_file(fp, mode_tg=mode_tg, mode_orca=mode_orca))
    return findings, file_count


def scan_diff(diff_text, mode_tg=False, mode_orca=False):
    findings = []
    current_file = "<diff>"
    new_lineno   = 0
    line_checks_raw = list(_BASE_LINE_CHECKS_RAW)
    if mode_tg:
        line_checks_raw.extend(_TG_LINE_CHECKS_RAW)
    if mode_orca:
        line_checks_raw.extend(_ORCA_LINE_CHECKS_RAW)
    line_checks = [(s, c, d, re.compile(p, f)) for s, c, d, p, f in line_checks_raw]

    for rawline in diff_text.splitlines():
        if rawline.startswith("+++ b/"):
            current_file = rawline[6:]
            new_lineno   = 0
        elif rawline.startswith("@@ "):
            m = re.search(r"\+(\d+)", rawline)
            new_lineno = int(m.group(1)) - 1 if m else 0
        elif rawline.startswith("+") and not rawline.startswith("+++"):
            new_lineno += 1
            line = rawline[1:]
            skip_tg_orca = (mode_tg or mode_orca) and _allowlist_hit(line)
            for sev, cat, desc, rx in line_checks:
                if skip_tg_orca and (cat.startswith("tg-") or cat.startswith("orca-")):
                    continue
                if rx.search(line):
                    findings.append(Finding(sev, cat, desc, current_file, new_lineno, line))
        elif rawline.startswith(" "):
            new_lineno += 1
    return findings


def retro_scan(commit_range, root, mode_tg=False, mode_orca=False):
    try:
        out = subprocess.check_output(
            ["git", "diff", "--name-only", commit_range],
            cwd=root, text=True, stderr=subprocess.DEVNULL,
        )
    except subprocess.CalledProcessError as e:
        print(f"[scrub] ERROR: git diff failed for range '{commit_range}': {e}", file=sys.stderr)
        return [], 0
    files = [f for f in out.strip().splitlines() if f]
    print(f"[scrub] Retro-scan: {len(files)} files in {commit_range}", file=sys.stderr)
    all_findings = []
    for f in files:
        all_findings.extend(scan_file(Path(root) / f, mode_tg=mode_tg, mode_orca=mode_orca))
    return all_findings, len(files)


def _out(msg):
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", errors="replace").decode("ascii"))


def report(findings, strict=False, label=""):
    errors = [f for f in findings if f.severity == "E"]
    warns  = [f for f in findings if f.severity == "W"]
    prefix = f"[scrub{' ' + label if label else ''}]"

    if errors:
        _out(f"\n{prefix} -- ERRORS ({len(errors)}) ----------------------")
        for f in errors:
            _out(str(f))
    if warns:
        _out(f"\n{prefix} -- WARNINGS ({len(warns)}) --------------------")
        for f in warns:
            _out(str(f))
    if not findings:
        _out(f"{prefix} PASS - no findings.")
    else:
        e_tag = f"  {len(errors)} error(s)" if errors else ""
        w_tag = f"  {len(warns)} warning(s)" if warns else ""
        _out(f"\n{prefix} SUMMARY:{e_tag}{w_tag}")
        if errors:
            _out(f"{prefix} -> Fix errors before committing.")
        elif strict:
            _out(f"{prefix} -> --strict: warnings treated as errors.")
        else:
            _out(f"{prefix} -> Warnings are informational; review before delivery.")
    return bool(errors), bool(warns)


def _find_root():
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True
        ).strip()
    except Exception:
        return str(Path.cwd())


def main():
    parser = argparse.ArgumentParser(
        description="audit-orc Orca delivery content scrub",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan staged files before TG commit:
  python precommit-scrub.py --tg --orca file1.md file2.py

  # Full repo scan (recommended before any Orca delivery commit):
  python precommit-scrub.py --tg --orca --all

  # Diff mode (use in pre-commit hook):
  git diff --cached | python precommit-scrub.py --tg --orca --from-diff

  # Base mode only (no TG/Orca rules):
  python precommit-scrub.py file1.py
""",
    )
    parser.add_argument("files", nargs="*", help="Files to scrub (file mode)")
    parser.add_argument("--tg",   action="store_true",
                        help="Enable TG-delivery substrate-leak checks")
    parser.add_argument("--orca", action="store_true",
                        help="Enable Orca-delivery checks (implies --tg context)")
    parser.add_argument("--from-diff", action="store_true",
                        help="Diff mode: read unified diff from stdin")
    parser.add_argument("--retro", metavar="RANGE",
                        help="Retro mode: git commit range (e.g. abc123..HEAD)")
    parser.add_argument("--all",  action="store_true",
                        help="All mode: scan every file under --root")
    parser.add_argument("--root", default=None,
                        help="Repo root (default: git rev-parse --show-toplevel)")
    parser.add_argument("--strict", action="store_true",
                        help="Treat warnings as errors (exit 1 on any finding)")
    args = parser.parse_args()

    mode_tg   = args.tg or args.orca   # --orca implies TG rules
    mode_orca = args.orca
    root  = args.root or _find_root()
    label = ""

    flags = []
    if mode_tg:   flags.append("tg")
    if mode_orca: flags.append("orca")
    if flags:
        print(f"[scrub] Modes active: {', '.join(flags)}", file=sys.stderr)

    if args.from_diff:
        diff_text = sys.stdin.read()
        findings  = scan_diff(diff_text, mode_tg=mode_tg, mode_orca=mode_orca)
        label = "diff"

    elif args.retro:
        findings, fc = retro_scan(args.retro, root, mode_tg=mode_tg, mode_orca=mode_orca)
        label = f"retro:{args.retro}"
        if fc:
            print(f"[scrub retro] {fc} files checked.", file=sys.stderr)

    elif args.all:
        findings, fc = scan_all_files(root, mode_tg=mode_tg, mode_orca=mode_orca)
        label = "all"
        print(f"[scrub all] {fc} files scanned.", file=sys.stderr)

    elif args.files:
        findings = []
        for f in args.files:
            findings.extend(scan_file(f, root, mode_tg=mode_tg, mode_orca=mode_orca))
        label = "staged"

    else:
        parser.print_help()
        return 2

    has_errors, has_warns = report(findings, strict=args.strict, label=label)

    if has_errors:
        return 1
    if has_warns and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

# L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
