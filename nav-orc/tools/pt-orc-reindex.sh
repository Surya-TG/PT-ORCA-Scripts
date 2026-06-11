#!/usr/bin/env bash
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md

# MRK:PT_ORC_REINDEX_NAV_TOC — Section index | nav,toc,index | L5-18
# - MRK:REINDEX_SH_SETUP — Setup: find Python tool + resolver | reindex,sh,setup,find,python | L19-39 | ⚠ same-commit:tools/pt-orc-reindex.ps1
# - MRK:REINDEX_SH_DISPATCH — Flag dispatch | reindex,sh,dispatch,flag,flags | L40-88 | ⚠ same-commit:tools/pt-orc-reindex.ps1
# NAV-LEN: 2 entries | Integrity-hash: 9a974ed784eea0d4 | Last-indexed: 2026-06-09T07:09:41Z

# =============================================================================
# pt-orc-reindex.sh — thin wrapper around canonical orc-nav-reindex.py
# TechGuard.
#
# Maps legacy PT-Orc reindex flags to the v1 Python tool's subcommands.
# Kept for operator muscle memory; new work should call orc-nav-reindex.py
# directly.
# =============================================================================

# MRK:REINDEX_SH_SETUP — Setup: find Python tool + resolver | reindex,sh,setup,find,python | L19-39
# NAV-RULE: same-commit:tools/pt-orc-reindex.ps1
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_TOOL="${DIR}/orc-nav-reindex.py"

if [[ ! -f "$PY_TOOL" ]]; then
    echo "[ERROR] Cannot find orc-nav-reindex.py in ${DIR}" >&2
    exit 2
fi

# Prefer python3 if available; fall back to python
if command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    PYTHON=python
fi

FIRST="${1:-}"

# MRK:REINDEX_SH_DISPATCH — Flag dispatch | reindex,sh,dispatch,flag,flags | L40-88
# NAV-RULE: same-commit:tools/pt-orc-reindex.ps1
case "$FIRST" in
    --mrk)
        shift
        exec "$PYTHON" "$PY_TOOL" index "$@"
        ;;
    --fix-nav)
        shift
        exec "$PYTHON" "$PY_TOOL" reindex "$@"
        ;;
    --verify)
        shift
        exec "$PYTHON" "$PY_TOOL" verify "$@"
        ;;
    --index)
        shift
        exec "$PYTHON" "$PY_TOOL" index "$@"
        ;;
    --pre-commit)
        shift
        "$PYTHON" "$PY_TOOL" reindex "$@" && "$PYTHON" "$PY_TOOL" index "$@" && "$PYTHON" "$PY_TOOL" verify "$@" || exit $?
        REPO_ROOT="$(dirname "$DIR")"
        (cd "$REPO_ROOT" && sha256sum \
            00_pt-orc.sh 01_dns_recon.sh 02_ip_analysis.sh \
            03_comp_scan.sh 04_tls_scan.sh 05_web_enum.sh \
            06_wpscan.sh 07_service_verify.sh orc-common-lib.sh > SHA256SUMS)
        exit $?
        ;;
    --diff)
        echo "[INFO] --diff is no longer supported (old docs/funcs.md line-table drift check)." >&2
        echo "       Use 'orc-nav-reindex.py verify' for integrity drift detection." >&2
        exit 1
        ;;
    -h|--help|"")
        exec "$PYTHON" "$PY_TOOL" --help
        ;;
    migrate|verify|reindex|index)
        exec "$PYTHON" "$PY_TOOL" "$@"
        ;;
    *)
        echo "[ERROR] Unknown flag: $FIRST" >&2
        echo "        See: $PY_TOOL --help" >&2
        exit 1
        ;;
esac

# L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
