#!/usr/bin/env pwsh
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
# L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md

# MRK:PT_ORC_REINDEX_NAV_TOC — Section index | nav,toc,index | L5-18
# - MRK:REINDEX_PS1_SETUP — Setup: find Python tool + resolver | reindex,ps1,setup,find,python | L19-39 | ⚠ same-commit:tools/pt-orc-reindex.sh
# - MRK:REINDEX_PS1_DISPATCH — Flag dispatch | reindex,ps1,dispatch,flag,flags | L40-102 | ⚠ same-commit:tools/pt-orc-reindex.sh
# NAV-LEN: 2 entries | Integrity-hash: 82a09363fca98b13 | Last-indexed: 2026-06-09T07:09:41Z

# =============================================================================
# pt-orc-reindex.ps1 — thin wrapper around canonical orc-nav-reindex.py
# TechGuard.
#
# Maps legacy PT-Orc reindex flags to the v1 Python tool's subcommands.
# Kept for operator muscle memory; new work should call orc-nav-reindex.py
# directly.
# =============================================================================

# MRK:REINDEX_PS1_SETUP — Setup: find Python tool + resolver | reindex,ps1,setup,find,python | L19-39
# NAV-RULE: same-commit:tools/pt-orc-reindex.sh
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PyTool = Join-Path $ScriptDir 'orc-nav-reindex.py'

if (-not (Test-Path $PyTool)) {
    Write-Error "Cannot find orc-nav-reindex.py in $ScriptDir"
    exit 2
}

# Prefer python; fall back to python3
$Python = 'python'
if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
    $Python = 'python3'
}

$First = if ($args.Count -gt 0) { $args[0] } else { '' }
$Rest = if ($args.Count -gt 1) { $args[1..($args.Count - 1)] } else { @() }

# MRK:REINDEX_PS1_DISPATCH — Flag dispatch | reindex,ps1,dispatch,flag,flags | L40-102
# NAV-RULE: same-commit:tools/pt-orc-reindex.sh
switch ($First) {
    '--mrk' {
        & $Python $PyTool index @Rest
        exit $LASTEXITCODE
    }
    '--fix-nav' {
        & $Python $PyTool reindex @Rest
        exit $LASTEXITCODE
    }
    '--verify' {
        & $Python $PyTool verify @Rest
        exit $LASTEXITCODE
    }
    '--index' {
        & $Python $PyTool index @Rest
        exit $LASTEXITCODE
    }
    '--pre-commit' {
        & $Python $PyTool reindex @Rest
        if ($LASTEXITCODE -eq 0) {
            & $Python $PyTool index @Rest
        }
        if ($LASTEXITCODE -eq 0) {
            & $Python $PyTool verify @Rest
        }
        if ($LASTEXITCODE -eq 0) {
            $RepoRoot = Split-Path -Parent $ScriptDir
            $scripts = @(
                '00_pt-orc.sh','01_dns_recon.sh','02_ip_analysis.sh',
                '03_comp_scan.sh','04_tls_scan.sh','05_web_enum.sh',
                '06_wpscan.sh','07_service_verify.sh','orc-common-lib.sh'
            )
            $lines = foreach ($s in $scripts) {
                $h = (Get-FileHash (Join-Path $RepoRoot $s) -Algorithm SHA256).Hash.ToLower()
                "$h  $s"
            }
            $lines | Set-Content (Join-Path $RepoRoot 'SHA256SUMS') -Encoding UTF8NoBOM
        }
        exit $LASTEXITCODE
    }
    '--diff' {
        Write-Host "[INFO] --diff is no longer supported (old docs/funcs.md line-table drift check)." -ForegroundColor Yellow
        Write-Host "       Use 'orc-nav-reindex.py verify' for integrity drift detection." -ForegroundColor Yellow
        exit 1
    }
    { $_ -in '-h', '--help', '' } {
        & $Python $PyTool --help
        exit $LASTEXITCODE
    }
    { $_ -in 'migrate', 'verify', 'reindex', 'index' } {
        & $Python $PyTool @args
        exit $LASTEXITCODE
    }
    default {
        Write-Error "Unknown flag: $First`nSee: $PyTool --help"
        exit 1
    }
}

# L2 NAV:v1 → ../../AUDIT-ORC-INDEX.md
# L1 ORC-NAV — read MRK:NAV_TOC first; fetch MRK ranges precisely (no default line count)
