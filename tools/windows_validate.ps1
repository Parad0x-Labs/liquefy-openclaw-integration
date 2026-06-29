param(
    [switch] $SkipSetup,
    [switch] $SkipFullPython,
    [switch] $SkipNode,
    [switch] $SkipAudit,
    [switch] $FreshNodeInstall
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $RepoRoot

function Invoke-Checked {
    param(
        [string] $Label,
        [scriptblock] $Command
    )

    Write-Host ""
    Write-Host "== $Label ==" -ForegroundColor Cyan
    & $Command
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Invoke-PackageCheck {
    param(
        [string] $Dir,
        [bool] $Audit = $true
    )

    Push-Location $Dir
    try {
        if ($FreshNodeInstall -and (Test-Path package-lock.json)) {
            Invoke-Checked "$Dir npm ci" { npm ci }
        } elseif (-not (Test-Path node_modules) -and (Test-Path package-lock.json)) {
            Invoke-Checked "$Dir npm ci" { npm ci }
        }

        Invoke-Checked "$Dir npm test" { npm test }

        if ($Audit -and -not $SkipAudit -and (Test-Path package-lock.json)) {
            Invoke-Checked "$Dir npm audit high" {
                npm audit --omit=dev --omit=peer --audit-level=high
            }
        }
    } finally {
        Pop-Location
    }
}

if (-not $SkipSetup) {
    Invoke-Checked "Windows setup" { powershell -NoProfile -ExecutionPolicy Bypass -File .\setup.ps1 }
}

$Python = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $Python)) {
    throw "Missing venv Python: $Python"
}

Invoke-Checked "CMD launcher" { .\liquefy.cmd openclaw --version --json }
Invoke-Checked "PowerShell launcher" {
    powershell -NoProfile -ExecutionPolicy Bypass -File .\liquefy.ps1 openclaw --version --json
}

Invoke-Checked "Focused Python regression" {
    & $Python -m pytest `
        tests\test_cli_contracts.py `
        tests\test_liquefy_openclaw_cli.py `
        tests\test_repo_wrapper.py `
        tests\test_history_guard.py `
        tests\test_windows_runtime_paths.py `
        -q
}

if (-not $SkipFullPython) {
    Invoke-Checked "Full Python validation" {
        & $Python tools\run_all_validation.py --skip-bench --skip-matrix
    }
}

if (-not $SkipNode) {
    $packages = @(
        @{ Dir = "plugins\openclaw-plugin"; Audit = $false },
        @{ Dir = "plugins\agent-passport"; Audit = $true },
        @{ Dir = "plugins\web0-onboard"; Audit = $true },
        @{ Dir = "plugins\payment-session"; Audit = $true },
        @{ Dir = "skills\mcp-server"; Audit = $true },
        @{ Dir = "skills\x402-pay"; Audit = $true },
        @{ Dir = "skills\x402-gate"; Audit = $true },
        @{ Dir = "skills\context-capsule"; Audit = $true }
    )

    foreach ($pkg in $packages) {
        Invoke-PackageCheck -Dir $pkg.Dir -Audit ([bool] $pkg.Audit)
    }
}

Write-Host ""
Write-Host "WINDOWS_VALIDATION_OK" -ForegroundColor Green
