# Liquefy — Windows Setup (PowerShell)
# One command: .\setup.ps1

Write-Host ""
Write-Host "  Liquefy — Windows Setup" -ForegroundColor Cyan
Write-Host "  =======================" -ForegroundColor Cyan
Write-Host ""

$pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { "python" }
             elseif (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" }
             else { $null }

if (-not $pythonCmd) {
    Write-Host "[ERROR] Python not found. Install Python 3.11+ from python.org" -ForegroundColor Red
    exit 1
}

$ver = & $pythonCmd --version 2>&1
Write-Host "  Using: $ver" -ForegroundColor DarkGray

if (-not (Test-Path ".venv")) {
    Write-Host "[1/4] Creating virtual environment..." -ForegroundColor Yellow
    & $pythonCmd -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to create venv." -ForegroundColor Red
        exit 1
    }
}

Write-Host "[2/4] Upgrading pip..." -ForegroundColor Yellow
& .venv\Scripts\pip install --quiet --upgrade pip

Write-Host "[3/4] Installing dependencies..." -ForegroundColor Yellow
& .venv\Scripts\pip install --quiet -r api\requirements.txt

Write-Host "[4/4] Running smoke test..." -ForegroundColor Yellow
$env:PYTHONPATH = "tools;api"
try {
    $result = & .venv\Scripts\python tools\liquefy_cli.py self-test --json 2>$null | ConvertFrom-Json
    if ($result.ok) {
        Write-Host "  SELF-TEST: PASS" -ForegroundColor Green
    } else {
        Write-Host "  SELF-TEST: FAIL" -ForegroundColor Red
    }
} catch {
    Write-Host "  SELF-TEST: could not verify (non-blocking)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "  READY." -ForegroundColor Green
Write-Host ""
Write-Host "  Quick start:" -ForegroundColor Cyan
Write-Host '    .venv\Scripts\python tools\tracevault_pack.py .\your\data --org default --out .\vault\output --json'
Write-Host '    .venv\Scripts\python tools\liquefy_openclaw.py --workspace $env:USERPROFILE\.openclaw --out .\vault --json'
Write-Host '    .venv\Scripts\python tools\liquefy_vision.py scan .\screenshots --json'
Write-Host '    .venv\Scripts\python tools\liquefy_compliance.py report --vault .\vault --output report.html'
Write-Host ""
