param(
    [switch] $PersistUserEnv
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RepoRoot

function Invoke-Checked {
    param(
        [scriptblock] $Command,
        [string] $Label
    )
    try {
        & $Command
    } catch {
        if ($LASTEXITCODE -eq 0) {
            throw
        }
    }
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

function Test-NativeSuccess {
    param([scriptblock] $Command)
    try {
        & $Command
    } catch {
        return $false
    }
    return $LASTEXITCODE -eq 0
}

Write-Host ""
Write-Host "  Liquefy Windows Setup" -ForegroundColor Cyan
Write-Host "  =======================" -ForegroundColor Cyan
Write-Host ""

$pythonCmd = if (Get-Command python -ErrorAction SilentlyContinue) { "python" }
             elseif (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" }
             else { $null }

if (-not $pythonCmd) {
    Write-Host "[ERROR] Python not found. Install Python 3.9+ from python.org." -ForegroundColor Red
    exit 1
}

$ver = & $pythonCmd --version 2>&1
Write-Host "  Using: $ver" -ForegroundColor DarkGray

if (-not (Test-Path ".venv")) {
    Write-Host "[1/6] Creating virtual environment..." -ForegroundColor Yellow
    Invoke-Checked { & $pythonCmd -m venv .venv } "venv creation"
}

$VenvPython = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "[ERROR] Virtualenv Python is missing: $VenvPython" -ForegroundColor Red
    exit 1
}

Write-Host "[2/6] Checking pip..." -ForegroundColor Yellow
if (-not (Test-NativeSuccess { & $VenvPython -m pip --version *> $null })) {
    Invoke-Checked { & $VenvPython -m ensurepip --upgrade } "pip bootstrap"
}

Write-Host "[3/6] Upgrading pip/build tooling..." -ForegroundColor Yellow
Invoke-Checked { & $VenvPython -m pip install --quiet --upgrade pip setuptools wheel } "pip/build tooling upgrade"

Write-Host "[4/6] Installing dependencies..." -ForegroundColor Yellow
Invoke-Checked { & $VenvPython -m pip install --quiet -r requirements.txt } "dependency install"

Write-Host "[5/6] Installing local CLI metadata..." -ForegroundColor Yellow
Invoke-Checked { & $VenvPython -m pip install --quiet --no-build-isolation -e . } "local package install"

Write-Host "[6/6] Running smoke tests..." -ForegroundColor Yellow
$env:PYTHONPATH = @("tools", "api", $env:PYTHONPATH) -join [IO.Path]::PathSeparator
try {
    $selfTest = & $VenvPython tools\liquefy_cli.py self-test --json 2>$null | ConvertFrom-Json
    if (-not $selfTest.ok) { throw "self-test returned ok=false" }
    Write-Host "  SELF-TEST: PASS" -ForegroundColor Green

    $version = & $VenvPython tools\liquefy_cli.py openclaw --version --json 2>$null | ConvertFrom-Json
    if (-not $version.ok) { throw "openclaw version returned ok=false" }
    Write-Host "  OPENCLAW CLI: PASS" -ForegroundColor Green
} catch {
    Write-Host "  SMOKE TEST: FAIL" -ForegroundColor Red
    Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

$LiquefyBin = Join-Path $RepoRoot "liquefy.cmd"
$env:LIQUEFY_OPENCLAW_BIN = $LiquefyBin
if ($PersistUserEnv) {
    [Environment]::SetEnvironmentVariable("LIQUEFY_OPENCLAW_BIN", $LiquefyBin, "User")
    Write-Host "  Persisted LIQUEFY_OPENCLAW_BIN for this Windows user." -ForegroundColor Green
}

Write-Host ""
Write-Host "  READY." -ForegroundColor Green
Write-Host ""
Write-Host "  Quick start:" -ForegroundColor Cyan
Write-Host '    .\liquefy.cmd self-test --json'
Write-Host '    .\liquefy.cmd openclaw --workspace "$env:USERPROFILE\.openclaw" --out .\vault --json'
Write-Host '    .\liquefy.cmd vision scan .\screenshots --json'
Write-Host ""
Write-Host "  OpenClaw plugin binary path for this shell:" -ForegroundColor Cyan
Write-Host "    `$env:LIQUEFY_OPENCLAW_BIN = `"$LiquefyBin`""
Write-Host ""
