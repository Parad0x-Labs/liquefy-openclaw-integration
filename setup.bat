@echo off
REM Liquefy — Windows Setup (CMD)
REM One command: setup.bat

echo.
echo   Liquefy — Windows Setup
echo   =======================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] python not found. Install Python 3.11+ from python.org and rerun.
    exit /b 1
)

if not exist .venv (
    echo [1/4] Creating virtual environment...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create venv. Make sure python3-venv is available.
        exit /b 1
    )
)

echo [2/4] Upgrading pip...
.venv\Scripts\pip install --quiet --upgrade pip

echo [3/4] Installing dependencies...
.venv\Scripts\pip install --quiet -r api\requirements.txt

echo [4/4] Running smoke test...
set PYTHONPATH=tools;api
.venv\Scripts\python tools\liquefy_cli.py self-test --json 2>nul | .venv\Scripts\python -c "import sys,json; d=json.load(sys.stdin); print('  SELF-TEST:', 'PASS' if d.get('ok') else 'FAIL')" 2>nul || echo   SELF-TEST: could not verify (non-blocking)

echo.
echo   READY. Quick start:
echo.
echo     .venv\Scripts\python tools\tracevault_pack.py .\your\data --org default --out .\vault\output --json
echo     .venv\Scripts\python tools\liquefy_openclaw.py --workspace %%USERPROFILE%%\.openclaw --out .\vault --json
echo     .venv\Scripts\python tools\liquefy_vision.py scan .\screenshots --json
echo     .venv\Scripts\python tools\liquefy_compliance.py report --vault .\vault --output report.html
echo.
