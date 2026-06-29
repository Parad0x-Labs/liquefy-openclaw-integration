@echo off
setlocal
REM Liquefy Windows Setup (CMD)
REM One command: setup.bat

cd /d "%~dp0"

echo.
echo   Liquefy Windows Setup
echo   =======================
echo.

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] python not found. Install Python 3.9+ from python.org and rerun.
    exit /b 1
)

if not exist .venv (
    echo [1/6] Creating virtual environment...
    python -m venv .venv
    if %errorlevel% neq 0 (
        echo [ERROR] Failed to create venv.
        exit /b 1
    )
)

if not exist .venv\Scripts\python.exe (
    echo [ERROR] Virtualenv Python is missing: .venv\Scripts\python.exe
    exit /b 1
)

echo [2/6] Checking pip...
.venv\Scripts\python.exe -m pip --version >nul 2>nul
if %errorlevel% neq 0 (
    .venv\Scripts\python.exe -m ensurepip --upgrade
    if %errorlevel% neq 0 exit /b %errorlevel%
)

echo [3/6] Upgrading pip/build tooling...
.venv\Scripts\python.exe -m pip install --quiet --upgrade pip setuptools wheel
if %errorlevel% neq 0 exit /b %errorlevel%

echo [4/6] Installing dependencies...
.venv\Scripts\python.exe -m pip install --quiet -r requirements.txt
if %errorlevel% neq 0 exit /b %errorlevel%

echo [5/6] Installing local CLI metadata...
.venv\Scripts\python.exe -m pip install --quiet --no-build-isolation -e .
if %errorlevel% neq 0 exit /b %errorlevel%

echo [6/6] Running smoke tests...
set PYTHONPATH=tools;api
.venv\Scripts\python.exe tools\liquefy_cli.py self-test --json 2>nul | .venv\Scripts\python.exe -c "import sys,json; d=json.load(sys.stdin); print('  SELF-TEST:', 'PASS' if d.get('ok') else 'FAIL'); sys.exit(0 if d.get('ok') else 1)"
if %errorlevel% neq 0 exit /b %errorlevel%
.venv\Scripts\python.exe tools\liquefy_cli.py openclaw --version --json 2>nul | .venv\Scripts\python.exe -c "import sys,json; d=json.load(sys.stdin); print('  OPENCLAW CLI:', 'PASS' if d.get('ok') else 'FAIL'); sys.exit(0 if d.get('ok') else 1)"
if %errorlevel% neq 0 exit /b %errorlevel%

set "LIQUEFY_OPENCLAW_BIN=%~dp0liquefy.cmd"

echo.
echo   READY. Quick start:
echo.
echo     liquefy.cmd self-test --json
echo     liquefy.cmd openclaw --workspace "%%USERPROFILE%%\.openclaw" --out .\vault --json
echo     liquefy.cmd vision scan .\screenshots --json
echo.
echo   OpenClaw plugin binary path for this shell:
echo     LIQUEFY_OPENCLAW_BIN=%LIQUEFY_OPENCLAW_BIN%
echo.
