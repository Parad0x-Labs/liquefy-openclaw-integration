@echo off
setlocal

set "ROOT_DIR=%~dp0"
set "PYTHON_BIN="

if defined PYTHON (
  set "PYTHON_BIN=%PYTHON%"
) else if exist "%ROOT_DIR%.venv\Scripts\python.exe" (
  set "PYTHON_BIN=%ROOT_DIR%.venv\Scripts\python.exe"
) else (
  for %%P in (python py) do (
    if not defined PYTHON_BIN (
      where %%P >nul 2>nul
      if not errorlevel 1 set "PYTHON_BIN=%%P"
    )
  )
)

if not defined PYTHON_BIN (
  echo [ERROR] Python not found. Run setup.bat or install Python 3.9+.
  exit /b 1
)

set "PYTHONPATH=%ROOT_DIR%tools;%ROOT_DIR%api;%PYTHONPATH%"
"%PYTHON_BIN%" "%ROOT_DIR%tools\liquefy_cli.py" %*
exit /b %ERRORLEVEL%
