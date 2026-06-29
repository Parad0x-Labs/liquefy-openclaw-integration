param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Args
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvPython = Join-Path $RootDir ".venv\Scripts\python.exe"

if ($env:PYTHON) {
    $PythonBin = $env:PYTHON
} elseif (Test-Path $VenvPython) {
    $PythonBin = $VenvPython
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $PythonBin = "python"
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    $PythonBin = "py"
} else {
    Write-Error "Python not found. Run setup.ps1 or install Python 3.9+."
    exit 1
}

$env:PYTHONPATH = @(
    (Join-Path $RootDir "tools"),
    (Join-Path $RootDir "api"),
    $env:PYTHONPATH
) -join [IO.Path]::PathSeparator

& $PythonBin (Join-Path $RootDir "tools\liquefy_cli.py") @Args
exit $LASTEXITCODE
