# Windows OpenClaw Skills Support

This document tracks the Windows support path for the Liquefy/OpenClaw skills in this repo.

## Current Status

Windows is supported for the local source workflow:

- PowerShell setup: `.\setup.ps1`
- CMD setup: `setup.bat`
- Native repo launchers: `.\liquefy.cmd` and `.\liquefy.ps1`
- OpenClaw plugin binary handoff through `LIQUEFY_OPENCLAW_BIN`
- Python CLI contracts for `liquefy openclaw --json`
- OpenClaw plugin wrapper tests, including Windows `.cmd` process launch

This is not yet a polished consumer installer. There is no signed MSI/MSIX, no GUI, and no automatic OpenClaw marketplace install flow from the Windows setup script. The Windows path is source-first and local-first.

## Setup

PowerShell:

```powershell
cd "G:\Local Nulla\openclaw-skills"
.\setup.ps1
```

To persist the plugin binary path for the current Windows user:

```powershell
.\setup.ps1 -PersistUserEnv
```

CMD:

```cmd
cd /d "G:\Local Nulla\openclaw-skills"
setup.bat
```

The setup scripts create `.venv`, install Python dependencies from `requirements.txt`, install local package metadata, and run smoke checks for:

- `liquefy self-test --json`
- `liquefy openclaw --version --json`

## OpenClaw Plugin Configuration

The OpenClaw plugin shells out to the Liquefy CLI. On Windows, point it at the repo launcher:

```powershell
$env:LIQUEFY_OPENCLAW_BIN = "G:\Local Nulla\openclaw-skills\liquefy.cmd"
```

For persistent user scope:

```powershell
[Environment]::SetEnvironmentVariable(
  "LIQUEFY_OPENCLAW_BIN",
  "G:\Local Nulla\openclaw-skills\liquefy.cmd",
  "User"
)
```

The plugin resolution order is:

1. Plugin config `binaryPath`
2. `LIQUEFY_OPENCLAW_BIN`
3. `liquefy` on `PATH`

Use an absolute `binaryPath` or `LIQUEFY_OPENCLAW_BIN` on Windows. Relying on `PATH` is weaker because `.cmd` shims have different process-launch behavior than native executables.

## Local-First Storage

The skills do not download or choose LLMs. Model placement and local-model recommendation belong to `nulla-local`.

For Liquefy vaults, choose the output drive explicitly:

```powershell
.\liquefy.cmd openclaw --workspace "$env:USERPROFILE\.openclaw" --out "G:\OpenClawVaults\current" --json
```

Use a fast drive for active vaults and a large slower drive for long-term archive output. The CLI will not silently move data between drives.

## Validation

Windows regression checks:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_cli_contracts.py tests\test_liquefy_openclaw_cli.py tests\test_repo_wrapper.py tests\test_history_guard.py tests\test_windows_runtime_paths.py -q
cd plugins\openclaw-plugin
npm test
```

Full Python suite:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Full repo validation script:

```powershell
.\.venv\Scripts\python.exe tools\run_all_validation.py --skip-bench --skip-matrix
```

One-command Windows validation:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\windows_validate.ps1
```

The PR gate for this path is `.github\workflows\windows-validation.yml`, which
runs the same validator on `windows-latest` with the full Python and Node matrix
disabled for CI speed.

For a faster local check after the full suite already passed:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\windows_validate.ps1 -SkipFullPython -SkipNode
```

Node/OpenClaw package validation:

```powershell
cd skills\x402-pay; npm ci; npm test; npm audit --omit=dev --omit=peer --audit-level=high
cd ..\x402-gate; npm ci; npm test; npm audit --omit=dev --omit=peer --audit-level=high
cd ..\context-capsule; npm ci; npm test; npm audit --omit=dev --omit=peer --audit-level=high
cd ..\mcp-server; npm ci; npm test; npm audit --omit=dev --omit=peer --audit-level=high
```

x402-gate private-reputation proof integration needs local proving artifacts. Set:

```powershell
$env:X402_GATE_TRACK_ARTIFACTS = "D:\path\to\track-artifacts"
```

That directory must contain `track_record.wasm` and `track_record_final.zkey`. Without those large artifacts, the package still runs fee/manifest tests and explicitly skips the proof-generation integration test.

## Known Gaps

- OpenClaw itself must already be installed and working on Windows.
- Node-based skills still need package-level `npm install` before their own tests can run.
- No signed Windows installer exists yet.
- No GUI installer exists yet.
- No automatic OpenClaw plugin install is performed by `setup.ps1` or `setup.bat`.
- Release artifacts need checksum/signature publication before this is consumer-grade.
- `@solana/web3.js@1.98.4` still carries npm's moderate transitive `uuid` advisory through `jayson`; npm's suggested `--force` fix is a breaking downgrade and is intentionally not applied.
