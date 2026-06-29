"""Smoke tests for the repo wrapper shell script."""

from __future__ import annotations

import os
import json
import pytest
import shutil
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _make_wrapper_sandbox(tmp_path: Path) -> Path:
    sandbox = tmp_path / "wrapper_sandbox"
    sandbox.mkdir()
    wrapper_path = sandbox / "liquefy"
    shutil.copy2(REPO_ROOT / "liquefy", wrapper_path)
    wrapper_path.chmod(0o755)
    (sandbox / "tools").symlink_to(REPO_ROOT / "tools", target_is_directory=True)
    if (REPO_ROOT / ".venv").exists():
        (sandbox / ".venv").symlink_to(REPO_ROOT / ".venv", target_is_directory=True)
    return wrapper_path


def _bash_executable() -> str:
    candidates = []
    if os.name == "nt":
        candidates.extend(
            [
                r"C:\Program Files\Git\bin\bash.exe",
                r"C:\Program Files\Git\usr\bin\bash.exe",
            ]
        )
    found = shutil.which("bash")
    if found:
        candidates.append(found)
    candidates.append("/bin/bash")
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    pytest.skip("bash is not available")


def _run_wrapper(tmp_path: Path, *args: str):
    env = dict(os.environ)
    env["PATH"] = ""
    env.pop("PYTHON", None)
    return subprocess.run(
        [_bash_executable(), str(_make_wrapper_sandbox(tmp_path)), *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_repo_wrapper_routes_context_gate_without_path_python(tmp_path):
    proc = _run_wrapper(tmp_path, "context-gate", "--help")
    assert proc.returncode == 0, proc.stderr
    assert "Compile bounded runtime context" in proc.stdout


def test_repo_wrapper_routes_safe_run_without_path_python(tmp_path):
    proc = _run_wrapper(tmp_path, "safe-run", "--help")
    assert proc.returncode == 0, proc.stderr
    assert "Automated rollback wrapper" in proc.stdout


def test_windows_cmd_wrapper_routes_openclaw_version():
    if os.name != "nt":
        pytest.skip("Windows command shim smoke")
    proc = subprocess.run(
        [str(REPO_ROOT / "liquefy.cmd"), "openclaw", "--version", "--json"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema_version"] == "liquefy.openclaw.cli.v1"
    assert payload["tool"] == "liquefy_openclaw"
    assert payload["command"] == "version"
    assert payload["ok"] is True


def test_windows_powershell_wrapper_routes_openclaw_version():
    if os.name != "nt":
        pytest.skip("Windows PowerShell shim smoke")
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        pytest.skip("PowerShell is not available")
    proc = subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(REPO_ROOT / "liquefy.ps1"),
            "openclaw",
            "--version",
            "--json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["schema_version"] == "liquefy.openclaw.cli.v1"
    assert payload["tool"] == "liquefy_openclaw"
    assert payload["command"] == "version"
    assert payload["ok"] is True
