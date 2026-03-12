"""Smoke tests for the repo wrapper shell script."""

from __future__ import annotations

import os
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
    return wrapper_path


def _run_wrapper(tmp_path: Path, *args: str):
    env = dict(os.environ)
    env["PATH"] = ""
    env.pop("PYTHON", None)
    return subprocess.run(
        ["/bin/bash", str(_make_wrapper_sandbox(tmp_path)), *args],
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
