"""Smoke tests for the repo wrapper shell script."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def _run_wrapper(*args: str):
    env = dict(os.environ)
    env["PATH"] = ""
    return subprocess.run(
        ["/bin/bash", str(REPO_ROOT / "liquefy"), *args],
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_repo_wrapper_routes_context_gate_without_path_python():
    proc = _run_wrapper("context-gate", "--help")
    assert proc.returncode == 0, proc.stderr
    assert "Compile bounded runtime context" in proc.stdout


def test_repo_wrapper_routes_safe_run_without_path_python():
    proc = _run_wrapper("safe-run", "--help")
    assert proc.returncode == 0, proc.stderr
    assert "Automated rollback wrapper" in proc.stdout
