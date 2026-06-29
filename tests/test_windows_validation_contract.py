from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def test_windows_validation_script_is_fresh_runner_safe() -> None:
    validator = (REPO_ROOT / "tools" / "windows_validate.ps1").read_text(encoding="utf-8")

    assert "setup.ps1" in validator
    assert "pytest==8.4.2" in validator
    assert ".\\liquefy.cmd openclaw --version --json" in validator
    assert ".\\liquefy.ps1 openclaw --version --json" in validator
    assert "tests\\test_windows_runtime_paths.py" in validator
    assert "WINDOWS_VALIDATION_OK" in validator


def test_windows_validation_workflow_runs_the_repo_validator() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "windows-validation.yml").read_text(encoding="utf-8")
    docs = (REPO_ROOT / "docs" / "WINDOWS_OPENCLAW_SKILLS.md").read_text(encoding="utf-8")

    assert "runs-on: windows-latest" in workflow
    assert "actions/checkout@v6" in workflow
    assert "actions/setup-python@v6" in workflow
    assert "tools\\windows_validate.ps1" in workflow or "tools/windows_validate.ps1" in workflow
    assert ".\\tools\\windows_validate.ps1 -SkipFullPython -SkipNode" in workflow
    assert "windows-validation.yml" in docs
