#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
HISTORY_GUARD = REPO_ROOT / "tools" / "liquefy_history_guard.py"


def _run_json(cmd, env=None):
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True, env=env)
    try:
        return json.loads(proc.stdout)
    except Exception as exc:  # pragma: no cover - assertion path
        raise AssertionError(
            f"stdout was not valid JSON: {exc}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )


def _run_json_no_check(cmd, env=None):
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, env=env)
    payload = None
    if proc.stdout.strip():
        try:
            payload = json.loads(proc.stdout)
        except Exception as exc:  # pragma: no cover - assertion path
            raise AssertionError(
                f"stdout was not valid JSON: {exc}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
            )
    return proc, payload


def _config_path(workspace: Path) -> Path:
    return workspace / ".liquefy" / "history_guard.json"


def _write_config(workspace: Path, mutate):
    cpath = _config_path(workspace)
    cfg = json.loads(cpath.read_text(encoding="utf-8"))
    mutate(cfg)
    cpath.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")


def test_history_guard_init_creates_config_and_state(tmp_path):
    workspace = tmp_path / "workspace"
    payload = _run_json(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "init",
            "--workspace",
            str(workspace),
            "--json",
        ]
    )
    assert payload["schema_version"] == "liquefy.history-guard.cli.v1"
    assert payload["tool"] == "liquefy_history_guard"
    assert payload["command"] == "init"
    assert payload["ok"] is True

    result = payload["result"]
    assert Path(result["config_path"]).exists()
    assert Path(result["state_path"]).exists()
    cfg = json.loads(Path(result["config_path"]).read_text(encoding="utf-8"))
    assert cfg["schema"] == "liquefy.history-guard.config.v1"
    assert isinstance(cfg["providers"], list)
    assert any(p["id"] == "gmail" for p in cfg["providers"])


def test_history_guard_gate_action_requires_configured_approval(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "data.txt").parent.mkdir(parents=True, exist_ok=True)
    (workspace / "data.txt").write_text("sample\n", encoding="utf-8")

    _run_json(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "init",
            "--workspace",
            str(workspace),
            "--json",
        ]
    )
    _write_config(workspace, lambda cfg: cfg.update({"no_encrypt": True, "sign": False}))

    proc, payload = _run_json_no_check(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "gate-action",
            "--workspace",
            str(workspace),
            "--command",
            "echo delete everything",
            "--json",
        ]
    )
    assert proc.returncode != 0
    assert payload is not None
    assert payload["ok"] is False
    assert payload["result"]["risky"] is True
    assert payload["result"]["error_code"] == "LIQUEFY_APPROVAL_CONFIG_MISSING"


def test_history_guard_gate_action_requires_token_when_configured(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "data.txt").parent.mkdir(parents=True, exist_ok=True)
    (workspace / "data.txt").write_text("sample\n", encoding="utf-8")

    _run_json(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "init",
            "--workspace",
            str(workspace),
            "--json",
        ]
    )
    _write_config(workspace, lambda cfg: cfg.update({"no_encrypt": True, "sign": False}))
    _run_json(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "set-approval-token",
            "--workspace",
            str(workspace),
            "--token",
            "correct-token-123",
            "--json",
        ]
    )

    proc, payload = _run_json_no_check(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "gate-action",
            "--workspace",
            str(workspace),
            "--command",
            "echo delete old records",
            "--json",
        ]
    )
    assert proc.returncode != 0
    assert payload is not None
    assert payload["ok"] is False
    assert payload["result"]["error_code"] == "LIQUEFY_APPROVAL_REQUIRED"


def test_history_guard_gate_action_rejects_wrong_token(tmp_path):
    workspace = tmp_path / "workspace"
    (workspace / "data.txt").parent.mkdir(parents=True, exist_ok=True)
    (workspace / "data.txt").write_text("sample\n", encoding="utf-8")

    _run_json(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "init",
            "--workspace",
            str(workspace),
            "--json",
        ]
    )
    _write_config(workspace, lambda cfg: cfg.update({"no_encrypt": True, "sign": False}))
    _run_json(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "set-approval-token",
            "--workspace",
            str(workspace),
            "--token",
            "correct-token-123",
            "--json",
        ]
    )

    env = os.environ.copy()
    env["LIQUEFY_APPROVAL_TOKEN"] = "WRONG"
    proc, payload = _run_json_no_check(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "gate-action",
            "--workspace",
            str(workspace),
            "--command",
            "echo delete old records",
            "--json",
        ],
        env=env,
    )
    assert proc.returncode != 0
    assert payload is not None
    assert payload["ok"] is False
    assert payload["result"]["error_code"] == "LIQUEFY_APPROVAL_INVALID"


def test_history_guard_gate_action_allows_with_token_and_avoids_recursive_snapshot(tmp_path):
    workspace = Path(tempfile.mkdtemp(prefix="hg-allow-", dir="/tmp")) / "workspace"
    (workspace / "history" / "events.jsonl").parent.mkdir(parents=True, exist_ok=True)
    (workspace / "history" / "events.jsonl").write_text("{\"event\":1}\n", encoding="utf-8")

    _run_json(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "init",
            "--workspace",
            str(workspace),
            "--json",
        ]
    )

    def _mutate(cfg):
        cfg["no_encrypt"] = True
        cfg["sign"] = False
        cfg["hash_cache"] = False
        # Intentionally dangerous placement inside workspace.
        cfg["snapshot_vault_root"] = str(workspace / ".liquefy" / "history_vaults")

    _write_config(workspace, _mutate)

    _run_json(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "set-approval-token",
            "--workspace",
            str(workspace),
            "--token",
            "correct-token-123",
            "--json",
        ]
    )

    env = os.environ.copy()
    env["LIQUEFY_APPROVAL_TOKEN"] = "correct-token-123"
    payload = _run_json(
        [
            sys.executable,
            str(HISTORY_GUARD),
            "gate-action",
            "--workspace",
            str(workspace),
            "--command",
            "echo delete old records",
            "--json",
        ],
        env=env,
    )

    assert payload["ok"] is True
    result = payload["result"]
    assert result["risky"] is True
    assert result["approval_ok"] is True
    assert result["snapshot"]["ok"] is True
    assert result["action"]["returncode"] == 0

    snapshot_vault = Path(result["snapshot"]["vault_dir"]).resolve()
    workspace_resolved = workspace.resolve()
    assert workspace_resolved != snapshot_vault
    assert workspace_resolved not in snapshot_vault.parents
    assert str(snapshot_vault).startswith(
        ("/tmp/liquefy-history-guard-snapshots", "/private/tmp/liquefy-history-guard-snapshots")
    )
