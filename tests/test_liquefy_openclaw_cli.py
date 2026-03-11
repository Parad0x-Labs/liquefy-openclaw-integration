#!/usr/bin/env python3
"""Tests for the integration-friendly OpenClaw wrapper helpers."""
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from liquefy_openclaw import load_index, scan_workspace
from path_policy import PathPolicy, CATEGORY_ENV_FILE


FIXTURES = Path(__file__).resolve().parent / "fixtures" / "openclaw_state"


class TestOpenClawScanWorkspace:
    def test_scan_returns_denied_and_eligible(self):
        result = scan_workspace(FIXTURES, list_limit=50)
        summary = result["summary"]

        assert summary["files_seen"] >= 4
        assert summary["eligible_files"] == 2
        assert summary["denied_files_count"] >= 2
        assert summary["eligible_bytes"] > 0
        assert summary["estimated_ratio"] > 1.0

        denied_paths = {row["path"] for row in result["denied_files"]}
        assert "openclaw.json" in denied_paths
        assert any(p.startswith("credentials/") for p in denied_paths)

    def test_scan_respects_max_bytes_per_run(self):
        result = scan_workspace(FIXTURES, max_bytes_per_run=300, list_limit=50)
        summary = result["summary"]

        assert summary["max_bytes_cap_reached"] is True
        assert summary["eligible_files"] >= 1
        assert summary["skipped_files_count"] >= 1

    def test_strict_policy_blocks_secret_like_files_in_temp_workspace(self, tmp_path):
        (tmp_path / "agent").mkdir()
        (tmp_path / "agent" / "notes.txt").write_text("ok", encoding="utf-8")
        (tmp_path / ".env").write_text("TOKEN=abc", encoding="utf-8")
        (tmp_path / "demo.pem").write_text("-----BEGIN PRIVATE KEY-----", encoding="utf-8")

        result = scan_workspace(tmp_path, list_limit=50)
        denied = {row["path"]: row.get("reason") for row in result["denied_files"]}
        assert ".env" in denied
        assert "demo.pem" in denied
        assert result["summary"]["eligible_files"] == 1
        assert result["risk_summary"]["risky_files_included"] == 0

    def test_allow_category_env_only_still_blocks_private_key(self, tmp_path):
        (tmp_path / ".env").write_text("TOKEN=abc", encoding="utf-8")
        (tmp_path / "demo.pem").write_text("-----BEGIN PRIVATE KEY-----", encoding="utf-8")
        (tmp_path / "ok.txt").write_text("ok", encoding="utf-8")

        policy = PathPolicy(mode="strict", allow_categories={CATEGORY_ENV_FILE})
        result = scan_workspace(tmp_path, list_limit=50, policy=policy)
        eligible = {row["path"] for row in result["eligible_files"]}
        denied = {row["path"] for row in result["denied_files"]}

        assert ".env" in eligible
        assert "ok.txt" in eligible
        assert "demo.pem" in denied
        assert result["risk_summary"]["risky_files_included"] >= 1

    @pytest.mark.skipif(os.name == "nt", reason="symlink setup differs on Windows")
    def test_scan_blocks_symlink_file(self, tmp_path):
        target = tmp_path / "outside.txt"
        target.write_text("secret", encoding="utf-8")
        (tmp_path / "link.txt").symlink_to(target)
        (tmp_path / "ok.txt").write_text("ok", encoding="utf-8")

        result = scan_workspace(tmp_path, list_limit=50)
        denied = {row["path"]: row.get("reason") for row in result["denied_files"]}
        eligible = {row["path"] for row in result["eligible_files"]}

        assert "link.txt" in denied
        assert denied["link.txt"] == "symlink_file"
        assert "ok.txt" in eligible


class TestLoadIndex:
    def test_load_index_non_dict_returns_empty(self, tmp_path):
        p = tmp_path / "tracevault_index.json"
        p.write_text("null", encoding="utf-8")
        assert load_index(p) == {}


class TestOpenClawRunWrapper:
    def test_run_routes_through_safe_run_and_exports_capsule(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "SOUL.md").write_text("You are helpful.\n", encoding="utf-8")
        (workspace / "HEARTBEAT.md").write_text("interval: 30s\n", encoding="utf-8")
        (workspace / "auth-profiles.json").write_text('{"provider":"openai"}\n', encoding="utf-8")
        (workspace / "trace.jsonl").write_text(
            json.dumps(
                {
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": "repeat me"}],
                    "usage": {"prompt_tokens": 600, "completion_tokens": 60, "total_tokens": 660},
                }
            )
            + "\n",
            encoding="utf-8",
        )

        payload_file = workspace / "seen_env.json"
        code = (
            "import json, os, pathlib; "
            "keys=['LIQUEFY_CONTEXT_BOOTSTRAP_FILE','LIQUEFY_CONTEXT_CAPSULE_JSON','LIQUEFY_CONTEXT_REDUCTION_PCT','LIQUEFY_CONTEXT_GATE_FILE','LIQUEFY_CONTEXT_GATE_JSON']; "
            f"pathlib.Path({str(payload_file)!r}).write_text(json.dumps({{k: os.environ.get(k) for k in keys}}))"
        )
        wrapped_cmd = f"{shlex.quote(sys.executable)} -c {shlex.quote(code)}"

        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
                "run",
                "--workspace",
                str(workspace),
                "--cmd",
                wrapped_cmd,
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["schema_version"] == "liquefy.openclaw.cli.v1"
        assert payload["command"] == "run"
        assert payload["ok"] is True
        assert payload["wrapper"] == "liquefy_safe_run"
        assert payload["defaults"]["capsule_enabled"] is True
        assert payload["defaults"]["context_gate_enabled"] is True
        assert payload["defaults"]["heartbeat_enabled"] is True
        assert payload["defaults"]["replay_blocking_enabled"] is True
        assert payload["result"]["heartbeat_active"] is True
        assert payload["result"]["phases"]["prime_context"]["ok"] is True
        assert payload["result"]["phases"]["capsule_state"]["status"] == "fresh"
        assert payload["result"]["phases"]["context_gate"]["ok"] is True
        assert payload["result"]["phases"]["context_gate"]["blocked"] is False
        assert payload["result"]["phases"]["prime_context"]["scoreboard"]["summary"]["unique_runs"] == 1
        assert payload["result"]["phases"]["sentinels"]["monitored"] == [
            "SOUL.md",
            "HEARTBEAT.md",
            "auth-profiles.json",
        ]
        seen_env = json.loads(payload_file.read_text(encoding="utf-8"))
        assert seen_env["LIQUEFY_CONTEXT_BOOTSTRAP_FILE"]
        assert Path(seen_env["LIQUEFY_CONTEXT_BOOTSTRAP_FILE"]).exists()
        assert Path(seen_env["LIQUEFY_CONTEXT_GATE_FILE"]).exists()

    def test_run_can_disable_capsule_and_heartbeat(self, tmp_path):
        workspace = tmp_path / "workspace"
        workspace.mkdir()
        (workspace / "SOUL.md").write_text("You are helpful.\n", encoding="utf-8")
        (workspace / "HEARTBEAT.md").write_text("interval: 30s\n", encoding="utf-8")
        (workspace / "auth-profiles.json").write_text('{"provider":"openai"}\n', encoding="utf-8")

        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
                "run",
                "--workspace",
                str(workspace),
                "--cmd",
                f"{shlex.quote(sys.executable)} -c {shlex.quote('print(123)')}",
                "--no-capsule",
                "--no-heartbeat",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        assert proc.returncode == 0, proc.stderr
        payload = json.loads(proc.stdout)
        assert payload["defaults"]["capsule_enabled"] is False
        assert payload["defaults"]["context_gate_enabled"] is True
        assert payload["defaults"]["heartbeat_enabled"] is False
        assert payload["result"]["heartbeat_active"] is False
        assert payload["result"]["phases"]["prime_context"] is None

    def test_run_prefers_history_dir_for_repeatable_capsule_metrics(self, tmp_path):
        workspace = tmp_path / "workspace"
        history = workspace / "history"
        history.mkdir(parents=True)
        (workspace / "SOUL.md").write_text("You are helpful.\n", encoding="utf-8")
        (workspace / "HEARTBEAT.md").write_text("interval: 30s\n", encoding="utf-8")
        (workspace / "auth-profiles.json").write_text('{"provider":"openai"}\n', encoding="utf-8")
        (history / "session.jsonl").write_text(
            "\n".join(
                [
                    json.dumps(
                        {
                            "model": "gpt-4o",
                            "messages": [{"role": "user", "content": "summarize the same trace again"}],
                            "usage": {"prompt_tokens": 1800, "completion_tokens": 120, "total_tokens": 1920},
                        }
                    )
                    for _ in range(4)
                ]
            )
            + "\n",
            encoding="utf-8",
        )

        payload_file = workspace / "seen_env.json"
        code = (
            "import json, os, pathlib; "
            "keys=['LIQUEFY_CONTEXT_REDUCTION_PCT']; "
            f"pathlib.Path({str(payload_file)!r}).write_text(json.dumps({{k: os.environ.get(k) for k in keys}}))"
        )
        wrapped_cmd = f"{shlex.quote(sys.executable)} -c {shlex.quote(code)}"
        base_cmd = [
            sys.executable,
            str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
            "run",
            "--workspace",
            str(workspace),
            "--cmd",
            wrapped_cmd,
            "--allow-replay",
            "--json",
        ]

        first = json.loads(subprocess.run(base_cmd, capture_output=True, text=True, check=False).stdout)
        second = json.loads(subprocess.run(base_cmd, capture_output=True, text=True, check=False).stdout)

        first_reduction = first["result"]["phases"]["prime_context"]["reduction_pct"]
        second_reduction = second["result"]["phases"]["prime_context"]["reduction_pct"]
        assert first["ok"] is True
        assert second["ok"] is True
        assert first_reduction == second_reduction
        assert first["defaults"]["replay_blocking_enabled"] is False
        assert first["result"]["phases"]["prime_context"]["trace_dir"].endswith("/history")
        assert second["result"]["phases"]["prime_context"]["replay_detected"] is True

    def test_run_blocks_exact_replay_by_default(self, tmp_path):
        workspace = tmp_path / "workspace"
        history = workspace / "history"
        history.mkdir(parents=True)
        (workspace / "SOUL.md").write_text("You are helpful.\n", encoding="utf-8")
        (workspace / "HEARTBEAT.md").write_text("interval: 30s\n", encoding="utf-8")
        (workspace / "auth-profiles.json").write_text('{"provider":"openai"}\n', encoding="utf-8")
        (history / "session.jsonl").write_text(
            json.dumps(
                {
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": "repeat me"}],
                    "usage": {"prompt_tokens": 600, "completion_tokens": 60, "total_tokens": 660},
                }
            ) + "\n",
            encoding="utf-8",
        )
        cmd = [
            sys.executable,
            str(REPO_ROOT / "tools" / "liquefy_openclaw.py"),
            "run",
            "--workspace",
            str(workspace),
            "--cmd",
            f"{shlex.quote(sys.executable)} -c {shlex.quote('print(123)')}",
            "--json",
        ]
        first = subprocess.run(cmd, capture_output=True, text=True, check=False)
        second = subprocess.run(cmd, capture_output=True, text=True, check=False)
        first_payload = json.loads(first.stdout)
        second_payload = json.loads(second.stdout)

        assert first.returncode == 0
        assert first_payload["result"]["phases"]["context_gate"]["blocked"] is False
        assert second.returncode == 1
        assert second_payload["ok"] is False
        assert second_payload["result"]["blocked"] is True
        assert second_payload["result"]["block_reason"] == "exact_replay_detected"
