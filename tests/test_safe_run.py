"""Tests for liquefy_safe_run.py — automated rollback wrapper."""
from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "api"))

from liquefy_safe_run import (
    _file_sha256,
    _snapshot_workspace,
    _restore_workspace,
    _hash_sentinel_files,
    _check_sentinels,
    _start_heartbeat,
    _stop_heartbeat,
    _check_token_cost,
    _prime_context_for_run,
    SNAPSHOT_DIR_NAME,
    HEARTBEAT_FILE,
)


@pytest.fixture
def workspace(tmp_path):
    ws = tmp_path / "openclaw"
    ws.mkdir()
    (ws / "SOUL.md").write_text("You are a helpful assistant.\n")
    (ws / "HEARTBEAT.md").write_text("interval: 30s\n")
    (ws / "auth-profiles.json").write_text('{"provider": "openai"}\n')
    (ws / "history").mkdir()
    (ws / "history" / "session1.md").write_text("User: hello\nAgent: hi\n")
    return ws


class TestSnapshot:
    def test_creates_manifest(self, workspace):
        snap = workspace / SNAPSHOT_DIR_NAME
        meta = _snapshot_workspace(workspace, snap)
        assert meta["file_count"] == 4
        assert (snap / "manifest.json").exists()

    def test_copies_files(self, workspace):
        snap = workspace / SNAPSHOT_DIR_NAME
        _snapshot_workspace(workspace, snap)
        assert (snap / "SOUL.md").exists()
        assert (snap / "SOUL.md").read_text() == "You are a helpful assistant.\n"
        assert (snap / "history" / "session1.md").exists()

    def test_overwrites_existing_snapshot(self, workspace):
        snap = workspace / SNAPSHOT_DIR_NAME
        _snapshot_workspace(workspace, snap)
        (workspace / "new_file.txt").write_text("added\n")
        meta2 = _snapshot_workspace(workspace, snap)
        assert meta2["file_count"] == 5


class TestRestore:
    def test_restores_modified_file(self, workspace):
        snap = workspace / SNAPSHOT_DIR_NAME
        _snapshot_workspace(workspace, snap)
        (workspace / "SOUL.md").write_text("HACKED: You are evil.\n")
        result = _restore_workspace(workspace, snap)
        assert result["ok"] is True
        assert (workspace / "SOUL.md").read_text() == "You are a helpful assistant.\n"

    def test_removes_new_files(self, workspace):
        snap = workspace / SNAPSHOT_DIR_NAME
        _snapshot_workspace(workspace, snap)
        (workspace / "malware.sh").write_text("rm -rf /\n")
        result = _restore_workspace(workspace, snap)
        assert result["ok"] is True
        assert not (workspace / "malware.sh").exists()

    def test_restores_deleted_file(self, workspace):
        snap = workspace / SNAPSHOT_DIR_NAME
        _snapshot_workspace(workspace, snap)
        (workspace / "HEARTBEAT.md").unlink()
        result = _restore_workspace(workspace, snap)
        assert result["ok"] is True
        assert (workspace / "HEARTBEAT.md").exists()
        assert (workspace / "HEARTBEAT.md").read_text() == "interval: 30s\n"


class TestSentinels:
    def test_hash_existing_files(self, workspace):
        hashes = _hash_sentinel_files(workspace, ["SOUL.md", "HEARTBEAT.md"])
        assert len(hashes) == 2
        assert len(hashes["SOUL.md"]) == 64

    def test_hash_missing_file(self, workspace):
        hashes = _hash_sentinel_files(workspace, ["nonexistent.md"])
        assert hashes["nonexistent.md"] == "MISSING"

    def test_detects_modification(self, workspace):
        pre = _hash_sentinel_files(workspace, ["SOUL.md"])
        (workspace / "SOUL.md").write_text("HIJACKED IDENTITY\n")
        tampered = _check_sentinels(workspace, ["SOUL.md"], pre)
        assert len(tampered) == 1
        assert tampered[0]["status"] == "MODIFIED"
        assert tampered[0]["file"] == "SOUL.md"

    def test_detects_deletion(self, workspace):
        pre = _hash_sentinel_files(workspace, ["SOUL.md"])
        (workspace / "SOUL.md").unlink()
        tampered = _check_sentinels(workspace, ["SOUL.md"], pre)
        assert len(tampered) == 1
        assert tampered[0]["status"] == "DELETED"

    def test_detects_creation(self, workspace):
        pre = _hash_sentinel_files(workspace, ["new_skill.md"])
        assert pre["new_skill.md"] == "MISSING"
        (workspace / "new_skill.md").write_text("malicious skill\n")
        tampered = _check_sentinels(workspace, ["new_skill.md"], pre)
        assert len(tampered) == 1
        assert tampered[0]["status"] == "CREATED"

    def test_no_change_clean(self, workspace):
        pre = _hash_sentinel_files(workspace, ["SOUL.md", "HEARTBEAT.md"])
        tampered = _check_sentinels(workspace, ["SOUL.md", "HEARTBEAT.md"], pre)
        assert len(tampered) == 0


class TestHeartbeat:
    def test_heartbeat_writes_file(self, workspace):
        _start_heartbeat(workspace)
        import time
        time.sleep(1)
        hb = workspace / HEARTBEAT_FILE
        assert hb.exists()
        data = json.loads(hb.read_text())
        assert "pid" in data
        assert "ts" in data
        assert data["interval_s"] == 5
        _stop_heartbeat(workspace)
        assert not hb.exists()

    def test_stop_removes_file(self, workspace):
        _start_heartbeat(workspace)
        import time
        time.sleep(0.5)
        _stop_heartbeat(workspace)
        assert not (workspace / HEARTBEAT_FILE).exists()

    def test_stop_on_missing_file(self, workspace):
        _stop_heartbeat(workspace)


class TestCostCheck:
    def test_no_overspend(self, workspace):
        (workspace / "trace.jsonl").write_text(json.dumps({
            "model": "gpt-4o-mini",
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        }) + "\n")
        result = _check_token_cost(workspace, max_cost=10.0)
        assert result is not None
        assert result["exceeded"] is False
        assert result["total_cost_usd"] < 10.0
        assert result["cost_mode"] == "estimated"

    def test_overspend_detected(self, workspace):
        lines = []
        for i in range(50):
            lines.append(json.dumps({
                "model": "gpt-4",
                "usage": {"prompt_tokens": 100000, "completion_tokens": 50000},
            }))
        (workspace / "heavy.jsonl").write_text("\n".join(lines) + "\n")
        result = _check_token_cost(workspace, max_cost=0.01)
        assert result is not None
        assert result["exceeded"] is True
        assert result["total_cost_usd"] > 0.01
        assert result["cost_mode"] == "estimated"

    def test_no_logs_returns_under_budget(self, tmp_path):
        ws = tmp_path / "empty"
        ws.mkdir()
        result = _check_token_cost(ws, max_cost=5.0)
        if result is not None:
            assert result["exceeded"] is False
            assert result["total_cost_usd"] == 0.0
            assert result["cost_mode"] == "unavailable"

    def test_prefers_exact_billed_cost_when_present(self, workspace):
        (workspace / "trace.jsonl").write_text(json.dumps({
            "model": "gpt-4o",
            "provider": "openai",
            "cost_usd": 2.5,
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        }) + "\n")
        result = _check_token_cost(workspace, max_cost=1.0)
        assert result is not None
        assert result["exceeded"] is True
        assert result["total_cost_usd"] == 2.5
        assert result["cost_mode"] == "exact"
        assert result["exact_entries"] == 1
        assert result["estimated_entries"] == 0

    def test_ignores_internal_liquefy_ledgers(self, workspace):
        ledger_dir = workspace / ".liquefy-tokens"
        ledger_dir.mkdir()
        (ledger_dir / "ledger.jsonl").write_text(json.dumps({
            "model": "gpt-4",
            "input_tokens": 500000,
            "output_tokens": 500000,
            "total_tokens": 1000000,
            "entry_fingerprint": "legacy-ledger-entry",
        }) + "\n", encoding="utf-8")
        result = _check_token_cost(workspace, max_cost=0.01)
        assert result is not None
        assert result["total_cost_usd"] == 0.0
        assert result["total_tokens"] == 0
        assert result["cost_mode"] == "unavailable"


class TestContextPrime:
    def test_prime_context_installs_bootstrap(self, workspace):
        (workspace / "trace.jsonl").write_text(json.dumps({
            "model": "gpt-4o-mini",
            "usage": {"prompt_tokens": 300, "completion_tokens": 60, "total_tokens": 360},
            "messages": [{"role": "user", "content": "compress this"}],
        }) + "\n", encoding="utf-8")

        result = _prime_context_for_run(workspace)
        assert result["ok"] is True
        assert Path(result["bootstrap_file"]).exists()
        assert Path(result["capsule_json"]).exists()
        assert result["scoreboard"]["summary"]["unique_runs"] == 1

    def test_safe_run_exports_capsule_env(self, workspace):
        (workspace / "trace.jsonl").write_text(json.dumps({
            "model": "gpt-4o-mini",
            "usage": {"prompt_tokens": 300, "completion_tokens": 60, "total_tokens": 360},
            "messages": [{"role": "user", "content": "compress this"}],
        }) + "\n", encoding="utf-8")

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
                str(REPO_ROOT / 'tools' / 'liquefy_safe_run.py'),
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
        result = json.loads(proc.stdout)
        assert result["ok"] is True
        assert result["phases"]["prime_context"]["ok"] is True
        assert result["phases"]["capsule_state"]["status"] == "fresh"
        assert result["phases"]["context_gate"]["ok"] is True
        assert result["phases"]["context_gate"]["blocked"] is False
        payload = json.loads(payload_file.read_text(encoding="utf-8"))
        assert payload["LIQUEFY_CONTEXT_BOOTSTRAP_FILE"]
        assert Path(payload["LIQUEFY_CONTEXT_BOOTSTRAP_FILE"]).exists()
        assert Path(payload["LIQUEFY_CONTEXT_GATE_FILE"]).exists()

    def test_safe_run_blocks_exact_replay_before_execute(self, workspace):
        (workspace / "trace.jsonl").write_text(json.dumps({
            "model": "gpt-4o-mini",
            "usage": {"prompt_tokens": 300, "completion_tokens": 60, "total_tokens": 360},
            "messages": [{"role": "user", "content": "compress this"}],
        }) + "\n", encoding="utf-8")

        cmd = [
            sys.executable,
            str(REPO_ROOT / 'tools' / 'liquefy_safe_run.py'),
            "--workspace",
            str(workspace),
            "--cmd",
            f"{shlex.quote(sys.executable)} -c {shlex.quote('print(123)')}",
            "--block-replay",
            "--json",
        ]
        first = subprocess.run(cmd, capture_output=True, text=True, check=False)
        second = subprocess.run(cmd, capture_output=True, text=True, check=False)
        first_payload = json.loads(first.stdout)
        second_payload = json.loads(second.stdout)

        assert first.returncode == 0, first.stderr
        assert first_payload["phases"]["context_gate"]["blocked"] is False
        assert second.returncode == 1
        assert second_payload["blocked"] is True
        assert second_payload["block_reason"] == "exact_replay_detected"
        assert second_payload["phases"]["execute"] is None


class TestFileSha256:
    def test_deterministic(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world\n")
        h1 = _file_sha256(f)
        h2 = _file_sha256(f)
        assert h1 == h2
        assert len(h1) == 64

    def test_different_content(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        a.write_text("aaa\n")
        b.write_text("bbb\n")
        assert _file_sha256(a) != _file_sha256(b)
