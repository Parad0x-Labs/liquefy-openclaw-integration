"""Tests for liquefy_policy_enforcer.py — active policy enforcement."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "api"))

from liquefy_policy_enforcer import (
    _scan_secrets,
    _scan_directory,
    _write_kill_signal,
    cmd_audit,
    cmd_enforce,
    cmd_kill,
    SCHEMA,
)


class _Args:
    def __init__(self, **kwargs):
        self.json = True
        self.dir = ""
        self.policy = None
        self.signal = None
        self.pid = None
        for k, v in kwargs.items():
            setattr(self, k, v)


@pytest.fixture
def clean_dir(tmp_path):
    d = tmp_path / "agent-output"
    d.mkdir()
    (d / "trace.jsonl").write_text('{"event": "compress", "result": "ok"}\n')
    (d / "config.yaml").write_text("model: gpt-4o\ntemp: 0.7\n")
    return d


@pytest.fixture
def dirty_dir(tmp_path):
    d = tmp_path / "agent-output"
    d.mkdir()
    (d / "trace.jsonl").write_text('{"event": "ok"}\n')
    (d / "leaked.env").write_text("API_KEY=sk-proj-abc123def456ghi789jkl012mno\nDATABASE_URL=postgres://user:pass@host/db\n")
    (d / "malware.exe").write_bytes(b"\x00" * 100)
    (d / "config.yaml").write_text("model: gpt-4o\n")
    return d


class TestScanSecrets:
    def test_detects_api_key(self, tmp_path):
        f = tmp_path / "leak.env"
        f.write_text("API_KEY=sk-proj-abc123def456ghi789jkl012mno345pqr\n")
        hits = _scan_secrets(f)
        assert len(hits) >= 1
        assert hits[0]["type"] == "secret_leak"
        assert hits[0]["severity"] == "critical"

    def test_detects_github_token(self, tmp_path):
        f = tmp_path / "config.json"
        f.write_text('{"token": "ghp_abc123def456ghi789jkl012mno345pqr678"}\n')
        hits = _scan_secrets(f)
        assert len(hits) >= 1

    def test_detects_private_key(self, tmp_path):
        f = tmp_path / "key.pem"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----\n")
        hits = _scan_secrets(f)
        assert len(hits) >= 1

    def test_detects_aws_key(self, tmp_path):
        f = tmp_path / "creds.txt"
        f.write_text("access_key=AKIAIOSFODNN7EXAMPLE\n")
        hits = _scan_secrets(f)
        assert len(hits) >= 1

    def test_clean_file_no_hits(self, tmp_path):
        f = tmp_path / "clean.json"
        f.write_text('{"name": "test", "value": 42}\n')
        hits = _scan_secrets(f)
        assert len(hits) == 0


class TestScanDirectory:
    def test_clean_dir(self, clean_dir):
        violations = _scan_directory(clean_dir)
        critical = [v for v in violations if v["severity"] == "critical"]
        assert len(critical) == 0

    def test_detects_secrets(self, dirty_dir):
        violations = _scan_directory(dirty_dir)
        secret_hits = [v for v in violations if v["type"] == "secret_leak"]
        assert len(secret_hits) >= 1

    def test_detects_forbidden_ext(self, dirty_dir):
        violations = _scan_directory(dirty_dir)
        ext_hits = [v for v in violations if v["type"] == "forbidden_ext"]
        assert len(ext_hits) >= 1
        assert ext_hits[0]["extension"] == ".exe"

    def test_detects_oversized(self, tmp_path):
        d = tmp_path / "big"
        d.mkdir()
        (d / "huge.json").write_bytes(b"x" * (51 * 1024 * 1024))
        violations = _scan_directory(d)
        oversized = [v for v in violations if v["type"] == "oversized"]
        assert len(oversized) >= 1

    def test_custom_policy_size(self, tmp_path):
        d = tmp_path / "data"
        d.mkdir()
        (d / "medium.json").write_bytes(b"x" * 5000)
        violations = _scan_directory(d, policy={"max_file_size": 1000})
        oversized = [v for v in violations if v["type"] == "oversized"]
        assert len(oversized) >= 1

    def test_skips_git_dir(self, tmp_path):
        d = tmp_path / "project"
        d.mkdir()
        git = d / ".git"
        git.mkdir()
        (git / "secret.env").write_text("API_KEY=sk-super-secret-key-1234567890abcdef\n")
        (d / "clean.json").write_text("{}\n")
        violations = _scan_directory(d)
        assert all(".git" not in v.get("file", "") for v in violations)


class TestCmdAudit:
    def test_clean_passes(self, clean_dir, capsys):
        args = _Args(dir=str(clean_dir))
        ret = cmd_audit(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["ok"] is True

    def test_dirty_reports(self, dirty_dir, capsys):
        args = _Args(dir=str(dirty_dir))
        ret = cmd_audit(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["violations"] > 0


class TestCmdEnforce:
    def test_clean_allows(self, clean_dir, capsys):
        args = _Args(dir=str(clean_dir))
        ret = cmd_enforce(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["action"] == "ALLOWED"

    def test_dirty_blocks(self, dirty_dir, capsys):
        args = _Args(dir=str(dirty_dir))
        ret = cmd_enforce(args)
        assert ret == 1
        output = json.loads(capsys.readouterr().out.strip())
        assert output["action"] == "BLOCKED"


class TestCmdKill:
    def test_no_critical_no_action(self, clean_dir, capsys):
        args = _Args(dir=str(clean_dir))
        ret = cmd_kill(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["action"] == "NO_ACTION"

    def test_critical_writes_signal(self, dirty_dir, capsys):
        signal_file = dirty_dir / "test.halt"
        args = _Args(dir=str(dirty_dir), signal=str(signal_file))
        ret = cmd_kill(args)
        assert ret == 1
        assert signal_file.exists()
        signal_data = json.loads(signal_file.read_text())
        assert signal_data["action"] == "HALT"
        assert signal_data["violation_count"] > 0


class TestWriteKillSignal:
    def test_creates_signal_file(self, tmp_path):
        sig = tmp_path / "halt.json"
        violations = [{"type": "secret_leak", "severity": "critical", "message": "test"}]
        data = _write_kill_signal(sig, violations)
        assert sig.exists()
        assert data["action"] == "HALT"
        assert data["schema"] == SCHEMA

    def test_includes_trace_id(self, tmp_path):
        sig = tmp_path / "halt.json"
        violations = [{"type": "secret_leak", "severity": "critical", "message": "test"}]
        data = _write_kill_signal(sig, violations, trace_id="agent-researcher-7f3a")
        assert data["trace_id"] == "agent-researcher-7f3a"

    def test_omits_trace_id_when_none(self, tmp_path):
        sig = tmp_path / "halt.json"
        violations = [{"type": "secret_leak", "severity": "critical", "message": "test"}]
        data = _write_kill_signal(sig, violations)
        assert "trace_id" not in data


class TestTraceId:
    def test_audit_includes_trace_id(self, clean_dir, capsys):
        args = _Args(dir=str(clean_dir), trace_id="swarm-task-42")
        ret = cmd_audit(args)
        assert ret == 0
        output = json.loads(capsys.readouterr().out.strip())
        assert output["trace_id"] == "swarm-task-42"

    def test_audit_omits_trace_id_when_absent(self, clean_dir, capsys):
        args = _Args(dir=str(clean_dir))
        ret = cmd_audit(args)
        output = json.loads(capsys.readouterr().out.strip())
        assert "trace_id" not in output

    def test_enforce_includes_trace_id(self, dirty_dir, capsys):
        args = _Args(dir=str(dirty_dir), trace_id="researcher-to-executor-9b")
        ret = cmd_enforce(args)
        output = json.loads(capsys.readouterr().out.strip())
        assert output["trace_id"] == "researcher-to-executor-9b"

    def test_kill_signal_file_has_trace_id(self, dirty_dir, capsys):
        signal_file = dirty_dir / "test.halt"
        args = _Args(dir=str(dirty_dir), signal=str(signal_file), trace_id="chain-abc-123")
        cmd_kill(args)
        signal_data = json.loads(signal_file.read_text())
        assert signal_data["trace_id"] == "chain-abc-123"
