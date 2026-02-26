"""Tests for liquefy_safe_run.py — automated rollback wrapper."""
from __future__ import annotations

import json
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
    SNAPSHOT_DIR_NAME,
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
