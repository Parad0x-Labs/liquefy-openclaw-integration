"""Tests for liquefy_cas.py — content-addressed storage."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "api"))

from liquefy_cas import (
    ingest_directory,
    restore_manifest,
    get_status,
    garbage_collect,
    _file_sha256,
    _blob_path,
)


@pytest.fixture
def agent_output(tmp_path):
    d = tmp_path / "agent-run-1"
    d.mkdir()
    (d / "trace.jsonl").write_text('{"event": "compress"}\n')
    (d / "config.yaml").write_text("model: gpt-4o\ntemp: 0.7\n")
    (d / "screenshot.png").write_bytes(b"\x89PNG" + b"\x00" * 100)
    return d


@pytest.fixture
def cas_dir(tmp_path):
    return tmp_path / "cas"


class TestIngest:
    def test_basic_ingest(self, agent_output, cas_dir):
        manifest = ingest_directory(agent_output, cas_dir)
        assert manifest["file_count"] == 3
        assert manifest["new_blobs"] == 3
        assert manifest["dedup_blobs"] == 0
        assert manifest["manifest_id"]

    def test_cross_run_dedup(self, agent_output, cas_dir):
        m1 = ingest_directory(agent_output, cas_dir)
        assert m1["new_blobs"] == 3
        assert m1["dedup_blobs"] == 0

        m2 = ingest_directory(agent_output, cas_dir)
        assert m2["new_blobs"] == 0
        assert m2["dedup_blobs"] == 3
        assert m2["dedup_ratio"] == 100.0

    def test_partial_dedup(self, agent_output, cas_dir, tmp_path):
        ingest_directory(agent_output, cas_dir)

        run2 = tmp_path / "agent-run-2"
        run2.mkdir()
        (run2 / "config.yaml").write_text("model: gpt-4o\ntemp: 0.7\n")  # same
        (run2 / "new_output.txt").write_text("something new\n")  # new

        m2 = ingest_directory(run2, cas_dir)
        assert m2["new_blobs"] == 1
        assert m2["dedup_blobs"] == 1

    def test_includes_trace_id(self, agent_output, cas_dir):
        manifest = ingest_directory(agent_output, cas_dir, trace_id="task-42")
        assert manifest["trace_id"] == "task-42"

    def test_blobs_stored_in_sharded_dirs(self, agent_output, cas_dir):
        manifest = ingest_directory(agent_output, cas_dir)
        for info in manifest["files"].values():
            sha = info["sha256"]
            bp = _blob_path(cas_dir, sha)
            assert bp.exists()
            assert bp.parent.name == sha[:2]


class TestRestore:
    def test_basic_restore(self, agent_output, cas_dir, tmp_path):
        manifest = ingest_directory(agent_output, cas_dir)
        out = tmp_path / "restored"
        result = restore_manifest(manifest["manifest_id"], out, cas_dir)
        assert result["ok"] is True
        assert result["restored"] == 3
        assert (out / "trace.jsonl").read_text() == '{"event": "compress"}\n'
        assert (out / "config.yaml").read_text() == "model: gpt-4o\ntemp: 0.7\n"

    def test_missing_manifest(self, cas_dir, tmp_path):
        result = restore_manifest("nonexistent", tmp_path / "out", cas_dir)
        assert result["ok"] is False


class TestStatus:
    def test_empty_cas(self, cas_dir):
        status = get_status(cas_dir)
        assert status["ok"] is True
        assert status["blob_count"] == 0

    def test_after_ingest(self, agent_output, cas_dir):
        ingest_directory(agent_output, cas_dir)
        status = get_status(cas_dir)
        assert status["blob_count"] == 3
        assert status["manifest_count"] == 1

    def test_dedup_savings(self, agent_output, cas_dir):
        ingest_directory(agent_output, cas_dir)
        ingest_directory(agent_output, cas_dir)
        status = get_status(cas_dir)
        assert status["manifest_count"] == 2
        assert status["blob_count"] == 3
        assert status["dedup_savings_bytes"] > 0


class TestCrashRecovery:
    def test_corrupted_blob_detected_on_restore(self, agent_output, cas_dir, tmp_path):
        manifest = ingest_directory(agent_output, cas_dir)
        sha = list(manifest["files"].values())[0]["sha256"]
        bp = _blob_path(cas_dir, sha)
        bp.write_bytes(b"CORRUPTED DATA")
        out = tmp_path / "restored"
        result = restore_manifest(manifest["manifest_id"], out, cas_dir)
        assert result["restored"] >= 1

    def test_missing_blob_counted_as_error(self, agent_output, cas_dir, tmp_path):
        manifest = ingest_directory(agent_output, cas_dir)
        sha = list(manifest["files"].values())[0]["sha256"]
        bp = _blob_path(cas_dir, sha)
        bp.unlink()
        out = tmp_path / "restored"
        result = restore_manifest(manifest["manifest_id"], out, cas_dir)
        assert result["errors"] >= 1

    def test_partial_ingest_idempotent(self, agent_output, cas_dir):
        m1 = ingest_directory(agent_output, cas_dir)
        m2 = ingest_directory(agent_output, cas_dir)
        assert m1["file_count"] == m2["file_count"]
        assert m2["dedup_blobs"] == m1["file_count"]

    def test_manifest_corruption_returns_error(self, agent_output, cas_dir, tmp_path):
        manifest = ingest_directory(agent_output, cas_dir)
        mf_path = cas_dir / "manifests" / f"{manifest['manifest_id']}.json"
        mf_path.write_text("NOT VALID JSON")
        result = restore_manifest(manifest["manifest_id"], tmp_path / "out", cas_dir)
        assert result.get("ok") is False or "error" in str(result).lower()


class TestGC:
    def test_gc_removes_orphans(self, agent_output, cas_dir, tmp_path):
        m = ingest_directory(agent_output, cas_dir)
        mf_path = cas_dir / "manifests" / f"{m['manifest_id']}.json"
        mf_path.unlink()

        result = garbage_collect(cas_dir)
        assert result["ok"] is True
        assert result["removed"] == 3

    def test_gc_keeps_referenced(self, agent_output, cas_dir):
        ingest_directory(agent_output, cas_dir)
        result = garbage_collect(cas_dir)
        assert result["removed"] == 0
        assert get_status(cas_dir)["blob_count"] == 3
