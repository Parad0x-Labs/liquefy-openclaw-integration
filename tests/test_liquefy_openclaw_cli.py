#!/usr/bin/env python3
"""Tests for the integration-friendly OpenClaw wrapper helpers."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

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
