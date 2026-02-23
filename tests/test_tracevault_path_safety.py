#!/usr/bin/env python3
"""Path safety tests for TraceVault pack/restore wrappers."""
import os
import sys
from pathlib import Path

import pytest

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from tracevault_pack import scan_run_dir  # type: ignore
from tracevault_restore import safe_restore_target_path  # type: ignore


@pytest.mark.skipif(os.name == "nt", reason="symlink setup differs on Windows")
def test_tracevault_scan_skips_symlink_file(tmp_path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    outside = tmp_path / "outside_secret.txt"
    outside.write_text("secret", encoding="utf-8")
    (run_dir / "ok.log").write_text("hello", encoding="utf-8")
    (run_dir / "link.log").symlink_to(outside)

    scan = scan_run_dir(
        run_dir=run_dir,
        max_file_mb=0,
        chunk_mb=64,
        bigfile_threshold_mb=64,
    )

    skipped = {row["run_relpath"]: row["reason"] for row in scan.get("path_policy_skipped", [])}
    included = {row["run_relpath"] for row in scan.get("included", [])}
    assert "link.log" in skipped
    assert skipped["link.log"] == "symlink_file"
    assert "link.log" not in included
    assert "ok.log" in included


def test_safe_restore_target_path_rejects_traversal(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with pytest.raises(ValueError, match="traversal"):
        safe_restore_target_path(out_dir, "../pwned.txt")


def test_safe_restore_target_path_rejects_absolute(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    with pytest.raises(ValueError, match="absolute"):
        safe_restore_target_path(out_dir, "/tmp/pwned.txt")


@pytest.mark.skipif(os.name == "nt", reason="symlink behavior differs on Windows")
def test_safe_restore_target_path_rejects_symlink_escape(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (out_dir / "link").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="outside_output_dir"):
        safe_restore_target_path(out_dir, "link/escape.txt")
