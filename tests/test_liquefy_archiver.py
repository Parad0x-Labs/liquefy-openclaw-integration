"""tests/test_liquefy_archiver.py — offline coverage for the archiver core paths.

Covers candidate detection (age/keep-active logic), once-mode packing of an
aged subdirectory, and the status command with no daemon running.
"""
import contextlib
import io
import json
import os
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "api"))

import liquefy_archiver as A  # noqa: E402


def _make_tree(root: Path) -> Path:
    """watch/sessions/{old_batch,new_batch} with aged and fresh files."""
    sessions = root / "watch" / "sessions"
    old = sessions / "old_batch"
    new = sessions / "new_batch"
    old.mkdir(parents=True)
    new.mkdir(parents=True)
    for i in range(3):
        (old / f"old_{i}.jsonl").write_text("INFO request served 200\n" * 20)
        (new / f"new_{i}.jsonl").write_text("INFO request served 200\n" * 20)
    aged = time.time() - 30 * 86400
    os.utime(old, (aged, aged))
    return sessions


class TestFindCandidates:
    def test_age_and_keep_active(self, tmp_path):
        sessions = _make_tree(tmp_path)
        # keep_active=1 keeps the newest item (new_batch); old_batch is a candidate
        candidates = A._find_candidates(
            [sessions], size_threshold_bytes=1, age_threshold_days=7, keep_active=1
        )
        names = {c.path.name for c in candidates}
        assert "old_batch" in names
        assert "new_batch" not in names
        old_cand = next(c for c in candidates if c.path.name == "old_batch")
        assert "age" in old_cand.reason


@pytest.mark.skipif(os.name == "nt", reason="path layout assumptions differ on Windows")
class TestOnceMode:
    def test_once_packs_aged_dir(self, tmp_path, monkeypatch):
        _make_tree(tmp_path)
        out = tmp_path / "vault"
        monkeypatch.setenv("LIQUEFY_SECRET", "archiver-test-secret-0123456789")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = A.main([
                "once",
                "--watch", str(tmp_path / "watch"),
                "--subdirs", "sessions",
                "--out", str(out),
                "--age-days", "7",
                "--keep", "1",
                "--size-mb", "0.001",
                "--json",
            ])
        assert rc == 0
        payload = json.loads(buf.getvalue())
        assert payload.get("ok") is True
        assert payload["result"].get("archived", 0) >= 1
        assert any(out.iterdir()), "vault output dir should not be empty"

    def test_status_without_daemon(self, tmp_path):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = A.main(["status", "--json"])
        assert rc == 0
        payload = json.loads(buf.getvalue())
        assert payload["result"]["status"] == "not_running"
