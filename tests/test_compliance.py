"""Tests for liquefy_compliance.py — compliance report generation."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "api"))

from liquefy_compliance import (
    _load_audit_chain,
    _verify_chain,
    _event_stats,
    _generate_html_report,
)


def _make_chain_entry(seq: int, event: str, prev_hash: str) -> dict:
    entry = {
        "seq": seq,
        "ts": f"2026-02-25T10:00:{seq:02d}.000000Z",
        "event": event,
        "prev_hash": prev_hash,
    }
    canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    entry["_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return entry


@pytest.fixture
def valid_chain():
    genesis = "0" * 64
    e1 = _make_chain_entry(0, "compress", genesis)
    e2 = _make_chain_entry(1, "verify", e1["_hash"])
    e3 = _make_chain_entry(2, "decompress", e2["_hash"])
    return [e1, e2, e3]


@pytest.fixture
def chain_dir(valid_chain, tmp_path):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir()
    chain_file = audit_dir / "chain.jsonl"
    with chain_file.open("w") as f:
        for entry in valid_chain:
            f.write(json.dumps(entry, sort_keys=True, separators=(",", ":")) + "\n")
    return tmp_path


class TestVerifyChain:
    def test_valid_chain(self, valid_chain):
        ok, issues = _verify_chain(valid_chain)
        assert ok is True
        assert len(issues) == 0

    def test_empty_chain(self):
        ok, issues = _verify_chain([])
        assert ok is True

    def test_tampered_chain(self, valid_chain):
        valid_chain[1]["event"] = "TAMPERED"
        ok, issues = _verify_chain(valid_chain)
        assert ok is False
        assert len(issues) > 0


class TestEventStats:
    def test_stats_counts(self, valid_chain):
        stats = _event_stats(valid_chain)
        assert stats["total_entries"] == 3
        assert stats["unique_events"] == 3
        assert stats["event_types"]["compress"] == 1
        assert stats["first_event"] is not None
        assert stats["last_event"] is not None


class TestLoadChain:
    def test_load_from_dir(self, chain_dir, valid_chain):
        entries = _load_audit_chain(chain_dir)
        assert len(entries) == 3
        assert entries[0]["event"] == "compress"

    def test_missing_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path / "fakehome")
        entries = _load_audit_chain(tmp_path / "nonexistent")
        assert len(entries) == 0


class TestHTMLReport:
    def test_generates_html(self, valid_chain):
        ok, issues = _verify_chain(valid_chain)
        stats = _event_stats(valid_chain)
        html = _generate_html_report(valid_chain, ok, issues, stats, "TestOrg", "Test Report", "/tmp/vault")
        assert "<!DOCTYPE html>" in html
        assert "Test Report" in html
        assert "TestOrg" in html
        assert "CHAIN INTACT" in html

    def test_failing_chain_html(self, valid_chain):
        valid_chain[1]["_hash"] = "tampered"
        ok, issues = _verify_chain(valid_chain)
        stats = _event_stats(valid_chain)
        html = _generate_html_report(valid_chain, ok, issues, stats, "Org", "Fail", "/tmp")
        assert "CHAIN BROKEN" in html
