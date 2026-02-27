"""Tests for liquefy_state_guard.py — persistent state protection."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

from liquefy_state_guard import (
    _discover_state_files,
    _file_sha256,
    _hash_state,
    _load_manifest,
    _save_manifest,
    cmd_check,
    cmd_checkpoint,
    cmd_init,
    cmd_recover,
    cmd_status,
    MANIFEST_NAME,
    CHECKPOINT_DIR,
)


def _ns(**kw):
    """Quick argparse.Namespace stand-in."""
    from types import SimpleNamespace
    defaults = {"json": False, "files": None, "strict": False, "max_stale": None}
    defaults.update(kw)
    return SimpleNamespace(**defaults)


class TestDiscoverStateFiles:
    def test_finds_known_patterns(self, tmp_path):
        (tmp_path / "wallet-state.json").write_text("{}")
        (tmp_path / "trade-history.jsonl").write_text("")
        (tmp_path / "random.txt").write_text("x")
        found = _discover_state_files(tmp_path)
        assert "wallet-state.json" in found
        assert "trade-history.jsonl" in found
        assert "random.txt" not in found

    def test_finds_custom_state_pattern(self, tmp_path):
        (tmp_path / "portfolio-state.json").write_text("{}")
        found = _discover_state_files(tmp_path)
        assert "portfolio-state.json" in found

    def test_empty_workspace(self, tmp_path):
        assert _discover_state_files(tmp_path) == []


class TestInit:
    def test_basic_init(self, tmp_path, capsys):
        (tmp_path / "wallet-state.json").write_text('{"sol": 1.5}')
        rc = cmd_init(_ns(workspace=str(tmp_path)))
        assert rc == 0
        mf = tmp_path / MANIFEST_NAME
        assert mf.exists()
        data = json.loads(mf.read_text())
        assert "wallet-state.json" in data["critical_files"]
        assert data["last_checkpoint"]["wallet-state.json"]["exists"]

    def test_init_json_output(self, tmp_path, capsys):
        (tmp_path / "balances.json").write_text("{}")
        rc = cmd_init(_ns(workspace=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["ok"]
        assert out["result"]["files_present"] >= 1

    def test_init_with_extra_files(self, tmp_path, capsys):
        rc = cmd_init(_ns(workspace=str(tmp_path), files=["custom-ledger.json"]))
        assert rc == 0
        mf = json.loads((tmp_path / MANIFEST_NAME).read_text())
        assert "custom-ledger.json" in mf["critical_files"]

    def test_init_missing_workspace(self, tmp_path, capsys):
        rc = cmd_init(_ns(workspace=str(tmp_path / "nonexistent"), json=True))
        assert rc == 1
        out = json.loads(capsys.readouterr().out)
        assert not out["ok"]

    def test_strict_mode(self, tmp_path, capsys):
        rc = cmd_init(_ns(workspace=str(tmp_path), strict=True, files=["wallet-state.json"]))
        assert rc == 0
        mf = json.loads((tmp_path / MANIFEST_NAME).read_text())
        assert mf["policy"]["require_all_present"] is True
        assert mf["policy"]["block_on_drift"] is True


class TestCheck:
    def _setup_workspace(self, tmp_path):
        (tmp_path / "wallet-state.json").write_text('{"sol": 10}')
        cmd_init(_ns(workspace=str(tmp_path)))

    def test_healthy_check(self, tmp_path, capsys):
        self._setup_workspace(tmp_path)
        rc = cmd_check(_ns(workspace=str(tmp_path)))
        assert rc == 0

    def test_healthy_check_json(self, tmp_path, capsys):
        self._setup_workspace(tmp_path)
        capsys.readouterr()
        rc = cmd_check(_ns(workspace=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["ok"]
        assert out["result"]["policy_verdict"] == "PASS"

    def test_missing_file_detected(self, tmp_path, capsys):
        self._setup_workspace(tmp_path)
        (tmp_path / "wallet-state.json").unlink()
        capsys.readouterr()
        rc = cmd_check(_ns(workspace=str(tmp_path), json=True))
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["critical_missing"] == 1

    def test_strict_blocks_on_missing(self, tmp_path, capsys):
        (tmp_path / "wallet-state.json").write_text("{}")
        cmd_init(_ns(workspace=str(tmp_path), strict=True))
        (tmp_path / "wallet-state.json").unlink()
        capsys.readouterr()
        rc = cmd_check(_ns(workspace=str(tmp_path), json=True))
        assert rc == 1
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["policy_verdict"] == "BLOCK"

    def test_drift_detected(self, tmp_path, capsys):
        self._setup_workspace(tmp_path)
        (tmp_path / "wallet-state.json").write_text('{"sol": 0}')
        capsys.readouterr()
        rc = cmd_check(_ns(workspace=str(tmp_path), json=True))
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["drifted"] == 1

    def test_strict_blocks_on_drift(self, tmp_path, capsys):
        (tmp_path / "wallet-state.json").write_text('{"sol": 10}')
        cmd_init(_ns(workspace=str(tmp_path), strict=True))
        (tmp_path / "wallet-state.json").write_text('{"sol": 0}')
        capsys.readouterr()
        rc = cmd_check(_ns(workspace=str(tmp_path), json=True))
        assert rc == 1
        out = json.loads(capsys.readouterr().out)
        assert out["result"]["policy_verdict"] == "BLOCK"

    def test_no_manifest_error(self, tmp_path, capsys):
        rc = cmd_check(_ns(workspace=str(tmp_path), json=True))
        assert rc == 1


class TestCheckpoint:
    def test_creates_backup(self, tmp_path, capsys):
        (tmp_path / "wallet-state.json").write_text('{"sol": 5}')
        cmd_init(_ns(workspace=str(tmp_path)))
        capsys.readouterr()
        rc = cmd_checkpoint(_ns(workspace=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert len(out["result"]["files_backed_up"]) == 1
        cp_dir = tmp_path / CHECKPOINT_DIR
        assert cp_dir.exists()
        cps = list(cp_dir.iterdir())
        assert len(cps) == 1
        assert (cps[0] / "wallet-state.json").exists()

    def test_updates_manifest_hashes(self, tmp_path, capsys):
        (tmp_path / "wallet-state.json").write_text('{"sol": 5}')
        cmd_init(_ns(workspace=str(tmp_path)))
        (tmp_path / "wallet-state.json").write_text('{"sol": 99}')
        cmd_checkpoint(_ns(workspace=str(tmp_path)))
        mf = json.loads((tmp_path / MANIFEST_NAME).read_text())
        stored_hash = mf["last_checkpoint"]["wallet-state.json"]["sha256"]
        assert stored_hash == _file_sha256(tmp_path / "wallet-state.json")


class TestRecover:
    def test_restores_from_checkpoint(self, tmp_path, capsys):
        (tmp_path / "wallet-state.json").write_text('{"sol": 100}')
        cmd_init(_ns(workspace=str(tmp_path)))
        cmd_checkpoint(_ns(workspace=str(tmp_path)))
        original_hash = _file_sha256(tmp_path / "wallet-state.json")

        (tmp_path / "wallet-state.json").write_text('{"sol": 0}')
        assert _file_sha256(tmp_path / "wallet-state.json") != original_hash

        capsys.readouterr()
        rc = cmd_recover(_ns(workspace=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert "wallet-state.json" in out["result"]["restored"]
        assert _file_sha256(tmp_path / "wallet-state.json") == original_hash

    def test_recover_no_checkpoint(self, tmp_path, capsys):
        (tmp_path / "wallet-state.json").write_text("{}")
        cmd_init(_ns(workspace=str(tmp_path)))
        rc = cmd_recover(_ns(workspace=str(tmp_path), json=True))
        assert rc == 1

    def test_recover_missing_file_in_checkpoint(self, tmp_path, capsys):
        cmd_init(_ns(workspace=str(tmp_path), files=["missing.json"]))
        cmd_checkpoint(_ns(workspace=str(tmp_path)))
        capsys.readouterr()
        rc = cmd_recover(_ns(workspace=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert "missing.json" in out["result"]["skipped"]


class TestStatus:
    def test_status_output(self, tmp_path, capsys):
        (tmp_path / "wallet-state.json").write_text("{}")
        cmd_init(_ns(workspace=str(tmp_path)))
        capsys.readouterr()
        rc = cmd_status(_ns(workspace=str(tmp_path), json=True))
        assert rc == 0
        out = json.loads(capsys.readouterr().out)
        assert out["ok"]
        assert len(out["result"]["files"]) >= 1

    def test_status_no_manifest(self, tmp_path, capsys):
        rc = cmd_status(_ns(workspace=str(tmp_path), json=True))
        assert rc == 1


class TestFullLifecycle:
    """End-to-end: init -> check -> modify -> detect drift -> checkpoint -> corrupt -> recover."""

    def test_lobster_scenario(self, tmp_path, capsys):
        wallet = tmp_path / "wallet-state.json"
        wallet.write_text('{"sol": 2.5, "tokens": {"LOBSTER": 52000000, "value_usd": 450000}}')

        cmd_init(_ns(workspace=str(tmp_path), strict=True))
        cmd_checkpoint(_ns(workspace=str(tmp_path)))

        capsys.readouterr()
        rc = cmd_check(_ns(workspace=str(tmp_path), json=True))
        assert rc == 0
        check_out = json.loads(capsys.readouterr().out)
        assert check_out["result"]["policy_verdict"] == "PASS"

        wallet.write_text('{"sol": 2.5, "tokens": {"LOBSTER": 0, "value_usd": 0}}')

        capsys.readouterr()
        rc = cmd_check(_ns(workspace=str(tmp_path), json=True))
        assert rc == 1
        check_out = json.loads(capsys.readouterr().out)
        assert check_out["result"]["policy_verdict"] == "BLOCK"
        assert check_out["result"]["drifted"] == 1

        capsys.readouterr()
        rc = cmd_recover(_ns(workspace=str(tmp_path), json=True))
        assert rc == 0
        restored = json.loads(wallet.read_text())
        assert restored["tokens"]["LOBSTER"] == 52000000
        assert restored["tokens"]["value_usd"] == 450000
