#!/usr/bin/env python3
"""Tests for tools/vault_evidence.py -- unified FIRC + TERS verification."""
from pathlib import Path
import sys
import json
import hashlib

import pytest  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import firc  # type: ignore  # noqa: E402
import ters  # type: ignore  # noqa: E402
import vault_evidence as ve  # type: ignore  # noqa: E402

MASTER = b"unit-test-master-secret-bytes-000"
SESSION = "sess-ve-1"


def _rx(i):
    return hashlib.sha256(("rx-%d" % i).encode()).digest()


def _chain(n):
    c = firc.FIRCChain.from_master(MASTER, SESSION)
    leaves = []
    for i in range(n):
        leaf = ("leaf-%d" % i).encode()
        leaves.append(leaf)
        c.append(leaf, receipt_hash=_rx(i))
    return c, leaves


# ---- library ----

def test_anchor_then_verify_roundtrip():
    c, leaves = _chain(4)
    a = ve.anchor_values(MASTER, SESSION, c.entries)
    res = ve.verify_evidence(
        MASTER, SESSION, c.entries, leaves=leaves,
        firc_head=a["firc_head"], ters_seal=a["ters_seal"],
        settlements=[_rx(i).hex() for i in range(4)],
    )
    assert res["ok"] is True
    assert res["failed"] == []
    assert res["firc"]["ok"] is True and res["ters"]["ok"] is True


def test_firc_only_when_no_seal():
    c, _ = _chain(3)
    res = ve.verify_evidence(MASTER, SESSION, c.entries)
    assert res["ok"] is True
    assert res["checks"] == ["firc.verify_chain"]
    assert res["ters"] is None


def test_detects_firc_leaf_tamper():
    c, leaves = _chain(4)
    a = ve.anchor_values(MASTER, SESSION, c.entries)
    leaves[2] = b"TAMPERED"
    res = ve.verify_evidence(
        MASTER, SESSION, c.entries, leaves=leaves,
        firc_head=a["firc_head"], ters_seal=a["ters_seal"],
    )
    assert res["ok"] is False
    assert "firc" in res["failed"]


def test_detects_truncation_via_ters():
    c, _ = _chain(5)
    a = ve.anchor_values(MASTER, SESSION, c.entries)
    res = ve.verify_evidence(
        MASTER, SESSION, list(c.entries[:3]),
        firc_head=a["firc_head"], ters_seal=a["ters_seal"],
    )
    assert res["ok"] is False
    assert "ters" in res["failed"]


def test_detects_omission_via_ters():
    c, _ = _chain(3)
    a = ve.anchor_values(MASTER, SESSION, c.entries)
    settled = [_rx(i).hex() for i in range(3)] + [hashlib.sha256(b"ghost").hexdigest()]
    res = ve.verify_evidence(
        MASTER, SESSION, c.entries,
        firc_head=a["firc_head"], ters_seal=a["ters_seal"], settlements=settled,
    )
    assert res["ok"] is False
    assert "ters" in res["failed"]


# ---- CLI ----

def _write_bundle(tmp_path, c, leaves=None, settlements=None, with_anchors=True):
    a = ve.anchor_values(MASTER, SESSION, c.entries)
    bundle = {"session_id": SESSION, "entries": c.entries}
    if with_anchors:
        bundle["firc_head"] = a["firc_head"]
        bundle["ters_seal"] = a["ters_seal"]
    if leaves is not None:
        bundle["leaves"] = [b.hex() for b in leaves]
    if settlements is not None:
        bundle["settlements"] = settlements
    p = tmp_path / "bundle.json"
    p.write_text(json.dumps(bundle), encoding="utf-8")
    return p


def test_cli_verify_ok(tmp_path, capsys):
    c, leaves = _chain(3)
    p = _write_bundle(tmp_path, c, leaves=leaves, settlements=[_rx(i).hex() for i in range(3)])
    rc = ve.main(["verify", "--bundle", str(p), "--key-hex", MASTER.hex()])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"ok": true' in out


def test_cli_verify_detects_tamper(tmp_path, capsys):
    c, _ = _chain(4)
    p = _write_bundle(tmp_path, c)
    b = json.loads(p.read_text())
    b["entries"][2]["entry_digest"] = "a" * 64
    p.write_text(json.dumps(b), encoding="utf-8")
    rc = ve.main(["verify", "--bundle", str(p), "--key-hex", MASTER.hex()])
    assert rc == 2


def test_cli_anchor(tmp_path, capsys):
    c, _ = _chain(2)
    p = _write_bundle(tmp_path, c, with_anchors=False)
    rc = ve.main(["anchor", "--bundle", str(p), "--key-hex", MASTER.hex()])
    out = capsys.readouterr().out
    assert rc == 0
    assert "firc_head" in out and "ters_seal" in out


def test_cli_missing_key(tmp_path, capsys, monkeypatch):
    monkeypatch.delenv("VAULT_EVIDENCE_KEY", raising=False)
    c, _ = _chain(1)
    p = _write_bundle(tmp_path, c)
    rc = ve.main(["verify", "--bundle", str(p)])
    out = capsys.readouterr().out
    assert rc == 2
    assert "NO_KEY" in out


def test_cli_bad_bundle_no_path_leak(tmp_path, capsys):
    p = tmp_path / "does-not-exist.json"
    rc = ve.main(["verify", "--bundle", str(p), "--key-hex", MASTER.hex()])
    out = capsys.readouterr().out
    assert rc == 2
    assert "BUNDLE_UNREADABLE" in out
    assert str(p) not in out  # error output must not leak the (private) path


def test_empty_chain_evidence_roundtrips():
    a = ve.anchor_values(MASTER, SESSION, [])
    res = ve.verify_evidence(MASTER, SESSION, [], firc_head=a["firc_head"], ters_seal=a["ters_seal"])
    assert res["ok"] is True
    assert res["anchored"] is True


def test_anchored_flag_reflects_inputs():
    c, _ = _chain(2)
    assert ve.verify_evidence(MASTER, SESSION, c.entries)["anchored"] is False
    a = ve.anchor_values(MASTER, SESSION, c.entries)
    assert ve.verify_evidence(MASTER, SESSION, c.entries, firc_head=a["firc_head"])["anchored"] is True
