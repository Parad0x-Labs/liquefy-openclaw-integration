#!/usr/bin/env python3
"""Tests for tools/ters.py -- Truncation-Evident Receipt Seal."""
from pathlib import Path
import sys
import hashlib

import pytest  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import firc  # type: ignore  # noqa: E402
import ters  # type: ignore  # noqa: E402

MASTER = b"unit-test-master-secret-bytes-000"
SESSION = "sess-ters-1"


def _rx(i):
    return hashlib.sha256(("rx-%d" % i).encode()).digest()


def _chain(n, receipts=True):
    c = firc.FIRCChain.from_master(MASTER, SESSION)
    for i in range(n):
        c.append(("leaf-%d" % i).encode(), receipt_hash=(_rx(i) if receipts else b""))
    return c


def test_seal_verify_roundtrip():
    c = _chain(5)
    s = ters.seal(MASTER, SESSION, c.entries)
    res = ters.verify_seal(MASTER, SESSION, c.entries, s)
    assert res["ok"] is True
    assert res["agg_ok"] and res["count_ok"] and res["settlement_root_ok"]


def test_detects_truncation_in_one_value():
    # Headline property: a single sealed value catches a dropped tail.
    c = _chain(5)
    s = ters.seal(MASTER, SESSION, c.entries)
    res = ters.verify_seal(MASTER, SESSION, list(c.entries[:4]), s)
    assert res["ok"] is False
    assert res["count_ok"] is False
    assert res["agg_ok"] is False


def test_detects_extension():
    c = _chain(3)
    s = ters.seal(MASTER, SESSION, c.entries)
    c.append(b"sneaky", receipt_hash=_rx(99))
    res = ters.verify_seal(MASTER, SESSION, c.entries, s)
    assert res["ok"] is False


def test_detects_entry_alteration():
    c = _chain(4)
    s = ters.seal(MASTER, SESSION, c.entries)
    c.entries[2]["entry_digest"] = "a" * 64
    res = ters.verify_seal(MASTER, SESSION, c.entries, s)
    assert res["ok"] is False
    assert res["agg_ok"] is False


def test_detects_reorder():
    c = _chain(4)
    s = ters.seal(MASTER, SESSION, c.entries)
    c.entries[1], c.entries[2] = c.entries[2], c.entries[1]
    res = ters.verify_seal(MASTER, SESSION, c.entries, s)
    assert res["ok"] is False


def test_settlement_reconcile_ok():
    c = _chain(4)
    s = ters.seal(MASTER, SESSION, c.entries)
    settled = [_rx(i).hex() for i in range(4)]
    res = ters.verify_seal(MASTER, SESSION, c.entries, s, settlements=settled)
    assert res["ok"] is True
    assert res["reconciled"] is True


def test_settlement_detects_omission():
    # A payment settled on-chain but never logged => omission surfaced.
    c = _chain(3)
    s = ters.seal(MASTER, SESSION, c.entries)
    settled = [_rx(i).hex() for i in range(3)] + [hashlib.sha256(b"ghost-payment").hexdigest()]
    res = ters.verify_seal(MASTER, SESSION, c.entries, s, settlements=settled)
    assert res["ok"] is False
    assert res["reconciled"] is False
    assert len(res["settled_but_unlogged"]) == 1


def test_settlement_detects_unsettled_log():
    c = _chain(3)
    s = ters.seal(MASTER, SESSION, c.entries)
    settled = [_rx(0).hex(), _rx(1).hex()]  # entry 2's receipt never settled
    res = ters.verify_seal(MASTER, SESSION, c.entries, s, settlements=settled)
    assert res["reconciled"] is False
    assert _rx(2).hex() in res["logged_but_unsettled"]


def test_wrong_master_fails():
    c = _chain(3)
    s = ters.seal(MASTER, SESSION, c.entries)
    res = ters.verify_seal(b"wrong-master-secret-bytes-0000000", SESSION, c.entries, s)
    assert res["ok"] is False
    assert res["agg_ok"] is False


def test_settlement_root_changes_with_receipts():
    c1 = _chain(3)
    s1 = ters.seal(MASTER, SESSION, c1.entries)
    c2 = firc.FIRCChain.from_master(MASTER, SESSION)
    for i in range(3):
        c2.append(("leaf-%d" % i).encode(), receipt_hash=hashlib.sha256(("other-%d" % i).encode()).digest())
    s2 = ters.seal(MASTER, SESSION, c2.entries)
    assert s1["settlement_root"] != s2["settlement_root"]


def test_empty_chain_seal_roundtrips():
    s = ters.seal(MASTER, SESSION, [])
    res = ters.verify_seal(MASTER, SESSION, [], s)
    assert res["ok"] is True
    assert res["count_ok"] is True


def test_verify_rejects_malformed_entry():
    # Hardening: a non-hex entry_digest must fail closed, not raise.
    c = _chain(3)
    s = ters.seal(MASTER, SESSION, c.entries)
    c.entries[1]["entry_digest"] = "not-hex-zz"
    res = ters.verify_seal(MASTER, SESSION, c.entries, s)
    assert res["ok"] is False
    assert res.get("malformed") is True


def test_verify_handles_bad_anchored_count():
    # Hardening: a garbage anchored count must fail closed, not raise.
    c = _chain(2)
    s = ters.seal(MASTER, SESSION, c.entries)
    s["count"] = "not-a-number"
    res = ters.verify_seal(MASTER, SESSION, c.entries, s)
    assert res["ok"] is False
    assert res["count_ok"] is False


def test_empty_chain_seal_is_authenticated():
    # Hardening: empty-chain seal is keyed (not a public constant) -- a wrong
    # master must NOT reproduce it.
    s = ters.seal(MASTER, SESSION, [])
    res = ters.verify_seal(b"different-master-secret-bytes-000", SESSION, [], s)
    assert res["ok"] is False
    assert res["agg_ok"] is False
