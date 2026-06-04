#!/usr/bin/env python3
"""Tests for tools/value_seal.py -- forward-secure value-conservation seal."""
from pathlib import Path
import sys
import hashlib

import pytest  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import value_seal as vs  # type: ignore  # noqa: E402

MASTER = b"unit-test-master-secret-bytes-000"
SESSION = "sess-vs-1"


def _items():
    return [
        {"asset_id": "USDC", "amount": "1000000", "recipient": "alice", "receipt_hash": hashlib.sha256(b"r0").hexdigest()},
        {"asset_id": "USDC", "amount": "2500000", "recipient": "bob", "receipt_hash": hashlib.sha256(b"r1").hexdigest()},
        {"asset_id": "NULL", "amount": "42", "recipient": "carol", "receipt_hash": hashlib.sha256(b"r2").hexdigest()},
    ]


def test_seal_verify_roundtrip():
    it = _items()
    s = vs.seal(MASTER, SESSION, it)
    res = vs.verify_value_seal(MASTER, SESSION, it, s)
    assert res["ok"] is True
    assert res["value_mac_ok"] and res["count_ok"] and res["totals_root_ok"]


def test_totals_are_correct_per_asset():
    s = vs.seal(MASTER, SESSION, _items())
    assert s["totals"] == {"USDC": "3500000", "NULL": "42"}


def test_detects_amount_substitution():
    it = _items()
    s = vs.seal(MASTER, SESSION, it)
    it[0] = {**it[0], "amount": "5000000000"}  # inflate a paid amount
    res = vs.verify_value_seal(MASTER, SESSION, it, s)
    assert res["ok"] is False
    assert res["value_mac_ok"] is False
    assert res["totals_root_ok"] is False


def test_detects_asset_substitution():
    it = _items()
    s = vs.seal(MASTER, SESSION, it)
    it[2] = {**it[2], "asset_id": "WBTC"}
    res = vs.verify_value_seal(MASTER, SESSION, it, s)
    assert res["ok"] is False


def test_detects_recipient_substitution():
    it = _items()
    s = vs.seal(MASTER, SESSION, it)
    it[1] = {**it[1], "recipient": "mallory"}
    res = vs.verify_value_seal(MASTER, SESSION, it, s)
    assert res["ok"] is False
    assert res["value_mac_ok"] is False


def test_detects_truncation_and_extension():
    it = _items()
    s = vs.seal(MASTER, SESSION, it)
    assert vs.verify_value_seal(MASTER, SESSION, it[:2], s)["ok"] is False
    extended = it + [{"asset_id": "USDC", "amount": "1", "recipient": "x"}]
    assert vs.verify_value_seal(MASTER, SESSION, extended, s)["ok"] is False


def test_reconcile_ok():
    it = _items()
    s = vs.seal(MASTER, SESSION, it)
    settled = [{"asset_id": "USDC", "amount": "3500000"}, {"asset_id": "NULL", "amount": "42"}]
    res = vs.verify_value_seal(MASTER, SESSION, it, s, settlements=settled)
    assert res["ok"] is True
    assert res["reconciled"] is True


def test_reconcile_detects_underreport():
    # Logged 3.5 USDC but 5000 USDC actually settled -> caught.
    it = _items()
    s = vs.seal(MASTER, SESSION, it)
    settled = [{"asset_id": "USDC", "amount": "5000000000"}, {"asset_id": "NULL", "amount": "42"}]
    res = vs.verify_value_seal(MASTER, SESSION, it, s, settlements=settled)
    assert res["ok"] is False
    assert res["reconciled"] is False
    assert "USDC" in res["asset_discrepancies"]
    assert res["asset_discrepancies"]["USDC"] == {"logged": "3500000", "settled": "5000000000"}


def test_reconcile_detects_unsettled_asset():
    it = _items()
    s = vs.seal(MASTER, SESSION, it)
    settled = [{"asset_id": "USDC", "amount": "3500000"}]  # NULL never settled
    res = vs.verify_value_seal(MASTER, SESSION, it, s, settlements=settled)
    assert res["reconciled"] is False
    assert "NULL" in res["asset_discrepancies"]


def test_wrong_master_fails():
    it = _items()
    s = vs.seal(MASTER, SESSION, it)
    res = vs.verify_value_seal(b"wrong-master-secret-bytes-0000000", SESSION, it, s)
    assert res["ok"] is False
    assert res["value_mac_ok"] is False


def test_bigint_amounts_no_overflow():
    big = str(2 ** 80)
    it = [{"asset_id": "USDC", "amount": big, "recipient": "a"},
          {"asset_id": "USDC", "amount": big, "recipient": "b"}]
    s = vs.seal(MASTER, SESSION, it)
    assert s["totals"]["USDC"] == str(2 * (2 ** 80))
    assert vs.verify_value_seal(MASTER, SESSION, it, s)["ok"] is True


def test_negative_amount_fails_closed():
    it = [{"asset_id": "USDC", "amount": "-5", "recipient": "a"}]
    # seal raises; verify catches and reports malformed
    s = vs.seal(MASTER, SESSION, _items())
    res = vs.verify_value_seal(MASTER, SESSION, it, s)
    assert res["ok"] is False
    assert res.get("malformed") is True


def test_float_amount_fails_closed():
    # int(5.9)==5 would silently under-report -- must be rejected, not truncated.
    s = vs.seal(MASTER, SESSION, _items())
    it = [{"asset_id": "USDC", "amount": 5.9, "recipient": "a"}]
    res = vs.verify_value_seal(MASTER, SESSION, it, s)
    assert res["ok"] is False
    assert res.get("malformed") is True


def test_nonstrict_amount_strings_fail_closed():
    s = vs.seal(MASTER, SESSION, _items())
    for bad in ("+5", " 5 ", "5_000", "5.0", "1e6", "0x10", ""):
        it = [{"asset_id": "USDC", "amount": bad, "recipient": "a"}]
        res = vs.verify_value_seal(MASTER, SESSION, it, s)
        assert res["ok"] is False, "expected reject for amount=%r" % bad


def test_bool_amount_fails_closed():
    s = vs.seal(MASTER, SESSION, _items())
    it = [{"asset_id": "USDC", "amount": True, "recipient": "a"}]
    res = vs.verify_value_seal(MASTER, SESSION, it, s)
    assert res["ok"] is False


def test_empty_items_roundtrips():
    s = vs.seal(MASTER, SESSION, [])
    res = vs.verify_value_seal(MASTER, SESSION, [], s)
    assert res["ok"] is True
    assert s["totals"] == {}


def test_malformed_settlement_fails_closed():
    it = _items()
    s = vs.seal(MASTER, SESSION, it)
    res = vs.verify_value_seal(MASTER, SESSION, it, s, settlements=[{"asset_id": "USDC", "amount": "oops"}])
    assert res["ok"] is False
