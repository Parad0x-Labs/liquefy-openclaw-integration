#!/usr/bin/env python3
"""Tests for tools/dual_tier.py -- public Ed25519 cosignature over the vault head."""
from pathlib import Path
import sys

import pytest

pytest.importorskip("cryptography")  # tier-2 needs Ed25519; CI pins cryptography

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import dual_tier as dt  # type: ignore  # noqa: E402


def _head():
    return dt.build_head(
        {"session_id": "s1", "count": 4, "head_hash": "ab" * 32},
        {"agg_mac": "cd" * 32, "settlement_root": "ef" * 32},
        {"value_mac": "12" * 32, "totals_root": "34" * 32},
    )


def test_cosign_then_public_verify_roundtrip():
    sk, pk = dt.generate_keypair()
    head = _head()
    cs = dt.cosign(sk, head)
    assert cs["public_key"] == pk
    # PUBLIC verify -- only the public key, no master secret anywhere
    assert dt.verify_cosignature(pk, head, cs["signature"]) is True


def test_verify_is_order_independent():
    sk, pk = dt.generate_keypair()
    head = _head()
    cs = dt.cosign(sk, head)
    # rebuild the same head with keys inserted in a different order
    reordered = {}
    for k in reversed(list(head.keys())):
        reordered[k] = head[k]
    assert dt.verify_cosignature(pk, reordered, cs["signature"]) is True


def test_detects_head_tamper():
    sk, pk = dt.generate_keypair()
    head = _head()
    cs = dt.cosign(sk, head)
    bad = dict(head)
    bad["firc"] = {"count": 999, "head_hash": "00" * 32}
    assert dt.verify_cosignature(pk, bad, cs["signature"]) is False


def test_detects_wrong_public_key():
    sk, _pk = dt.generate_keypair()
    _sk2, pk2 = dt.generate_keypair()
    head = _head()
    cs = dt.cosign(sk, head)
    assert dt.verify_cosignature(pk2, head, cs["signature"]) is False


def test_detects_signature_tamper():
    sk, pk = dt.generate_keypair()
    head = _head()
    cs = dt.cosign(sk, head)
    flipped = ("0" * len(cs["signature"])) if cs["signature"][0] != "0" else ("1" * len(cs["signature"]))
    assert dt.verify_cosignature(pk, head, flipped) is False


def test_verify_fail_closed_on_bad_hex():
    sk, pk = dt.generate_keypair()
    head = _head()
    cs = dt.cosign(sk, head)
    assert dt.verify_cosignature("zz", head, cs["signature"]) is False
    assert dt.verify_cosignature(pk, head, "nothex") is False


def test_verify_fail_closed_on_unserializable_head():
    sk, pk = dt.generate_keypair()
    head = _head()
    cs = dt.cosign(sk, head)
    bad = dict(head)
    bad["x"] = {1, 2, 3}  # a set is not JSON-serializable -> must fail closed, not raise
    assert dt.verify_cosignature(pk, bad, cs["signature"]) is False


def test_public_key_of_matches_generated():
    sk, pk = dt.generate_keypair()
    assert dt.public_key_of(sk) == pk


def test_staple_separates_tiers_explicitly():
    sk, pk = dt.generate_keypair()
    head = _head()
    cs = dt.cosign(sk, head)
    tier1 = {"firc_head": {"count": 4}, "ters_seal": {"agg_mac": "cd" * 32}}
    bundle = dt.staple(tier1, head, cs)
    assert bundle["schema"] == "vault.dual-tier.v1"
    assert "tier1_keyed" in bundle and "tier2_public" in bundle
    assert bundle["tier2_public"]["public_key"] == pk
    # tier-2 in the stapled bundle is independently public-verifiable
    assert dt.verify_cosignature(bundle["tier2_public"]["public_key"], bundle["head"], bundle["tier2_public"]["signature"]) is True
