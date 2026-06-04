#!/usr/bin/env python3
"""Tests for tools/firc.py -- the Forward-Integrity Receipt Chain."""
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import firc  # type: ignore  # noqa: E402
from firc import FIRCChain, verify_chain, derive_seed  # type: ignore  # noqa: E402


MASTER = b"unit-test-master-secret-bytes-000"
SESSION = "sess-abc-123"


def _build(n, master=MASTER, session=SESSION, receipts=None, mandates=None):
    chain = FIRCChain.from_master(master, session)
    for i in range(n):
        chain.append(
            ("leaf-%d" % i).encode(),
            receipt_hash=(receipts[i] if receipts else b""),
            mandate=(mandates[i] if mandates else b""),
        )
    return chain


def test_build_and_verify_roundtrip():
    chain = _build(5)
    res = verify_chain(MASTER, SESSION, chain.entries)
    assert res["ok"] is True
    assert res["verified"] == 5


def test_verify_with_real_leaves_roundtrip():
    chain = _build(4)
    leaves = [("leaf-%d" % i).encode() for i in range(4)]
    res = verify_chain(MASTER, SESSION, chain.entries, leaves=leaves)
    assert res["ok"] is True


def test_detects_leaf_content_tamper():
    chain = _build(4)
    leaves = [("leaf-%d" % i).encode() for i in range(4)]
    leaves[2] = b"TAMPERED"
    res = verify_chain(MASTER, SESSION, chain.entries, leaves=leaves)
    assert res["ok"] is False
    assert any(f.get("error") == "LEAF_HASH_MISMATCH" for f in res["failures"])


def test_detects_tag_forgery():
    chain = _build(3)
    e = chain.entries[1]
    e["tag"] = ("0" * len(e["tag"])) if e["tag"][0] != "0" else ("1" * len(e["tag"]))
    res = verify_chain(MASTER, SESSION, chain.entries)
    assert res["ok"] is False
    assert res["verified"] == 1  # entry 0 verifies, fails at 1


def test_detects_receipt_binding_tamper():
    chain = _build(3, receipts=[b"r0", b"r1", b"r2"])
    chain.entries[2]["receipt_hash"] = b"EVIL".hex()  # change a bound receipt without re-tagging
    res = verify_chain(MASTER, SESSION, chain.entries)
    assert res["ok"] is False


def test_detects_mandate_binding_tamper():
    chain = _build(2, mandates=[b"scope:pay<=100", b"scope:pay<=100"])
    chain.entries[1]["mandate_hash"] = ("a" * 64)
    res = verify_chain(MASTER, SESSION, chain.entries)
    assert res["ok"] is False


def test_detects_reorder():
    chain = _build(4)
    chain.entries[1], chain.entries[2] = chain.entries[2], chain.entries[1]
    res = verify_chain(MASTER, SESSION, chain.entries)
    assert res["ok"] is False


def test_detects_truncation_with_anchored_head():
    chain = _build(5)
    head = chain.head()  # this is what would be anchored on-chain
    truncated = list(chain.entries[:3])
    res = verify_chain(MASTER, SESSION, truncated, expected_head=head)
    assert res["ok"] is False
    assert res.get("head_ok") is False


def test_truncation_undetectable_without_head():
    # Honest property: FIRC alone (no anchored head) cannot detect a clean tail
    # truncation -- the surviving prefix is internally valid. The head/anchor
    # (TERS) is what seals this. This test pins that documented limitation.
    chain = _build(5)
    truncated = list(chain.entries[:3])
    res = verify_chain(MASTER, SESSION, truncated)
    assert res["ok"] is True


def test_wrong_master_secret_fails():
    chain = _build(3)
    res = verify_chain(b"wrong-master-secret-bytes-0000000", SESSION, chain.entries)
    assert res["ok"] is False
    assert res["verified"] == 0  # first tag already fails


def test_wrong_session_fails():
    chain = _build(3)
    res = verify_chain(MASTER, "different-session", chain.entries)
    assert res["ok"] is False


def test_forward_security_old_key_is_wiped():
    # After building, the chain holds only the CURRENT (post-last) epoch key.
    # Capturing it must NOT let an attacker reproduce a valid tag for entry 0.
    chain = _build(3)
    captured_current_key = bytes(chain._key)  # attacker grabs the live key
    e0 = chain.entries[0]
    forged = firc._tag(captured_current_key, bytes.fromhex(str(e0["entry_digest"]))).hex()
    assert forged != e0["tag"]


def test_seed_is_session_bound():
    s1 = derive_seed(MASTER, "s1")
    s2 = derive_seed(MASTER, "s2")
    assert s1 != s2
    assert len(s1) == 32


def test_empty_chain_verifies_vacuously():
    res = verify_chain(MASTER, SESSION, [])
    assert res["ok"] is True
    assert res["verified"] == 0
