#!/usr/bin/env python3
"""Tests for tools/firc_path.py -- key-free Merkle inclusion over a FIRC chain."""
from pathlib import Path
import sys
import hashlib

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import firc  # type: ignore  # noqa: E402
import firc_path as fp  # type: ignore  # noqa: E402

MASTER = b"unit-test-master-secret-bytes-000"
SESSION = "sess-fp-1"


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


# ---- pure Merkle core ----

@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 6, 8])
def test_inclusion_roundtrip_all_sizes_all_indices(n):
    c, _ = _chain(n)
    digests = [e["entry_digest"] for e in c.entries]
    root = fp.merkle_root(digests)
    for idx in range(n):
        pr = fp.inclusion_proof(digests, idx)
        assert pr["root"] == root
        assert fp.verify_inclusion(root, n, idx, digests[idx], pr["audit_path"]) is True


def test_root_is_deterministic():
    c, _ = _chain(4)
    digests = [e["entry_digest"] for e in c.entries]
    assert fp.merkle_root(digests) == fp.merkle_root(digests)


def test_single_entry_has_empty_path():
    c, _ = _chain(1)
    digests = [e["entry_digest"] for e in c.entries]
    pr = fp.inclusion_proof(digests, 0)
    assert pr["audit_path"] == []
    assert fp.verify_inclusion(pr["root"], 1, 0, digests[0], []) is True


def test_verify_rejects_wrong_leaf():
    c, _ = _chain(5)
    digests = [e["entry_digest"] for e in c.entries]
    pr = fp.inclusion_proof(digests, 2)
    wrong = "a" * 64
    assert fp.verify_inclusion(pr["root"], 5, 2, wrong, pr["audit_path"]) is False


def test_verify_rejects_wrong_index():
    c, _ = _chain(5)
    digests = [e["entry_digest"] for e in c.entries]
    pr = fp.inclusion_proof(digests, 2)
    # same leaf+path but claim a different index
    assert fp.verify_inclusion(pr["root"], 5, 3, digests[2], pr["audit_path"]) is False


def test_verify_rejects_tampered_path():
    c, _ = _chain(6)
    digests = [e["entry_digest"] for e in c.entries]
    pr = fp.inclusion_proof(digests, 1)
    bad = list(pr["audit_path"])
    bad[0] = ("0" * 64) if bad[0][0] != "0" else ("1" * 64)
    assert fp.verify_inclusion(pr["root"], 6, 1, digests[1], bad) is False


def test_verify_rejects_out_of_range():
    c, _ = _chain(3)
    digests = [e["entry_digest"] for e in c.entries]
    pr = fp.inclusion_proof(digests, 0)
    assert fp.verify_inclusion(pr["root"], 3, 3, digests[0], pr["audit_path"]) is False
    assert fp.verify_inclusion(pr["root"], 0, 0, digests[0], []) is False


def test_verify_rejects_restamped_count():
    # count is bound into the root: a re-stamped count (even same pow2 bucket)
    # must be rejected.
    c, _ = _chain(5)
    digests = [e["entry_digest"] for e in c.entries]
    pr = fp.inclusion_proof(digests, 2)
    assert fp.verify_inclusion(pr["root"], 5, 2, digests[2], pr["audit_path"]) is True
    for fake in (4, 6, 7, 8):
        assert fp.verify_inclusion(pr["root"], fake, 2, digests[2], pr["audit_path"]) is False


def test_verify_rejects_non_hex_path():
    c, _ = _chain(2)
    digests = [e["entry_digest"] for e in c.entries]
    pr = fp.inclusion_proof(digests, 0)
    assert fp.verify_inclusion(pr["root"], 2, 0, digests[0], ["zz"]) is False


# ---- reveal / verify_reveal (key-free single-action disclosure) ----

def test_reveal_verify_roundtrip_keyfree():
    c, leaves = _chain(5)
    b = fp.reveal(c.entries, 2)
    res = fp.verify_reveal(b, leaf=leaves[2])  # NOTE: no master secret used
    assert res["ok"] is True
    assert res["digest_ok"] and res["seq_ok"] and res["position_ok"] and res["leaf_ok"]


def test_reveal_needs_only_the_one_entry():
    # The verifier gets ONLY the revealed entry + path -- not the other entries.
    c, _ = _chain(6)
    b = fp.reveal(c.entries, 4)
    assert "entry" in b and isinstance(b["entry"], dict)
    # strip everything except the single bundle; verification still works
    res = fp.verify_reveal({"root": b["root"], "count": b["count"],
                            "index": b["index"], "entry": b["entry"],
                            "audit_path": b["audit_path"]})
    assert res["ok"] is True


def test_reveal_detects_field_tamper():
    c, _ = _chain(4)
    b = fp.reveal(c.entries, 1)
    b["entry"]["receipt_hash"] = hashlib.sha256(b"EVIL").hexdigest()
    res = fp.verify_reveal(b)
    assert res["ok"] is False
    assert res["digest_ok"] is False


def test_reveal_detects_position_lie():
    c, _ = _chain(5)
    b = fp.reveal(c.entries, 3)
    b["index"] = 2  # claim a different position
    res = fp.verify_reveal(b)
    assert res["ok"] is False
    # seq still says 3 while index claims 2
    assert res["seq_ok"] is False


def test_reveal_detects_wrong_leaf_content():
    c, _ = _chain(3)
    b = fp.reveal(c.entries, 0)
    res = fp.verify_reveal(b, leaf=b"not-the-real-leaf")
    assert res["ok"] is False
    assert res["leaf_ok"] is False


def test_reveal_malformed_entry_fails_closed():
    c, _ = _chain(3)
    b = fp.reveal(c.entries, 1)
    b["entry"]["entry_digest"] = "not-hex"
    res = fp.verify_reveal(b)
    assert res["ok"] is False
