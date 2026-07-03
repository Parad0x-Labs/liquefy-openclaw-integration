#!/usr/bin/env python3
"""Tests for tools/disclosure_envelope.py -- honest tiered disclosure bundle."""
from pathlib import Path
import sys
import hashlib

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import firc  # type: ignore  # noqa: E402
import ters  # type: ignore  # noqa: E402
import firc_path  # type: ignore  # noqa: E402
import dual_tier  # type: ignore  # noqa: E402
import disclosure_envelope as de  # type: ignore  # noqa: E402

try:
    import cryptography  # noqa: F401
    HAS_CRYPTO = True
except Exception:
    HAS_CRYPTO = False
needs_crypto = pytest.mark.skipif(not HAS_CRYPTO, reason="needs cryptography for the Ed25519 tier")

MASTER = b"unit-test-master-secret-bytes-000"
SESSION = "sess-de-1"


def _chain(n):
    c = firc.FIRCChain.from_master(MASTER, SESSION)
    leaves = []
    for i in range(n):
        leaf = ("leaf-%d" % i).encode()
        leaves.append(leaf)
        c.append(leaf, receipt_hash=hashlib.sha256(("rx-%d" % i).encode()).digest())
    return c, leaves


def _keyed_seal(c):
    return {"firc_head": c.head(), "ters_seal": ters.seal(MASTER, SESSION, c.entries)}


# ---- pure-stdlib tiers (no cryptography needed) ----

def test_single_action_only_is_keyfree_ok():
    c, _ = _chain(5)
    env = de.build_envelope(SESSION, {}, single_action=firc_path.reveal(c.entries, 2))
    res = de.verify_envelope(env)  # NO key, NO secret
    assert res["ok"] is True
    assert res["verified_tiers"] == ["single_action"]
    assert res["zk_verified"] is False


def test_tampered_single_action_fails():
    c, _ = _chain(4)
    sa = firc_path.reveal(c.entries, 1)
    sa["entry"]["receipt_hash"] = hashlib.sha256(b"EVIL").hexdigest()
    env = de.build_envelope(SESSION, {}, single_action=sa)
    res = de.verify_envelope(env)
    assert res["ok"] is False
    assert "single_action" in res["failed_tiers"]


def test_zk_placeholder_is_not_verified_as_zk():
    c, _ = _chain(3)
    env = de.build_envelope(SESSION, {}, single_action=firc_path.reveal(c.entries, 0),
                            zk_proof={"status": de.ZK_PLACEHOLDER})
    res = de.verify_envelope(env)
    assert res["ok"] is True  # single_action still valid
    assert res["zk_verified"] is False
    assert "HIDING" in res["zk"]["note"] or "not zero-knowledge" in res["zk"]["note"]


def test_zk_groth16_slot_reserved_not_verified():
    c, _ = _chain(3)
    env = de.build_envelope(SESSION, {}, single_action=firc_path.reveal(c.entries, 0),
                            zk_proof={"status": de.ZK_GROTH16})
    res = de.verify_envelope(env)
    assert res["zk"]["status"] == de.ZK_GROTH16
    assert res["zk_verified"] is False


def test_zk_is_never_verified_today():
    for st in (de.ZK_NONE, de.ZK_PLACEHOLDER, de.ZK_GROTH16):
        env = de.build_envelope(SESSION, {}, zk_proof={"status": st})
        assert de.verify_envelope(env)["zk_verified"] is False


def test_unknown_zk_status_handled():
    # hand-built envelope with an out-of-enum status (bypassing build_envelope coercion)
    env = {"schema": de.SCHEMA, "session_id": SESSION, "head": {}, "tiers": {},
           "zk_proof": {"status": "magic-zk"}}
    res = de.verify_envelope(env)
    assert res["zk_verified"] is False
    assert "unknown" in res["zk"]["note"].lower()


def test_bad_schema_rejected():
    assert de.verify_envelope({"schema": "nope"})["ok"] is False
    assert de.verify_envelope("not-a-dict")["ok"] is False


def test_keyed_tier_skipped_without_key():
    c, _ = _chain(3)
    env = de.build_envelope(SESSION, {}, single_action=firc_path.reveal(c.entries, 1),
                            keyed_seal=_keyed_seal(c))
    res = de.verify_envelope(env)  # no master/entries
    assert "keyed_seal" in res["skipped_tiers"]
    assert res["ok"] is True  # single_action carried it
    assert any("key-holder" in n for n in res["notes"])


def test_keyed_tier_verified_with_key():
    c, _ = _chain(3)
    env = de.build_envelope(SESSION, {}, keyed_seal=_keyed_seal(c))
    res = de.verify_envelope(env, master_secret=MASTER, entries=c.entries)
    assert res["results"]["keyed_seal"] is True
    assert res["ok"] is True


def test_empty_envelope_not_ok():
    env = de.build_envelope(SESSION, {})  # no tiers
    res = de.verify_envelope(env)
    assert res["ok"] is False  # nothing was checkable


def test_non_dict_zk_proof_fails_closed():
    # a hostile third party supplies a non-dict zk_proof -> must not crash
    env = {"schema": de.SCHEMA, "session_id": SESSION, "head": {}, "tiers": {}, "zk_proof": ["groth16"]}
    res = de.verify_envelope(env)
    assert res["zk_verified"] is False
    assert "malformed" in res["zk"]["note"].lower()


def test_cosign_trusted_key_flag_is_none_without_cosign():
    c, _ = _chain(3)
    env = de.build_envelope(SESSION, {}, single_action=firc_path.reveal(c.entries, 0))
    assert de.verify_envelope(env)["cosign_trusted_key"] is None


# ---- Ed25519 public tier (cryptography) ----


# ---- Ed25519 public tier (cryptography) ----

@needs_crypto
def test_public_cosign_ok_and_full_envelope():
    c, _ = _chain(4)
    head = dual_tier.build_head(c.head(), ters.seal(MASTER, SESSION, c.entries))
    sk, pk = dual_tier.generate_keypair()
    cs = dual_tier.cosign(sk, head)
    env = de.build_envelope(SESSION, head, public_cosign=cs,
                            single_action=firc_path.reveal(c.entries, 2),
                            keyed_seal=_keyed_seal(c))
    res = de.verify_envelope(env, trusted_public_key=pk, master_secret=MASTER, entries=c.entries)
    assert res["ok"] is True
    assert set(res["verified_tiers"]) == {"public_cosign", "single_action", "keyed_seal"}


@needs_crypto
def test_tampered_cosign_fails():
    c, _ = _chain(3)
    head = dual_tier.build_head(c.head(), ters.seal(MASTER, SESSION, c.entries))
    sk, pk = dual_tier.generate_keypair()
    cs = dual_tier.cosign(sk, head)
    env = de.build_envelope(SESSION, head, public_cosign=cs)
    env["head"] = dual_tier.build_head({"session_id": SESSION, "count": 999, "head_hash": "00" * 32},
                                       {"agg_mac": "00" * 32, "settlement_root": "00" * 32})
    res = de.verify_envelope(env, trusted_public_key=pk)
    assert res["ok"] is False
    assert "public_cosign" in res["failed_tiers"]


@needs_crypto
def test_cosign_trusted_key_flag_reflects_trust():
    c, _ = _chain(3)
    head = dual_tier.build_head(c.head(), ters.seal(MASTER, SESSION, c.entries))
    sk, pk = dual_tier.generate_keypair()
    cs = dual_tier.cosign(sk, head)
    env = de.build_envelope(SESSION, head, public_cosign=cs)
    # own-key path: signature valid, but authority NOT proven -> flagged False
    r1 = de.verify_envelope(env)
    assert r1["results"]["public_cosign"] is True
    assert r1["cosign_trusted_key"] is False
    # trusted-key path -> flagged True
    r2 = de.verify_envelope(env, trusted_public_key=pk)
    assert r2["cosign_trusted_key"] is True


@needs_crypto
def test_public_cosign_wrong_trusted_key_fails():
    c, _ = _chain(3)
    head = dual_tier.build_head(c.head(), ters.seal(MASTER, SESSION, c.entries))
    sk, _pk = dual_tier.generate_keypair()
    _sk2, pk2 = dual_tier.generate_keypair()
    cs = dual_tier.cosign(sk, head)
    env = de.build_envelope(SESSION, head, public_cosign=cs)
    res = de.verify_envelope(env, trusted_public_key=pk2)
    assert res["ok"] is False
