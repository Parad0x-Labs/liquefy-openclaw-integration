"""Tests for liquefy_vault_anchor.py — on-chain vault integrity anchoring."""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tools"))
sys.path.insert(0, str(REPO_ROOT / "api"))

from liquefy_vault_anchor import (
    compute_proof,
    _compute_vault_hash,
    _get_chain_tip,
    _get_key_fingerprint,
    _save_proof,
    PROOF_SCHEMA,
    ANCHOR_PROOF_FILE,
)


@pytest.fixture
def vault_dir(tmp_path):
    """Create a minimal vault with test files."""
    v = tmp_path / "vault"
    v.mkdir()
    (v / "run_001.null").write_bytes(b"compressed-vault-data-001")
    (v / "run_002.null").write_bytes(b"compressed-vault-data-002")
    (v / "run_001.manifest.json").write_text(json.dumps({
        "files": 3, "bytes": 1024, "ratio": 5.2,
    }))
    return v


@pytest.fixture
def vault_with_chain(vault_dir):
    """Vault with an audit chain."""
    audit_dir = vault_dir / "audit"
    audit_dir.mkdir()
    chain = audit_dir / "chain.jsonl"

    genesis = "0" * 64
    entry1 = {"seq": 0, "ts": "2026-02-25T10:00:00Z", "event": "compress", "prev_hash": genesis}
    canonical1 = json.dumps(entry1, sort_keys=True, separators=(",", ":"))
    hash1 = hashlib.sha256(canonical1.encode()).hexdigest()
    entry1["_hash"] = hash1

    entry2 = {"seq": 1, "ts": "2026-02-25T10:01:00Z", "event": "verify", "prev_hash": hash1}
    canonical2 = json.dumps(entry2, sort_keys=True, separators=(",", ":"))
    hash2 = hashlib.sha256(canonical2.encode()).hexdigest()
    entry2["_hash"] = hash2

    with chain.open("w") as f:
        f.write(json.dumps(entry1, sort_keys=True, separators=(",", ":")) + "\n")
        f.write(json.dumps(entry2, sort_keys=True, separators=(",", ":")) + "\n")

    return vault_dir, hash2


class TestComputeVaultHash:
    def test_deterministic(self, vault_dir):
        h1, c1, b1 = _compute_vault_hash(vault_dir)
        h2, c2, b2 = _compute_vault_hash(vault_dir)
        assert h1 == h2
        assert c1 == c2
        assert b1 == b2

    def test_file_count(self, vault_dir):
        _, count, _ = _compute_vault_hash(vault_dir)
        assert count == 3

    def test_total_bytes(self, vault_dir):
        _, _, total = _compute_vault_hash(vault_dir)
        assert total > 0

    def test_changes_when_file_added(self, vault_dir):
        h1, _, _ = _compute_vault_hash(vault_dir)
        (vault_dir / "new_file.null").write_bytes(b"extra data")
        h2, _, _ = _compute_vault_hash(vault_dir)
        assert h1 != h2

    def test_changes_when_file_modified(self, vault_dir):
        h1, _, _ = _compute_vault_hash(vault_dir)
        (vault_dir / "run_001.null").write_bytes(b"modified-data")
        h2, _, _ = _compute_vault_hash(vault_dir)
        assert h1 != h2

    def test_empty_vault(self, tmp_path):
        empty = tmp_path / "empty_vault"
        empty.mkdir()
        h, count, total = _compute_vault_hash(empty)
        assert count == 0
        assert total == 0


class TestGetChainTip:
    def test_with_chain(self, vault_with_chain):
        vault_dir, expected_hash = vault_with_chain
        tip = _get_chain_tip(vault_dir)
        assert tip == expected_hash

    def test_without_chain(self, vault_dir, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: vault_dir / "fakehome")
        tip = _get_chain_tip(vault_dir)
        assert tip == "0" * 64


class TestKeyFingerprint:
    def test_with_secret(self, monkeypatch):
        monkeypatch.setenv("LIQUEFY_SECRET", "test-secret-key-32bytes")
        fp = _get_key_fingerprint()
        assert len(fp) == 16
        expected = hashlib.sha256(b"test-secret-key-32bytes").hexdigest()[:16]
        assert fp == expected

    def test_without_secret(self, monkeypatch):
        monkeypatch.delenv("LIQUEFY_SECRET", raising=False)
        fp = _get_key_fingerprint()
        assert fp == "0" * 16


class TestComputeProof:
    def test_proof_schema(self, vault_dir):
        proof = compute_proof(vault_dir)
        assert proof["schema"] == PROOF_SCHEMA
        assert proof["version"] == 1

    def test_proof_fields(self, vault_dir):
        proof = compute_proof(vault_dir)
        assert "vault_hash" in proof
        assert "chain_tip" in proof
        assert "key_fingerprint" in proof
        assert "file_count" in proof
        assert "total_bytes" in proof
        assert "anchor_payload" in proof
        assert "anchor_payload_hex" in proof
        assert "timestamp" in proof

    def test_anchor_payload_format(self, vault_dir):
        proof = compute_proof(vault_dir)
        payload = proof["anchor_payload"]
        assert payload.startswith("LQFY|")
        parts = payload.split("|")
        assert len(parts) == 4

    def test_proof_deterministic(self, vault_dir):
        p1 = compute_proof(vault_dir)
        p2 = compute_proof(vault_dir)
        assert p1["vault_hash"] == p2["vault_hash"]
        assert p1["chain_tip"] == p2["chain_tip"]
        assert p1["anchor_payload"] == p2["anchor_payload"]

    def test_proof_with_chain(self, vault_with_chain):
        vault_dir, chain_hash = vault_with_chain
        proof = compute_proof(vault_dir)
        assert proof["chain_tip"] == chain_hash
        assert proof["chain_tip"] != "0" * 64


class TestSaveProof:
    def test_saves_file(self, vault_dir):
        proof = compute_proof(vault_dir)
        path = _save_proof(proof, vault_dir)
        assert path.exists()
        assert path.name == ANCHOR_PROOF_FILE

    def test_saved_is_valid_json(self, vault_dir):
        proof = compute_proof(vault_dir)
        path = _save_proof(proof, vault_dir)
        loaded = json.loads(path.read_text("utf-8"))
        assert loaded["schema"] == PROOF_SCHEMA
        assert loaded["vault_hash"] == proof["vault_hash"]

    def test_solana_tx_initially_none(self, vault_dir):
        proof = compute_proof(vault_dir)
        assert proof["solana_tx"] is None
        assert proof["solana_cluster"] is None


class TestVerifyFlow:
    def test_verify_matches_itself(self, vault_dir):
        proof = compute_proof(vault_dir)
        _save_proof(proof, vault_dir)

        current = compute_proof(vault_dir)
        assert proof["vault_hash"] == current["vault_hash"]
        assert proof["chain_tip"] == current["chain_tip"]

    def test_verify_detects_tampering(self, vault_dir):
        proof = compute_proof(vault_dir)
        _save_proof(proof, vault_dir)

        (vault_dir / "run_001.null").write_bytes(b"TAMPERED")
        current = compute_proof(vault_dir)
        assert proof["vault_hash"] != current["vault_hash"]

    def test_verify_detects_file_addition(self, vault_dir):
        proof = compute_proof(vault_dir)
        _save_proof(proof, vault_dir)

        (vault_dir / "injected.null").write_bytes(b"injected")
        current = compute_proof(vault_dir)
        assert proof["vault_hash"] != current["vault_hash"]
        assert proof["file_count"] != current["file_count"]

    def test_verify_detects_file_removal(self, vault_dir):
        proof = compute_proof(vault_dir)
        (vault_dir / "run_002.null").unlink()
        current = compute_proof(vault_dir)
        assert proof["vault_hash"] != current["vault_hash"]


class TestAnchorPayloadHex:
    def test_hex_roundtrip(self, vault_dir):
        proof = compute_proof(vault_dir)
        payload = proof["anchor_payload"]
        hex_payload = proof["anchor_payload_hex"]
        recovered = bytes.fromhex(hex_payload).decode("utf-8")
        assert recovered == payload

    def test_payload_under_80_bytes(self, vault_dir):
        proof = compute_proof(vault_dir)
        payload_bytes = proof["anchor_payload"].encode("utf-8")
        assert len(payload_bytes) <= 80, f"Anchor payload is {len(payload_bytes)} bytes, must be <= 80"
