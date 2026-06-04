#!/usr/bin/env python3
from pathlib import Path
import hashlib
import json
import sys


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from common_signing import sign_vault_artifacts, verify_vault_signature  # type: ignore


def _write_vault_files(vault_dir: Path):
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "tracevault_index.json").write_text(json.dumps({"version": "tracevault-index-v2"}), encoding="utf-8")
    (vault_dir / "vault_manifest.json").write_text(json.dumps({"vault_id": "v1", "included": []}), encoding="utf-8")
    (vault_dir / "run_metadata.json").write_text(json.dumps({"vault_id": "v1"}), encoding="utf-8")


# ── Default (Ed25519) round-trip / tamper (exercises the new default) ───────


def test_sign_and_verify_roundtrip(tmp_path):
    vault = tmp_path / "vault"
    key = tmp_path / "signing.key"
    _write_vault_files(vault)

    res = sign_vault_artifacts(vault, key_path=key)
    assert Path(res["signature_path"]).exists()
    verify = verify_vault_signature(vault, key_path=key)
    assert verify["ok"] is True
    assert all(c.get("ok") for c in verify["checks"])


def test_sign_verify_detects_tamper(tmp_path):
    vault = tmp_path / "vault"
    key = tmp_path / "signing.key"
    _write_vault_files(vault)
    sign_vault_artifacts(vault, key_path=key)

    (vault / "run_metadata.json").write_text(json.dumps({"vault_id": "v1", "tampered": True}), encoding="utf-8")
    verify = verify_vault_signature(vault, key_path=key)
    assert verify["ok"] is False
    assert any(not c.get("ok") for c in verify["checks"])


# ── Ed25519 is the default and is publicly verifiable ───────────────────────


def test_ed25519_is_default_algorithm(tmp_path):
    vault = tmp_path / "vault"
    key = tmp_path / "ed25519.key"
    _write_vault_files(vault)

    res = sign_vault_artifacts(vault, key_path=key)
    assert res["algorithm"] == "Ed25519"
    assert res["schema_version"] == "v2"
    assert len(res["public_key"]) == 64  # 32 raw bytes, hex
    assert "manifest_signature" in res and "key_fingerprint" in res
    # The private seed lives in the key file, never in the published signature.
    assert key.exists() and len(key.read_bytes()) == 32
    sig = json.loads((vault / ".liquefy" / "signature.json").read_text("utf-8"))
    assert "hmac_sha256" not in json.dumps(sig)
    assert Path(res["public_key_path"]).exists()


def test_ed25519_verifies_with_only_public_key(tmp_path):
    """The whole point: verification needs ONLY the public key — no secret."""
    vault = tmp_path / "vault"
    key = tmp_path / "ed25519.key"
    _write_vault_files(vault)
    res = sign_vault_artifacts(vault, key_path=key)
    pub_hex = res["public_key"]

    # Destroy the private key entirely — a third party would never have it.
    key.unlink()
    assert not key.exists()

    verify = verify_vault_signature(vault, public_key=pub_hex)
    assert verify["ok"] is True
    assert verify["algorithm"] == "Ed25519"
    assert verify["publicly_verifiable"] is True
    assert verify["manifest_signature_ok"] is True
    assert verify["public_key_source"] == "provided"
    assert all(c.get("ok") for c in verify["checks"])


def test_ed25519_verifies_from_published_pubkey_file(tmp_path):
    vault = tmp_path / "vault"
    key = tmp_path / "ed25519.key"
    _write_vault_files(vault)
    res = sign_vault_artifacts(vault, key_path=key)
    pub_path = Path(res["public_key_path"])

    key.unlink()
    verify = verify_vault_signature(vault, public_key=pub_path)
    assert verify["ok"] is True


def test_ed25519_tamper_detected_with_public_key(tmp_path):
    vault = tmp_path / "vault"
    key = tmp_path / "ed25519.key"
    _write_vault_files(vault)
    res = sign_vault_artifacts(vault, key_path=key)
    pub_hex = res["public_key"]
    key.unlink()

    (vault / "run_metadata.json").write_text(json.dumps({"vault_id": "v1", "tampered": True}), encoding="utf-8")
    verify = verify_vault_signature(vault, public_key=pub_hex)
    assert verify["ok"] is False
    assert any(not c.get("ok") for c in verify["checks"])


def test_ed25519_forged_manifest_fails_signature(tmp_path):
    """Attacker edits a file AND rewrites its manifest hash to match.

    Per-file SHA-256 now matches, but the Ed25519 signature covers the whole
    manifest — and the attacker cannot re-sign without the private key.
    """
    vault = tmp_path / "vault"
    key = tmp_path / "ed25519.key"
    _write_vault_files(vault)
    res = sign_vault_artifacts(vault, key_path=key)
    pub_hex = res["public_key"]
    key.unlink()

    target = vault / "run_metadata.json"
    target.write_text(json.dumps({"vault_id": "v1", "tampered": True}), encoding="utf-8")
    new_sha = hashlib.sha256(target.read_bytes()).hexdigest()

    sig_path = vault / ".liquefy" / "signature.json"
    sig = json.loads(sig_path.read_text("utf-8"))
    for row in sig["signed_files"]:
        if row["path"] == "run_metadata.json":
            row["sha256"] = new_sha
            row["bytes"] = target.stat().st_size
    sig_path.write_text(json.dumps(sig, indent=2, sort_keys=True), encoding="utf-8")

    verify = verify_vault_signature(vault, public_key=pub_hex)
    assert verify["ok"] is False
    assert verify["manifest_signature_ok"] is False


def test_ed25519_rejects_wrong_public_key(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    vault = tmp_path / "vault"
    key = tmp_path / "ed25519.key"
    _write_vault_files(vault)
    sign_vault_artifacts(vault, key_path=key)

    attacker_pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    verify = verify_vault_signature(vault, public_key=attacker_pub)
    assert verify["ok"] is False


def test_ed25519_key_fingerprint_binding(tmp_path):
    """Binding to the on-chain-anchored fingerprint catches a swapped key."""
    vault = tmp_path / "vault"
    key = tmp_path / "ed25519.key"
    _write_vault_files(vault)
    res = sign_vault_artifacts(vault, key_path=key)
    pub_hex = res["public_key"]
    fp = res["key_fingerprint"]
    key.unlink()

    ok = verify_vault_signature(vault, public_key=pub_hex, expected_key_fingerprint=fp)
    assert ok["ok"] is True
    assert ok["key_fingerprint_matches_expected"] is True

    bad = verify_vault_signature(vault, public_key=pub_hex, expected_key_fingerprint="deadbeefdeadbeef")
    assert bad["ok"] is False
    assert bad["key_fingerprint_matches_expected"] is False


# ── HMAC-SHA256 (legacy / local-only) is still supported ────────────────────


def test_hmac_legacy_roundtrip(tmp_path):
    vault = tmp_path / "vault"
    key = tmp_path / "hmac.key"
    _write_vault_files(vault)

    res = sign_vault_artifacts(vault, key_path=key, algorithm="HMAC-SHA256")
    assert res["algorithm"] == "HMAC-SHA256"
    assert res["schema_version"] == "v1"

    verify = verify_vault_signature(vault, key_path=key)
    assert verify["ok"] is True
    assert verify["algorithm"] == "HMAC-SHA256"
    assert verify["publicly_verifiable"] is False
    assert all(c.get("ok") for c in verify["checks"])


def test_hmac_legacy_detects_tamper(tmp_path):
    vault = tmp_path / "vault"
    key = tmp_path / "hmac.key"
    _write_vault_files(vault)
    sign_vault_artifacts(vault, key_path=key, algorithm="HMAC-SHA256")

    (vault / "run_metadata.json").write_text(json.dumps({"tampered": True}), encoding="utf-8")
    verify = verify_vault_signature(vault, key_path=key)
    assert verify["ok"] is False
    assert any(not c.get("ok") for c in verify["checks"])
