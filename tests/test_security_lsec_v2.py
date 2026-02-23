#!/usr/bin/env python3
"""LSEC v2 security-specific regression tests."""
import pytest

from liquefy_security import LiquefySecurity, PROTOCOL_SEC, VER_SEC


def test_lsec_v2_roundtrip_and_header_version(sample_json):
    sec = LiquefySecurity(master_secret="test_secret_key_for_ci")
    blob = sec.seal(sample_json, "org-alpha", {"engine": "liquefy-json-hypernebula-v1"})
    assert blob.startswith(PROTOCOL_SEC + bytes([VER_SEC]))
    restored, audit = sec.unseal(blob, "org-alpha")
    assert restored == sample_json
    assert audit["t"] == "org-alpha"
    assert audit["v"] == VER_SEC


def test_audit_json_not_plaintext_in_blob(sample_json):
    sec = LiquefySecurity(master_secret="test_secret_key_for_ci")
    blob = sec.seal(sample_json, "org-alpha", {"meta_probe": True})
    # audit metadata is now inside ciphertext; header should not expose these markers
    assert b'"meta"' not in blob
    assert b'"ts"' not in blob
    assert b'org-alpha' not in blob


def test_header_tamper_fails_via_aad(sample_json):
    sec = LiquefySecurity(master_secret="test_secret_key_for_ci")
    blob = bytearray(sec.seal(sample_json, "org-alpha", {"x": 1}))
    # Flip one byte in the authenticated header (salt region starts at offset 6).
    blob[6] ^= 0x01
    with pytest.raises((PermissionError, ValueError)):
        sec.unseal(bytes(blob), "org-alpha")


def test_missing_secret_rejected():
    with pytest.raises(ValueError, match="MISSING_SECRET"):
        LiquefySecurity(master_secret=None)


def test_weak_secret_rejected():
    with pytest.raises(ValueError, match="WEAK_SECRET"):
        LiquefySecurity(master_secret="short")
