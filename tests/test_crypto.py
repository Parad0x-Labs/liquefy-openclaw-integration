"""tests/test_crypto.py — Per-org AES-256-GCM encryption properties."""
import pytest

from liquefy_security import PROTOCOL_SEC, VER_SEC


class TestPerOrgEncryption:
    """Verify cryptographic isolation between tenants."""

    def test_seal_unseal_roundtrip(self, security_instance, sample_json):
        """Encrypt, then decrypt. Must get original bytes back."""
        sealed = security_instance.seal(
            sample_json, "org-alpha", {"test": True}
        )
        assert sealed != sample_json  # Must be encrypted
        assert len(sealed) > len(sample_json)  # Overhead from header/salt/nonce/GCM tag
        assert sealed.startswith(PROTOCOL_SEC + bytes([VER_SEC]))

        restored, _audit = security_instance.unseal(sealed, "org-alpha")
        assert restored == sample_json

    def test_different_orgs_different_ciphertext(self, security_instance, sample_json):
        """Same plaintext, different tenants. Ciphertext must differ."""
        sealed_a = security_instance.seal(sample_json, "org-alpha", {})
        sealed_b = security_instance.seal(sample_json, "org-beta", {})

        assert sealed_a != sealed_b

    def test_wrong_org_fails_to_decrypt(self, security_instance, sample_json):
        """Sealed for org-alpha, attempted unseal with org-beta. Must fail."""
        sealed = security_instance.seal(sample_json, "org-alpha", {})

        with pytest.raises(Exception):
            security_instance.unseal(sealed, "org-beta")

    def test_nonce_uniqueness(self, security_instance, sample_json):
        """Two seals of the same data must produce different ciphertext (unique nonce)."""
        sealed_1 = security_instance.seal(sample_json, "org-alpha", {})
        sealed_2 = security_instance.seal(sample_json, "org-alpha", {})

        assert sealed_1 != sealed_2  # Random nonce/salt should differ

    def test_empty_data(self, security_instance):
        """Sealing empty bytes should not crash."""
        sealed = security_instance.seal(b"", "org-empty", {})
        assert sealed is not None
        restored, _audit = security_instance.unseal(sealed, "org-empty")
        assert restored == b""

    def test_large_payload(self, security_instance):
        """Sealing a larger blob (1 MB) should work."""
        big = b"A" * (1024 * 1024)
        sealed = security_instance.seal(big, "org-large", {})
        restored, _audit = security_instance.unseal(sealed, "org-large")
        assert restored == big
