#!/usr/bin/env python3
"""
Liquefy Security - [LIQUEFY FORTRESS V2]
=========================================
MISSION: Provide AEAD-based tenant-isolated encryption with fail-closed secrets.
FEAT:    AES-256-GCM, PBKDF2-SHA256 tenant KDF, authenticated header (AAD).
STATUS:  Production Grade - LSEC v2 only (no legacy compatibility).
"""

import os
import time
import json
import struct
import collections
from typing import Optional, Tuple, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# =========================================================
# 1. SECURITY CONFIGURATION
# =========================================================

PROTOCOL_SEC = b'LSEC'
VER_SEC = 2
KDF_PBKDF2_SHA256 = 1
DEFAULT_PBKDF2_ITERS = 300_000
MAX_PBKDF2_ITERS = 2_000_000
MAX_AUDIT_LEN = 1_048_576  # 1 MiB

# No enforced usage limits in OSS/BUSL personal-use build.

class LiquefySecurity:
    def __init__(self, master_secret: Union[str, bytes, None] = None):
        """
        master_secret: Central key for deriving tenant-specific keys.
        """
        if master_secret is None or master_secret == "":
            raise ValueError("MISSING_SECRET: set LIQUEFY_SECRET or pass master_secret")
        self.master_secret = master_secret.encode() if isinstance(master_secret, str) else master_secret
        if not isinstance(self.master_secret, (bytes, bytearray)):
            raise TypeError("INVALID_SECRET_TYPE: master_secret must be str or bytes")
        self.master_secret = bytes(self.master_secret)
        if len(self.master_secret) < 16:
            raise ValueError("WEAK_SECRET: secret too short; use >=16 bytes (prefer 32+)")

        # usage_store tracks: {key_or_ip: {"calls": int, "bytes": int, "reset_at": float}}
        self.usage_store = collections.defaultdict(lambda: {"calls": 0, "bytes": 0, "reset_at": time.time() + 86400})

    def get_limit(self, api_key: str = None) -> tuple[int, float]:
        """Compatibility shim: limits are intentionally disabled."""
        return (2**31 - 1, float("inf"))

    def check_rate_limit(self, api_key: str = None, ip_address: str = None) -> bool:
        """Limits are disabled; always allow."""
        return True

    def register_usage(self, data_size_bytes: int, api_key: str = None, ip_address: str = None):
        """No-op when limits are disabled."""
        return None

    def _derive_tenant_key(self, tenant_id: str, salt: bytes, iterations: int) -> bytes:
        """KDF to ensure multi-tenant cryptographic isolation."""
        if not tenant_id:
            raise ValueError("INVALID_TENANT_ID")
        if len(salt) != 16:
            raise ValueError("INVALID_SALT")
        if int(iterations) <= 0 or int(iterations) > MAX_PBKDF2_ITERS:
            raise ValueError("INVALID_PBKDF2_ITERS")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=int(iterations),
            backend=default_backend()
        )
        return kdf.derive(self.master_secret + tenant_id.encode("utf-8"))

    def seal(
        self,
        data: bytes,
        tenant_id: str,
        metadata: Optional[dict] = None,
        iters: int = DEFAULT_PBKDF2_ITERS,
    ) -> bytes:
        """
        LSEC v2 seal:
        1. PBKDF2-SHA256 tenant-isolated key derivation
        2. AES-256-GCM authenticated encryption (AEAD)
        3. Header authenticated via AAD (no separate HMAC layer)
        """
        if metadata is None:
            metadata = {}
        if data is None:
            data = b""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("INVALID_DATA_TYPE")
        data = bytes(data)

        audit_trail = {
            "t": tenant_id,
            "ts": time.time(),
            "meta": metadata,
            "v": VER_SEC
        }
        audit_json = json.dumps(
            audit_trail,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        if len(audit_json) > MAX_AUDIT_LEN:
            raise ValueError("AUDIT_TOO_LARGE")

        salt = os.urandom(16)
        nonce = os.urandom(12)
        flags = 0
        kdf_id = KDF_PBKDF2_SHA256
        iters_i = int(iters)
        if iters_i <= 0 or iters_i > MAX_PBKDF2_ITERS:
            raise ValueError("INVALID_PBKDF2_ITERS")

        header = bytearray()
        header.extend(PROTOCOL_SEC)
        header.append(VER_SEC)
        header.append(flags)
        header.extend(salt)
        header.extend(nonce)
        header.append(kdf_id)
        header.extend(struct.pack(">I", iters_i))
        header.extend(struct.pack(">H", 0))  # aad_len placeholder
        aad_len = len(header)
        header[-2:] = struct.pack(">H", aad_len)

        aad = bytes(header)
        inner = bytearray()
        inner.extend(struct.pack(">I", len(audit_json)))
        inner.extend(audit_json)
        inner.extend(data)

        key = self._derive_tenant_key(tenant_id, salt, iters_i)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, bytes(inner), aad)

        return bytes(header) + ciphertext

    def unseal(self, secure_blob: bytes, tenant_id: str) -> Tuple[bytes, dict]:
        """Verifies and decrypts a secure blob."""
        if not isinstance(secure_blob, (bytes, bytearray)):
            raise TypeError("INVALID_BLOB_TYPE")
        blob = bytes(secure_blob)

        min_header_len = 4 + 1 + 1 + 16 + 12 + 1 + 4 + 2
        if len(blob) < min_header_len:
            raise ValueError("INVALID_BLOB: too short")

        p = 0
        if blob[p:p + 4] != PROTOCOL_SEC:
            raise ValueError("INVALID_MAGIC")
        p += 4

        ver = blob[p]
        p += 1
        if ver != VER_SEC:
            raise ValueError(f"UNSUPPORTED_VER: {ver}")

        _flags = blob[p]
        p += 1

        salt = blob[p:p + 16]
        p += 16
        if len(salt) != 16:
            raise ValueError("INVALID_SALT")

        nonce = blob[p:p + 12]
        p += 12
        if len(nonce) != 12:
            raise ValueError("INVALID_NONCE")

        kdf_id = blob[p]
        p += 1
        if kdf_id != KDF_PBKDF2_SHA256:
            raise ValueError("UNSUPPORTED_KDF")

        if p + 4 > len(blob):
            raise ValueError("INVALID_ITERS")
        iters = struct.unpack(">I", blob[p:p + 4])[0]
        p += 4
        if iters <= 0 or iters > MAX_PBKDF2_ITERS:
            raise ValueError("INVALID_ITERS")

        if p + 2 > len(blob):
            raise ValueError("INVALID_AAD_LEN")
        aad_len = struct.unpack(">H", blob[p:p + 2])[0]
        p += 2
        if aad_len < min_header_len or aad_len > len(blob):
            raise ValueError("INVALID_AAD_LEN")

        header = blob[:aad_len]
        ciphertext = blob[aad_len:]
        if not ciphertext:
            raise ValueError("INVALID_CIPHERTEXT")

        key = self._derive_tenant_key(tenant_id, salt, iters)
        try:
            inner = AESGCM(key).decrypt(nonce, ciphertext, header)
        except Exception:
            raise PermissionError("DECRYPTION_FAILURE")

        if len(inner) < 4:
            raise ValueError("INVALID_INNER")
        q = 0
        audit_len = struct.unpack(">I", inner[q:q + 4])[0]
        q += 4
        if audit_len > MAX_AUDIT_LEN or q + audit_len > len(inner):
            raise ValueError("INVALID_AUDIT_LEN")

        audit_json = inner[q:q + audit_len]
        q += audit_len
        data = inner[q:]

        try:
            audit_metadata = json.loads(audit_json.decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"INVALID_AUDIT_JSON: {exc}")
        return data, audit_metadata

def secure_audit_log(event: str, metadata: dict):
    """Placeholder for SOC 2 compliant central audit logging."""
    log_entry = {
        "event": event,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "details": metadata
    }
    print(f"[AUDIT] {json.dumps(log_entry)}")
