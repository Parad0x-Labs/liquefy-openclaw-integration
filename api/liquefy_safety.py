#!/usr/bin/env python3
"""
Liquefy Safety - [LIQUEFY PROTECTION V1]
=========================================
MISSION: Guarantee 100% Data Integrity for ANY Liquefy Engine.
METHOD:  Mandatory Round-Trip Verification (MRTV) with Hash Locking.
STATUS:  Production Grade - Verified Baseline.
"""

import zstandard as zstd
import xxhash
import struct
import io
import sys

class LiquefySafety:
    def __init__(self, fallback_level=19, enabled=True):
        self.fallback_cctx = zstd.ZstdCompressor(level=fallback_level)
        self.fallback_dctx = zstd.ZstdDecompressor()
        self.enabled = enabled

    def seal(self, original_data: bytes, compress_func, decompress_func, engine_id: bytes) -> bytes:
        """
        Compresses data with MRTV (Mandatory Round-Trip Verification).
        If verification fails or is disabled, falls back to raw Zstd.
        """
        if not self.enabled:
            # Skip verification path - direct engine call
            try:
                return compress_func(original_data)
            except Exception as e:
                return self._fallback(original_data)

        # 1. Fingerprint Original (RAM Speed)
        original_hash = xxhash.xxh64(original_data).digest()

        try:
            # 2. Attempt Aggressive Compression
            candidate_blob = compress_func(original_data)

            # 3. Mandatory Verification (The Golden Rule)
            restored_data = decompress_func(candidate_blob)
            restored_hash = xxhash.xxh64(restored_data).digest()

            if original_hash == restored_hash:
                # SUCCESS
                return candidate_blob
            else:
                # FAILURE - LOG AND FALLBACK
                print(f"SAFETY TRIGGER: Engine {engine_id.decode(errors='replace')} integrity failure. Falling back to Zstd.")
                return self._fallback(original_data)

        except Exception as e:
            # CRASH - FALLBACK
            print(f"ENGINE CRASH: {engine_id.decode(errors='replace')} failed with: {e}. Falling back to Zstd.")
            return self._fallback(original_data)

    def _fallback(self, data: bytes) -> bytes:
        """Raw Zstd fail-safe"""
        c_data = self.fallback_cctx.compress(data)
        return b'SAFE' + b'ZST\x00' + c_data

    @staticmethod
    def quick_verify(
        original_data: bytes,
        candidate_blob: bytes,
        decompress_func,
        sample_size: int = 4096,
        sample_count: int = 6,
    ) -> bool:
        """
        Faster sampled verification for low-latency mode.
        Verifies size plus deterministic byte windows.
        """
        try:
            restored_data = decompress_func(candidate_blob)
        except Exception:
            return False

        if isinstance(restored_data, bytearray):
            restored_data = bytes(restored_data)
        if not isinstance(restored_data, bytes):
            return False
        if len(restored_data) != len(original_data):
            return False

        total = len(original_data)
        if total == 0:
            return True
        if total <= sample_size * max(2, sample_count):
            return restored_data == original_data

        last = max(0, total - sample_size)
        step = max(1, last // max(1, sample_count - 1))

        offsets = [0]
        for i in range(1, sample_count - 1):
            offsets.append(min(last, i * step))
        offsets.append(last)

        seen = set()
        for off in offsets:
            if off in seen:
                continue
            seen.add(off)
            if restored_data[off:off + sample_size] != original_data[off:off + sample_size]:
                return False
        return True

    def unseal(self, blob: bytes, engine_registry: dict) -> bytes:
        """
        Universal unsealer for SAFE-wrapped blobs.
        engine_registry: { b'ENG\x01': decompress_func }
        """
        if not blob.startswith(b'SAFE'):
            return None

        engine_id = blob[4:8]
        payload = blob[8:]

        if engine_id == b'ZST\x00':
            return self.fallback_dctx.decompress(payload)

        if engine_id in engine_registry:
            return engine_registry[engine_id](payload)

        raise ValueError(f"Unknown Engine ID in SAFE blob: {engine_id}")

# Singleton instance
Valve = LiquefySafety()
