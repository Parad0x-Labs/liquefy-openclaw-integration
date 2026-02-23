"""tests/test_mrtv.py — MRTV (Mandatory Round-Trip Verification) tamper tests."""
import pytest
import zstandard as zstd


class TestMRTVSafety:
    """Verify the Safety Valve catches corruption and falls back cleanly."""

    def test_valid_roundtrip_succeeds(self, safety_valve, sample_json):
        """Normal compress/decompress returns the engine payload when verification passes."""
        cctx = zstd.ZstdCompressor(level=3)
        dctx = zstd.ZstdDecompressor()

        result = safety_valve.seal(
            sample_json,
            cctx.compress,
            dctx.decompress,
            b'ZST1',
        )

        assert result is not None
        assert len(result) > 0
        # Success path returns the verified engine payload directly (no SAFE wrapper overhead).
        assert result[:4] != b"SAFE"
        assert dctx.decompress(result) == sample_json

    def test_corrupt_compress_falls_back(self, safety_valve, sample_json):
        """If compress returns garbage that decompresses to wrong hash, MRTV falls back."""
        def bad_compress(data):
            return b"this is not valid compressed data"

        def bad_decompress(data):
            return b"different data entirely"

        result = safety_valve.seal(
            sample_json,
            bad_compress,
            bad_decompress,
            b'BAD\x00',
        )

        # Should not crash. Should return valid bytes (Zstd fallback).
        assert result is not None
        assert len(result) > 0
        assert result[:4] == b"SAFE"

    def test_compress_exception_falls_back(self, safety_valve, sample_json):
        """If compress() throws, MRTV should catch it and fall back."""
        def exploding_compress(data):
            raise RuntimeError("Engine exploded")

        def noop_decompress(data):
            return data

        result = safety_valve.seal(
            sample_json,
            exploding_compress,
            noop_decompress,
            b'EXP\x00',
        )

        assert result is not None
        assert len(result) > 0
        assert result[:4] == b"SAFE"

    def test_single_byte_tamper_detected(self, safety_valve, sample_json):
        """Flip one byte in compressed output. MRTV should detect hash mismatch."""
        cctx = zstd.ZstdCompressor(level=3)

        def tamper_compress(data):
            compressed = cctx.compress(data)
            # Flip one byte in the middle
            tampered = bytearray(compressed)
            mid = len(tampered) // 2
            tampered[mid] ^= 0xFF
            return bytes(tampered)

        def decompress_that_fails(data):
            try:
                dctx = zstd.ZstdDecompressor()
                return dctx.decompress(data)
            except Exception:
                return b"corrupted"

        result = safety_valve.seal(
            sample_json,
            tamper_compress,
            decompress_that_fails,
            b'TMP\x00',
        )

        # Must not crash. Falls back to Zstd.
        assert result is not None
        assert len(result) > 0
        assert result[:4] == b"SAFE"
