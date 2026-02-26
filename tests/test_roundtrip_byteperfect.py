#!/usr/bin/env python3
"""Golden roundtrip regression tests for key engines/profiles."""
import hashlib
import json
from pathlib import Path

import pytest

from orchestrator.engine_map import get_engine_instance


REPO_ROOT = Path(__file__).resolve().parent.parent
GOLDEN_PATH = REPO_ROOT / "tests" / "golden" / "engine_profiles_v1.json"
ZSTD_MAGIC_HEX = "28b52ffd"


def _load_golden():
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))


def test_golden_runtime_metadata_has_determinism_marker():
    golden = _load_golden()
    runtime = golden.get("runtime", {})
    assert runtime.get("python")
    assert runtime.get("zstandard")
    assert runtime.get("xxhash")
    # Golden generation must record deterministic mode for review/debugging.
    assert runtime.get("liquefy_deterministic") in {"1", True}
    assert runtime.get("lsec_ver") == 2
    assert int(runtime.get("lsec_kdf_iters", 0)) > 0


def _set_profile(monkeypatch, profile: str):
    monkeypatch.setenv("LIQUEFY_DETERMINISTIC", "1")
    if profile == "default":
        monkeypatch.delenv("LIQUEFY_PROFILE", raising=False)
    else:
        monkeypatch.setenv("LIQUEFY_PROFILE", profile)


@pytest.mark.parametrize(
    "engine_id,fixture_rel,profile,expected",
    [
        (
            fixture["engine_id"],
            fixture["fixture"],
            profile,
            pdata,
        )
        for fixture in _load_golden()["fixtures"]
        for profile, pdata in fixture["profiles"].items()
    ],
)
def test_roundtrip_byteperfect(monkeypatch, engine_id, fixture_rel, profile, expected):
    _set_profile(monkeypatch, profile)
    engine = get_engine_instance(engine_id)
    assert engine is not None

    raw = (REPO_ROOT / fixture_rel).read_bytes()
    compressed = engine.compress(raw)
    restored = engine.decompress(compressed)

    # Critical invariant: bit-perfect roundtrip
    assert restored == raw, "roundtrip corruption detected"
    assert hashlib.sha256(restored).hexdigest() == expected["restored_sha256"]

    # Compressed size varies across OS/compiler/zstd versions — warn, don't fail
    expected_bytes = expected["output_bytes"]
    actual_bytes = len(compressed)
    if actual_bytes != expected_bytes:
        import warnings
        warnings.warn(
            f"compressed size {actual_bytes} != golden {expected_bytes} "
            f"(delta {actual_bytes - expected_bytes:+d}, likely zstd version difference)"
        )
    expected_prefix = str(expected["prefix_hex"])
    if expected_prefix.startswith(ZSTD_MAGIC_HEX):
        # zstd frame payload bytes can change across encoder versions; assert magic only.
        assert compressed[:4].hex() == ZSTD_MAGIC_HEX
    else:
        # Custom container paths: assert container preamble, not arbitrary payload bytes.
        assert compressed[:4].hex() == expected_prefix[:8]
