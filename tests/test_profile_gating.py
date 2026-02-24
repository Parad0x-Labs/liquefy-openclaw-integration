#!/usr/bin/env python3
"""Profile gating tests for structured path selection across profiles."""
from pathlib import Path

from orchestrator.engine_map import get_engine_instance


REPO_ROOT = Path(__file__).resolve().parent.parent
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def _set_profile(monkeypatch, profile: str):
    monkeypatch.setenv("LIQUEFY_DETERMINISTIC", "1")
    if profile == "default":
        monkeypatch.delenv("LIQUEFY_PROFILE", raising=False)
    else:
        monkeypatch.setenv("LIQUEFY_PROFILE", profile)


def test_hypernebula_default_profile_can_use_hy2_on_hyperfriendly_jsonl(monkeypatch):
    raw = (REPO_ROOT / "tests" / "fixtures" / "golden_inputs" / "generic_json_hyperfriendly_1024.jsonl").read_bytes()

    _set_profile(monkeypatch, "default")
    default_engine = get_engine_instance("liquefy-json-hypernebula-v1")
    c_default = default_engine.compress(raw)
    assert c_default.startswith(ZSTD_MAGIC) or c_default.startswith(b"HY2\x01")

    _set_profile(monkeypatch, "ratio")
    ratio_engine = get_engine_instance("liquefy-json-hypernebula-v1")
    c_ratio = ratio_engine.compress(raw)
    assert c_ratio.startswith(b"HY2\x01")

    _set_profile(monkeypatch, "speed")
    speed_engine = get_engine_instance("liquefy-json-hypernebula-v1")
    c_speed = speed_engine.compress(raw)
    assert c_speed.startswith(ZSTD_MAGIC)


def test_vpcflow_ratio_profile_can_activate_vpc_legacy_path_on_canonical_fixture(monkeypatch):
    raw = (REPO_ROOT / "tests" / "fixtures" / "golden_inputs" / "vpcflow_canonical_256.log").read_bytes()

    _set_profile(monkeypatch, "default")
    c_default = get_engine_instance("liquefy-vpcflow-v1").compress(raw)
    assert c_default.startswith(ZSTD_MAGIC)

    _set_profile(monkeypatch, "ratio")
    c_ratio = get_engine_instance("liquefy-vpcflow-v1").compress(raw)
    assert c_ratio.startswith(b"VPC\x01")


def test_hypernebula_longline_jsonl_ratio_profile_roundtrips_safely(monkeypatch):
    raw = (REPO_ROOT / "tests" / "fixtures" / "jsonl" / "generic_json_longline_16.jsonl").read_bytes()
    assert not raw.endswith(b"\n")

    _set_profile(monkeypatch, "ratio")
    ratio_engine = get_engine_instance("liquefy-json-hypernebula-v1")
    c_public = ratio_engine.compress(raw)
    assert c_public.startswith(ZSTD_MAGIC) or c_public.startswith(b"HY2\x01")
    assert ratio_engine.decompress(c_public) == raw


def test_hypernebula_hy2_internal_path_handles_no_trailing_newline_on_canonical_jsonl(monkeypatch):
    raw_with_nl = (REPO_ROOT / "tests" / "fixtures" / "golden_inputs" / "generic_json_hyperfriendly_64.jsonl").read_bytes()
    assert raw_with_nl.endswith(b"\n")
    raw = raw_with_nl[:-1]
    assert not raw.endswith(b"\n")

    _set_profile(monkeypatch, "ratio")
    ratio_engine = get_engine_instance("liquefy-json-hypernebula-v1")
    c_hy2 = ratio_engine._compress_canonical_jsonl_columnar(raw)
    assert c_hy2 is not None
    assert c_hy2.startswith(b"HY2\x01")
    assert ratio_engine.decompress(c_hy2) == raw


def test_vpcflow_custom_order_fixture_roundtrips_across_profiles(monkeypatch):
    raw = (REPO_ROOT / "tests" / "fixtures" / "vpcflow" / "vpcflow_custom_order_64.log").read_bytes()
    assert raw.endswith(b"\n")

    for profile in ("default", "ratio", "speed"):
        _set_profile(monkeypatch, profile)
        engine = get_engine_instance("liquefy-vpcflow-v1")
        comp = engine.compress(raw)
        assert engine.decompress(comp) == raw
        if profile in ("default", "speed"):
            assert comp.startswith(ZSTD_MAGIC)
        else:
            assert comp.startswith(ZSTD_MAGIC) or comp.startswith(b"VPC\x01")
