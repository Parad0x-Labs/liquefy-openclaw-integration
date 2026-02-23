"""Targeted tests for guarded legacy columnar encode paths."""
import json

from orchestrator.engine_map import get_engine_instance

ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def test_vpcflow_legacy_columnar_encoder_roundtrips():
    engine = get_engine_instance("liquefy-vpcflow-v1")
    assert engine is not None

    line1 = (
        b"2 123456789012 eni-1234567 10.0.0.1 10.0.0.2 443 51515 6 "
        b"10 840 1700000000 1700000001 ACCEPT OK\n"
    )
    line2 = (
        b"2 123456789012 eni-1234567 10.0.0.3 10.0.0.4 80 12345 6 "
        b"5 420 1700000002 1700000003 REJECT OK\n"
    )
    line3 = (
        b"2 123456789012 eni-7654321 172.16.0.1 172.16.0.2 22 54321 6 "
        b"3 180 1700000004 1700000005 ACCEPT OK\n"
    )
    raw = (line1 + line2 + line3) * 4
    compressed = engine._compress_legacy_columnar(raw)

    assert compressed is not None
    assert compressed.startswith(b"VPC\x01")
    assert not compressed.startswith(b"VPC\x01RZ")
    assert engine.decompress(compressed) == raw


def test_vpcflow_falls_back_to_raw_zstd_on_noncanonical_spacing():
    engine = get_engine_instance("liquefy-vpcflow-v1")
    assert engine is not None

    line = (
        b"2  123456789012 eni-1234567 10.0.0.1 10.0.0.2 443 55555 6 "
        b"10 2048 1700000000 1700000010 ACCEPT OK\n"
    )
    raw = line * 4
    compressed = engine.compress(raw)

    assert compressed.startswith(ZSTD_MAGIC)
    assert engine.decompress(compressed) == raw


def test_hypernebula_canonical_jsonl_columnar_encoder_roundtrips():
    engine = get_engine_instance("liquefy-json-hypernebula-v1")
    assert engine is not None

    rows = []
    for i in range(16):
        rows.append({
            "ts": f"2026-02-23T00:00:{i:02d}Z",
            "tenant": f"t{i % 4}",
            "seq": i,
            "ok": (i % 2 == 0),
            "meta": {
                "latency_ms": 100 + i,
                "service": ["auth", "search", "memory", "trace"][i % 4],
            },
        })
    lines = [json.dumps(r, separators=(",", ":")).encode("utf-8") for r in rows]
    raw = b"\n".join(lines) + b"\n"
    assert len(raw) >= 512

    compressed = engine._compress_canonical_jsonl_columnar(raw)
    assert compressed is not None
    assert compressed.startswith(b"HY2\x01")
    assert engine.decompress(compressed) == raw


def test_hypernebula_falls_back_for_noncanonical_jsonl_spacing():
    engine = get_engine_instance("liquefy-json-hypernebula-v1")
    assert engine is not None

    rows = []
    for i in range(16):
        rows.append({"a": i, "b": {"x": i % 3, "y": True}, "msg": "hello"})
    # default json.dumps() emits spaces after separators; guarded columnar path must refuse it
    raw = b"".join(json.dumps(r).encode("utf-8") + b"\n" for r in rows)
    assert len(raw) >= 512

    compressed = engine.compress(raw)
    assert compressed.startswith(ZSTD_MAGIC)
    assert engine.decompress(compressed) == raw
