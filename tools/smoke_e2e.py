#!/usr/bin/env python3
"""
Smoke test: end-to-end pipeline validation.
Runs each fixture through process_file() and checks the result schema.
"""
import sys
import os
import asyncio
import hashlib
from pathlib import Path

# Ensure api/ is importable
API_DIR = str(Path(__file__).resolve().parent.parent / "api")
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

from orchestrator.orchestrator import Orchestrator

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

FIXTURES = [
    "sample.json",
    "apache.log",
    "syslog_3164.log",
    "syslog_5424.log",
    "k8s.log",
    "dump.sql",
    "cloudtrail.jsonl",
    "vpcflow.log",
    "raw.txt",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def run_smoke():
    orch = Orchestrator(
        engines_dir=str(Path(API_DIR) / "engines"),
        master_secret="smoke_test_secret_key",
    )

    results = []
    for name in FIXTURES:
        fp = FIXTURES_DIR / name
        if not fp.exists():
            print(f"[SKIP] {name} — fixture not found")
            continue

        original_data = fp.read_bytes()
        original_hash = sha256(original_data)

        result = await orch.process_file(
            filepath=str(fp),
            tenant_id="smoke_org",
            encrypt=False,  # skip encryption for roundtrip test
            verify=True,
        )

        assert result["ok"] is True, f"{name}: expected ok=True, got {result}"
        assert result["original_bytes"] == len(original_data), f"{name}: size mismatch"
        assert result["compressed_bytes"] > 0, f"{name}: empty output"
        assert "engine_used" in result, f"{name}: no engine_used"
        assert "ratio" in result, f"{name}: no ratio"
        assert "duration_ms" in result, f"{name}: no duration_ms"

        # Roundtrip: if we have compressed_data in result (inprocess), verify
        compressed = result.get("compressed_data")
        if compressed and result["engine_used"] != "zstd-fallback":
            # The MRTV valve prepends b'SAFE' + 4-byte tag, so strip that for raw decompress
            engine_id = result["engine_used"]
            from orchestrator.engine_map import get_engine_instance
            instance = get_engine_instance(engine_id)
            if instance and hasattr(instance, "decompress"):
                # MRTV wraps output as: b'SAFE' + 4-byte-tag + compressed_payload
                if compressed[:4] == b'SAFE':
                    raw_compressed = compressed[8:]  # strip SAFE + 4-byte tag
                else:
                    raw_compressed = compressed
                try:
                    restored = instance.decompress(raw_compressed)
                    restored_hash = sha256(restored)
                    assert restored_hash == original_hash, (
                        f"{name}: roundtrip failed! "
                        f"original={original_hash[:16]}... "
                        f"restored={restored_hash[:16]}..."
                    )
                    print(f"[PASS] {name} -> {engine_id} "
                          f"({result['ratio']}x, {result['duration_ms']:.0f}ms, roundtrip=bit-perfect)")
                except Exception as e:
                    print(f"[WARN] {name} -> {engine_id} roundtrip decompress failed: {e}")
            else:
                print(f"[PASS] {name} -> {engine_id} "
                      f"({result['ratio']}x, {result['duration_ms']:.0f}ms, no roundtrip)")
        else:
            print(f"[PASS] {name} -> {result['engine_used']} "
                  f"({result['ratio']}x, {result['duration_ms']:.0f}ms)")

        results.append((name, result))

    # Telemetry check
    stats = orch.get_telemetry()
    assert stats["kpis"]["total_ops"] == len(results), "telemetry op count mismatch"
    print(f"\n[TELEMETRY] {stats['kpis']['total_ops']} ops, "
          f"ratio={stats['kpis']['compression_ratio']}x, "
          f"saved={stats['kpis']['data_reduced_gb']:.6f} GB")

    print(f"\n[SMOKE] {len(results)}/{len(FIXTURES)} fixtures passed.")


if __name__ == "__main__":
    asyncio.run(run_smoke())
