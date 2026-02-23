#!/usr/bin/env python3
import time
import json
import zstandard as zstd
import gzip
import os
import lzma
from JsonChampion_Repetitive_Universal import JsonUniversalChampion

def benchmark_json_repetition():
    print(f"{' JSON REPETITIVE SHOWDOWN: CHAMPION VS TOP COMPETITION ':=^75}")

    # Dataset: High-Volume Repetitive JSON Heartbeats
    # 50,000 lines of heartbeats, mostly identical with occasional variations
    heartbeat = b'{"status": "UP", "service": "auth-api", "node": "worker-01", "load": 0.05, "timestamp": 1735123456}\n'
    variation = b'{"status": "UP", "service": "auth-api", "node": "worker-02", "load": 0.12, "timestamp": 1735123457}\n'

    lines = []
    for i in range(50000):
        if i % 1000 == 0:
            lines.append(variation)
        else:
            lines.append(heartbeat)
    data = b"".join(lines)

    print(f">>> DATASET: Repetitive JSON Heartbeats ({len(data):,} bytes)")
    print(f"{'Codec':<25} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
    print("-" * 70)

    results = []

    # 1. Gzip -9
    t0 = time.time()
    c = gzip.compress(data, compresslevel=9)
    t1 = time.time()
    results.append(("Gzip -9", len(c), t1-t0))

    # 2. LZMA -9 (XZ)
    t0 = time.time()
    c = lzma.compress(data, preset=9)
    t1 = time.time()
    results.append(("LZMA -9 (XZ)", len(c), t1-t0))

    # 3. Zstd -19
    t0 = time.time()
    c = zstd.ZstdCompressor(level=19).compress(data)
    t1 = time.time()
    results.append(("Zstd -19", len(c), t1-t0))

    # 4. Zstd -22 --long
    zparams = zstd.ZstdCompressionParameters.from_level(22, window_log=27)
    t0 = time.time()
    c = zstd.ZstdCompressor(compression_params=zparams).compress(data)
    t1 = time.time()
    results.append(("Zstd -22 Long", len(c), t1-t0))

    # 5. OUR CHAMPION (Repetitive Universal)
    codec = JsonUniversalChampion(level=22)
    t0 = time.time()
    c = codec.compress(data)
    t1 = time.time()
    results.append(("JSON REP CHAMPION (OURS)", len(c), t1-t0))

    # Print Results Sorted by Size
    for name, size, duration in sorted(results, key=lambda x: x[1]):
        ratio = len(data) / max(size, 1)
        speed = len(data) / max(duration, 0.001) / 1024 / 1024
        winner = "[WINNER]" if "OURS" in name else ""
        print(f"{name:<25} | {size:>12,} | {ratio:>9.1f}x | {speed:>9.1f} MB/s {winner}")

if __name__ == "__main__":
    benchmark_json_repetition()
