#!/usr/bin/env python3
import time
import json
import zstandard as zstd
import os
from JsonChampion_Complex_Compact import JsonChampion

def benchmark_json():
    print(f"{' JSON CHAMPION BENCHMARK ':=^60}")

    # Dataset: Sequential JSON Telemetry (5000 records)
    records = []
    ts = 1600000000
    for i in range(5000):
        ts += 10
        records.append({
            "ts": ts,
            "id": 1000 + i,
            "val": 50.5 + (i % 10),
            "status": "OK",
            "meta": {"prio": 1, "load": i % 100}
        })
    data = b"\n".join(json.dumps(r).encode('utf-8') for r in records)

    codec = JsonChampion(level=22)

    # 1. Zstd
    t0 = time.time()
    z_comp = zstd.ZstdCompressor(level=19).compress(data)
    t_zstd = time.time() - t0

    # 2. Our Champion
    with open("test.json", "wb") as f: f.write(data)
    t0 = time.time()
    c_data = codec.compress(data)
    t_champ = time.time() - t0

    # Lossless check
    rec = codec.decompress(c_data)
    is_lossless = (rec == data)
    if not is_lossless:
        print(f"DEBUG: Original len {len(data)}, Rec len {len(rec)}")
        for i in range(min(len(data), len(rec))):
            if data[i] != rec[i]:
                print(f"Mismatch at {i}: {data[i:i+20]!r} vs {rec[i:i+20]!r}")
                break

    size_zstd = len(z_comp)
    size_champ = len(c_data)

    print(f"Raw Size:   {len(data):,} bytes")
    print(f"Zstd -19:   {size_zstd:,} bytes ({(len(data)/size_zstd):.1f}x)")
    print(f"Champion:   {size_champ:,} bytes ({(len(data)/size_champ):.1f}x)")
    print(f"Lossless:   {'PASS' if is_lossless else 'FAIL'}")

    if size_champ < size_zstd:
        print(f"RESULT: CHAMPION WINS (+{(1 - size_champ/size_zstd)*100:.1f}%)")
    else:
        print(f"RESULT: CHAMPION TRAILS")

if __name__ == "__main__":
    benchmark_json()
