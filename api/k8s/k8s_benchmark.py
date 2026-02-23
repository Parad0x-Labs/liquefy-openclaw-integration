#!/usr/bin/env python3
import time
import zstandard as zstd
import gzip
import os
import random
import sys

# Add path to load the champion
sys.path.append(os.path.abspath("production_engines/k8s"))
from K8sChampion_Complex_Unicorn import K8sUnicorn
from K8sChampion_MaxSpeed_Nitro import K8sNitroUnicorn

def gen_k8s_logs(count=10000):
    lines = []
    # K8s JSON Log Template
    base_json = '{"log":"[%s] %s user_id=%d request_id=%s","stream":"%s","time":"2023-12-25T12:%02d:%02d.000000Z"}\n'
    levels = ["INFO", "WARN", "ERROR", "DEBUG"]
    msgs = ["User login successful", "Failed to connect to database", "Processing transaction", "Cache miss for key", "Sending email notification"]
    streams = ["stdout", "stderr"]

    for i in range(count):
        # 1. Standard JSON log
        lvl = random.choice(levels)
        msg = random.choice(msgs)
        uid = random.randint(1000, 9999)
        rid = hex(random.getrandbits(32))[2:]
        stream = random.choice(streams)
        m = i % 60
        s = random.randint(0, 59)

        line = (base_json % (lvl, msg, uid, rid, stream, m, s)).encode()
        lines.append(line)

        # 2. Mixed-in raw text (Stack traces, non-JSON output)
        if i % 200 == 0:
            lines.append(b"CRITICAL: Failed to start server - Out of Memory\n")
            lines.append(b"java.lang.OutOfMemoryError: Java heap space\n")
            lines.append(b"    at com.enterprise.App.start(App.java:154)\n")
            lines.append(b"    at com.enterprise.Main.main(Main.java:23)\n")

    return b"".join(lines)

def benchmark_k8s():
    print(f"{' K8S CHAMPION SHOWDOWN ':=^70}")
    data = gen_k8s_logs(15000)
    print(f">>>> DATASET: K8s Mixed Logs ({len(data):,} bytes)")
    print(f"{'Codec':<35} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
    print("-" * 80)

    results = []

    # 1. Gzip -9
    t0 = time.time()
    c = gzip.compress(data, compresslevel=9)
    results.append(("Gzip -9", len(c), time.time()-t0))

    # 2. Zstd -19
    t0 = time.time()
    c = zstd.ZstdCompressor(level=19).compress(data)
    results.append(("Zstd -19", len(c), time.time()-t0))

    # 3. K8s UNICORN
    codec_k = K8sUnicorn(level=22)
    t0 = time.time()
    c_k = codec_k.compress(data)
    t_k = time.time() - t0

    # Lossless verification
    rec_k = codec_k.decompress(c_k)
    if rec_k != data:
        print("ERROR: K8S UNICORN NOT LOSSLESS!")
        # Debug small part
        for i in range(min(len(data), len(rec_k))):
            if data[i] != rec_k[i]:
                print(f"Mismatch at {i}: {data[i:i+20]} != {rec_k[i:i+20]}")
                break

    results.append(("[CHAMPION: K8s Unicorn]", len(c_k), t_k))

    # 4. K8s NITRO
    codec_n = K8sNitroUnicorn(level=6)
    t0 = time.time()
    c_n = codec_n.compress(data)
    t_n = time.time() - t0
    # Lossless verification
    rec_n = codec_n.decompress(c_n)
    if rec_n != data: print("ERROR: K8S NITRO NOT LOSSLESS!")
    results.append(("[CHAMPION: K8s Nitro Speed]", len(c_n), t_n))

    for name, size, duration in sorted(results, key=lambda x: x[1]):
        ratio = len(data) / max(size, 1)
        speed = len(data) / max(duration, 0.001) / 1024 / 1024
        print(f"{name:<35} | {size:>12,} | {ratio:>9.1f}x | {speed:>9.1f} MB/s")

if __name__ == "__main__":
    benchmark_k8s()
