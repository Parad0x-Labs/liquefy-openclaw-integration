#!/usr/bin/env python3
import time
import zstandard as zstd
import gzip
import os
import random

# Import the Final Fleet
from SqlChampion_MaxRatio_Unicorn import SqlUnicorn
from SqlChampion_MaxSpeed_Native import SqlNativeChampion
from SqlChampion_Repetitive_Universal import SqlUniversalChampion

def gen_sql_data(count=5000):
    users = [b"'alice'", b"'bob'", b"'charlie'", b"'david'", b"'eve'"]
    tables = [b"`users`", b"`orders`", b"`products`", b"`sessions`", b"`logs`"]

    lines = []
    ts = 1735120800
    for i in range(count):
        ts += random.randint(1, 60)
        u = random.choice(users)
        t = random.choice(tables)
        id_val = random.randint(1, 100000)

        lines.append(f"# Time: {time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(ts))}.000000Z\n".encode())
        lines.append(f"# User@Host: root[root] @ localhost []  Id: {random.randint(1,100)}\n".encode())
        lines.append(f"# Query_time: {random.uniform(0.5, 5.0):.6f}  Lock_time: 0.000000 Rows_sent: {random.randint(0,1000)}  Rows_examined: {random.randint(1000,100000)}\n".encode())
        lines.append(f"SET timestamp={ts};\n".encode())

        op = random.choice([0, 1, 2])
        if op == 0: # SELECT
            lines.append(f"SELECT * FROM {t.decode()} WHERE id = {id_val} AND owner = {u.decode()};\n".encode())
        elif op == 1: # UPDATE
            lines.append(f"UPDATE {t.decode()} SET last_login = {ts} WHERE id = {id_val};\n".encode())
        else: # INSERT
            lines.append(f"INSERT INTO {t.decode()} (id, val, user) VALUES ({id_val}, {random.randint(0,100)}, {u.decode()});\n".encode())

    return b"".join(lines)

def benchmark_sql():
    print(f"{' SQL CHAMPION FLEET SHOWDOWN ':=^70}")
    data = gen_sql_data(10000)
    print(f">>> DATASET: MySQL Mixed Slow Logs ({len(data):,} bytes)")
    print(f"{'Codec':<35} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
    print("-" * 80)

    results = []

    # 1. Gzip -9 (Industry Standard)
    t0 = time.time()
    c = gzip.compress(data, compresslevel=9)
    results.append(("Gzip -9 (Standard)", len(c), time.time()-t0))

    # 2. Zstd -19 (Strong Competitor)
    t0 = time.time()
    c = zstd.ZstdCompressor(level=19).compress(data)
    results.append(("Zstd -19 (Strong)", len(c), time.time()-t0))

    # 3. CHAMPION: MAX RATIO (UNICORN)
    codec_u = SqlUnicorn(level=22)
    t0 = time.time()
    c_u = codec_u.compress(data)
    t_u = time.time() - t0
    rec_u = codec_u.decompress(c_u)
    assert rec_u == data, "Unicorn Lossless Fail"
    results.append(("[CHAMPION: Max-Ratio (Unicorn)]", len(c_u), t_u))

    # 4. CHAMPION: MAX SPEED (NATIVE C)
    codec_n = SqlNativeChampion(level=3)
    t0 = time.time()
    c_n = codec_n.compress(data)
    t_n = time.time() - t0
    rec_n = codec_n.decompress(c_n)
    assert rec_n == data, "Native Lossless Fail"
    results.append(("[CHAMPION: Max-Speed (Native C)]", len(c_n), t_n))

    # 5. CHAMPION: REPETITIVE (UNIVERSAL)
    codec_r = SqlUniversalChampion(level=3)
    t0 = time.time()
    c_r = codec_r.compress(data)
    t_r = time.time() - t0
    results.append(("[CHAMPION: Repetitive (Universal)]", len(c_r), t_r))

    for name, size, duration in sorted(results, key=lambda x: x[1]):
        ratio = len(data) / max(size, 1)
        speed = len(data) / max(duration, 0.001) / 1024 / 1024
        print(f"{name:<35} | {size:>12,} | {ratio:>9.1f}x | {speed:>9.1f} MB/s")

if __name__ == "__main__":
    benchmark_sql()
