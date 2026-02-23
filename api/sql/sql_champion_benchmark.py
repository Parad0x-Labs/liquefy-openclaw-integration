#!/usr/bin/env python3
import time
import zstandard as zstd
import gzip
import os
import random
from SqlChampion_Complex_Liquefy_V3 import SqlLiquefyChampion as SqlLiquefyChampionV3
from SqlChampion_Complex_Native import SqlNativeChampion
from SqlChampion_Repetitive_Universal import SqlUniversalChampion
from SqlChampion_Titan_User import SqlTitan
from SqlChampion_Unicorn_User import SqlUnicorn

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

        # MySQL Slow Log Format
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
    print(f"{' SQL CHAMPION SHOWDOWN ':=^70}")
    data = gen_sql_data(5000)
    print(f">>> DATASET: MySQL Slow Logs ({len(data):,} bytes)")
    print(f"{'Codec':<30} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
    print("-" * 75)

    results = []

    # 1. Gzip -9
    t0 = time.time()
    c = gzip.compress(data, compresslevel=9)
    results.append(("Gzip -9", len(c), time.time()-t0))

    # 2. Zstd -19
    t0 = time.time()
    c = zstd.ZstdCompressor(level=19).compress(data)
    results.append(("Zstd -19", len(c), time.time()-t0))

    # 3. SQL CHAMPION: Complex (Speed Tuned)
    codec3 = SqlLiquefyChampionV3(level=3)
    t0 = time.time()
    c3 = codec3.compress(data)
    t_champ3 = time.time() - t0
    results.append(("CHAMPION: SQL Complex (Speed)", len(c3), t_champ3))

    # 4. SQL CHAMPION: Repetitive
    codec_r = SqlUniversalChampion(level=3)
    t0 = time.time()
    c_r = codec_r.compress(data)
    t_champ_r = time.time() - t0
    results.append(("CHAMPION: SQL Repetitive", len(c_r), t_champ_r))

    # 5. SQL CHAMPION: C-POWERED NATIVE
    codec_n = SqlNativeChampion(level=3)
    t0 = time.time()
    c_n = codec_n.compress(data)
    t_champ_n = time.time() - t0
    # Lossless check
    rec_n = codec_n.decompress(c_n)
    if rec_n != data: print("ERROR: NATIVE SQL CHAMPION NOT LOSSLESS!")
    results.append(("CHAMPION: SQL Native (C)", len(c_n), t_champ_n))

    # 6. YOUR UNICORN CHAMPION (Safe Titan)
    codec_u = SqlUnicorn(level=22)
    t0 = time.time()
    c_u = codec_u.compress(data)
    t_champ_u = time.time() - t0
    # Lossless check
    rec_u = codec_u.decompress(c_u)
    if rec_u != data: print("ERROR: UNICORN SQL CHAMPION NOT LOSSLESS!")
    results.append(("CHAMPION: SQL Unicorn (V16)", len(c_u), t_champ_u))

    for name, size, duration in sorted(results, key=lambda x: x[1]):
        ratio = len(data) / max(size, 1)
        speed = len(data) / max(duration, 0.001) / 1024 / 1024
        winner = "[WINNER]" if "CHAMPION" in name else ""
        print(f"{name:<30} | {size:>12,} | {ratio:>9.1f}x | {speed:>9.1f} MB/s {winner}")

if __name__ == "__main__":
    benchmark_sql()
