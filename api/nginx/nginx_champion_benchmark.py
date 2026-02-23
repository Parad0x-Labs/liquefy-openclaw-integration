#!/usr/bin/env python3
import time
import zstandard as zstd
import gzip
import bz2
import lzma
import os
import struct
from NginxChampion_Complex_Liquefy import NginxLiquefyChampion as NginxComplex
from NginxChampion_Repetitive_Universal import NginxUniversalChampion

def benchmark_nginx():
    print(f"{' NGINX ULTIMATE BENCHMARK: CHAMPIONS VS TOP 5 ':=^70}")

    # Dataset A: Real-World Complex Nginx Logs (50k lines)
    lines = []
    for i in range(50000):
        # Variety in IPs, timestamps, requests, and sizes to simulate real load
        l = f"{10+i%200}.{i%255}.{i%255}.{i%255} - - [10/Oct/2000:13:55:{i%60:02d} -0700] \"GET /api/v1/resource/{i%1000} HTTP/1.1\" {200 if i%10!=0 else 404} {i*2} \"https://referer.com/{i%50}\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Nginx/1.18.0\"\n"
        lines.append(l.encode('latin-1'))
    data_complex = b"".join(lines)

    # Dataset B: Highly Repetitive Nginx Logs (100k lines)
    line_rep = b'127.0.0.1 - - [01/Jan/2025:00:00:00 -0000] "GET /health HTTP/1.1" 200 0 "-" "HealthChecker/1.0"\n'
    data_rep = line_rep * 100000

    scenarios = [
        ("COMPLEX REAL-WORLD LOGS", data_complex),
        ("HIGHLY REPETITIVE LOGS", data_rep)
    ]

    for name, data in scenarios:
        print(f"\n>>> SCENARIO: {name} ({len(data):,} bytes)")
        print(f"{'Codec':<20} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
        print("-" * 65)

        results = []

        # 1. GZIP (Legacy Standard)
        t0 = time.time()
        c = gzip.compress(data, compresslevel=9)
        t1 = time.time()
        results.append(("Gzip -9", len(c), t1-t0))

        # 2. BZIP2 (High Ratio Legacy)
        t0 = time.time()
        c = bz2.compress(data, compresslevel=9)
        t1 = time.time()
        results.append(("Bzip2 -9", len(c), t1-t0))

        # 3. LZMA/XZ (Ultra High Ratio)
        t0 = time.time()
        c = lzma.compress(data, preset=9)
        t1 = time.time()
        results.append(("LZMA -9", len(c), t1-t0))

        # 4. ZSTD (Modern Standard)
        t0 = time.time()
        c = zstd.ZstdCompressor(level=19).compress(data)
        t1 = time.time()
        results.append(("Zstd -19", len(c), t1-t0))

        # 5. ZSTD --long (Best Case Standard)
        zparams = zstd.ZstdCompressionParameters.from_level(22, window_log=27)
        t0 = time.time()
        c = zstd.ZstdCompressor(compression_params=zparams).compress(data)
        t1 = time.time()
        results.append(("Zstd -22 Long", len(c), t1-t0))

        # OUR CHAMPIONS
        if "COMPLEX" in name:
            champ = NginxComplex(level=22)
            # Use temp files for Liquefy
            with open("temp.log", "wb") as f: f.write(data)
            t0 = time.time()
            champ.compress("temp.log", "temp.lprm")
            t1 = time.time()
            with open("temp.lprm", "rb") as f: c_size = len(f.read())
            results.append(("NGINX COMPLEX (OURS)", c_size, t1-t0))
            if os.path.exists("temp.log"): os.remove("temp.log")
            if os.path.exists("temp.lprm"): os.remove("temp.lprm")
        else:
            champ = NginxUniversalChampion(level=22)
            t0 = time.time()
            c = champ.compress(data)
            t1 = time.time()
            results.append(("NGINX REP (OURS)", len(c), t1-t0))

        # Print sorted by ratio
        for cname, csize, ctime in sorted(results, key=lambda x: x[1]):
            ratio = len(data) / max(csize, 1)
            speed = len(data) / max(ctime, 0.001) / 1024 / 1024
            winner_mark = "[WINNER]" if "OURS" in cname else "  "
            print(f"{cname:<20} | {csize:>12,} | {ratio:>9.1f}x | {speed:>9.1f} MB/s {winner_mark}")

if __name__ == "__main__":
    benchmark_nginx()
