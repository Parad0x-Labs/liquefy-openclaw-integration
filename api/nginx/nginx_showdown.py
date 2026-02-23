#!/usr/bin/env python3
import time
import zstandard as zstd
import os
from apache_universal import ApacheUniversal
from apache_nuclear import ApacheNuclear
from liquefy import LiquefyLogPrism

def run_nginx_benchmark():
    print(f"{' NGINX SHOWDOWN: UNIVERSAL vs NUCLEAR vs LIQUEFY vs ZSTD ':=^60}")

    # Load Nginx Data
    log_file = "nginx_access.log"
    if os.path.exists(log_file):
        with open(log_file, "rb") as f:
            data_nginx = f.read()
    else:
        print(f"File {log_file} not found. Creating synthetic Nginx data.")
        lines = []
        for i in range(5000):
            l = f"127.0.0.1 - - [10/Oct/2000:13:55:{i%60:02d} -0700] \"GET /nginx_test{i}.html HTTP/1.1\" 200 {i*5} \"-\" \"Nginx/1.18.0\"\n"
            lines.append(l.encode())
        data_nginx = b"".join(lines)

    scenarios = [
        ("NGINX LOG DATA", data_nginx)
    ]

    universal = ApacheUniversal(level=22)
    nuclear = ApacheNuclear(level=22)
    liquefy = LiquefyLogPrism(zstd_level=22)

    for name, data in scenarios:
        print(f"\n>>> Scenario: {name} ({len(data):,} bytes)")

        # 0. Prepare temp files for Liquefy
        with open("temp_nginx_input.log", "wb") as f: f.write(data)

        # 1. ZSTD --long
        zparams = zstd.ZstdCompressionParameters.from_level(22, window_log=27)
        cctx_zstd = zstd.ZstdCompressor(compression_params=zparams)
        t0 = time.time()
        z_comp = cctx_zstd.compress(data)
        t_zstd = time.time() - t0

        # 2. Universal
        t0 = time.time()
        try:
            u_comp, _, _ = universal.compress(data)
            t_universal = time.time() - t0
            u_rec = universal.decompress(u_comp)
            u_lossless = (u_rec == data)
        except Exception as e:
            print(f"Universal Error: {e}")
            u_comp, t_universal, u_lossless = b"", 0, False

        # 3. Nuclear
        t0 = time.time()
        try:
            n_comp, _, n_bloom = nuclear.compress(data)
            t_nuclear = time.time() - t0
            n_rec = nuclear.decompress(n_comp)
            n_lossless = (n_rec == data)
        except Exception as e:
            print(f"Nuclear Error: {e}")
            n_comp, n_bloom, t_nuclear, n_lossless = b"", b"", 0, False

        # 4. Liquefy
        t0 = time.time()
        try:
            liquefy.compress("temp_nginx_input.log", "temp_nginx_output.lprm")
            t_liquefy = time.time() - t0
            with open("temp_nginx_output.lprm", "rb") as f: l_comp = f.read()
            liquefy.decompress("temp_nginx_output.lprm", "temp_nginx_dec.log")
            with open("temp_nginx_dec.log", "rb") as f: l_rec = f.read()
            l_lossless = (l_rec == data)
        except Exception as e:
            print(f"Liquefy Error: {e}")
            l_comp, t_liquefy, l_lossless = b"", 0, False

        # Results
        print(f"{'Codec':<15} | {'Size':>10} | {'Factor':>8} | {'Speed':>10} | {'Lossless'}")
        print("-" * 75)

        def print_row(name, comp_size, t, lossless):
            factor = len(data) / max(comp_size, 1)
            speed = len(data) / max(t, 0.001) / 1024 / 1024
            print(f"{name:<15} | {comp_size:>10,} | {factor:>7.1f}x | {speed:>7.1f} MB/s | {lossless}")

        print_row("Zstd Long -22", len(z_comp), t_zstd, "YES")
        print_row("Universal", len(u_comp), t_universal, "YES" if u_lossless else "FAIL")
        print_row("Nuclear", len(n_comp) + len(n_bloom), t_nuclear, "YES" if n_lossless else "FAIL")
        print_row("Liquefy V15", len(l_comp), t_liquefy, "YES" if l_lossless else "FAIL")

        # Cleanup
        for f in ["temp_nginx_input.log", "temp_nginx_output.lprm", "temp_nginx_dec.log"]:
            if os.path.exists(f): os.remove(f)

if __name__ == "__main__":
    run_nginx_benchmark()
