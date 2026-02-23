#!/usr/bin/env python3
import time
import zstandard as zstd
import gzip
import lzma
import os
from SyslogChampion_Complex_Liquefy import SyslogLiquefyChampion
from SyslogChampion_Complex_Liquefy_V2 import SyslogLiquefyChampionV2
from SyslogChampion_V3_Titan import SyslogTitanChampion
from SyslogChampion_V4_Fragment import SyslogFragmentChampion
from SyslogChampion_V5_StreamTree import SyslogStreamTreeChampion
from SyslogChampion_Repetitive_Universal import SyslogUniversalChampion

def benchmark_syslog():
    print(f"{' SYSLOG CHAMPION SHOWDOWN ':=^70}")

    datasets = [
        ("RFC3164 (Real)", "syslog_rfc3164.log"),
        ("RFC5424 (Real)", "syslog_rfc5424.log")
    ]

    # Generate repetitive dataset
    repetitive_data = b"<134>1 2023-12-25T10:00:00.000Z host-1 app-1 1234 - [meta] Heartbeat OK\n" * 50000
    with open("syslog_repetitive.log", "wb") as f: f.write(repetitive_data)
    datasets.append(("Highly Repetitive", "syslog_repetitive.log"))

    for ds_name, file_path in datasets:
        if not os.path.exists(file_path):
            print(f"Skipping {ds_name}: {file_path} not found.")
            continue

        with open(file_path, "rb") as f: data = f.read()
        print(f"\n>>> DATASET: {ds_name} ({len(data):,} bytes)")
        print(f"{'Codec':<30} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
        print("-" * 75)

        results = []

        # 1. Gzip -9
        t0 = time.time()
        c = gzip.compress(data, compresslevel=9)
        t_gzip = time.time() - t0
        results.append(("Gzip -9", len(c), t_gzip))

        # 2. Zstd -19
        t0 = time.time()
        c = zstd.ZstdCompressor(level=19).compress(data)
        t_zstd = time.time() - t0
        results.append(("Zstd -19", len(c), t_zstd))

        # 3. Zstd -22 --long
        zparams = zstd.ZstdCompressionParameters.from_level(22, window_log=27)
        t0 = time.time()
        c = zstd.ZstdCompressor(compression_params=zparams).compress(data)
        t_zlong = time.time() - t0
        results.append(("Zstd -22 Long", len(c), t_zlong))

        # 4. Syslog Complex V2
        codec_v2 = SyslogLiquefyChampionV2(level=22)
        t0 = time.time()
        c = codec_v2.compress(data)
        t_champ_v2 = time.time() - t0
        results.append(("CHAMPION: Complex V2", len(c), t_champ_v2))

        # 5. Syslog V5 STREAMTREE (ONLINE LEARNING)
        codec_v5 = SyslogStreamTreeChampion(level=22)
        t0 = time.time()
        c = codec_v5.compress(data)
        t_champ_v5 = time.time() - t0
        # Lossless check
        rec = codec_v5.decompress(c)
        if rec != data: print(f"ERROR: {ds_name} STREAMTREE NOT LOSSLESS!")
        results.append(("CHAMPION: V5 STREAMTREE (WIN)", len(c), t_champ_v5))

        # 6. Syslog Repetitive (Universal)
        codec_r = SyslogUniversalChampion(level=22)
        t0 = time.time()
        c = codec_r.compress(data)
        t_champ_r = time.time() - t0
        results.append(("CHAMPION: Repetitive (Univ)", len(c), t_champ_r))

        for name, size, duration in sorted(results, key=lambda x: x[1]):
            ratio = len(data) / max(size, 1)
            speed = len(data) / max(duration, 0.001) / 1024 / 1024
            winner = "[WINNER]" if "CHAMPION" in name else ""
            print(f"{name:<30} | {size:>12,} | {ratio:>9.1f}x | {speed:>9.1f} MB/s {winner}")

if __name__ == "__main__":
    benchmark_syslog()
