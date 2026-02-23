#!/usr/bin/env python3
import time
import struct
import sys
import os
import socket
import random
import zstandard as zstd

# Add path to load the champion
sys.path.append(os.path.abspath("production_engines/netflow"))
from NetflowChampion_V5_Liquefy import NetflowLiquefyChampion

def gen_mock_netflow_v5(packet_count=5000):
    packets = []
    srcs = [socket.inet_aton(f"10.0.0.{i}") for i in range(100)]
    dsts = [socket.inet_aton(f"192.168.1.{i}") for i in range(100)]

    for i in range(packet_count):
        count = 30
        # Header (24 bytes): ver, count, sys_uptime, unix_secs, unix_nsecs, flow_seq, engine_type, engine_id, sampling_interval
        header = struct.pack("!HHIIIIBBH", 5, count, 1000 + i, 1620000000 + i, 0, i, 0, 0, 0)

        records = bytearray()
        for _ in range(count):
            # Record (48 bytes)
            src = random.choice(srcs)
            dst = random.choice(dsts)
            # Dummy record data (ports, counters, etc)
            rest = struct.pack("!IIHHIIIIHHBBBB", 0, 0, 80, 443, 0, 0, 100, 1500, 0, 0, 6, 0, 0, 0)
            records.extend(src + dst + rest)

        packets.append(header + records)

    return b"".join(packets)

def benchmark_netflow():
    print(f"{' NETFLOW CHAMPION SHOWDOWN ':=^70}")
    data = gen_mock_netflow_v5(10000)
    print(f">>>> DATASET: Netflow v5 Binary Stream ({len(data)/1024/1024:.2f} MB)")
    print(f"{'Codec':<35} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
    print("-" * 80)

    # 1. NITRO MODE (Level 3)
    champ_nitro = NetflowLiquefyChampion(level=3)
    t0 = time.time()
    comp_nitro = champ_nitro.compress(data)
    t_nitro = time.time() - t0

    r_nitro = len(data) / len(comp_nitro)
    s_nitro = len(data) / t_nitro / 1024 / 1024

    # 2. ARCHIVE MODE (Level 19)
    champ_arch = NetflowLiquefyChampion(level=19)
    t0 = time.time()
    comp_arch = champ_arch.compress(data)
    t_arch = time.time() - t0

    r_arch = len(data) / len(comp_arch)
    s_arch = len(data) / t_arch / 1024 / 1024

    # Baseline Zstd Level 3
    z_comp = zstd.compress(data, level=3)
    z_ratio = len(data) / len(z_comp)

    print(f"Zstd Raw (Level 3)                  | {len(z_comp):>12,} | {z_ratio:>9.1f}x | -- MB/s")
    print(f"[CHAMPION: Netflow Nitro (Speed)]   | {len(comp_nitro):>12,} | {r_nitro:>9.1f}x | {s_nitro:>9.1f} MB/s")
    print(f"[CHAMPION: Netflow Archival]        | {len(comp_arch):>12,} | {r_arch:>9.1f}x | {s_arch:>9.1f} MB/s")

    # Verify Lossless
    dec = champ_nitro.decompress(comp_nitro)
    if dec == data:
        print("PASS: 100% BYTE-PERFECT MATCH")
    else:
        print("FAIL: CORRUPTION")

    # Search speed
    t0 = time.time()
    champ_nitro.grep(comp_nitro, "10.0.0.1")
    print(f"Search Time: {time.time()-t0:.3f}s")

if __name__ == "__main__":
    benchmark_netflow()
