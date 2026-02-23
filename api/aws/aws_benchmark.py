#!/usr/bin/env python3
import time
import zstandard as zstd
import gzip
import os
import random
import sys

# Add path to load the champion
sys.path.append(os.path.abspath("production_engines/aws"))
from NULL_Aws_VpcFlow_Entropy_Focused import NULL_Aws_VpcFlow_Entropy_Focused

def gen_vpc_flow_logs(count=20000):
    # version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status
    lines = []
    base_time = 1735120800
    acc_id = "123456789012"
    interface_id = "eni-0a1b2c3d4e5f6g7h8"

    for i in range(count):
        src_ip = f"10.0.{random.randint(0, 255)}.{random.randint(0, 255)}"
        dst_ip = f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 53, 3306])
        protocol = random.choice([6, 17, 1]) # TCP, UDP, ICMP
        packets = random.randint(1, 1000)
        bytes_count = packets * random.randint(40, 1500)
        start_time = base_time + i
        end_time = start_time + random.randint(1, 60)
        action = random.choice(["ACCEPT", "REJECT"])
        log_status = "OK"

        line = f"2 {acc_id} {interface_id} {src_ip} {dst_ip} {src_port} {dst_port} {protocol} {packets} {bytes_count} {start_time} {end_time} {action} {log_status}\n".encode()
        lines.append(line)

    return b"".join(lines)

def benchmark_aws():
    print(f"{' AWS VPC FLOW CHAMPION SHOWDOWN ':=^70}")
    data = gen_vpc_flow_logs(30000)
    print(f">>>> DATASET: AWS VPC Flow Logs ({len(data):,} bytes)")
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

    # 3. AWS VPC Liquefy
    codec_v = VpcFlowLiquefyChampion(level=22)
    t0 = time.time()
    c_v = codec_v.compress(data)
    t_v = time.time() - t0

    # Lossless verification
    rec_v = codec_v.decompress(c_v)
    if rec_v != data:
        print("ERROR: AWS VPC LIQUEFY NOT LOSSLESS!")
        # Debug small part
        for i in range(min(len(data), len(rec_v))):
            if data[i] != rec_v[i]:
                print(f"Mismatch at {i}: {data[i:i+20]} != {rec_v[i:i+20]}")
                break

    results.append(("[CHAMPION: AWS VPC Liquefy]", len(c_v), t_v))

    for name, size, duration in sorted(results, key=lambda x: x[1]):
        ratio = len(data) / max(size, 1)
        speed = len(data) / max(duration, 0.001) / 1024 / 1024
        print(f"{name:<35} | {size:>12,} | {ratio:>9.1f}x | {speed:>9.1f} MB/s")

if __name__ == "__main__":
    benchmark_aws()
