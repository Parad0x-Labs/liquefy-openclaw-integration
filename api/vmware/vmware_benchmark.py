#!/usr/bin/env python3
import time, os, sys, random, zstandard as zstd

# Add path to load the champion
sys.path.append(os.path.abspath("production_engines/vmware"))
from VmwareChampion_Liquefy import VmwareLiquefyChampion

def gen_vmware_logs(count=5000):
    lines = []
    hosts = ["esxi-prod-01", "esxi-prod-02", "vcenter-vcsa"]
    procs = ["Hostd", "Vpxa", "Rhttpproxy", "hostd-probe"]
    metas = ["[sub=Vpxa opID=123]", "[sub=A opID=abc]", "[sub=Main]", "[sub=PropertyProvider]"]

    for i in range(count):
        ts = f"2023-12-25T12:00:{i%60:02d}.{i%999:03d}Z"
        host = random.choice(hosts)
        proc = random.choice(procs)
        meta = random.choice(metas)
        msg = f"Reaching session limit for user root-{i%10}. Connection count={i}"

        line = f"{ts} {host} {proc}: {meta} {msg}\n"
        lines.append(line.encode())

        # 1% Noise
        if i % 100 == 0:
            lines.append(b"Random ESXi kernel dump line with no format\n")

    return b"".join(lines)

def benchmark():
    print(f"{' VMWARE ESXi CHAMPION SHOWDOWN ':=^70}")
    data = gen_vmware_logs(10000)
    print(f">>>> DATASET: VMware ESXi Logs ({len(data):,} bytes)")
    print(f"{'Codec':<35} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
    print("-" * 80)

    # 1. NITRO (Level 3)
    champ = VmwareLiquefyChampion(level=3)
    t0 = time.time(); comp = champ.compress(data); t_comp = time.time()-t0
    dec = champ.decompress(comp)

    # Baseline Zstd
    z_comp = zstd.compress(data, level=3)

    print(f"Zstd Raw (Level 3)                  | {len(z_comp):>12,} | {len(data)/len(z_comp):>9.1f}x | -- MB/s")
    print(f"[CHAMPION: VMware Liquefy]          | {len(comp):>12,} | {len(data)/len(comp):>9.1f}x | {len(data)/t_comp/1024/1024:>9.1f} MB/s")
    print(f"Lossless: {'PASS' if dec.strip() == data.strip() else 'FAIL'}")

if __name__ == "__main__":
    benchmark()
