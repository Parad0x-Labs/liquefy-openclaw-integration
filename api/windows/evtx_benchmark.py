#!/usr/bin/env python3
import io
import time
import struct
import sys
import os

# Add path to load the champion
sys.path.append(os.path.abspath("production_engines/windows"))
from WindowsChampion_Evtx_Unicorn import EvtxUnicorn

def gen_mock_evtx(count=10000):
    buffer = io.BytesIO()
    services = ["lsass.exe", "svchost.exe", "SearchIndexer.exe", "System"]
    users = ["SYSTEM", "NETWORK SERVICE", "Administrator", "User-01"]

    for i in range(count):
        buffer.write(b"\x2A\x2A\x00\x00") # ElfChnk sig
        buffer.write(struct.pack("<Q", i)) # Event Record ID

        # UTF-16LE Payload
        msg = f"Event ID {1000 + (i%50)}: Process {services[i%4]} accessed by {users[i%4]} at offset 0x{i:08x}"
        buffer.write(msg.encode("utf-16le"))

        buffer.write(f" Noise_{i} ".encode("ascii"))
        buffer.write(b"\x00" * 8)

    return buffer.getvalue()

def benchmark_evtx():
    print(f"{' WINDOWS EVTX CHAMPION SHOWDOWN ':=^70}")
    data = gen_mock_evtx(20000)
    print(f">>>> DATASET: Windows EVTX Binary Logs ({len(data):,} bytes)")
    print(f"{'Codec':<35} | {'Size (B)':>12} | {'Ratio':>10} | {'Speed':>12}")
    print("-" * 80)

    # 1. NITRO MODE (Level 3)
    uni_nitro = EvtxUnicorn(level=3)
    in_buf = io.BytesIO(data)
    out_buf = io.BytesIO()
    t0 = time.time()
    uni_nitro.compress(in_buf, out_buf)
    t_nitro = time.time() - t0

    c_nitro = out_buf.getvalue()
    r_nitro = len(data) / len(c_nitro)
    s_nitro = len(data) / t_nitro / 1024 / 1024

    print(f"[CHAMPION: EVTX Nitro (Speed)]     | {len(c_nitro):>12,} | {r_nitro:>9.1f}x | {s_nitro:>9.1f} MB/s")

    # 2. ARCHIVE MODE (Level 19)
    uni_arch = EvtxUnicorn(level=19)
    in_buf.seek(0)
    out_buf_arch = io.BytesIO()
    t0 = time.time()
    uni_arch.compress(in_buf, out_buf_arch)
    t_arch = time.time() - t0

    c_arch = out_buf_arch.getvalue()
    r_arch = len(data) / len(c_arch)
    s_arch = len(data) / t_arch / 1024 / 1024

    print(f"[CHAMPION: EVTX Archival (Ratio)]  | {len(c_arch):>12,} | {r_arch:>9.1f}x | {s_arch:>9.1f} MB/s")

    # Verify Lossless
    out_buf.seek(0)
    dec_buf = io.BytesIO()
    uni_nitro.decompress(out_buf, dec_buf)
    if dec_buf.getvalue() == data:
        print("PASS: 100% BYTE-PERFECT MATCH")
    else:
        print("FAIL: CORRUPTION")

    # Search speed - use exactly what was put in (Administrator)
    out_buf.seek(0)
    t0 = time.time()
    uni_nitro.grep(out_buf, "Administrator")
    print(f"Search Time: {time.time()-t0:.3f}s")

if __name__ == "__main__":
    benchmark_evtx()
