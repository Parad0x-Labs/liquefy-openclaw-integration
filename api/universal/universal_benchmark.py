import time
import os
import zstandard as zstd
from production_engines.universal.UniversalChampion_MaxRatio_EventHorizon import UniversalEventHorizon
from production_engines.universal.UniversalChampion_MaxSpeed_RLE import UniversalRleChampion

def run_bench():
    # Dataset: A mix of some structured and some repetitive data
    data_path = "production_engines/data/mixed_bloat.log"
    if not os.path.exists(data_path):
        # Create dummy mixed data
        print("Creating dummy mixed data...")
        os.makedirs(os.path.dirname(data_path), exist_ok=True)
        with open(data_path, "wb") as f:
            for i in range(5000):
                # Repetitive part
                f.write(b"REPETITIVE_LINE_SIGNAL_OK_12345\n")
                # Structured part
                f.write(f"127.0.0.1 - - [26/Dec/2025:10:00:{i%60:02d} +0000] \"GET /api/v1/resource/{i//100} HTTP/1.1\" 200 {i*10}\n".encode())

    with open(data_path, "rb") as f:
        raw = f.read()

    print(f"Dataset: {data_path} ({len(raw)/1024:.1f} KB)")
    print("-" * 75)
    print(f"{'Engine':25} | {'Size':10} | {'Ratio':8} | {'Speed':10}")
    print("-" * 75)

    engines = [
        ("Zstd -19", lambda d: zstd.ZstdCompressor(level=19).compress(d)),
        ("Universal MaxSpeed (RLE)", lambda d: UniversalRleChampion(level=3).compress(d)),
        ("Event Horizon (MaxRatio)", lambda d: UniversalEventHorizon(level=22).compress(d)),
    ]

    for name, func in engines:
        t0 = time.time()
        try:
            compressed = func(raw)
            t1 = time.time()
            ratio = len(raw) / len(compressed)
            speed = (len(raw) / (1024*1024)) / (t1 - t0)
            print(f"{name:25} | {len(compressed)/1024:8.1f} KB | {ratio:6.2f}x | {speed:6.2f} MB/s")
        except Exception as e:
            print(f"{name:25} | ERROR: {e}")

if __name__ == "__main__":
    run_bench()
