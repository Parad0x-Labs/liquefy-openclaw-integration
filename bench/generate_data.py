#!/usr/bin/env python3
import os
import json
import random
import argparse
from pathlib import Path
from datetime import datetime, timedelta

def generate_jsonl(path: Path, bytes_target: int, seed: int):
    random.seed(seed)
    current_bytes = 0
    tools = ["web_search", "run_python", "file_read", "file_write", "bash"]
    with open(path, "w", encoding="utf-8") as f:
        while current_bytes < bytes_target:
            record = {
                "eventVersion": "1.08",
                "userIdentity": {"type": "Agent", "id": f"agent_{random.randint(1, 100)}"},
                "eventTime": (datetime.utcnow() - timedelta(seconds=random.randint(0, 86400))).isoformat() + "Z",
                "eventName": "ToolCall",
                "tool": random.choice(tools),
                "input": {"query": "".join(random.choices("abcdefghijklmnopqrstuvwxyz ", k=random.randint(10, 50)))},
                "output": {"status": "success", "data": "A" * random.randint(100, 500)},
                "duration_ms": random.randint(10, 5000),
                "context": {
                    "session_id": f"sess_{random.randint(1000, 9999)}",
                    "trace_id": "".join(random.choices("0123456789abcdef", k=32))
                }
            }
            line = json.dumps(record) + "\n"
            f.write(line)
            current_bytes += len(line.encode("utf-8"))

def generate_log(path: Path, bytes_target: int, seed: int):
    random.seed(seed)
    current_bytes = 0
    methods = ["GET", "POST", "PUT", "DELETE"]
    endpoints = ["/api/v1/query", "/api/v1/auth", "/health", "/metrics", "/user/profile"]
    statuses = [200, 201, 400, 401, 403, 404, 500, 502, 503]
    with open(path, "w", encoding="utf-8") as f:
        while current_bytes < bytes_target:
            ip = f"192.168.{random.randint(1, 255)}.{random.randint(1, 255)}"
            method = random.choice(methods)
            endpoint = random.choice(endpoints)
            status = random.choice(statuses)
            size = random.randint(100, 10000)
            user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
            dt = (datetime.utcnow() - timedelta(seconds=random.randint(0, 86400))).strftime("%d/%b/%Y:%H:%M:%S +0000")
            line = f'{ip} - - [{dt}] "{method} {endpoint} HTTP/1.1" {status} {size} "-" "{user_agent}"\n'
            f.write(line)
            current_bytes += len(line.encode("utf-8"))

def generate_md(path: Path, bytes_target: int, seed: int):
    random.seed(seed)
    current_bytes = 0
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Agent Memory Notes\n\n")
        current_bytes += 22
        while current_bytes < bytes_target:
            heading = f"## Observation {random.randint(1, 10000)}\n"
            content = "The user requested a complex operation. I have analyzed the resulting data and found the following patterns: "
            content += "".join(random.choices("abcdefghijklmnopqrstuvwxyz ", k=random.randint(50, 200))) + ".\n\n"
            f.write(heading + content)
            current_bytes += len((heading + content).encode("utf-8"))

def generate_html(path: Path, bytes_target: int, seed: int):
    random.seed(seed)
    current_bytes = 0
    chars = "abcdefghijklmnopqrstuvwxyz \t\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write("<!DOCTYPE html><html><head><title>Web Cache</title></head><body>\n")
        current_bytes += 65
        while current_bytes < bytes_target:
            rnd_str = "".join(random.choices(chars, k=random.randint(100, 500)))
            div = f'<div class="item" id="item-{random.randint(1, 10000)}"><h3>Result</h3><p>{rnd_str}</p></div>\n'
            f.write(div)
            current_bytes += len(div.encode("utf-8"))
        f.write("</body></html>\n")

def create_dataset(base_dir: Path, size_name: str, total_mb: int, seed: int):
    print(f"Generating {size_name} dataset (~{total_mb} MB) at {base_dir} ...")
    run_dir = base_dir / "run_0001"
    run_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "sessions").mkdir(exist_ok=True)
    (run_dir / "memories").mkdir(exist_ok=True)
    (run_dir / "tool_trace").mkdir(exist_ok=True)
    (run_dir / "web_cache").mkdir(exist_ok=True)
    (run_dir / "errors").mkdir(exist_ok=True)
    (run_dir / "metrics").mkdir(exist_ok=True)

    bytes_target = total_mb * 1024 * 1024

    # Distributions
    # Sessions (JSONL): 40%
    # Tool trace (JSONL): 25%
    # Logs / Errors: 15%
    # HTML Cache: 15%
    # MD memories: 5%

    generate_jsonl(run_dir / "sessions" / "session_0001.jsonl", int(bytes_target * 0.2), seed)
    generate_jsonl(run_dir / "sessions" / "session_0002.jsonl", int(bytes_target * 0.2), seed+1)
    generate_jsonl(run_dir / "tool_trace" / "tool_trace.jsonl", int(bytes_target * 0.25), seed+2)
    generate_log(run_dir / "errors" / "errors.log", int(bytes_target * 0.15), seed+3)
    generate_html(run_dir / "web_cache" / "page_0001.html", int(bytes_target * 0.15), seed+4)
    generate_md(run_dir / "memories" / "notes.md", int(bytes_target * 0.05), seed+5)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", nargs="+", default=["small"], help="Dataset sizes to generate")
    args = parser.parse_args()

    sizes_mb = {
        "50mb": 50,
        "200mb": 200,
        "small": 200,
        "medium": 500,
        "medium2g": 2048,
        "large": 10000
    }

    out_base = Path(__file__).resolve().parent / "datasets" / "openclaw_like"

    for size in args.sizes:
        if size not in sizes_mb:
            print(f"Unknown size: {size}")
            continue
        create_dataset(out_base / size, size, sizes_mb[size], seed=123)

if __name__ == "__main__":
    main()
