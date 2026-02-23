#!/usr/bin/env python3
"""
run_format_matrix.py
====================
Per-file format benchmark matrix:
- OpenClaw dataset files (sessions/tool trace/log/html/md)
- Server-format suite (apache/syslog/k8s/cloudtrail/vpcflow/sql)
- High-entropy JSONL

Compares:
- Liquefy router path
- zstd -3
- zstd -6
- zstd -19
- zstd -22

Outputs:
- bench/results/format_matrix.csv
- bench/results/FORMAT_REPORT.md
"""

import argparse
import asyncio
import csv
import hashlib
import json
import os
import random
import shutil
import string
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import zstandard as zstd

REPO_ROOT = Path(__file__).resolve().parent.parent
API_DIR = REPO_ROOT / "api"

import sys
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from orchestrator.orchestrator import Orchestrator
from orchestrator.engine_map import get_engine_instance


def ensure_dataset(size: str):
    base = REPO_ROOT / "bench" / "datasets" / "openclaw_like" / size / "run_0001"
    if base.exists():
        return
    cmd = [sys.executable, str(REPO_ROOT / "bench" / "generate_data.py"), "--sizes", size]
    res = os.spawnv(os.P_WAIT, sys.executable, cmd)
    if res != 0:
        raise RuntimeError(f"dataset generation failed for size={size}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_liquefy_blob(blob: bytes, engine_used: str) -> bytes:
    payload = blob
    safe_tag = None
    if payload.startswith(b"SAFE") and len(payload) >= 8:
        safe_tag = payload[4:8]
        payload = payload[8:]

    if engine_used == "zstd-fallback" or safe_tag == b"ZST\x00":
        return zstd.ZstdDecompressor().decompress(payload)

    instance = get_engine_instance(engine_used)
    if instance is None:
        raise RuntimeError(f"engine instance missing: {engine_used}")
    out = instance.decompress(payload)
    if isinstance(out, bytearray):
        out = bytes(out)
    if not isinstance(out, bytes):
        raise RuntimeError(f"invalid decompressed payload type from {engine_used}")
    return out


def bench_liquefy(
    loop: asyncio.AbstractEventLoop,
    orch: Orchestrator,
    file_path: Path,
    verify: bool,
    verify_mode: str,
) -> Dict[str, object]:
    raw = file_path.read_bytes()
    raw_hash = sha256_bytes(raw)

    t0 = time.perf_counter()
    result = loop.run_until_complete(
        orch.process_file(
            filepath=str(file_path),
            tenant_id="bench",
            api_key="bench",
            encrypt=False,
            verify=verify,
            verify_mode=verify_mode,
        )
    )
    t1 = time.perf_counter()

    if not result.get("ok"):
        raise RuntimeError(f"liquefy failed: {result.get('error')}")

    blob = result.get("output_data", b"")
    if not isinstance(blob, (bytes, bytearray)):
        raise RuntimeError("liquefy output_data missing/invalid")
    blob = bytes(blob)

    t2_start = time.perf_counter()
    restored = decode_liquefy_blob(blob, result.get("engine_used", "zstd-fallback"))
    t2 = time.perf_counter()

    ok = sha256_bytes(restored) == raw_hash
    return {
        "method": "Liquefy (.null)",
        "level": "engine-router",
        "engine_used": result.get("engine_used", "unknown"),
        "mrtv_fallback": "Yes" if result.get("engine_used") == "zstd-fallback" else "No",
        "input_bytes": len(raw),
        "output_bytes": len(blob),
        "compress_s": t1 - t0,
        "decompress_s": t2 - t2_start,
        "hash_verify": "PASS" if ok else "FAIL",
    }


def bench_zstd(file_path: Path, level: int) -> Dict[str, object]:
    raw = file_path.read_bytes()
    raw_hash = sha256_bytes(raw)

    cctx = zstd.ZstdCompressor(level=level)
    dctx = zstd.ZstdDecompressor()

    t0 = time.perf_counter()
    comp = cctx.compress(raw)
    t1 = time.perf_counter()

    t2_start = time.perf_counter()
    restored = dctx.decompress(comp)
    t2 = time.perf_counter()

    ok = sha256_bytes(restored) == raw_hash
    return {
        "method": f"zstd -{level}",
        "level": str(level),
        "engine_used": "zstd",
        "mrtv_fallback": "No",
        "input_bytes": len(raw),
        "output_bytes": len(comp),
        "compress_s": t1 - t0,
        "decompress_s": t2 - t2_start,
        "hash_verify": "PASS" if ok else "FAIL",
    }


def write_scaled_file(src: Path, dst: Path, target_bytes: int):
    data = src.read_bytes()
    if not data:
        raise RuntimeError(f"source fixture is empty: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    with dst.open("wb") as out:
        written = 0
        while written < target_bytes:
            to_write = min(len(data), target_bytes - written)
            out.write(data[:to_write])
            written += to_write


def write_lines_file(dst: Path, target_bytes: int, line_fn) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and dst.stat().st_size >= target_bytes:
        return
    written = 0
    with dst.open("w", encoding="utf-8") as out:
        while written < target_bytes:
            line = line_fn()
            if not line.endswith("\n"):
                line += "\n"
            out.write(line)
            written += len(line.encode("utf-8"))


def rand_phrase(rng: random.Random, min_words: int = 4, max_words: int = 14) -> str:
    words = [
        "auth", "cache", "timeout", "connect", "retry", "worker", "trace", "span",
        "memory", "vector", "token", "route", "policy", "ingest", "parser", "event",
        "latency", "pod", "service", "queue", "session", "tenant", "backup", "index",
        "search", "restore", "compress", "dedupe", "audit", "kernel", "network",
    ]
    count = rng.randint(min_words, max_words)
    return " ".join(rng.choice(words) for _ in range(count))


def rand_ts_apache(rng: random.Random) -> str:
    base = datetime(2026, 2, 22, 0, 0, 0)
    dt = base + timedelta(seconds=rng.randint(0, 8 * 24 * 3600))
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def rand_ts_iso(rng: random.Random) -> str:
    base = datetime(2026, 2, 22, 0, 0, 0)
    dt = base + timedelta(seconds=rng.randint(0, 8 * 24 * 3600), milliseconds=rng.randint(0, 999))
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def generate_apache(dst: Path, target_bytes: int, rng: random.Random) -> None:
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    paths = ["/api/v1/login", "/api/v1/search", "/api/v1/orders", "/healthz", "/metrics", "/static/app.js"]
    statuses = [200, 201, 204, 301, 400, 401, 403, 404, 429, 500, 502, 503]
    uagents = [
        "Mozilla/5.0",
        "curl/8.4.0",
        "python-requests/2.32.3",
        "OpenClaw-Agent/0.9",
        "kube-probe/1.30",
    ]

    def line() -> str:
        ip = f"{rng.randint(1, 255)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 255)}"
        method = rng.choice(methods)
        path = rng.choice(paths)
        if "?" not in path and rng.random() < 0.55:
            path += f"?tenant=t{rng.randint(1,180)}&q={rng.randint(1000,9999)}"
        status = rng.choice(statuses)
        size = rng.randint(140, 220000)
        referer = "-" if rng.random() < 0.65 else f"https://site{rng.randint(1,7)}.example.com/"
        return (
            f'{ip} - - [{rand_ts_apache(rng)}] "{method} {path} HTTP/1.1" '
            f"{status} {size} \"{referer}\" \"{rng.choice(uagents)}\""
        )

    write_lines_file(dst, target_bytes, line)


def generate_syslog_3164(dst: Path, target_bytes: int, rng: random.Random) -> None:
    hosts = ["api-01", "api-02", "db-01", "queue-03", "edge-01", "worker-09"]
    apps = ["kernel", "sshd", "nginx", "systemd", "vault", "openclawd", "liquefyd"]
    levels = ["INFO", "WARN", "ERROR", "DEBUG"]

    def line() -> str:
        dt = datetime(2026, 2, 22) + timedelta(seconds=rng.randint(0, 8 * 24 * 3600))
        ts = dt.strftime("%b %d %H:%M:%S")
        app = rng.choice(apps)
        pid = rng.randint(100, 99999)
        msg = rand_phrase(rng, 6, 18)
        return (
            f"{ts} {rng.choice(hosts)} {app}[{pid}]: level={rng.choice(levels)} "
            f"trace_id={rng.randint(10**10, 10**11-1)} tenant=t{rng.randint(1,180)} msg=\"{msg}\""
        )

    write_lines_file(dst, target_bytes, line)


def generate_syslog_5424(dst: Path, target_bytes: int, rng: random.Random) -> None:
    hosts = ["core-1", "core-2", "edge-1", "db-2", "router-4"]
    apps = ["svc-auth", "svc-search", "svc-metrics", "svc-memory", "svc-openclaw"]

    def line() -> str:
        pri = rng.randint(1, 191)
        app = rng.choice(apps)
        proc = rng.randint(1000, 9999)
        msgid = f"ID{rng.randint(1, 999)}"
        sd = (
            f'[meta tenant="t{rng.randint(1,180)}" pod="p-{rng.randint(1,800)}" '
            f'trace="{rng.randint(10**10, 10**11-1)}"]'
        )
        return (
            f"<{pri}>1 {rand_ts_iso(rng)} {rng.choice(hosts)} {app} {proc} {msgid} {sd} "
            f"{rand_phrase(rng, 5, 16)}"
        )

    write_lines_file(dst, target_bytes, line)


def generate_k8s(dst: Path, target_bytes: int, rng: random.Random) -> None:
    namespaces = ["prod", "staging", "payments", "search", "platform"]
    pods = ["api", "worker", "ingest", "scheduler", "tools"]
    levels = ["info", "warn", "error", "debug"]

    def line() -> str:
        payload = {
            "ts": rand_ts_iso(rng),
            "level": rng.choice(levels),
            "namespace": rng.choice(namespaces),
            "pod": f"{rng.choice(pods)}-{rng.randint(1, 3000)}",
            "container": f"c{rng.randint(1, 12)}",
            "trace_id": f"{rng.getrandbits(128):032x}",
            "latency_ms": rng.randint(1, 8000),
            "status": rng.choice([200, 201, 204, 400, 401, 404, 429, 500, 503]),
            "msg": rand_phrase(rng, 5, 20),
        }
        # Match common Kubernetes container JSON log framing.
        obj = {
            "log": json.dumps(payload, separators=(",", ":")) + "\n",
            "stream": rng.choice(["stdout", "stderr"]),
            "time": rand_ts_iso(rng),
        }
        return json.dumps(obj, separators=(",", ":"))

    write_lines_file(dst, target_bytes, line)


def generate_cloudtrail(dst: Path, target_bytes: int, rng: random.Random) -> None:
    events = ["AssumeRole", "GetObject", "PutObject", "Invoke", "ListBuckets", "RunTask"]
    services = ["sts.amazonaws.com", "s3.amazonaws.com", "lambda.amazonaws.com", "ecs.amazonaws.com"]
    regions = ["eu-west-1", "us-east-1", "eu-central-1"]

    def line() -> str:
        obj = {
            "eventVersion": "1.08",
            "eventTime": rand_ts_iso(rng),
            "eventSource": rng.choice(services),
            "eventName": rng.choice(events),
            "awsRegion": rng.choice(regions),
            "sourceIPAddress": f"{rng.randint(1,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,255)}",
            "userAgent": rng.choice(["aws-cli/2.15", "botocore/1.34", "OpenClaw/agent"]),
            "userIdentity": {
                "type": "AssumedRole",
                "principalId": f"AID{rng.randint(10**9,10**10-1)}",
                "arn": f"arn:aws:iam::123456789012:role/r{rng.randint(1,500)}",
            },
            "requestParameters": {
                "bucketName": f"b-{rng.randint(1,900)}",
                "key": f"k/{rng.randint(1,100000)}.json",
            },
            "responseElements": {"x-amz-request-id": f"{rng.getrandbits(64):016x}"},
            "readOnly": rng.choice([True, False]),
        }
        return json.dumps(obj, separators=(",", ":"))

    write_lines_file(dst, target_bytes, line)


def generate_vpcflow(dst: Path, target_bytes: int, rng: random.Random) -> None:
    actions = ["ACCEPT", "REJECT"]
    statuses = ["OK", "NODATA", "SKIPDATA"]

    def line() -> str:
        start = 1700000000 + rng.randint(0, 7 * 24 * 3600)
        end = start + rng.randint(1, 300)
        return (
            f"2 123456789012 eni-{rng.randint(10**6,10**7-1)} "
            f"{rng.randint(1,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,255)} "
            f"{rng.randint(1,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,255)} "
            f"{rng.randint(1024,65535)} {rng.randint(1,65535)} {rng.choice([6,17])} "
            f"{rng.randint(1,10000)} {rng.randint(60,5_000_000)} {start} {end} "
            f"{rng.choice(actions)} {rng.choice(statuses)}"
        )

    write_lines_file(dst, target_bytes, line)


def generate_sql(dst: Path, target_bytes: int, rng: random.Random) -> None:
    tables = ["users", "sessions", "orders", "events", "traces"]

    def line() -> str:
        table = rng.choice(tables)
        mode = rng.random()
        if mode < 0.65:
            return (
                f"INSERT INTO {table} (id, tenant_id, status, score, updated_at) VALUES "
                f"({rng.randint(1,10**8)}, {rng.randint(1,180)}, '{rng.choice(['ok','warn','fail'])}', "
                f"{rng.randint(0,9999)}, '{rand_ts_iso(rng)}');"
            )
        if mode < 0.9:
            return (
                f"UPDATE {table} SET status='{rng.choice(['ok','warn','fail'])}', "
                f"score={rng.randint(0,9999)} WHERE id={rng.randint(1,10**8)};"
            )
        return (
            f"DELETE FROM {table} WHERE updated_at < '{rand_ts_iso(rng)}' "
            f"AND tenant_id={rng.randint(1,180)};"
        )

    write_lines_file(dst, target_bytes, line)


def generate_generic_json(dst: Path, target_bytes: int, rng: random.Random) -> None:
    def line() -> str:
        obj = {
            "ts": rand_ts_iso(rng),
            "tenant": f"t{rng.randint(1,180)}",
            "session": f"s-{rng.randint(1,10**9)}",
            "trace_id": f"{rng.getrandbits(128):032x}",
            "source": rng.choice(["api", "worker", "scheduler", "edge"]),
            "meta": {
                "retries": rng.randint(0, 6),
                "latency_ms": rng.randint(1, 6000),
                "ok": rng.choice([True, False]),
            },
            "message": rand_phrase(rng, 5, 22),
        }
        return json.dumps(obj, separators=(",", ":"))

    write_lines_file(dst, target_bytes, line)


def generate_raw_text(dst: Path, target_bytes: int, rng: random.Random) -> None:
    def line() -> str:
        return (
            f"{rand_ts_iso(rng)} service={rng.choice(['auth','search','memory','trace'])} "
            f"tenant=t{rng.randint(1,180)} "
            f"message=\"{rand_phrase(rng, 8, 28)}\""
        )

    write_lines_file(dst, target_bytes, line)


def generate_high_entropy_jsonl(dst: Path, target_bytes: int, seed: int = 1337):
    random.seed(seed)
    dst.parent.mkdir(parents=True, exist_ok=True)
    letters = string.ascii_letters + string.digits
    written = 0
    with dst.open("w", encoding="utf-8") as out:
        while written < target_bytes:
            # high-entropy-ish random payload with low repetition
            payload = "".join(random.choices(letters, k=700))
            row = (
                f'{{"ts":"2026-02-22T00:00:00Z","event":"rand","trace":"{payload}",'
                f'"meta":"{"".join(random.choices(letters, k=220))}"}}\n'
            )
            out.write(row)
            written += len(row.encode("utf-8"))


def build_server_suite(target_mb: int, mode: str = "realistic", seed: int = 20260222) -> List[Tuple[str, Path, str]]:
    fixture_dir = REPO_ROOT / "tools" / "fixtures"
    out_dir = REPO_ROOT / "bench" / "datasets" / "server_suite" / f"{mode}_{target_mb}mb_s{seed}"
    target_bytes = target_mb * 1024 * 1024

    mapping = [
        ("apache_log", fixture_dir / "apache.log", "apache.log"),
        ("syslog_3164", fixture_dir / "syslog_3164.log", "syslog_3164.log"),
        ("syslog_5424", fixture_dir / "syslog_5424.log", "syslog_5424.log"),
        ("k8s_log", fixture_dir / "k8s.log", "k8s.log"),
        ("cloudtrail_jsonl", fixture_dir / "cloudtrail.jsonl", "cloudtrail.jsonl"),
        ("vpcflow_log", fixture_dir / "vpcflow.log", "vpcflow.log"),
        ("sql_dump", fixture_dir / "dump.sql", "dump.sql"),
        ("generic_json", fixture_dir / "sample.json", "sample.json"),
        ("raw_text", fixture_dir / "raw.txt", "raw.txt"),
    ]

    files: List[Tuple[str, Path, str]] = []

    if mode == "fixture-repeat":
        for label, src, name in mapping:
            dst = out_dir / name
            write_scaled_file(src, dst, target_bytes)
            files.append(("server_suite", dst, label))
    else:
        rng = random.Random(seed)
        gen_specs = [
            ("apache_log", out_dir / "apache.log", lambda: generate_apache(out_dir / "apache.log", target_bytes, rng)),
            ("syslog_3164", out_dir / "syslog_3164.log", lambda: generate_syslog_3164(out_dir / "syslog_3164.log", target_bytes, rng)),
            ("syslog_5424", out_dir / "syslog_5424.log", lambda: generate_syslog_5424(out_dir / "syslog_5424.log", target_bytes, rng)),
            ("k8s_log", out_dir / "k8s.log", lambda: generate_k8s(out_dir / "k8s.log", target_bytes, rng)),
            ("cloudtrail_jsonl", out_dir / "cloudtrail.jsonl", lambda: generate_cloudtrail(out_dir / "cloudtrail.jsonl", target_bytes, rng)),
            ("vpcflow_log", out_dir / "vpcflow.log", lambda: generate_vpcflow(out_dir / "vpcflow.log", target_bytes, rng)),
            ("sql_dump", out_dir / "dump.sql", lambda: generate_sql(out_dir / "dump.sql", target_bytes, rng)),
            ("generic_json", out_dir / "sample.json", lambda: generate_generic_json(out_dir / "sample.json", target_bytes, rng)),
            ("raw_text", out_dir / "raw.txt", lambda: generate_raw_text(out_dir / "raw.txt", target_bytes, rng)),
        ]
        for label, dst, fn in gen_specs:
            fn()
            files.append(("server_suite", dst, label))

    high_entropy = out_dir / "high_entropy.jsonl"
    generate_high_entropy_jsonl(high_entropy, target_bytes)
    files.append(("server_suite", high_entropy, "high_entropy_jsonl"))

    return files


def iter_openclaw_files(size: str) -> Iterable[Tuple[str, Path, str]]:
    run_dir = REPO_ROOT / "bench" / "datasets" / "openclaw_like" / size / "run_0001"
    for file_path in sorted(run_dir.rglob("*")):
        if file_path.is_file():
            rel = file_path.relative_to(run_dir).as_posix()
            yield ("openclaw", file_path, rel)


def rows_for_bench(
    loop: asyncio.AbstractEventLoop,
    orch: Orchestrator,
    scenario: str,
    file_path: Path,
    label: str,
    verify: bool,
    verify_mode: str,
    zstd_levels: Iterable[int],
) -> List[Dict[str, object]]:
    out_rows: List[Dict[str, object]] = []

    liq = bench_liquefy(loop, orch, file_path, verify=verify, verify_mode=verify_mode)
    out_rows.append({
        "scenario": scenario,
        "file_label": label,
        **liq,
    })

    for lvl in zstd_levels:
        row = bench_zstd(file_path, lvl)
        out_rows.append({
            "scenario": scenario,
            "file_label": label,
            **row,
        })

    return out_rows


def summarize_by_method(rows: List[Dict[str, object]]) -> List[Dict[str, object]]:
    agg: Dict[Tuple[str, str], Dict[str, float]] = {}
    for row in rows:
        key = (str(row["scenario"]), str(row["method"]))
        slot = agg.setdefault(key, {
            "input_bytes": 0.0,
            "output_bytes": 0.0,
            "compress_s": 0.0,
            "decompress_s": 0.0,
            "files": 0.0,
            "hash_pass": 0.0,
            "fallbacks": 0.0,
        })
        slot["input_bytes"] += float(row["input_bytes"])
        slot["output_bytes"] += float(row["output_bytes"])
        slot["compress_s"] += float(row["compress_s"])
        slot["decompress_s"] += float(row["decompress_s"])
        slot["files"] += 1.0
        if row["hash_verify"] == "PASS":
            slot["hash_pass"] += 1.0
        if row["mrtv_fallback"] == "Yes":
            slot["fallbacks"] += 1.0

    out: List[Dict[str, object]] = []
    for (scenario, method), slot in sorted(agg.items()):
        in_b = slot["input_bytes"]
        out_b = max(1.0, slot["output_bytes"])
        c_s = max(1e-9, slot["compress_s"])
        d_s = max(1e-9, slot["decompress_s"])
        out.append({
            "scenario": scenario,
            "method": method,
            "files": int(slot["files"]),
            "ratio": in_b / out_b,
            "compress_mb_s": (in_b / (1024 * 1024)) / c_s,
            "decompress_mb_s": (in_b / (1024 * 1024)) / d_s,
            "hash_pass_rate": f"{int(slot['hash_pass'])}/{int(slot['files'])}",
            "mrtv_fallbacks": int(slot["fallbacks"]),
        })
    return out


def write_outputs(rows: List[Dict[str, object]], summary: List[Dict[str, object]]):
    results_dir = REPO_ROOT / "bench" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    csv_path = results_dir / "format_matrix.csv"
    md_path = results_dir / "FORMAT_REPORT.md"

    fields = [
        "scenario",
        "file_label",
        "method",
        "level",
        "engine_used",
        "mrtv_fallback",
        "input_bytes",
        "output_bytes",
        "ratio",
        "compress_s",
        "compress_mb_s",
        "decompress_s",
        "decompress_mb_s",
        "hash_verify",
    ]

    csv_rows: List[Dict[str, object]] = []
    for row in rows:
        in_b = float(row["input_bytes"])
        out_b = max(1.0, float(row["output_bytes"]))
        c_s = max(1e-9, float(row["compress_s"]))
        d_s = max(1e-9, float(row["decompress_s"]))
        csv_rows.append({
            **row,
            "ratio": f"{in_b / out_b:.2f}x",
            "compress_mb_s": f"{(in_b / (1024 * 1024)) / c_s:.1f}",
            "decompress_mb_s": f"{(in_b / (1024 * 1024)) / d_s:.1f}",
            "compress_s": f"{c_s:.3f}",
            "decompress_s": f"{d_s:.3f}",
        })

    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(csv_rows)

    with md_path.open("w", encoding="utf-8") as f:
        f.write("# Format Matrix Benchmark\n\n")
        f.write("## Summary (weighted by bytes)\n\n")
        f.write("| Scenario | Method | Files | Ratio | Compress MB/s | Decompress MB/s | Hash Pass | MRTV Fallbacks |\n")
        f.write("|---|---:|---:|---:|---:|---:|---:|---:|\n")
        for s in summary:
            f.write(
                f"| {s['scenario']} | {s['method']} | {s['files']} | {s['ratio']:.2f}x | "
                f"{s['compress_mb_s']:.1f} | {s['decompress_mb_s']:.1f} | {s['hash_pass_rate']} | {s['mrtv_fallbacks']} |\n"
            )

        f.write("\n## Per File Detail\n\n")
        f.write("| Scenario | File | Method | Engine | MRTV Fallback | Ratio | Compress MB/s | Decompress MB/s | Hash |\n")
        f.write("|---|---|---|---|---|---|---|---|---|\n")
        for row in csv_rows:
            f.write(
                f"| {row['scenario']} | {row['file_label']} | {row['method']} | {row['engine_used']} | "
                f"{row['mrtv_fallback']} | {row['ratio']} | {row['compress_mb_s']} | {row['decompress_mb_s']} | {row['hash_verify']} |\n"
            )

    print(f"Wrote {csv_path}")
    print(f"Wrote {md_path}")


def main():
    parser = argparse.ArgumentParser(description="Run per-format benchmark matrix for OpenClaw and server formats.")
    parser.add_argument("--openclaw-size", default="200mb", help="OpenClaw dataset size key (default: 200mb)")
    parser.add_argument("--server-target-mb", type=int, default=50, help="Target MB per server-suite format file")
    parser.add_argument(
        "--server-mode",
        choices=["realistic", "fixture-repeat"],
        default="realistic",
        help="Server-suite data mode: realistic synthetic logs or repeated tiny fixtures.",
    )
    parser.add_argument("--server-seed", type=int, default=20260222, help="Seed for realistic server-suite generation")
    parser.add_argument(
        "--liquefy-profile",
        choices=["default", "ratio", "speed"],
        default="default",
        help="Optional Liquefy engine profile (default keeps current production tuning).",
    )
    parser.add_argument(
        "--zstd-levels",
        default="3,6,19,22",
        help="Comma-separated zstd levels to benchmark (default: 3,6,19,22).",
    )
    parser.add_argument("--no-verify", action="store_true", help="Disable Liquefy MRTV verification for speed-mode benchmarking.")
    parser.add_argument("--verify-mode", choices=["full", "fast", "off"], default="full", help="Liquefy verify mode.")
    args = parser.parse_args()
    try:
        zstd_levels = [int(x.strip()) for x in args.zstd_levels.split(",") if x.strip()]
    except ValueError as e:
        raise SystemExit(f"Invalid --zstd-levels value: {args.zstd_levels}") from e
    if not zstd_levels:
        raise SystemExit("Invalid --zstd-levels: no levels provided")
    zstd_levels = list(dict.fromkeys(zstd_levels))
    verify_mode = "off" if args.no_verify else args.verify_mode
    if args.liquefy_profile == "default":
        os.environ.pop("LIQUEFY_PROFILE", None)
    else:
        os.environ["LIQUEFY_PROFILE"] = args.liquefy_profile

    ensure_dataset(args.openclaw_size)
    server_files = build_server_suite(args.server_target_mb, mode=args.server_mode, seed=args.server_seed)

    orch = Orchestrator(
        engines_dir=str(REPO_ROOT / "api" / "engines"),
        master_secret="bench_secret_2026_matrix_runner_key",
    )
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    all_rows: List[Dict[str, object]] = []
    try:
        for scenario, path, label in iter_openclaw_files(args.openclaw_size):
            print(f"[OPENCLAW] {label}")
            all_rows.extend(rows_for_bench(
                loop,
                orch,
                scenario,
                path,
                label,
                verify=(verify_mode != "off"),
                verify_mode=verify_mode,
                zstd_levels=zstd_levels,
            ))

        for scenario, path, label in server_files:
            print(f"[SERVER] {label}")
            all_rows.extend(rows_for_bench(
                loop,
                orch,
                scenario,
                path,
                label,
                verify=(verify_mode != "off"),
                verify_mode=verify_mode,
                zstd_levels=zstd_levels,
            ))
    finally:
        loop.close()

    summary = summarize_by_method(all_rows)
    write_outputs(all_rows, summary)


if __name__ == "__main__":
    main()
