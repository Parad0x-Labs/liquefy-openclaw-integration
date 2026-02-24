#!/usr/bin/env python3
"""
liquefy_telemetry_sink.py
=========================
Drop-in replacement for the official telemetry JSONL plugin.

Ingests telemetry JSONL streams straight into the Liquefy vault format
with automatic redaction, bloom filter indexing, and MRTV proofs.

Can run as:
    - Stdin pipe:    cat telemetry.jsonl | python tools/liquefy_telemetry_sink.py pipe --out ./vault
    - File watcher:  python tools/liquefy_telemetry_sink.py watch ~/.openclaw/telemetry/ --out ./vault
    - Batch import:  python tools/liquefy_telemetry_sink.py ingest telemetry.jsonl --out ./vault

Features:
    - Streaming ingestion (no full-file buffering for pipe mode)
    - Automatic secret redaction using LeakHunter patterns
    - Bloom filter generation for each block (searchable while compressed)
    - MRTV verification on every block
    - Configurable flush interval and block size
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import signal
import sys
import time
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
TOOLS_DIR = REPO_ROOT / "tools"
API_DIR = REPO_ROOT / "api"
for _p in (TOOLS_DIR, API_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

try:
    import zstandard as zstd
    from common_zstd import make_cctx
except ImportError:
    zstd = None

    def make_cctx(**kw):
        raise RuntimeError("zstandard not installed")

try:
    from containers.bloom import Bloom
    from containers.utils import sha256
except ImportError:
    Bloom = None
    sha256 = lambda d: hashlib.sha256(d).digest()

CLI_SCHEMA_VERSION = "liquefy.telemetry.cli.v1"

DEFAULT_BLOCK_SIZE = 4 * 1024 * 1024   # 4 MB uncompressed per block
DEFAULT_FLUSH_SECONDS = 30
DEFAULT_MAX_LINE_BYTES = 1 * 1024 * 1024  # 1 MB per line limit

REDACT_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'), "***AWS_KEY***"),
    (re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'), "***GH_TOKEN***"),
    (re.compile(r'sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}'), "***OPENAI_KEY***"),
    (re.compile(r'sk-ant-[A-Za-z0-9\-]{80,}'), "***ANTHROPIC_KEY***"),
    (re.compile(r'(?:mongodb|postgres|mysql|redis|amqp)://[^\s"\']+@[^\s"\']+'), "***CONN_STRING***"),
    (re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), "***PRIVATE_KEY***"),
    (re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{8,}'), "***PASSWORD***"),
    (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'), "***JWT***"),
]


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact_line(line: str) -> tuple[str, int]:
    """Apply redaction patterns to a line. Returns (redacted_line, redaction_count)."""
    count = 0
    for pattern, replacement in REDACT_PATTERNS:
        line, n = pattern.subn(replacement, line)
        count += n
    return line, count


def _format_bytes(n: int) -> str:
    if n >= 1 << 30:
        return f"{n / (1 << 30):.2f} GB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MB"
    return f"{n} B"


class TelemetryBlock:
    """Accumulates JSONL lines into a compressible block with bloom + proof."""

    def __init__(self, block_id: int, cctx):
        self.block_id = block_id
        self.lines: list[bytes] = []
        self.raw_size = 0
        self.line_count = 0
        self.redactions = 0
        self.bloom = Bloom.empty() if Bloom else None
        self._cctx = cctx

    def add_line(self, raw_line: str) -> None:
        redacted, n_redactions = _redact_line(raw_line)
        self.redactions += n_redactions

        line_bytes = redacted.encode("utf-8")
        self.lines.append(line_bytes)
        self.raw_size += len(line_bytes) + 1  # +1 for newline
        self.line_count += 1

        if self.bloom is not None:
            for token in redacted.split()[:50]:
                self.bloom.add_token(token.encode("utf-8"))

    def flush(self) -> dict:
        """Compress the block and return metadata."""
        raw_data = b"\n".join(self.lines)
        raw_hash = hashlib.sha256(raw_data).hexdigest()

        if self._cctx:
            compressed = self._cctx.compress(raw_data)
        else:
            compressed = raw_data

        comp_hash = hashlib.sha256(compressed).hexdigest()

        if self._cctx:
            dctx = zstd.ZstdDecompressor()
            restored = dctx.decompress(compressed)
            mrtv_ok = hashlib.sha256(restored).hexdigest() == raw_hash
        else:
            mrtv_ok = True

        return {
            "block_id": self.block_id,
            "line_count": self.line_count,
            "raw_bytes": len(raw_data),
            "compressed_bytes": len(compressed),
            "ratio": round(len(raw_data) / max(1, len(compressed)), 2),
            "raw_sha256": raw_hash,
            "comp_sha256": comp_hash,
            "mrtv_ok": mrtv_ok,
            "redactions": self.redactions,
            "bloom_bits": self.bloom.bits.hex() if self.bloom else None,
            "compressed_data": compressed,
        }


class TelemetrySink:
    """Main sink that manages blocks and writes to vault output."""

    def __init__(
        self,
        out_dir: Path,
        *,
        block_size: int = DEFAULT_BLOCK_SIZE,
        flush_seconds: int = DEFAULT_FLUSH_SECONDS,
        org: str = "default",
        profile: str = "default",
    ):
        self.out_dir = out_dir
        self.block_size = block_size
        self.flush_seconds = flush_seconds
        self.org = org
        self.profile = profile

        self.out_dir.mkdir(parents=True, exist_ok=True)

        level = {"ratio": 19, "speed": 3}.get(profile, 12)
        self._cctx = make_cctx(level=level) if zstd else None
        self._block_counter = 0
        self._current_block = self._new_block()
        self._blocks_meta: list[dict] = []
        self._total_lines = 0
        self._total_raw = 0
        self._total_comp = 0
        self._total_redactions = 0
        self._last_flush = time.time()

    def _new_block(self) -> TelemetryBlock:
        self._block_counter += 1
        return TelemetryBlock(self._block_counter, self._cctx)

    def ingest_line(self, line: str) -> Optional[dict]:
        """Ingest a single JSONL line. Returns block metadata if a flush occurred."""
        line = line.rstrip("\n\r")
        if not line:
            return None

        if len(line) > DEFAULT_MAX_LINE_BYTES:
            line = line[:DEFAULT_MAX_LINE_BYTES] + "...TRUNCATED"

        self._current_block.add_line(line)
        self._total_lines += 1

        if self._current_block.raw_size >= self.block_size:
            return self._flush_block()

        if time.time() - self._last_flush >= self.flush_seconds:
            return self._flush_block()

        return None

    def _flush_block(self) -> dict:
        meta = self._current_block.flush()
        compressed_data = meta.pop("compressed_data")

        block_file = self.out_dir / f"block_{meta['block_id']:06d}.zst"
        block_file.write_bytes(compressed_data)

        self._total_raw += meta["raw_bytes"]
        self._total_comp += meta["compressed_bytes"]
        self._total_redactions += meta["redactions"]
        meta["output_path"] = str(block_file)
        self._blocks_meta.append(meta)
        self._current_block = self._new_block()
        self._last_flush = time.time()
        return meta

    def finalize(self) -> dict:
        """Flush remaining data and write index."""
        if self._current_block.line_count > 0:
            self._flush_block()

        index = {
            "schema_version": CLI_SCHEMA_VERSION,
            "sink_type": "telemetry",
            "ts": _utc_now(),
            "org": self.org,
            "profile": self.profile,
            "total_lines": self._total_lines,
            "total_blocks": len(self._blocks_meta),
            "total_raw_bytes": self._total_raw,
            "total_compressed_bytes": self._total_comp,
            "overall_ratio": round(self._total_raw / max(1, self._total_comp), 2),
            "total_redactions": self._total_redactions,
            "blocks": self._blocks_meta,
        }

        index_path = self.out_dir / "telemetry_index.json"
        index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")

        return index


def cmd_pipe(args: argparse.Namespace) -> int:
    """Read JSONL from stdin and sink into vault blocks."""
    out_dir = Path(args.out).expanduser().resolve()
    sink = TelemetrySink(
        out_dir,
        block_size=args.block_size,
        flush_seconds=args.flush_seconds,
        org=args.org,
        profile=args.profile,
    )

    try:
        for line in sys.stdin:
            meta = sink.ingest_line(line)
            if meta and not args.quiet:
                print(f"[sink] block {meta['block_id']}: {meta['line_count']} lines, "
                      f"{meta['ratio']}x, {meta['redactions']} redacted", file=sys.stderr)
    except KeyboardInterrupt:
        pass

    index = sink.finalize()
    if args.json:
        print(json.dumps({"ok": True, "result": {k: v for k, v in index.items() if k != "blocks"}}, indent=2))
    else:
        print(f"\nTelemetry Sink Complete:")
        print(f"  Lines: {index['total_lines']}")
        print(f"  Blocks: {index['total_blocks']}")
        print(f"  Raw: {_format_bytes(index['total_raw_bytes'])} -> Compressed: {_format_bytes(index['total_compressed_bytes'])}")
        print(f"  Ratio: {index['overall_ratio']}x")
        print(f"  Redactions: {index['total_redactions']}")
        print(f"  Index: {out_dir / 'telemetry_index.json'}")

    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    """Batch ingest a JSONL file."""
    input_path = Path(args.input).expanduser().resolve()
    if not input_path.exists():
        print(f"File not found: {input_path}", file=sys.stderr)
        return 1

    out_dir = Path(args.out).expanduser().resolve()
    sink = TelemetrySink(
        out_dir,
        block_size=args.block_size,
        flush_seconds=999999,
        org=args.org,
        profile=args.profile,
    )

    with input_path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            sink.ingest_line(line)

    index = sink.finalize()
    if args.json:
        print(json.dumps({"ok": True, "result": {k: v for k, v in index.items() if k != "blocks"}}, indent=2))
    else:
        print(f"Ingested {index['total_lines']} lines -> {index['total_blocks']} blocks "
              f"({_format_bytes(index['total_raw_bytes'])} -> {_format_bytes(index['total_compressed_bytes'])}, "
              f"{index['overall_ratio']}x, {index['total_redactions']} redacted)")

    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    """Watch a directory for new/modified JSONL files and ingest them."""
    watch_dir = Path(args.target).expanduser().resolve()
    out_dir = Path(args.out).expanduser().resolve()

    if not watch_dir.exists():
        print(f"Watch directory not found: {watch_dir}", file=sys.stderr)
        return 1

    processed_mtimes: Dict[str, float] = {}
    running = True

    def _stop(s, f):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    print(f"[telemetry-sink] watching {watch_dir} -> {out_dir}, poll={args.poll}s", file=sys.stderr)

    while running:
        for jsonl_file in sorted(watch_dir.glob("*.jsonl")):
            try:
                mtime = jsonl_file.stat().st_mtime
            except OSError:
                continue

            key = str(jsonl_file)
            if key in processed_mtimes and processed_mtimes[key] >= mtime:
                continue

            vault_name = jsonl_file.stem
            file_out = out_dir / vault_name
            sink = TelemetrySink(
                file_out,
                block_size=args.block_size,
                flush_seconds=999999,
                org=args.org,
                profile=args.profile,
            )

            with jsonl_file.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    sink.ingest_line(line)

            index = sink.finalize()
            processed_mtimes[key] = mtime
            print(f"[telemetry-sink] {jsonl_file.name}: {index['total_lines']} lines, "
                  f"{index['overall_ratio']}x, {index['total_redactions']} redacted", file=sys.stderr)

        for _ in range(args.poll):
            if not running:
                break
            time.sleep(1)

    print("[telemetry-sink] stopped", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="liquefy-telemetry-sink", description="Liquefy Telemetry Vault Sink")
    sub = ap.add_subparsers(dest="command")

    p_pipe = sub.add_parser("pipe", help="Read JSONL from stdin")
    p_pipe.add_argument("--out", required=True, help="Output vault directory")
    p_pipe.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE)
    p_pipe.add_argument("--flush-seconds", type=int, default=DEFAULT_FLUSH_SECONDS)
    p_pipe.add_argument("--org", default="default")
    p_pipe.add_argument("--profile", choices=["default", "ratio", "speed"], default="default")
    p_pipe.add_argument("--quiet", action="store_true")
    p_pipe.add_argument("--json", action="store_true")

    p_ingest = sub.add_parser("ingest", help="Batch ingest a JSONL file")
    p_ingest.add_argument("input", help="Input JSONL file")
    p_ingest.add_argument("--out", required=True, help="Output vault directory")
    p_ingest.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE)
    p_ingest.add_argument("--org", default="default")
    p_ingest.add_argument("--profile", choices=["default", "ratio", "speed"], default="default")
    p_ingest.add_argument("--json", action="store_true")

    p_watch = sub.add_parser("watch", help="Watch directory for JSONL files")
    p_watch.add_argument("target", help="Directory to watch")
    p_watch.add_argument("--out", required=True, help="Output vault directory")
    p_watch.add_argument("--poll", type=int, default=30, help="Seconds between scans")
    p_watch.add_argument("--block-size", type=int, default=DEFAULT_BLOCK_SIZE)
    p_watch.add_argument("--org", default="default")
    p_watch.add_argument("--profile", choices=["default", "ratio", "speed"], default="default")

    return ap


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)

    if not args.command:
        ap.print_help()
        return 1

    handlers = {"pipe": cmd_pipe, "ingest": cmd_ingest, "watch": cmd_watch}
    return handlers[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
