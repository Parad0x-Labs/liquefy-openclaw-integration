"""
liquefy_resilience.py
=====================
Graceful degradation + self-healing for production environments.

Handles:
    - Memory pressure detection and adaptive compression level downgrade
    - Malformed trace recovery (corrupted JSONL, truncated files)
    - Engine crash isolation and automatic fallback
    - Slow HDD detection and I/O scheduling
    - Self-healing on partial writes / power loss
    - Automatic error reporting with "here's exactly how to fix it"
"""
from __future__ import annotations

import gc
import json
import os
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class HealthStatus:
    memory_pressure: str = "normal"  # "normal" | "elevated" | "critical"
    available_memory_mb: int = 0
    disk_speed: str = "fast"  # "fast" | "slow" | "degraded"
    engine_failures: Dict[str, int] = field(default_factory=dict)
    recovery_events: List[Dict[str, Any]] = field(default_factory=list)


def check_memory_pressure() -> Tuple[str, int]:
    """Check current memory pressure. Returns (level, available_mb)."""
    try:
        import psutil
        mem = psutil.virtual_memory()
        available_mb = int(mem.available / (1024 * 1024))
        if mem.percent > 90:
            return "critical", available_mb
        if mem.percent > 75:
            return "elevated", available_mb
        return "normal", available_mb
    except ImportError:
        pass

    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    kb = int(line.split()[1])
                    mb = kb // 1024
                    if mb < 512:
                        return "critical", mb
                    if mb < 2048:
                        return "elevated", mb
                    return "normal", mb
    except (FileNotFoundError, ValueError):
        pass

    return "normal", 0


def adaptive_zstd_level(base_level: int = 12) -> int:
    """Downgrade zstd compression level under memory pressure."""
    pressure, mb = check_memory_pressure()
    if pressure == "critical":
        return min(base_level, 3)
    if pressure == "elevated":
        return min(base_level, 6)
    return base_level


def check_disk_speed(path: Path, threshold_mbps: float = 10.0) -> str:
    """Quick disk speed check. Returns 'fast', 'slow', or 'degraded'."""
    test_file = path / ".liquefy_speed_test"
    try:
        data = os.urandom(1024 * 1024)  # 1 MB
        start = time.monotonic()
        test_file.write_bytes(data)
        test_file.unlink()
        elapsed = time.monotonic() - start

        mbps = 1.0 / max(elapsed, 0.001)
        if mbps < 1.0:
            return "degraded"
        if mbps < threshold_mbps:
            return "slow"
        return "fast"
    except OSError:
        return "degraded"
    finally:
        test_file.unlink(missing_ok=True)


def recover_malformed_jsonl(data: bytes) -> Tuple[bytes, int, int]:
    """
    Attempt to recover valid JSONL lines from potentially corrupted input.
    Returns (recovered_bytes, valid_lines, skipped_lines).
    """
    valid_lines: List[bytes] = []
    skipped = 0

    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        text = data.decode("latin-1")

    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue

        try:
            json.loads(line)
            valid_lines.append(line.encode("utf-8"))
        except json.JSONDecodeError:
            balanced = _try_fix_json_line(line)
            if balanced:
                try:
                    json.loads(balanced)
                    valid_lines.append(balanced.encode("utf-8"))
                    continue
                except json.JSONDecodeError:
                    pass
            skipped += 1

    recovered = b"\n".join(valid_lines)
    return recovered, len(valid_lines), skipped


def _try_fix_json_line(line: str) -> Optional[str]:
    """Attempt to fix common JSON corruption patterns."""
    line = line.strip()
    if not line:
        return None

    if line.startswith("{") and not line.endswith("}"):
        depth = 0
        for ch in line:
            if ch == "{": depth += 1
            elif ch == "}": depth -= 1
        if depth > 0:
            line += "}" * depth
            return line

    if line.endswith(","):
        return line[:-1]

    return None


def recover_truncated_vault(vault_dir: Path) -> Dict[str, Any]:
    """
    Attempt to recover a vault that was partially written (e.g., power loss).
    Reads whatever blocks are intact, rebuilds a partial index.
    """
    results = {"recovered_files": 0, "lost_files": 0, "errors": []}
    index_path = vault_dir / "tracevault_index.json"

    if index_path.exists():
        try:
            index = json.loads(index_path.read_text(encoding="utf-8"))
            valid_receipts = []
            for receipt in index.get("receipts", []):
                output_path = receipt.get("output_path")
                if output_path and Path(output_path).exists():
                    valid_receipts.append(receipt)
                    results["recovered_files"] += 1
                else:
                    results["lost_files"] += 1

            index["receipts"] = valid_receipts
            index["_recovered"] = True
            index["_recovery_ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
            return results
        except json.JSONDecodeError:
            results["errors"].append("Index file corrupted")

    null_files = list(vault_dir.glob("*.null")) + list(vault_dir.glob("*.zst"))
    results["recovered_files"] = len(null_files)

    partial_index = {
        "metadata": {"_recovered": True, "_recovery_ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
        "receipts": [
            {
                "output_path": str(f),
                "original_bytes": 0,
                "compressed_bytes": f.stat().st_size,
                "engine_id": "unknown",
                "_partial_recovery": True,
            }
            for f in null_files
        ],
    }
    index_path.write_text(json.dumps(partial_index, indent=2), encoding="utf-8")
    return results


class ResilientEngine:
    """Wraps any engine with crash isolation, retry, and fallback."""

    def __init__(self, engine: Any, engine_id: str, max_retries: int = 1):
        self._engine = engine
        self._engine_id = engine_id
        self._max_retries = max_retries
        self._failure_count = 0
        self._disabled = False

    @property
    def disabled(self) -> bool:
        return self._disabled

    def compress(self, raw_data: bytes) -> bytes:
        if self._disabled:
            return self._fallback_compress(raw_data)

        for attempt in range(self._max_retries + 1):
            try:
                gc.collect()
                result = self._engine.compress(raw_data)
                self._failure_count = max(0, self._failure_count - 1)
                return result
            except MemoryError:
                self._failure_count += 1
                if self._failure_count >= 3:
                    self._disabled = True
                return self._fallback_compress(raw_data)
            except Exception:
                self._failure_count += 1
                if attempt == self._max_retries:
                    if self._failure_count >= 5:
                        self._disabled = True
                    return self._fallback_compress(raw_data)

        return self._fallback_compress(raw_data)

    def decompress(self, compressed_data: bytes) -> bytes:
        return self._engine.decompress(compressed_data)

    def _fallback_compress(self, data: bytes) -> bytes:
        import zstandard as zstd
        level = adaptive_zstd_level(6)
        return zstd.ZstdCompressor(level=level).compress(data)


# ── Error Messages with Auto-Fix ──


ERROR_FIXES = {
    "MISSING_SECRET": {
        "message": "Encryption is enabled but LIQUEFY_SECRET is not set.",
        "fix": "export LIQUEFY_SECRET=\"$(python3 -c \"import secrets; print(secrets.token_urlsafe(32))\")\"\n# Add to your shell profile for persistence.",
        "auto_fix": None,
    },
    "ZSTANDARD_NOT_FOUND": {
        "message": "The zstandard Python package is not installed.",
        "fix": "pip install zstandard==0.22.0\n# Or: make setup",
        "auto_fix": "pip install zstandard",
    },
    "XXHASH_NOT_FOUND": {
        "message": "The xxhash Python package is not installed.",
        "fix": "pip install xxhash==3.4.1\n# Or: make setup",
        "auto_fix": "pip install xxhash",
    },
    "CRYPTOGRAPHY_NOT_FOUND": {
        "message": "The cryptography package is required for encryption.",
        "fix": "pip install cryptography==41.0.7\n# Or: make setup",
        "auto_fix": "pip install cryptography",
    },
    "UNSAFE_OUTPUT_DIR": {
        "message": "Output directory has group/world-writable permissions.",
        "fix": "chmod 700 <output_dir>\n# Or use: --unsafe-perms-ok to override",
        "auto_fix": None,
    },
    "MEMORY_PRESSURE": {
        "message": "System is under memory pressure. Compression level has been reduced.",
        "fix": "Free up memory or use PRESET=speed for lower memory usage.\n# Close other applications or increase swap.",
        "auto_fix": None,
    },
    "ENGINE_DISABLED": {
        "message": "An engine has been disabled after repeated failures.",
        "fix": "Restart the process to re-enable all engines.\n# The fallback (raw zstd) is being used automatically.",
        "auto_fix": None,
    },
    "MALFORMED_JSONL": {
        "message": "Input contains malformed JSONL lines.",
        "fix": "Run: python tools/liquefy_intelligence.py migrate <file> --out ./vault\n# The migration tool auto-recovers valid lines.",
        "auto_fix": None,
    },
    "VAULT_CORRUPTED": {
        "message": "Vault index is corrupted or incomplete (possible power loss).",
        "fix": "Recovery available. Run recovery with:\npython -c \"from liquefy_resilience import recover_truncated_vault; print(recover_truncated_vault(Path('<vault_dir>')))\"",
        "auto_fix": None,
    },
}


def explain_error(error_code: str, context: Optional[Dict] = None) -> str:
    """Return a human-readable error message with fix instructions."""
    info = ERROR_FIXES.get(error_code, {})
    msg = info.get("message", f"Unknown error: {error_code}")
    fix = info.get("fix", "No auto-fix available. Check the documentation.")

    output = f"\n  ERROR: {msg}\n\n  HOW TO FIX:\n"
    for line in fix.split("\n"):
        output += f"    {line}\n"

    if context:
        output += f"\n  Context: {json.dumps(context, indent=4)}\n"

    return output


def get_health_status(vault_dir: Optional[Path] = None) -> HealthStatus:
    """Get comprehensive system health status."""
    status = HealthStatus()
    pressure, mb = check_memory_pressure()
    status.memory_pressure = pressure
    status.available_memory_mb = mb

    if vault_dir:
        status.disk_speed = check_disk_speed(vault_dir)

    return status
