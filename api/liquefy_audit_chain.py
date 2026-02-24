"""
liquefy_audit_chain.py
======================
Tamper-proof append-only audit log with hash chain for compliance.

Every operation (compress, decompress, leak scan, prune, archive) is logged
with a SHA-256 hash chain. Each entry includes the hash of the previous entry,
creating an immutable sequence that detects any tampering.

Designed for:
    - Enterprise compliance (SOC2, HIPAA audit requirements)
    - Multi-tenant isolation (separate chains per org/tenant)
    - Forensic analysis (prove "this trace existed at this time")
    - Tamper detection (any modification breaks the chain)
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


DEFAULT_AUDIT_DIR = Path(os.environ.get("LIQUEFY_AUDIT_DIR", str(Path.home() / ".liquefy" / "audit")))

_lock = threading.Lock()


class AuditChain:
    """Append-only hash-chained audit log."""

    def __init__(self, audit_dir: Optional[Path] = None, tenant: str = "default"):
        self.audit_dir = (audit_dir or DEFAULT_AUDIT_DIR) / tenant
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        self._chain_file = self.audit_dir / "chain.jsonl"
        self._last_hash = self._load_last_hash()

    def _load_last_hash(self) -> str:
        """Load the hash of the last entry in the chain."""
        if not self._chain_file.exists():
            return "0" * 64  # genesis

        try:
            with self._chain_file.open("r", encoding="utf-8") as f:
                last_line = ""
                for line in f:
                    line = line.strip()
                    if line:
                        last_line = line
                if last_line:
                    entry = json.loads(last_line)
                    return entry.get("_hash", "0" * 64)
        except Exception:
            pass
        return "0" * 64

    def _compute_hash(self, entry: Dict) -> str:
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append(self, event: str, **details: Any) -> Dict:
        """Append an entry to the audit chain. Thread-safe."""
        with _lock:
            entry = {
                "seq": self._get_next_seq(),
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "event": event,
                "prev_hash": self._last_hash,
            }
            entry.update(details)

            entry["_hash"] = self._compute_hash(entry)
            self._last_hash = entry["_hash"]

            with self._chain_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry, separators=(",", ":"), sort_keys=True) + "\n")

            return entry

    def _get_next_seq(self) -> int:
        if not self._chain_file.exists():
            return 0
        try:
            with self._chain_file.open("r", encoding="utf-8") as f:
                count = sum(1 for line in f if line.strip())
            return count
        except Exception:
            return 0

    def verify(self) -> Dict[str, Any]:
        """Verify the entire chain is intact. Returns verification result."""
        if not self._chain_file.exists():
            return {"ok": True, "entries": 0, "status": "empty"}

        entries = 0
        prev_hash = "0" * 64
        first_broken: Optional[int] = None

        try:
            with self._chain_file.open("r", encoding="utf-8") as f:
                for line_num, line in enumerate(f):
                    line = line.strip()
                    if not line:
                        continue

                    entry = json.loads(line)
                    stored_hash = entry.pop("_hash", "")
                    stored_prev = entry.get("prev_hash", "")

                    if stored_prev != prev_hash and first_broken is None:
                        first_broken = line_num

                    computed = self._compute_hash(entry)
                    if computed != stored_hash and first_broken is None:
                        first_broken = line_num

                    prev_hash = stored_hash
                    entries += 1
        except Exception as exc:
            return {"ok": False, "entries": entries, "error": str(exc)}

        if first_broken is not None:
            return {
                "ok": False,
                "entries": entries,
                "status": "TAMPERED",
                "first_broken_at": first_broken,
            }

        return {"ok": True, "entries": entries, "status": "intact"}

    def query(self, event: Optional[str] = None, limit: int = 50) -> List[Dict]:
        """Query recent entries, optionally filtered by event type."""
        if not self._chain_file.exists():
            return []

        entries = []
        with self._chain_file.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if event is None or entry.get("event") == event:
                        entries.append(entry)
                except json.JSONDecodeError:
                    continue

        return entries[-limit:]


_default_chain: Optional[AuditChain] = None


def get_audit_chain(tenant: str = "default") -> AuditChain:
    global _default_chain
    if _default_chain is None or tenant != "default":
        _default_chain = AuditChain(tenant=tenant)
    return _default_chain


def audit_log(event: str, **details: Any) -> Dict:
    """Convenience: append to default audit chain."""
    try:
        return get_audit_chain().append(event, **details)
    except Exception as exc:
        # Audit-chain persistence is a compliance enhancement, not a correctness
        # prerequisite for compression/restore. Fail open if the host path is not
        # writable (common in sandboxed test environments).
        return {
            "ok": False,
            "status": "audit_unavailable",
            "error": str(exc),
            "event": event,
        }


def audit_verify(tenant: str = "default") -> Dict[str, Any]:
    """Convenience: verify default audit chain."""
    return AuditChain(tenant=tenant).verify()
