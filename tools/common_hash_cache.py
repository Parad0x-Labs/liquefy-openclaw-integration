#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Optional


def _file_fingerprint(path: Path) -> Dict[str, int]:
    st = path.stat()
    return {
        "size": int(st.st_size),
        "mtime_ns": int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))),
    }


class HashCache:
    def __init__(self, path: Path, max_entries: int = 200_000):
        self.path = Path(path)
        self.max_entries = max(1, int(max_entries))
        self._entries: "OrderedDict[str, Dict[str, object]]" = OrderedDict()
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            entries = raw.get("entries", {})
            if isinstance(entries, dict):
                for k in sorted(entries.keys()):
                    v = entries[k]
                    if not isinstance(v, dict):
                        continue
                    self._entries[str(k)] = {
                        "size": int(v.get("size", -1)),
                        "mtime_ns": int(v.get("mtime_ns", -1)),
                        "sha256": str(v.get("sha256", "")),
                    }
        except Exception:
            # Corrupt cache is non-fatal; start fresh.
            self._entries.clear()

    def clear(self) -> None:
        self._entries.clear()
        self._dirty = True
        if self.path.exists():
            self.path.unlink(missing_ok=True)

    def lookup(self, path: Path) -> Optional[str]:
        key = str(path.resolve())
        row = self._entries.get(key)
        if not row:
            return None
        try:
            fp = _file_fingerprint(path)
        except OSError:
            return None
        if int(row.get("size", -1)) != fp["size"] or int(row.get("mtime_ns", -1)) != fp["mtime_ns"]:
            return None
        sha = str(row.get("sha256", ""))
        if not sha:
            return None
        # LRU bump
        self._entries.move_to_end(key)
        return sha

    def record(self, path: Path, sha256_hex: str) -> None:
        try:
            fp = _file_fingerprint(path)
        except OSError:
            return
        key = str(path.resolve())
        self._entries[key] = {
            "size": fp["size"],
            "mtime_ns": fp["mtime_ns"],
            "sha256": str(sha256_hex),
        }
        self._entries.move_to_end(key)
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)
        self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema": "liquefy.hash_cache",
            "schema_version": "v1",
            "max_entries": self.max_entries,
            "entries": dict(self._entries),
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        if os.name != "nt":
            try:
                self.path.chmod(0o600)
            except OSError:
                pass
        self._dirty = False
