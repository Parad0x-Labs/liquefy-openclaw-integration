#!/usr/bin/env python3
"""Regenerate tests/golden/engine_profiles_v1.json from current engine outputs."""
import hashlib
import json
import os
import platform
import sys
from pathlib import Path

import xxhash
import zstandard as zstd

REPO_ROOT = Path(__file__).resolve().parents[2]
API_DIR = REPO_ROOT / "api"
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from orchestrator.engine_map import get_engine_instance
from liquefy_security import VER_SEC as LSEC_VER, DEFAULT_PBKDF2_ITERS as LSEC_DEFAULT_PBKDF2_ITERS


FIXTURES = [
    ("liquefy-json-hypernebula-v1", "tests/fixtures/golden_inputs/generic_json_hyperfriendly_1024.jsonl"),
    ("liquefy-json-hypernebula-v1", "tests/fixtures/jsonl/generic_json_longline_16.jsonl"),
    ("liquefy-vpcflow-v1", "tests/fixtures/golden_inputs/vpcflow_canonical_256.log"),
    ("liquefy-vpcflow-v1", "tests/fixtures/vpcflow/vpcflow_custom_order_64.log"),
]
PROFILES = ["default", "ratio", "speed"]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def set_profile(profile: str):
    if profile == "default":
        os.environ.pop("LIQUEFY_PROFILE", None)
    else:
        os.environ["LIQUEFY_PROFILE"] = profile


def main():
    # Golden regeneration must be deterministic so committed expectations stay stable.
    os.environ["LIQUEFY_DETERMINISTIC"] = "1"
    out = {
        "schema_version": "liquefy.engine_golden.v1",
        "runtime": {
            "python": sys.version.split()[0],
            "zstandard": zstd.__version__,
            "xxhash": xxhash.VERSION,
            "platform": platform.system(),
            "machine": platform.machine(),
            "liquefy_deterministic": os.environ.get("LIQUEFY_DETERMINISTIC", ""),
            "lsec_ver": LSEC_VER,
            "lsec_kdf_iters": LSEC_DEFAULT_PBKDF2_ITERS,
        },
        "fixtures": [],
    }
    for engine_id, rel in FIXTURES:
        path = REPO_ROOT / rel
        raw = path.read_bytes()
        row = {
            "engine_id": engine_id,
            "fixture": rel,
            "input_bytes": len(raw),
            "input_sha256": sha256_bytes(raw),
            "profiles": {},
        }
        for profile in PROFILES:
            set_profile(profile)
            engine = get_engine_instance(engine_id)
            if engine is None:
                raise RuntimeError(f"engine not found: {engine_id}")
            comp = engine.compress(raw)
            restored = engine.decompress(comp)
            row["profiles"][profile] = {
                "output_bytes": len(comp),
                "prefix_hex": comp[:8].hex(),
                "restored_sha256": sha256_bytes(restored),
                "byteperfect": restored == raw,
            }
        out["fixtures"].append(row)

    out_path = Path(__file__).resolve().parent / "engine_profiles_v1.json"
    out_path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
