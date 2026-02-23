#!/usr/bin/env python3
"""Small fuzz/smoke harness for LiquefySecurity.unseal blob parsing."""
from __future__ import annotations

import argparse
import os
import random
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent
API_DIR = str(REPO_ROOT / "api")
if API_DIR not in sys.path:
    sys.path.insert(0, API_DIR)

from liquefy_security import LiquefySecurity  # type: ignore


EXPECTED_EXC = (ValueError, PermissionError, TypeError)


def mutate_bytes(buf: bytes, rng: random.Random) -> bytes:
    data = bytearray(buf)
    if not data:
        return bytes([rng.randrange(256)])

    mode = rng.randrange(6)
    if mode == 0:
        # flip 1-4 bytes
        for _ in range(1 + rng.randrange(min(4, len(data)))):
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randrange(8)
        return bytes(data)
    if mode == 1:
        # truncate
        return bytes(data[: rng.randrange(len(data) + 1)])
    if mode == 2:
        # append junk
        data.extend(os.urandom(rng.randrange(1, 33)))
        return bytes(data)
    if mode == 3:
        # overwrite header-ish bytes
        for i in range(min(len(data), 48)):
            if rng.random() < 0.2:
                data[i] = rng.randrange(256)
        return bytes(data)
    if mode == 4:
        # random bytes similar length
        return os.urandom(max(1, len(data) + rng.randrange(-8, 9)))
    # splice
    cut = rng.randrange(len(data))
    tail = os.urandom(rng.randrange(0, 16))
    return bytes(data[:cut] + tail)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=20260223)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    sec = LiquefySecurity(master_secret="fuzz_secret_value_32bytes_min")
    tenant = "fuzz_tenant"
    data = b"fuzz-payload-" + (b"x" * 256)
    # Use lower PBKDF2 cost in fuzz smoke so parser mutation coverage is practical in CI.
    blob = sec.seal(data, tenant, {"case": "fuzz"}, iters=2_000)

    # Baseline roundtrip sanity.
    plain, meta = sec.unseal(blob, tenant)
    assert plain == data
    assert isinstance(meta, dict)

    # Deterministic attack variants.
    variants = [
        blob[:-1],  # truncated
        bytes([blob[0] ^ 0x01]) + blob[1:],  # magic tamper
        blob[:8] + bytes([blob[8] ^ 0x80]) + blob[9:],  # salt/header tamper
    ]

    # Wrong tenant must fail.
    try:
        sec.unseal(blob, "other_tenant")
        raise AssertionError("wrong tenant unexpectedly decrypted")
    except EXPECTED_EXC:
        pass

    for v in variants:
        try:
            sec.unseal(v, tenant)
        except EXPECTED_EXC:
            pass
        else:
            raise AssertionError("tampered variant unexpectedly decrypted")

    for _ in range(max(1, args.iterations)):
        mutated = mutate_bytes(blob, rng)
        try:
            sec.unseal(mutated, tenant)
        except EXPECTED_EXC:
            continue
        except Exception as exc:  # pragma: no cover
            raise AssertionError(f"unexpected exception type: {type(exc).__name__}: {exc}") from exc

    print(f"[OK] fuzz_security_unseal iterations={args.iterations}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
