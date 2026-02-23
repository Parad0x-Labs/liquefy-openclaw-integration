from __future__ import annotations
import hashlib
from typing import Iterable, Optional, Tuple

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def blake3_256(b: bytes) -> Optional[bytes]:
    try:
        from blake3 import blake3
    except Exception:
        return None
    return blake3(b).digest()

def hash64(s: bytes) -> int:
    # Stable, dependency-free 64-bit hash for tokens
    return int.from_bytes(hashlib.blake2b(s, digest_size=8).digest(), "little", signed=False)

def grams3(s: bytes) -> Iterable[int]:
    # 3-gram hashes for substring narrowing
    if len(s) < 3:
        yield hash64(b"g:" + s)
        return
    for i in range(len(s)-2):
        yield hash64(b"g:" + s[i:i+3])

def enc_varint(n: int) -> bytes:
    if n < 0:
        raise ValueError("varint expects unsigned")
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)

def dec_varint(buf: bytes, i: int) -> Tuple[int,int]:
    shift = 0
    val = 0
    while True:
        if i >= len(buf):
            raise ValueError("varint truncated")
        b = buf[i]; i += 1
        val |= (b & 0x7F) << shift
        if not (b & 0x80):
            return val, i
        shift += 7
        if shift > 63:
            raise ValueError("varint too large")


def sha256_file(path: str, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()
