#!/usr/bin/env python3
"""
Liquefy Shared Primitives
=========================
Canonical implementations of utilities shared across all Liquefy engines:
  - pack_varint / unpack_varint_buf  (variable-length integer encoding)
  - zigzag_enc / zigzag_dec          (signed-to-unsigned mapping)
  - AdaptiveSearchIndex              (Bloom filter for search indexing)
  - ZSTD_MAGIC                       (raw zstd frame magic bytes)
"""

import math
import xxhash


ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def pack_varint(val: int) -> bytes:
    if val < 0x80:
        return bytes([val])
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val & 0x7F)
    return bytes(out)


def unpack_varint_buf(data: bytes, pos: int) -> tuple[int, int]:
    res = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, pos


def zigzag_enc(n: int) -> int:
    return (n << 1) ^ (n >> 63)


def zigzag_dec(n: int) -> int:
    return (n >> 1) ^ -(n & 1)


class AdaptiveSearchIndex:
    """Bloom-filter based search index shared across all Liquefy engines."""

    def __init__(self, num_items: int, fpr: float = 0.01):
        num_items = max(10, num_items)
        m = -(num_items * math.log(fpr)) / (math.log(2) ** 2)
        self.num_bits = max(64, int(m))
        self.num_bytes = (self.num_bits + 7) // 8
        self.ba = bytearray(self.num_bytes)
        self.k = max(1, int((self.num_bits / num_items) * math.log(2)))

    def add(self, token: bytes):
        h1 = xxhash.xxh64(token, seed=0).intdigest()
        h2 = xxhash.xxh64(token, seed=1).intdigest()
        for i in range(self.k):
            pos = (h1 + i * h2) % self.num_bits
            self.ba[pos >> 3] |= 1 << (pos & 7)

    def check(self, token: bytes) -> bool:
        return self.maybe_has(token)

    def maybe_has(self, token: bytes) -> bool:
        h1 = xxhash.xxh64(token, seed=0).intdigest()
        h2 = xxhash.xxh64(token, seed=1).intdigest()
        for i in range(self.k):
            pos = (h1 + i * h2) % self.num_bits
            if not (self.ba[pos >> 3] & (1 << (pos & 7))):
                return False
        return True

    def __bytes__(self):
        return pack_varint(self.k) + pack_varint(self.num_bits) + bytes(self.ba)

    @staticmethod
    def from_bytes(data: bytes, pos: int) -> tuple["AdaptiveSearchIndex", int]:
        k, pos = unpack_varint_buf(data, pos)
        num_bits, pos = unpack_varint_buf(data, pos)
        num_bytes = (num_bits + 7) // 8
        idx = AdaptiveSearchIndex(10)
        idx.k = k
        idx.num_bits = num_bits
        idx.num_bytes = num_bytes
        idx.ba = bytearray(data[pos : pos + num_bytes])
        return idx, pos + num_bytes
