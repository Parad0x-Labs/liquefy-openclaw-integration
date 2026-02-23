#!/usr/bin/env python3
"""
NULL_Aws_CloudTrail_Entropy_Focused - [NULL ENTROPY v1 - LOSSLESS]
==================================================================
TARGET: AWS CloudTrail Logs (.json or .json.gz).
TECH:   Zstd LDM + Adaptive Search Index.
STATUS: 100% Lossless, Searchable.
"""

import time
import re
import io
import zstandard as zstd
import math
import xxhash
import sys
import struct
import json

PROTOCOL_ID = b'CTL\x01'
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

def pack_varint(val: int) -> bytes:
    if val < 0x80: return struct.pack("B", val)
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80); val >>= 7
    out.append(val & 0x7F)
    return bytes(out)

def unpack_varint_buf(data: bytes, pos: int) -> tuple[int, int]:
    val = data[pos]; pos += 1
    if val < 0x80: return val, pos
    res = val & 0x7F; shift = 7
    while True:
        b = data[pos]; pos += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80): break
        shift += 7
    return res, pos

class AdaptiveSearchIndex:
    def __init__(self, num_items: int, fpr=0.01):
        num_items = max(10, num_items)
        m = -(num_items * math.log(fpr)) / (math.log(2)**2)
        self.num_bits = max(64, int(m))
        self.num_bytes = (self.num_bits + 7) // 8
        self.ba = bytearray(self.num_bytes)
        self.k = max(1, int((self.num_bits / num_items) * math.log(2)))

    def add(self, token: bytes):
        h1 = xxhash.xxh64(token, seed=0).intdigest()
        h2 = xxhash.xxh64(token, seed=1).intdigest()
        for i in range(self.k):
            pos = (h1 + i * h2) % self.num_bits
            self.ba[pos >> 3] |= (1 << (pos & 7))

    def check(self, token: bytes) -> bool:
        h1 = xxhash.xxh64(token, seed=0).intdigest()
        h2 = xxhash.xxh64(token, seed=1).intdigest()
        for i in range(self.k):
            pos = (h1 + i * h2) % self.num_bits
            if not (self.ba[pos >> 3] & (1 << (pos & 7))): return False
        return True

    def __bytes__(self):
        return pack_varint(self.k) + pack_varint(self.num_bits) + bytes(self.ba)

    @staticmethod
    def from_bytes(data: bytes, pos: int):
        k, pos = unpack_varint_buf(data, pos); num_bits, pos = unpack_varint_buf(data, pos)
        num_bytes = (num_bits + 7) // 8; idx = AdaptiveSearchIndex(10)
        idx.k = k; idx.num_bits = num_bits; idx.num_bytes = num_bytes
        idx.ba = bytearray(data[pos:pos+num_bytes])
        return idx, pos + num_bytes

class LiquefyCloudTrailV1:
    def __init__(self, level=19):
        self.level = level
        self.raw_cctx = zstd.ZstdCompressor(
            level=level,
            write_content_size=False,
            write_checksum=False,
            write_dict_id=False,
        )
        self.dctx = zstd.ZstdDecompressor()

    def compress(self, raw: bytes) -> bytes:
        if not raw: return b""

        # Fast path for highly repetitive streams.
        raw_candidate = self.raw_cctx.compress(raw)
        if len(raw_candidate) * 4 < len(raw):
            return raw_candidate

        # 1. Search Index (Extract common fields)
        tokens = set()
        # Find "eventTime":"...", "eventName":"...", etc.
        for m in re.finditer(rb'"(eventTime|eventName|eventSource|sourceIPAddress|userAgent)":"(.*?)"', raw[:200000]):
            tokens.add(m.group(2))

        idx = AdaptiveSearchIndex(len(tokens))
        for t in tokens: idx.add(t)
        idx_bytes = bytes(idx)

        # 2. Lossless Zstd with LDM.
        # Use from_level(...) so configured level is preserved.
        try:
            params = zstd.ZstdCompressionParameters.from_level(
                self.level,
                enable_ldm=True,
                window_log=22,
                write_content_size=False,
                write_checksum=False,
                write_dict_id=False,
            )
            cctx = zstd.ZstdCompressor(compression_params=params)
        except:
            cctx = self.raw_cctx

        c_raw = cctx.compress(raw)
        indexed_candidate = PROTOCOL_ID + pack_varint(len(idx_bytes)) + idx_bytes + c_raw
        return raw_candidate if len(raw_candidate) <= len(indexed_candidate) else indexed_candidate

    def _zstd_decompress(self, payload: bytes) -> bytes:
        with self.dctx.stream_reader(io.BytesIO(payload)) as reader:
            return reader.read()

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(ZSTD_MAGIC):
            return self._zstd_decompress(blob)
        if not blob.startswith(PROTOCOL_ID): return b""
        p = 4
        idx_len, p = unpack_varint_buf(blob, p); p += idx_len
        return self._zstd_decompress(blob[p:])

    def grep(self, blob: bytes, query: str):
        if blob.startswith(ZSTD_MAGIC):
            data = self._zstd_decompress(blob)
            q_bytes = query.encode("utf-8")
            print(f"Found {data.count(q_bytes)} matches for '{query}'")
            return
        if not blob.startswith(PROTOCOL_ID): return
        p = 4
        idx_len, p = unpack_varint_buf(blob, p)
        idx, _ = AdaptiveSearchIndex.from_bytes(blob, p)
        q_bytes = query.encode('utf-8')
        if not idx.check(q_bytes):
            print(f"Index: '{query}' NOT FOUND"); return
        data = self.decompress(blob)
        print(f"Found {data.count(q_bytes)} matches for '{query}'")

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: [compress|decompress] <in> <out>"); sys.exit(1)
    codec = LiquefyCloudTrailV1()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(d))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: d=f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(d))
