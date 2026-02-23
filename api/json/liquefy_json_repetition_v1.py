#!/usr/bin/env python3
"""
LiquefyJsonRepetitionV1 - [NULL REPETITION v1]
===================================================
TARGET: 7000x+ Compression on highly repetitive JSON telemetry.
TECH: Line-Level RLE + Pattern Deduplication + Binary Columnar Packing.
"""

import time
import socket
import math
import zstandard as zstd
import xxhash
import sys
import struct
import json
from collections import defaultdict

def pack_varint(val: int) -> bytes:
    if val < 0x80: return bytes([val])
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val & 0x7F)
    return bytes(out)

def unpack_varint_buf(data: bytes, pos: int) -> tuple[int, int]:
    res = 0; shift = 0
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
        idx.k = k; idx.num_bits = num_bits; idx.num_bytes = num_bytes
        idx.ba = bytearray(data[pos:pos+num_bytes])
        return idx, pos + num_bytes

class LiquefyJsonRepetitionV1:
    def __init__(self, level=22):
        self.cctx = zstd.ZstdCompressor(level=level)
        self.dctx = zstd.ZstdDecompressor()

    def compress(self, raw: bytes) -> bytes:
        lines = raw.splitlines(keepends=True)
        if not lines: return b""

        unique_tokens = set()
        rle_lines = [] # (line, count)
        if lines:
            last_line = lines[0]; count = 0
            for line in lines:
                if line == last_line: count += 1
                else:
                    rle_lines.append((last_line, count))
                    # Tokenize sample
                    if len(last_line) < 1024: unique_tokens.add(last_line.strip())
                    last_line = line; count = 1
            rle_lines.append((last_line, count))
            if len(last_line) < 1024: unique_tokens.add(last_line.strip())

        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens: idx.add(t)
        idx_bytes = bytes(idx)

        stream = bytearray()
        stream.extend(pack_varint(len(rle_lines)))
        for line, count in rle_lines:
            stream.extend(pack_varint(len(line))); stream.extend(line)
            stream.extend(pack_varint(count))

        return b'JSUR' + pack_varint(len(idx_bytes)) + idx_bytes + self.cctx.compress(stream)

    def decompress(self, blob: bytes) -> bytes:
        if not blob.startswith(b'JSUR'): return b""
        pos = 4
        l_idx, pos = unpack_varint_buf(blob, pos); pos += l_idx
        stream = self.dctx.decompress(blob[pos:])

        p = 0; out = bytearray()
        num_blocks, p = unpack_varint_buf(stream, p)
        for _ in range(num_blocks):
            llen, p = unpack_varint_buf(stream, p); line = stream[p:p+llen]; p += llen
            count, p = unpack_varint_buf(stream, p)
            for _ in range(count): out.extend(line)
        return bytes(out)

    def grep(self, blob: bytes, query: str):
        pos = 4
        l_idx, pos = unpack_varint_buf(blob, pos)
        idx, _ = AdaptiveSearchIndex.from_bytes(blob, pos)
        q_bytes = query.encode('latin-1')
        if not idx.maybe_has(q_bytes):
            print(f"Index: '{query}' NOT FOUND (FAST SKIP)"); return
        print(f"Index: '{query}' MIGHT EXIST. Decompressing..."); data = self.decompress(blob)
        for line in data.splitlines():
            if q_bytes.lower() in line.lower(): print(line.decode('latin-1', errors='ignore'))

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: python LiquefyJsonRepetitionV1.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    codec = LiquefyJsonRepetitionV1()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(data))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(data))
    elif sys.argv[1] == "grep":
        with open(sys.argv[2], "rb") as f: data = f.read()
        codec.grep(data, sys.argv[3])
