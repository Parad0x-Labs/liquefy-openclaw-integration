#!/usr/bin/env python3
"""
NULL_Windows_Evtx_Entropy_Focused - [NULL ENTROPY v1]
====================================================
TARGET: Windows Event Logs (.evtx).
TECH:   UTF-16LE String Lifting + Block Framing + Adaptive Index.
STATUS: 100% Lossless, Searchable.
"""

import time
import re
import zstandard as zstd
import math
import xxhash
import sys
import struct
import io

PROTOCOL_ID = b'EVT\x01'

def pack_varint(val: int) -> bytes:
    if val < 0x80: return struct.pack("B", val)
    out = bytearray()
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80); val >>= 7
    out.append(val & 0x7F)
    return bytes(out)

def unpack_varint_buf(data: bytes, pos: int) -> tuple:
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
        k, p = unpack_varint_buf(data, pos); nb, p = unpack_varint_buf(data, p)
        nby = (nb + 7) // 8; idx = AdaptiveSearchIndex(10)
        idx.k = k; idx.num_bits = nb; idx.num_bytes = nby
        idx.ba = bytearray(data[p:p+nby])
        return idx, p + nby

class StringLifter:
    def __init__(self):
        self.re_wide = re.compile(rb'(?:[\x20-\x7E]\x00){3,}')
        self.re_ascii = re.compile(rb'[\x20-\x7E]{4,}')

    def lift(self, block: bytes) -> tuple:
        tokens = set()
        for m in self.re_wide.finditer(block):
            try:
                tokens.add(m.group(0))
                val = m.group(0).decode('utf-16le')
                if len(val) < 64: tokens.add(val.encode('utf-8'))
            except: pass
        for m in self.re_ascii.finditer(block):
            val = m.group(0)
            if len(val) < 64: tokens.add(val)
        return block, tokens

def zstandard_params(level):
    try:
        return zstd.ZstdCompressionParameters.from_level(level, window_log=27)
    except:
        return None

class LiquefyWindowsV1:
    def __init__(self, level=3):
        self.cctx = zstd.ZstdCompressor(level=level, compression_params=zstandard_params(level))
        self.dctx = zstd.ZstdDecompressor()
        self.lifter = StringLifter()
        self.block_size = 2 * 1024 * 1024

    def compress(self, raw: bytes) -> bytes:
        out = io.BytesIO()
        out.write(PROTOCOL_ID)

        pos = 0
        while pos < len(raw):
            chunk = raw[pos : pos + self.block_size]
            pos += len(chunk)
            _, tokens = self.lifter.lift(chunk)
            idx = AdaptiveSearchIndex(len(tokens))
            for t in tokens: idx.add(t)
            idx_bytes = bytes(idx)
            z_data = self.cctx.compress(chunk)
            out.write(pack_varint(len(idx_bytes)) + idx_bytes + pack_varint(len(z_data)))
            out.write(z_data)
        return out.getvalue()

    def decompress(self, blob: bytes) -> bytes:
        if not blob.startswith(PROTOCOL_ID): raise ValueError("Invalid Magic")
        in_io = io.BytesIO(blob)
        in_io.read(4) # Skip magic

        out = io.BytesIO()
        while True:
            idx_len = self._read_v_stream(in_io)
            if idx_len is None: break
            in_io.read(idx_len) # Skip index
            z_len = self._read_v_stream(in_io)
            if z_len is None: break
            out.write(self.dctx.decompress(in_io.read(z_len)))
        return out.getvalue()

    def _read_v_stream(self, stream):
        b = stream.read(1)
        if not b: return None
        val = b[0]
        if val < 0x80: return val
        res = val & 0x7F; shift = 7
        while True:
            raw = stream.read(1)
            if not raw: break
            b = raw[0]; res |= (b & 0x7F) << shift
            if not (b & 0x80): break
            shift += 7
        return res

    def grep(self, blob: bytes, query: str):
        if not blob.startswith(PROTOCOL_ID): return
        in_io = io.BytesIO(blob)
        in_io.read(4)
        q_bytes, q_wide = query.encode('utf-8'), query.encode('utf-16le')
        hits, skipped, total = 0, 0, 0
        while True:
            idx_len = self._read_v_stream(in_io)
            if idx_len is None: break
            idx_data = in_io.read(idx_len)
            idx, _ = AdaptiveSearchIndex.from_bytes(idx_data, 0)
            z_len = self._read_v_stream(in_io); total += 1
            if idx.check(q_bytes) or idx.check(q_wide):
                raw = self.dctx.decompress(in_io.read(z_len))
                hits += (raw.count(q_bytes) + raw.count(q_wide))
            else:
                skipped += 1; in_io.read(z_len)
        print(f"Found {hits} matches. Skipped {skipped}/{total} blocks.")

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: python NULL_Windows_Evtx_Entropy_Focused.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    codec = NULL_Windows_Evtx_Entropy_Focused()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(data))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(data))
    elif sys.argv[1] == "grep":
        with open(sys.argv[2], "rb") as f: data = f.read()
        codec.grep(data, sys.argv[3])
