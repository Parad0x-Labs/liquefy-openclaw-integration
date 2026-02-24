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
import sys
import struct
import io
from common_zstd import make_cctx
from liquefy_primitives import pack_varint, unpack_varint_buf, AdaptiveSearchIndex

PROTOCOL_ID = b'EVT\x01'

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
        self.cctx = make_cctx(level=level, text_like=True)
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
        custom = out.getvalue()
        raw_zstd = self.cctx.compress(raw)
        return raw_zstd if len(raw_zstd) <= len(custom) else custom

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(b"\x28\xb5\x2f\xfd"):
            return zstd.ZstdDecompressor().decompress(blob)
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
