#!/usr/bin/env python3
"""
NULL_Json_Entropy_Focused - [NULL ENTROPY v1]
=============================================
TARGET: 100% Lossless, Structured JSON Telemetry.
TECH: Field-Aware Delta Encoding + Pattern Deduplication + Adaptive Bloom.
"""

import time
import json
import random
import re
import zstandard as zstd
import math
import xxhash
import sys
from typing import List, Dict, Tuple
from dataclasses import dataclass

PROTOCOL_ID = b'JSC\x01'
VERSION = 1

# ==========================================
# 1. ADAPTIVE UTILITIES
# ==========================================

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

def zigzag_enc(n: int) -> int:
    return (n << 1) ^ (n >> 63)

def zigzag_dec(n: int) -> int:
    return (n >> 1) ^ -(n & 1)

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

# Regex: Captures Punctuation/WS individually, or Tokens
TOKEN_RE = re.compile(
    rb'(?P<PUNC>[{}\[\]:,]|\n)|(?P<WS>\s+)|(?P<STR>"(?:\\.|[^"\\])*")|(?P<NUM>-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)|(?P<LIT>\btrue\b|\bfalse\b|\bnull\b)|(?P<OTHER>.)',
    re.VERBOSE
)

class LiquefyJsonV1:
    def __init__(self, level=22):
        self.cctx = zstd.ZstdCompressor(level=level)
        self.dctx = zstd.ZstdDecompressor()

    def compress(self, raw: bytes) -> bytes:
        tags = bytearray(); vals = bytearray(); nums = bytearray()
        st_map = {}; st_list = []; ws_map = {}; ws_list = []
        field_deltas = {"ts": 0, "timestamp": 0, "time": 0, "id": 0, "user_id": 0, "prio": 0, "load": 0, "status": 0}
        current_field = None; unique_tokens = set()

        for m in TOKEN_RE.finditer(raw):
            kind = m.lastgroup; tok = m.group(0)
            if kind == "PUNC": tags.append(tok[0])
            elif kind == "STR":
                x = st_map.get(tok)
                if x is None:
                    x = len(st_list); st_map[tok] = x; st_list.append(tok)
                    if len(tok) <= 64:
                        key = tok[1:-1]; unique_tokens.add(key)

                # Check if this string is a recognized field key
                if len(tok) <= 64:
                    key_str = tok[1:-1].decode('ascii', errors='ignore')
                    if key_str in field_deltas:
                        current_field = key_str
                    else:
                        current_field = None # Reset if not a recognized key
                else:
                    current_field = None

                tags.append(128); vals.extend(pack_varint(x))
            elif kind == "NUM":
                tags.append(129)
                try:
                    val = int(tok)
                    if current_field and current_field in field_deltas:
                        diff = val - field_deltas[current_field]; field_deltas[current_field] = val
                    else: diff = val
                    nums.extend(pack_varint(zigzag_enc(diff)))
                except ValueError:
                    x = st_map.get(tok)
                    if x is None: x = len(st_list); st_map[tok] = x; st_list.append(tok)
                    tags.pop(); tags.append(128); vals.extend(pack_varint(x))
            elif kind == "WS":
                if tok == b" ": tags.append(32)
                else:
                    x = ws_map.get(tok)
                    if x is None: x = len(ws_list); ws_map[tok] = x; ws_list.append(tok)
                    tags.append(130); vals.extend(pack_varint(x))
            elif kind == "LIT":
                if tok == b"true": tags.append(131)
                elif tok == b"false": tags.append(132)
                else: tags.append(133)
            else:
                tags.append(134); vals.extend(pack_varint(len(tok))); vals.extend(tok)

        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens: idx.add(t)
        idx_bytes = bytes(idx)

        # Meta pack
        def pack_dict(items):
            out = bytearray(); out.extend(pack_varint(len(items)))
            for it in items: out.extend(pack_varint(len(it))); out.extend(it)
            return out

        meta_raw = pack_dict(ws_list) + pack_dict(st_list)

        # Combine streams
        stream = bytearray()
        stream.extend(pack_varint(len(tags))); stream.extend(tags)
        stream.extend(pack_varint(len(vals))); stream.extend(vals)
        stream.extend(nums)

        payload = self.cctx.compress(stream)
        meta = self.cctx.compress(meta_raw)

        final = PROTOCOL_ID + pack_varint(len(idx_bytes)) + idx_bytes + \
                pack_varint(len(meta)) + meta + payload
        return final

    def decompress(self, blob: bytes) -> bytes:
        if not blob.startswith(PROTOCOL_ID): return b""
        pos = 4
        l_idx, pos = unpack_varint_buf(blob, pos); pos += l_idx
        l_meta, pos = unpack_varint_buf(blob, pos)
        meta_raw = self.dctx.decompress(blob[pos:pos+l_meta]); pos += l_meta
        stream = self.dctx.decompress(blob[pos:])

        # Unpack dicts
        def unpack_dict(buf, p):
            n, p = unpack_varint_buf(buf, p); items = []
            for _ in range(n):
                ln, p = unpack_varint_buf(buf, p); items.append(buf[p:p+ln]); p += ln
            return items, p

        p_m = 0
        ws_list, p_m = unpack_dict(meta_raw, p_m)
        st_list, p_m = unpack_dict(meta_raw, p_m)

        # Unpack streams
        p = 0
        tag_len, p = unpack_varint_buf(stream, p); tags_start = p; tags_end = p + tag_len; p = tags_end
        val_len, p = unpack_varint_buf(stream, p); vals_start = p; vals_end = p + val_len; nums_ptr = vals_end

        out = bytearray(); t_ptr = tags_start; v_ptr = vals_start
        field_deltas = {"ts": 0, "timestamp": 0, "time": 0, "id": 0, "user_id": 0, "prio": 0, "load": 0, "status": 0}
        current_field = None

        while t_ptr < tags_end:
            tag = stream[t_ptr]; t_ptr += 1
            if tag < 128: out.append(tag)
            elif tag == 128: # STR
                idx, v_ptr = unpack_varint_buf(stream, v_ptr); s_data = st_list[idx]; out.extend(s_data)
                if len(s_data) <= 64:
                    key = s_data[1:-1].decode('ascii', errors='ignore')
                    if key in field_deltas:
                        current_field = key
                    else:
                        current_field = None
                else:
                    current_field = None
            elif tag == 129: # NUM
                enc_diff, nums_ptr = unpack_varint_buf(stream, nums_ptr); diff = zigzag_dec(enc_diff)
                if current_field and current_field in field_deltas:
                    field_deltas[current_field] += diff; val = field_deltas[current_field]
                else: val = diff
                out.extend(str(val).encode('ascii'))
            elif tag == 130: # WS
                idx, v_ptr = unpack_varint_buf(stream, v_ptr); out.extend(ws_list[idx])
            elif tag == 131: out.extend(b"true")
            elif tag == 132: out.extend(b"false")
            elif tag == 133: out.extend(b"null")
            elif tag == 134:
                ln, v_ptr = unpack_varint_buf(stream, v_ptr); out.extend(stream[v_ptr:v_ptr+ln]); v_ptr += ln
        return bytes(out)

    def grep(self, blob: bytes, query: str):
        pos = 4
        l_idx, pos = unpack_varint_buf(blob, pos)
        idx, _ = AdaptiveSearchIndex.from_bytes(blob, pos)
        if not idx.maybe_has(query.encode('latin-1')):
            print(f"Index: '{query}' NOT FOUND (FAST SKIP)"); return
        print(f"Index: '{query}' MIGHT EXIST. Decompressing..."); data = self.decompress(blob)
        for line in data.splitlines():
            if query.encode('latin-1').lower() in line.lower(): print(line.decode('latin-1', errors='ignore'))

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: python NULL_Json_Entropy_Focused.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    codec = NULL_Json_Entropy_Focused()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(data))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(data))
    elif sys.argv[1] == "grep":
        with open(sys.argv[2], "rb") as f: data = f.read()
        codec.grep(data, sys.argv[3])
