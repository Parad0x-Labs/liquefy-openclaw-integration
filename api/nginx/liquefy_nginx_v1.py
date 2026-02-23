#!/usr/bin/env python3
"""
NULL_Nginx_Entropy_Focused - [NULL ENTROPY v1]
==============================================
TARGET: 100% Lossless, Complex Nginx Logs.
TECH: Template-based Columnar Extraction + Adaptive Bloom.
"""

import struct
import zstandard as zstd
import json
import re
import time
import os
import sys
import math
import xxhash
from collections import defaultdict

PROTOCOL_ID = b'LPRM'
VERSION = 1

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

class LogTemplateExtractor:
    def __init__(self):
        self.re_combined = re.compile(r'(^[^\s]+)|(\[.*?\])|(".*?")|(\b\d+\b)')
    def extract(self, line_str):
        variables = []
        def replacer(match):
            variables.append(match.group(0))
            return '\x00'
        s = self.re_combined.sub(replacer, line_str)
        return s, variables

class LiquefyNginxV1:
    def __init__(self, level=22):
        self.extractor = LogTemplateExtractor()
        self.level = level

    def compress(self, input_path, output_path):
        templates = {}; rev_templates = []
        template_buffers = defaultdict(lambda: defaultdict(list))
        structure_stream = []
        unique_tokens = set()

        with open(input_path, 'r', encoding='latin-1') as f:
            for line in f:
                if not line: continue
                template, vars_ = self.extractor.extract(line)
                if template not in templates:
                    tid = len(rev_templates); templates[template] = tid
                    rev_templates.append(template)
                else: tid = templates[template]
                structure_stream.append(tid)
                for i, v in enumerate(vars_):
                    template_buffers[tid][i].append(v)
                    if len(v) > 3: unique_tokens.add(v.encode('latin-1'))

        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens: idx.add(t)
        idx_bytes = bytes(idx)
        cctx = zstd.ZstdCompressor(level=self.level)
        c_tpl = cctx.compress(json.dumps(rev_templates).encode('utf-8'))
        rle_struct = []
        if structure_stream:
            last = structure_stream[0]; run = 0
            for s in structure_stream:
                if s == last: run += 1
                else:
                    rle_struct.extend([last, run]); last = s; run = 1
            rle_struct.extend([last, run])
        c_struct = cctx.compress(NULL_Nginx_Entropy_Focused.pack_vlist(rle_struct))
        col_blob = bytearray()
        for tid in sorted(template_buffers.keys()):
            for col_idx, values in template_buffers[tid].items():
                raw_data = "\x00".join(values).encode('latin-1')
                c_data = cctx.compress(raw_data)
                col_blob.extend(struct.pack('>HBI', tid, col_idx, len(c_data)))
                col_blob.extend(c_data)

        with open(output_path, 'wb') as f:
            f.write(struct.pack('>4sBIIII', PROTOCOL_ID, VERSION, len(c_tpl), len(c_struct), len(col_blob), len(idx_bytes)))
            f.write(idx_bytes); f.write(c_tpl); f.write(c_struct); f.write(col_blob)

    @staticmethod
    def pack_vlist(data):
        buf = bytearray()
        for x in data: buf.extend(pack_varint(x))
        return buf

    def decompress(self, input_path, output_path):
        with open(input_path, 'rb') as f:
            header = f.read(21)
            magic, ver, l_tpl, l_str, l_col, l_idx = struct.unpack('>4sBIIII', header)
            f.read(l_idx) # Skip Index
            dctx = zstd.ZstdDecompressor()
            templates = json.loads(dctx.decompress(f.read(l_tpl)))
            s_iter = self.iter_v(dctx.decompress(f.read(l_str)))
            structure = []
            try:
                while True: structure.extend([next(s_iter)] * next(s_iter))
            except StopIteration: pass
            col_data = f.read(l_col); col_iters = defaultdict(dict); ptr = 0
            while ptr < len(col_data):
                tid, c_idx, size = struct.unpack('>HBI', col_data[ptr:ptr+7])
                ptr += 7; chunk = col_data[ptr:ptr+size]; ptr += size
                raw = dctx.decompress(chunk).decode('latin-1')
                col_iters[tid][c_idx] = iter(raw.split('\x00'))

        with open(output_path, 'w', encoding='latin-1', newline='') as out:
            for tid in structure:
                parts = templates[tid].split('\x00'); res = []
                for j, part in enumerate(parts):
                    res.append(part)
                    if j < len(parts) - 1:
                        try: res.append(next(col_iters[tid][j]))
                        except: res.append("ERR")
                out.write("".join(res))

    def iter_v(self, data):
        idx = 0; n = len(data)
        while idx < n:
            val, idx = unpack_varint_buf(data, idx)
            yield val

    def grep(self, input_path, query_str, max_results=100):
        """Search compressed log file without full decompression."""
        with open(input_path, 'rb') as f:
            magic, ver, l_tpl, l_str, l_col, l_idx = struct.unpack('>4sBIIII', f.read(21))
            idx_data = f.read(l_idx)
            search_idx, _ = AdaptiveSearchIndex.from_bytes(idx_data, 0)

            q_bytes = query_str.encode('latin-1')
            if not search_idx.maybe_has(q_bytes):
                print(f"Index says: '{query_str}' NOT FOUND (FAST SKIP)")
                return

            print(f"Index says: '{query_str}' MIGHT EXIST. Decompressing...")
            dctx = zstd.ZstdDecompressor()
            templates = json.loads(dctx.decompress(f.read(l_tpl)))
            s_iter = self.iter_v(dctx.decompress(f.read(l_str)))
            structure = []
            try:
                while True: structure.extend([next(s_iter)] * next(s_iter))
            except StopIteration: pass
            col_data = f.read(l_col); col_iters = defaultdict(dict); ptr = 0
            while ptr < len(col_data):
                tid, c_idx, size = struct.unpack('>HBI', col_data[ptr:ptr+7])
                ptr += 7; chunk = col_data[ptr:ptr+size]; ptr += size
                raw = dctx.decompress(chunk).decode('latin-1')
                col_iters[tid][c_idx] = iter(raw.split('\x00'))

        results = []
        for line_idx, tid in enumerate(structure):
            parts = templates[tid].split('\x00'); res = []
            for j, part in enumerate(parts):
                res.append(part)
                if j < len(parts) - 1:
                    try: res.append(next(col_iters[tid][j]))
                    except: res.append("ERR")
            line = "".join(res)
            if query_str.lower() in line.lower():
                results.append(f"Line {line_idx+1}: {line}")
                if len(results) >= max_results: break

        for r in results: print(r)
        print(f"Found {len(results)} matches.")

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: python NULL_Nginx_Entropy_Focused.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    lprm = NULL_Nginx_Entropy_Focused()
    if sys.argv[1] == "compress": lprm.compress(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "decompress": lprm.decompress(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "grep": lprm.grep(sys.argv[2], sys.argv[3])
