#!/usr/bin/env python3
"""
NULL_Sql_Entropy_Focused - [NULL ENTROPY v1]
============================================
TARGET: Maximum SQL Compression + 100% Lossless.
TECH:   Safe-Delta Columnar + Regex Tokenizer + Zstd.
"""

import time
import re
import zstandard as zstd
import sys
import struct
from collections import defaultdict
from common_zstd import make_cctx
from liquefy_primitives import pack_varint, unpack_varint_buf, zigzag_enc, zigzag_dec, AdaptiveSearchIndex

PROTOCOL_ID = b'UNI\x01'

class SafeSmartColumn:
    @staticmethod
    def encode(raw_values: list[bytes]) -> bytes:
        if not raw_values: return pack_varint(0) + pack_varint(0)
        count = len(raw_values)
        if raw_values.count(raw_values[0]) == count:
             return pack_varint(3) + pack_varint(count) + pack_varint(len(raw_values[0])) + raw_values[0]

        unique_vals = set(raw_values)
        if len(unique_vals) < 256 and len(unique_vals) < count * 0.2:
            sorted_uniq = sorted(list(unique_vals)); val_map = {v: i for i, v in enumerate(sorted_uniq)}
            dict_blob = bytearray()
            dict_blob.extend(pack_varint(len(sorted_uniq)))
            for v in sorted_uniq: dict_blob.extend(pack_varint(len(v)) + v)
            idx_blob = bytearray([val_map[v] for v in raw_values])
            return pack_varint(1) + dict_blob + pack_varint(count) + idx_blob

        is_safe_numeric = True; nums = []
        try:
            for x in raw_values:
                if not (x.isdigit() or (x.startswith(b'-') and x[1:].isdigit())): is_safe_numeric = False; break
                if len(x) > 1 and x.startswith(b'0'): is_safe_numeric = False; break
                if x.startswith(b'-0'): is_safe_numeric = False; break
                nums.append(int(x))
        except: is_safe_numeric = False

        if is_safe_numeric:
            deltas = []; last = 0
            for n in nums: deltas.append(zigzag_enc(n - last)); last = n
            delta_blob = bytearray()
            for d in deltas: delta_blob.extend(pack_varint(d))
            return pack_varint(2) + pack_varint(count) + delta_blob

        raw_blob = bytearray()
        for v in raw_values: raw_blob.extend(pack_varint(len(v)) + v)
        return pack_varint(0) + pack_varint(count) + raw_blob

    @staticmethod
    def decode(data: bytes, pos: int) -> tuple[list[bytes], int]:
        mode, pos = unpack_varint_buf(data, pos); values = []
        if mode == 0:
            count, pos = unpack_varint_buf(data, pos)
            for _ in range(count):
                vlen, pos = unpack_varint_buf(data, pos); values.append(data[pos:pos+vlen]); pos += vlen
        elif mode == 3:
            count, pos = unpack_varint_buf(data, pos); vlen, pos = unpack_varint_buf(data, pos)
            val = data[pos:pos+vlen]; pos += vlen; values = [val] * count
        elif mode == 1:
            d_size, pos = unpack_varint_buf(data, pos); dictionary = []
            for _ in range(d_size):
                vlen, pos = unpack_varint_buf(data, pos); dictionary.append(data[pos:pos+vlen]); pos += vlen
            count, pos = unpack_varint_buf(data, pos)
            for _ in range(count): values.append(dictionary[data[pos]]); pos += 1
        elif mode == 2:
            count, pos = unpack_varint_buf(data, pos); last = 0
            for _ in range(count):
                z_delta, pos = unpack_varint_buf(data, pos); last += zigzag_dec(z_delta)
                values.append(str(last).encode('ascii'))
        return values, pos

class LiquefySqlV1:
    def __init__(self, level=22):
        self.cctx = make_cctx(level=level, text_like=True)
        self.dctx = zstd.ZstdDecompressor()
        self.re_token = re.compile(rb"('[^'\\]*(?:\\.[^'\\]*)*'|\"[^\"\\]*(?:\\.[^\"\\]*)*\"|`[^`]+`|0x[0-9a-fA-F]+|-?\d+(?:\.\d+)?|\bNULL\b)", re.IGNORECASE)

    def compress(self, raw: bytes) -> bytes:
        templates = {}; rev_templates = []; tpl_columns = defaultdict(lambda: defaultdict(list))
        line_struct = []; unique_tokens = set()
        for line in raw.splitlines(keepends=True):
            parts = []; last_idx = 0; vars_found = []
            for m in self.re_token.finditer(line):
                start, end = m.span()
                if start > last_idx: parts.append(line[last_idx:start])
                parts.append(b'\x00'); val = m.group(0); vars_found.append(val); last_idx = end
                if len(val) > 2 and (val[0] in b"'\"`"): unique_tokens.add(val[1:-1])
            if last_idx < len(line): parts.append(line[last_idx:])
            tpl_bytes = b"".join(parts)
            tid = templates.get(tpl_bytes)
            if tid is None: tid = len(rev_templates); templates[tpl_bytes] = tid; rev_templates.append(tpl_bytes)
            line_struct.append(tid)
            for i, v in enumerate(vars_found): tpl_columns[tid][i].append(v)

        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens: idx.add(t)
        idx_bytes = bytes(idx)

        t_blob = bytearray()
        t_blob.extend(pack_varint(len(rev_templates)))
        for t in rev_templates: t_blob.extend(pack_varint(len(t)) + t)

        l_blob = bytearray()
        if line_struct:
            l_blob.extend(pack_varint(len(line_struct)))
            last = line_struct[0]; run = 0; rle = []
            for tid in line_struct:
                if tid == last: run += 1
                else: rle.extend([last, run]); last = tid; run = 1
            rle.extend([last, run])
            l_blob.extend(pack_varint(len(rle)//2))
            for x in rle: l_blob.extend(pack_varint(x))
        else:
            l_blob.extend(pack_varint(0))

        c_blob = bytearray()
        for tid in sorted(tpl_columns.keys()):
            for col_idx in sorted(tpl_columns[tid].keys()):
                enc = SafeSmartColumn.encode(tpl_columns[tid][col_idx])
                c_blob.extend(pack_varint(tid) + pack_varint(col_idx) + pack_varint(len(enc)) + enc)

        iv_len_packed = pack_varint(len(idx_bytes))
        custom = PROTOCOL_ID + iv_len_packed + idx_bytes + self.cctx.compress(t_blob + l_blob + c_blob)
        raw_zstd = self.cctx.compress(raw)
        return raw_zstd if len(raw_zstd) <= len(custom) else custom

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(b"\x28\xb5\x2f\xfd"):
            return self.dctx.decompress(blob)
        if not blob.startswith(PROTOCOL_ID): return b""
        pos = 4; idx_len, pos = unpack_varint_buf(blob, pos); pos += idx_len
        stream = self.dctx.decompress(blob[pos:]); p = 0
        num_tpl, p = unpack_varint_buf(stream, p); templates = []
        for _ in range(num_tpl):
            tl, p = unpack_varint_buf(stream, p); templates.append(stream[p:p+tl]); p += tl
        total_lines, p = unpack_varint_buf(stream, p); num_runs, p = unpack_varint_buf(stream, p); struct_tids = []
        for _ in range(num_runs):
            tid, p = unpack_varint_buf(stream, p); run, p = unpack_varint_buf(stream, p); struct_tids.extend([tid]*run)
        col_map = defaultdict(dict)
        while p < len(stream):
            tid, p = unpack_varint_buf(stream, p); col_idx, p = unpack_varint_buf(stream, p)
            dlen, p = unpack_varint_buf(stream, p); vals, _ = SafeSmartColumn.decode(stream[p:p+dlen], 0)
            col_map[tid][col_idx] = iter(vals); p += dlen
        out = []
        for tid in struct_tids:
            parts = templates[tid].split(b"\x00"); line = bytearray()
            for i in range(len(parts)-1):
                line.extend(parts[i]); line.extend(next(col_map[tid][i], b"ERR"))
            line.extend(parts[-1]); out.append(line)
        return b"".join(out)

    def grep(self, blob: bytes, query: str):
        pos = 4; idx_len, pos = unpack_varint_buf(blob, pos); idx, _ = AdaptiveSearchIndex.from_bytes(blob, pos)
        q_bytes = query.encode('utf-8')
        if not idx.check(q_bytes): return
        data = self.decompress(blob); found = data.count(q_bytes)
        print(f"Found {found} matches for '{query}'")

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: python NULL_Sql_Entropy_Focused.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    codec = NULL_Sql_Entropy_Focused()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(data))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(data))
    elif sys.argv[1] == "grep":
        with open(sys.argv[2], "rb") as f: data = f.read()
        codec.grep(data, sys.argv[3])
