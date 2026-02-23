#!/usr/bin/env python3
"""
LiquefyNginxRepetitionV1 - [NULL REPETITION v1]
=====================================================
TARGET: 7000x+ Compression on highly repetitive Nginx logs.
TECH: Pattern Deduplication + RLE + Binary Columnar Packing + Adaptive Search Index.
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

class LiquefyNginxRepetitionV1:
    def __init__(self, level=22):
        self.cctx = zstd.ZstdCompressor(level=level)
        self.dctx = zstd.ZstdDecompressor()

    def compress(self, raw: bytes) -> bytes:
        patterns = {}; pat_list = []
        s_pats = bytearray(); s_code = bytearray(); s_size = bytearray(); s_raw = bytearray()
        last_pat_id = -1; run_count = 0; last_code = 200; last_size = 0
        unique_tokens = set()

        # Nginx regex (standard)
        import re
        # $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
        nx_re = re.compile(rb'^(\S+) - (\S+) \[(.*?)\] "(.*?)" (\d+|-) (\d+|-) "(.*?)" "(.*?)"(\r?\n?)$')

        lines = raw.splitlines(keepends=True)
        if not lines: return b""

        for line in lines:
            m = nx_re.match(line)
            if m:
                ip, user, ts, req, code_b, size_b, ref, ua, eol = m.groups()

                try: code = int(code_b) if code_b != b'-' else -1
                except: code = -2
                try: size = int(size_b) if size_b != b'-' else -1
                except: size = -2

                unique_tokens.add(ip); unique_tokens.add(req); unique_tokens.add(ref); unique_tokens.add(ua)

                pat_key = (ip, user, ts, req, ref, ua, eol)
                pid = patterns.get(pat_key)
                if pid is None:
                    pid = len(pat_list) + 1; patterns[pat_key] = pid; pat_list.append(pat_key)

                if pid == last_pat_id: run_count += 1
                else:
                    self._flush_run(s_pats, last_pat_id, run_count); last_pat_id = pid; run_count = 1

                cdiff = code - last_code; s_code.extend(pack_varint((cdiff << 1) ^ (cdiff >> 63))); last_code = code
                sdiff = size - last_size; s_size.extend(pack_varint((sdiff << 1) ^ (sdiff >> 63))); last_size = size
            else:
                self._flush_run(s_pats, last_pat_id, run_count); last_pat_id = -1; run_count = 0
                s_pats.append(0); s_raw.extend(pack_varint(len(line))); s_raw.extend(line)

        self._flush_run(s_pats, last_pat_id, run_count)

        # Search Index
        idx = AdaptiveSearchIndex(len(unique_tokens))
        for t in unique_tokens: idx.add(t)
        idx_bytes = bytes(idx)

        col_ip = bytearray(); col_user = bytearray()
        col_ts = bytearray(); col_req = bytearray(); col_ref = bytearray(); col_ua = bytearray(); col_eol = bytearray()

        for (ip, user, ts, req, ref, ua, eol) in pat_list:
            try: packed = socket.inet_aton(ip.decode('ascii')); col_ip.append(0); col_ip.extend(packed)
            except: col_ip.append(1); col_ip.extend(pack_varint(len(ip))); col_ip.extend(ip)
            for col, val in [(col_user, user), (col_ts, ts), (col_req, req), (col_ref, ref), (col_ua, ua), (col_eol, eol)]:
                col.extend(pack_varint(len(val))); col.extend(val)

        payload = bytearray()
        def add_chunk(b): payload.extend(pack_varint(len(b))); payload.extend(b)
        for c in [col_ip, col_user, col_ts, col_req, col_ref, col_ua, col_eol, s_pats, s_code, s_size, s_raw]: add_chunk(c)

        compressed_payload = self.cctx.compress(payload)
        return b'UNI\x01' + pack_varint(len(idx_bytes)) + idx_bytes + compressed_payload

    def _flush_run(self, stream, pid, count):
        if pid == -1: return
        stream.extend(pack_varint(pid)); stream.extend(pack_varint(count))

    def decompress(self, blob: bytes) -> bytes:
        if not blob.startswith(b'UNI\x01'): return b""
        pos = 4
        l_idx, pos = unpack_varint_buf(blob, pos)
        pos += l_idx # Skip index
        payload = self.dctx.decompress(blob[pos:])
        def get_chunk(p): ln, p = unpack_varint_buf(payload, p); return payload[p:p+ln], p+ln

        p = 0
        chunks = []
        for _ in range(11): chunk, p = get_chunk(p); chunks.append(chunk)

        c_ip, c_user, c_ts, c_req, c_ref, c_ua, c_eol, s_pats, s_code, s_size, s_raw = chunks
        pat_list = []; p_ip = 0; p_user = 0; p_ts = 0; p_req = 0; p_ref = 0; p_ua = 0; p_eol = 0
        while p_ip < len(c_ip):
            tag = c_ip[p_ip]; p_ip += 1
            if tag == 0: ip = socket.inet_ntoa(c_ip[p_ip:p_ip+4]).encode(); p_ip += 4
            else: vlen, p_ip = unpack_varint_buf(c_ip, p_ip); ip = c_ip[p_ip:p_ip+vlen]; p_ip += vlen

            def next_v(c, cp): vlen, cp = unpack_varint_buf(c, cp); return c[cp:cp+vlen], cp+vlen
            user, p_user = next_v(c_user, p_user); ts, p_ts = next_v(c_ts, p_ts); req, p_req = next_v(c_req, p_req)
            ref, p_ref = next_v(c_ref, p_ref); ua, p_ua = next_v(c_ua, p_ua); eol, p_eol = next_v(c_eol, p_eol)
            pat_list.append((ip, user, ts, req, ref, ua, eol))

        out = bytearray(); p_pats = 0; p_code = 0; p_size = 0; p_raw = 0; last_code = 200; last_size = 0
        while p_pats < len(s_pats):
            try: pid, p_pats = unpack_varint_buf(s_pats, p_pats)
            except: break
            if pid == 0:
                try: ln, p_raw = unpack_varint_buf(s_raw, p_raw); out.extend(s_raw[p_raw:p_raw+ln]); p_raw += ln
                except: break
            else:
                try: count, p_pats = unpack_varint_buf(s_pats, p_pats)
                except: break
                if pid > len(pat_list): break
                pat = pat_list[pid-1]
                for _ in range(count):
                    c_delta, p_code = unpack_varint_buf(s_code, p_code); code = last_code + zigzag_dec(c_delta); last_code = code
                    s_delta, p_size = unpack_varint_buf(s_size, p_size); size = last_size + zigzag_dec(s_delta); last_size = size
                    c_str = b"-" if code == -1 else str(code).encode()
                    s_str = b"-" if size == -1 else str(size).encode()
                    out.extend(pat[0] + b' - ' + pat[1] + b' [' + pat[2] + b'] "' + pat[3] + b'" ' + c_str + b' ' + s_str + b' "' + pat[4] + b'" "' + pat[5] + b'"' + pat[6])
        return bytes(out)

    def grep(self, blob: bytes, query: str):
        if not blob.startswith(b'UNI\x01'): return
        pos = 4
        l_idx, pos = unpack_varint_buf(blob, pos)
        idx_data = blob[pos:pos+l_idx]
        idx, _ = AdaptiveSearchIndex.from_bytes(idx_data, 0)

        q_bytes = query.encode('latin-1')
        if not idx.maybe_has(q_bytes):
            print(f"Index says: '{query}' NOT FOUND (FAST SKIP)")
            return

        print(f"Index says: '{query}' MIGHT EXIST. Decompressing...")
        full_data = self.decompress(blob)
        lines = full_data.splitlines()
        results = [l for l in lines if q_bytes.lower() in l.lower()]
        for r in results: print(r.decode('latin-1'))
        print(f"Found {len(results)} matches.")

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: python LiquefyNginxRepetitionV1.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    codec = LiquefyNginxRepetitionV1()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(data))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(data))
    elif sys.argv[1] == "grep":
        with open(sys.argv[2], "rb") as f: data = f.read()
        codec.grep(data, sys.argv[3])
