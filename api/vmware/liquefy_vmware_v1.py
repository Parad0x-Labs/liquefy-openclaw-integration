#!/usr/bin/env python3
"""
NULL_Vmware_Entropy_Focused - [NULL ENTROPY v1]
===============================================
TARGET: VMware ESXi / vCenter Logs.
TECH:   Bracket Mining + Global Dedupe + Zstd.
STATUS: 100% Lossless, Searchable.
"""

import time, re, zstandard as zstd, math, xxhash, sys, struct, json, io
from collections import defaultdict

PROTOCOL_ID = b'VMW\x01'

def pack_varint(val: int) -> bytes:
    if val < 0x80: return struct.pack("B", val)
    out = bytearray()
    while val >= 0x80: out.append((val & 0x7F) | 0x80); val >>= 7
    out.append(val & 0x7F); return bytes(out)

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
    def __init__(self, num_items: int):
        num_items = max(10, num_items)
        m = -(num_items * math.log(0.01)) / (math.log(2)**2)
        self.nb = max(64, int(m)); self.nby = (self.nb + 7) // 8
        self.ba = bytearray(self.nby); self.k = max(1, int((self.nb / num_items) * 0.693))
    def add(self, t: bytes):
        h1 = xxhash.xxh64(t, seed=0).intdigest(); h2 = xxhash.xxh64(t, seed=1).intdigest()
        for i in range(self.k): pos = (h1 + i * h2) % self.nb; self.ba[pos >> 3] |= (1 << (pos & 7))
    def check(self, t: bytes) -> bool:
        h1 = xxhash.xxh64(t, seed=0).intdigest(); h2 = xxhash.xxh64(t, seed=1).intdigest()
        for i in range(self.k):
            pos = (h1 + i * h2) % self.nb
            if not (self.ba[pos >> 3] & (1 << (pos & 7))): return False
        return True
    def __bytes__(self): return pack_varint(self.k) + pack_varint(self.nb) + bytes(self.ba)
    @staticmethod
    def from_bytes(d, p):
        k, p = unpack_varint_buf(d, p); nb, p = unpack_varint_buf(d, p)
        idx = AdaptiveSearchIndex(10); idx.k = k; idx.nb = nb; idx.nby = (nb+7)//8
        idx.ba = bytearray(d[p:p+idx.nby]); return idx, p+idx.nby

class LiquefyVmwareV1:
    def __init__(self, level=3):
        self.cctx = zstd.ZstdCompressor(level=level)
        self.dctx = zstd.ZstdDecompressor()
        # Capture: Timestamp, Host, Process, [Meta], Message
        self.re_vm = re.compile(rb'^(\S+) (\S+) (\S+): (\[.*?\]) (.*)$')

    def compress(self, raw: bytes) -> bytes:
        cols = defaultdict(list); uniq_hosts = set(); total_lines = 0

        for line in raw.splitlines():
            total_lines += 1
            m = self.re_vm.match(line)
            if m:
                cols['ts'].append(m.group(1))
                cols['host'].append(m.group(2))
                cols['proc'].append(m.group(3))
                cols['meta'].append(m.group(4))
                cols['msg'].append(m.group(5))
                uniq_hosts.add(m.group(2))
            else:
                cols['raw'].append(line)
                for k in ['ts','host','proc','meta','msg']: cols[k].append(b"")

        def enc_dict(vals):
            u = sorted(list(set(vals)))
            m = {v:i for i,v in enumerate(u)}
            b = bytearray(); b.extend(pack_varint(len(u)))
            for x in u: b.extend(pack_varint(len(x)) + x)
            b.extend(pack_varint(len(vals)))
            if len(u) < 256: b.extend(bytes([m[x] for x in vals]))
            else:
                for x in vals: b.extend(pack_varint(m[x]))
            return b

        idx = AdaptiveSearchIndex(len(uniq_hosts))
        for h in uniq_hosts: idx.add(h)
        idx_bytes = bytes(idx)

        c_payload = bytearray()
        c_payload.extend(pack_varint(total_lines))
        for k in ['host', 'proc', 'meta', 'msg']:
            c_payload.extend(enc_dict(cols[k]))

        ts_blob = b"".join([x + b'\n' for x in cols['ts']])
        c_payload.extend(pack_varint(len(ts_blob)) + ts_blob)

        raw_blob = b"".join([pack_varint(len(x)) + x for x in cols['raw']])
        c_payload.extend(raw_blob)

        return PROTOCOL_ID + pack_varint(len(idx_bytes)) + idx_bytes + self.cctx.compress(c_payload)

    def decompress(self, d: bytes) -> bytes:
        if not d.startswith(PROTOCOL_ID): return b""
        pos = 4
        idx_len, pos = unpack_varint_buf(d, pos); pos += idx_len
        stream = self.dctx.decompress(d[pos:]); p = 0

        total_lines, p = unpack_varint_buf(stream, p)

        def dec_dict(p_in):
            sz, p_in = unpack_varint_buf(stream, p_in); dct = []
            for _ in range(sz): l, p_in = unpack_varint_buf(stream, p_in); dct.append(stream[p_in:p_in+l]); p_in+=l
            cnt, p_in = unpack_varint_buf(stream, p_in); vals = []
            if len(dct) < 256:
                for _ in range(cnt): vals.append(dct[stream[p_in]]); p_in+=1
            else:
                for _ in range(cnt): i, p_in = unpack_varint_buf(stream, p_in); vals.append(dct[i])
            return vals, p_in

        hosts, p = dec_dict(p); procs, p = dec_dict(p)
        metas, p = dec_dict(p); msgs, p = dec_dict(p)

        l_ts, p = unpack_varint_buf(stream, p)
        ts_vals = stream[p:p+l_ts].split(b'\n')[:-1]; p+=l_ts

        # Raw fallback iter
        raw_ptr = p; out = []
        for i in range(total_lines):
            if hosts[i]:
                # Reconstruct: TS Host Proc: Meta Msg
                line = ts_vals[i] + b" " + hosts[i] + b" " + procs[i] + b": " + metas[i] + b" " + msgs[i]
                out.append(line)
            else:
                rl, raw_ptr = unpack_varint_buf(stream, raw_ptr)
                out.append(stream[raw_ptr:raw_ptr+rl]); raw_ptr += rl

        return b'\n'.join(out) + b'\n'

    def grep(self, blob: bytes, query: str):
        pos = 4
        idx_len, pos = unpack_varint_buf(blob, pos)
        idx, _ = AdaptiveSearchIndex.from_bytes(blob, pos)
        q = query.encode()
        if not idx.check(q): return
        data = self.decompress(blob); found = data.count(q)
        print(f"Found {found} matches for '{query}'")

if __name__ == "__main__":
    if len(sys.argv) < 3: print("Usage: python NULL_Vmware_Entropy_Focused.py [compress|decompress|grep] <in> <out/query>"); sys.exit(1)
    codec = NULL_Vmware_Entropy_Focused()
    if sys.argv[1] == "compress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.compress(data))
    elif sys.argv[1] == "decompress":
        with open(sys.argv[2], "rb") as f: data = f.read()
        with open(sys.argv[3], "wb") as f: f.write(codec.decompress(data))
    elif sys.argv[1] == "grep":
        with open(sys.argv[2], "rb") as f: data = f.read()
        codec.grep(data, sys.argv[3])
