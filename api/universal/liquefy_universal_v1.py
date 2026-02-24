#!/usr/bin/env python3
"""
LiquefyUniversalV1
==================
Universal byte-preserving container with legacy decoder compatibility.

v6 format (current):
  NMX5 + version(1) + compressed_len(u32 be) + zstd_frame

v5 format (legacy):
  Supported for backwards reads only.
"""

import base64
import binascii
import io
import math
import struct
import sys
from collections import Counter
from typing import Tuple

import xxhash
import zstandard as zstd
from common_zstd import make_cctx
from liquefy_primitives import pack_varint, unpack_varint_buf, ZSTD_MAGIC

PROTOCOL_ID = b"NMX5"
VERSION = 6
LEGACY_VERSION = 5


class LiquefyUniversalV1:
    def __init__(
        self,
        level: int = 9,
        threads: int = 0,
        high_compression_level: int = 19,
        entropy_threshold: float = 5.5,
    ):
        self.level = level
        self.threads = threads
        self.high_compression_level = high_compression_level
        self.entropy_threshold = entropy_threshold
        self.dctx = zstd.ZstdDecompressor()
        self._cctx_default = make_cctx(
            level=self.level,
            text_like=True,
            write_content_size=True,
            write_checksum=False,
            write_dict_id=False,
        )
        self._cctx_high = (
            self._cctx_default
            if self.high_compression_level == self.level
            else make_cctx(
                level=self.high_compression_level,
                text_like=True,
                write_content_size=True,
                write_checksum=False,
                write_dict_id=False,
            )
        )

    @staticmethod
    def _sample_entropy(data: bytes, sample_size: int = 1 << 20) -> float:
        data = data[:sample_size]
        if not data:
            return 0.0
        freq_counts = Counter(data)
        total = float(len(data))
        h = 0.0
        for c in freq_counts.values():
            if c:
                p = c / total
                h -= p * math.log2(p)
        return h

    def _select_level(self, raw: bytes) -> int:
        # Use higher level only for very low-entropy text-like streams.
        entropy = self._sample_entropy(raw)
        if entropy <= self.entropy_threshold:
            return self.high_compression_level
        return self.level

    def compress(self, raw: bytes) -> bytes:
        raw = raw or b""
        level = self._select_level(raw)
        cctx = self._cctx_high if level == self.high_compression_level else self._cctx_default
        payload = cctx.compress(raw)
        candidate_raw = payload
        candidate_v6 = PROTOCOL_ID + bytes([VERSION]) + struct.pack(">I", len(payload)) + payload
        return candidate_raw if len(candidate_raw) <= len(candidate_v6) else candidate_v6

    def _zstd_decompress(self, payload: bytes) -> bytes:
        with self.dctx.stream_reader(io.BytesIO(payload)) as reader:
            return reader.read()

    def decompress(self, blob: bytes) -> bytes:
        if blob.startswith(ZSTD_MAGIC):
            return self._zstd_decompress(blob)
        if not blob.startswith(PROTOCOL_ID) or len(blob) < 5:
            return b""

        ver = blob[4]
        if ver == VERSION:
            if len(blob) < 9:
                return b""
            payload_len = struct.unpack(">I", blob[5:9])[0]
            payload = blob[9:9 + payload_len]
            if len(payload) != payload_len:
                return b""
            return self._zstd_decompress(payload)

        if ver == LEGACY_VERSION:
            return self._decompress_legacy_v5(blob)

        return b""

    def grep(self, archive: bytes, query: str) -> int:
        if archive.startswith(ZSTD_MAGIC):
            data = self._zstd_decompress(archive)
            return data.count(query.encode())
        if not archive.startswith(PROTOCOL_ID) or len(archive) < 5:
            return 0

        ver = archive[4]
        q = query.encode()

        if ver == VERSION:
            data = self.decompress(archive)
            return data.count(q)

        if ver == LEGACY_VERSION:
            return self._grep_legacy_v5(archive, q)

        return 0

    def _decompress_legacy_v5(self, blob: bytes) -> bytes:
        p = 4
        _ver = blob[p]
        p += 1
        dl, p = unpack_varint_buf(blob, p)
        dd = blob[p:p + dl]
        p += dl
        dctx = zstd.ZstdDecompressor(dict_data=zstd.ZstdCompressionDict(dd))
        nb, p = unpack_varint_buf(blob, p)
        _k = blob[p]
        p += 1
        bits = struct.unpack(">I", blob[p:p + 4])[0]
        p += 4

        block_lengths = []
        bloom_bytes = (bits + 7) // 8
        for _ in range(nb):
            p += bloom_bytes
            block_lengths.append(struct.unpack(">I", blob[p:p + 4])[0])
            p += 4

        out = bytearray()
        for blen in block_lengths:
            out.extend(self._dec_block_legacy(dctx.decompress(blob[p:p + blen])))
            p += blen
        return bytes(out)

    def _dec_block_legacy(self, block: bytes) -> bytes:
        p = 0
        skel_len, p = unpack_varint_buf(block, p)
        skel = block[p:p + skel_len]
        p += skel_len
        bin_count, p = unpack_varint_buf(block, p)
        tok_count = skel.count(0)
        tags = block[p:p + tok_count]
        p += tok_count
        ids = []
        for _ in range(tok_count):
            v, p = unpack_varint_buf(block, p)
            ids.append(v)
        bin_lens = []
        for _ in range(bin_count):
            v, p = unpack_varint_buf(block, p)
            bin_lens.append(v)
        bins = []
        for blen in bin_lens:
            bins.append(block[p:p + blen])
            p += blen

        parts = skel.split(b"\x00")
        out = bytearray()
        for i in range(tok_count):
            out.extend(parts[i])
            tag = tags[i]
            data = bins[ids[i]]
            if tag == 0:
                out.extend(binascii.hexlify(data))
            elif tag == 1:
                out.extend(binascii.hexlify(data).upper())
            elif tag == 2:
                out.extend(base64.b64encode(data))
        out.extend(parts[-1])
        return bytes(out)

    def _grep_legacy_v5(self, archive: bytes, query: bytes) -> int:
        p = 4
        _ver = archive[p]
        p += 1
        dl, p = unpack_varint_buf(archive, p)
        dd = archive[p:p + dl]
        p += dl
        dctx = zstd.ZstdDecompressor(dict_data=zstd.ZstdCompressionDict(dd))
        nb, p = unpack_varint_buf(archive, p)
        k = archive[p]
        p += 1
        bits = struct.unpack(">I", archive[p:p + 4])[0]
        p += 4

        bb = (bits + 7) // 8
        h1 = xxhash.xxh64(query, seed=0).intdigest()
        h2 = xxhash.xxh64(query, seed=1).intdigest()

        infos = []
        for _ in range(nb):
            bloom = archive[p:p + bb]
            match = True
            for j in range(k):
                pos = (h1 + j * h2) % bits
                if not (bloom[pos >> 3] & (1 << (pos & 7))):
                    match = False
                    break
            p += bb
            blen = struct.unpack(">I", archive[p:p + 4])[0]
            p += 4
            infos.append((match, blen))

        count = 0
        for match, blen in infos:
            if match:
                chunk = dctx.decompress(archive[p:p + blen])
                count += self._dec_block_legacy(chunk).count(query)
            p += blen
        return count


if __name__ == "__main__":
    codec = LiquefyUniversalV1()
    if len(sys.argv) < 3:
        raw = b"NMX5 test data"
        comp = codec.compress(raw)
        dec = codec.decompress(comp)
        print("MATCH" if dec == raw else "FAIL")
    else:
        if sys.argv[1] == "compress":
            with open(sys.argv[2], "rb") as f:
                data = f.read()
            with open(sys.argv[3], "wb") as f:
                f.write(codec.compress(data))
        elif sys.argv[1] == "decompress":
            with open(sys.argv[2], "rb") as f:
                data = f.read()
            with open(sys.argv[3], "wb") as f:
                f.write(codec.decompress(data))
