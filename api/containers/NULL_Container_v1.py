from __future__ import annotations
import os, struct
from dataclasses import dataclass
from typing import BinaryIO, Dict, List, Optional, Tuple

import zstandard as zstd

from .utils import sha256, enc_varint, dec_varint
from .bloom import Bloom

MAGIC = b"NULLA\x01"
VERSION = 1

# Header: MAGIC(6) + VER(1) + RESERVED(1) + INDEX_OFF(u64) + FLAGS(u32) + RESERVED(12) = 32 bytes
HDR_FMT = "<6sBBQI12s"
HDR_SIZE = struct.calcsize(HDR_FMT)

# Block header:
# codec_id(u8) + reserved(u8) + flags(u16)
# u_len(u32) + c_len(u32) + m_len(u32)
# bloom(256) + sha256(32)
BLK_FMT = "<BBHIII256s32s"
BLK_SIZE = struct.calcsize(BLK_FMT)

# Index entry:
# off(u64) + codec_id(u8) + reserved(7) + u_len(u32) + c_len(u32) + m_len(u32)
IDX_FMT = "<QB7sIII"
IDX_SIZE = struct.calcsize(IDX_FMT)

@dataclass
class BlockRef:
    off: int
    codec_id: int
    u_len: int
    c_len: int
    m_len: int
    bloom: bytes
    digest: bytes

def _zstd_c(level: int = 12) -> zstd.ZstdCompressor:
    return zstd.ZstdCompressor(level=level)

def _zstd_d() -> zstd.ZstdDecompressor:
    return zstd.ZstdDecompressor()

def write_header(f: BinaryIO, index_off: int = 0, flags: int = 0) -> None:
    f.write(struct.pack(HDR_FMT, MAGIC, VERSION, 0, index_off, flags, b"\x00"*12))

def patch_index_off(f: BinaryIO, index_off: int) -> None:
    f.seek(0)
    f.write(struct.pack(HDR_FMT, MAGIC, VERSION, 0, index_off, 0, b"\x00"*12))

def read_header(f: BinaryIO) -> int:
    f.seek(0)
    magic, ver, _, index_off, _, _ = struct.unpack(HDR_FMT, f.read(HDR_SIZE))
    if magic != MAGIC:
        raise ValueError("Bad magic (not .nulla)")
    if ver != VERSION:
        raise ValueError(f"Unsupported version {ver}")
    return index_off

def write_block(f: BinaryIO, codec_id: int, meta: bytes, comp: bytes, raw: bytes, bloom: Bloom) -> Tuple[int,int,int,int,int,bytes,bytes]:
    off = f.tell()
    u_len = len(raw)
    c_len = len(comp)
    m_len = len(meta)
    digest = sha256(raw)
    f.write(struct.pack(BLK_FMT, codec_id, 0, 0, u_len, c_len, m_len, bytes(bloom.bits), digest))
    if m_len:
        f.write(meta)
    f.write(comp)
    return off, codec_id, u_len, c_len, m_len, bytes(bloom.bits), digest

def write_index(f: BinaryIO, blocks: List[Tuple[int,int,int,int,int,bytes,bytes]], gmeta: bytes) -> int:
    # gmeta is zstd-compressed bytes
    index_off = f.tell()
    f.write(enc_varint(len(gmeta)))
    f.write(gmeta)
    f.write(enc_varint(len(blocks)))
    for off, codec_id, u_len, c_len, m_len, _, _ in blocks:
        f.write(struct.pack(IDX_FMT, off, codec_id, b"\x00"*7, u_len, c_len, m_len))
    return index_off

def read_index(f: BinaryIO) -> Tuple[bytes, List[BlockRef]]:
    index_off = read_header(f)
    f.seek(index_off)

    # read gmeta
    def read_varint_file() -> int:
        shift = 0
        val = 0
        while True:
            b = f.read(1)
            if not b:
                raise ValueError("EOF in varint")
            x = b[0]
            val |= (x & 0x7F) << shift
            if not (x & 0x80):
                return val
            shift += 7
            if shift > 63:
                raise ValueError("varint too large")

    g_len = read_varint_file()
    gmeta = f.read(g_len)
    n = read_varint_file()

    blocks: List[BlockRef] = []
    for _ in range(n):
        off, codec_id, _, u_len, c_len, m_len = struct.unpack(IDX_FMT, f.read(IDX_SIZE))
        # read block header to grab bloom+hash without duplicating in index
        cur = f.tell()
        f.seek(off)
        hdr = f.read(BLK_SIZE)
        codec2, _, _, u2, c2, m2, bloom, digest = struct.unpack(BLK_FMT, hdr)
        if codec2 != codec_id or u2 != u_len or c2 != c_len or m2 != m_len:
            raise ValueError("Index/header mismatch (corrupt archive)")
        blocks.append(BlockRef(off, codec_id, u_len, c_len, m_len, bloom, digest))
        f.seek(cur)
    return gmeta, blocks
