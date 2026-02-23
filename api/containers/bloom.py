from __future__ import annotations
from dataclasses import dataclass
from typing import Iterable
from .utils import hash64

@dataclass
class Bloom:
    # Fixed-size bloom: 2048 bits (256 bytes)
    bits: bytearray

    @staticmethod
    def empty() -> "Bloom":
        return Bloom(bytearray(256))

    def add_u64(self, x: int) -> None:
        # 3 hashes derived from x
        for k in (x, x * 0x9E3779B97F4A7C15 & ((1<<64)-1), x ^ (x >> 33)):
            bit = k % (2048)
            self.bits[bit >> 3] |= (1 << (bit & 7))

    def add_token(self, token: bytes) -> None:
        self.add_u64(hash64(token))

    def add_tokens(self, tokens: Iterable[bytes]) -> None:
        for t in tokens:
            self.add_token(t)

    def maybe_has_u64(self, x: int) -> bool:
        for k in (x, x * 0x9E3779B97F4A7C15 & ((1<<64)-1), x ^ (x >> 33)):
            bit = k % 2048
            if not (self.bits[bit >> 3] & (1 << (bit & 7))):
                return False
        return True

    def maybe_has_token(self, token: bytes) -> bool:
        return self.maybe_has_u64(hash64(token))
