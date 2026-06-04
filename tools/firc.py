#!/usr/bin/env python3
"""FIRC -- Forward-Integrity Receipt Chain.

A forward-secure, append-only MAC chain over a sequence of receipt leaves for
the OpenClaw vault. Each appended entry is:

  * chained to its predecessor (a hash chain over a domain-separated,
    length-prefixed entry digest) so insertion / reordering is detected; and
  * tagged with an *epoch key* that ratchets forward and is wiped after use.

Why it exists
-------------
``common_signing.py`` signs vault artifacts with a single static HMAC key for
all of history. If that key ever leaks, every past signature becomes forgeable.
FIRC closes that window: the per-entry key ``A_j`` is derived only forward
(``A_{j+1} = H("evolve" || A_j)``) and the prior key is zeroized, so an attacker
who captures the *current* key cannot forge, reorder, or alter any entry < j.

Each entry is additionally bound to an x402 receipt hash and a mandate scope, so
a tag certifies not just "this happened" but "this paid action happened under
this mandate" -- the payments-grade property a record-only log cannot make.

Honest scope (read before pitching)
-----------------------------------
* Symmetric / keyed-verifier model: a verifier that can re-derive the seed
  (holds ``master_secret`` + ``session_id``) checks the whole chain. Public,
  key-free verification is a separate signature tier -- NOT this module.
* Forward security protects PAST entries against a FUTURE key compromise. It
  does NOT stop an attacker holding the current key from appending forged
  *future* entries -- that is bounded by anchoring / checkpoints, not FIRC.
* Standalone, FIRC detects forge / alter / reorder of the entries you hold.
  Detecting *truncation* of the tail requires comparing against a known
  (e.g. on-chain anchored) head -- pass ``expected_head`` to ``verify_chain``.
* Key zeroization is best-effort (CPython may retain copies); it is defense in
  depth, not a guarantee.

Pure standard library (hashlib + hmac) -- same crypto family as common_signing.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Dict, List, Optional, Sequence

_DOMAIN = b"firc/v1"
_KEY_LEN = 32


def _u64(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("sequence number out of range")
    return n.to_bytes(8, "big")


def _lp(b: bytes) -> bytes:
    """Length-prefix a field so concatenation is unambiguous (no canonical gaps)."""
    return _u64(len(b)) + b


def _h(*parts: bytes) -> bytes:
    """Domain-separated SHA-256 over length-prefixed parts."""
    m = hashlib.sha256()
    m.update(_lp(_DOMAIN))
    for p in parts:
        m.update(_lp(p))
    return m.digest()


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = _KEY_LEN) -> bytes:
    """RFC 5869 HKDF-SHA256 (extract + expand)."""
    if not salt:
        salt = b"\x00" * hashlib.sha256().digest_size
    if length > 255 * hashlib.sha256().digest_size:
        raise ValueError("HKDF: requested length exceeds 255*HashLen")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_seed(master_secret: bytes, session_id: str) -> bytes:
    """A0 -- the genesis epoch key, bound to this session."""
    return hkdf_sha256(master_secret, session_id.encode("utf-8"), _DOMAIN + b"/seed", _KEY_LEN)


def genesis_prev(session_id: str) -> bytes:
    return _h(b"genesis", session_id.encode("utf-8"))


def _entry_digest(seq: int, prev_hash: bytes, leaf_hash: bytes, receipt_hash: bytes, mandate_hash: bytes) -> bytes:
    return _h(b"entry", _u64(seq), prev_hash, leaf_hash, receipt_hash, mandate_hash)


def _tag(epoch_key: bytes, entry_digest: bytes) -> bytes:
    # fixed-length inputs keep the raw concat unambiguous; enforce the invariant
    if len(epoch_key) != _KEY_LEN or len(entry_digest) != 32:
        raise ValueError("FIRC internal: unexpected key/digest length")
    return hmac.new(epoch_key, _DOMAIN + b"/tag" + entry_digest, hashlib.sha256).digest()


def _evolve(epoch_key: bytes) -> bytes:
    if len(epoch_key) != _KEY_LEN:
        raise ValueError("FIRC internal: unexpected key length")
    return hashlib.sha256(_DOMAIN + b"/evolve" + epoch_key).digest()


class FIRCChain:
    """Builder for a forward-integrity receipt chain.

    Construct from a genesis seed (see :meth:`from_master`) and ``append`` leaves.
    The current epoch key lives in a ``bytearray`` and is wiped on each ratchet.
    """

    def __init__(self, seed: bytes, *, session_id: str) -> None:
        if len(seed) != _KEY_LEN:
            raise ValueError("seed must be %d bytes" % _KEY_LEN)
        self.session_id = session_id
        self._key: Optional[bytearray] = bytearray(seed)
        self._seq = 0
        self._prev = genesis_prev(session_id)
        self.entries: List[Dict[str, object]] = []

    @classmethod
    def from_master(cls, master_secret: bytes, session_id: str) -> "FIRCChain":
        return cls(derive_seed(master_secret, session_id), session_id=session_id)

    def append(self, leaf: bytes, *, receipt_hash: bytes = b"", mandate: bytes = b"") -> Dict[str, object]:
        """Append a leaf to the chain.

        ``receipt_hash`` is the caller-provided digest of the bound x402 receipt
        (already hashed); ``mandate`` is the raw mandate-scope bytes (hashed
        internally). Empty bytes mean "none" for that field.
        """
        if self._key is None:
            raise RuntimeError("chain is closed")
        for _name, _val in (("leaf", leaf), ("receipt_hash", receipt_hash), ("mandate", mandate)):
            if not isinstance(_val, (bytes, bytearray)):
                raise TypeError("%s must be bytes, got %s" % (_name, type(_val).__name__))
        leaf_hash = hashlib.sha256(leaf).digest()
        mandate_hash = hashlib.sha256(mandate).digest() if mandate else b""
        digest = _entry_digest(self._seq, self._prev, leaf_hash, receipt_hash, mandate_hash)
        tag = _tag(bytes(self._key), digest)
        entry: Dict[str, object] = {
            "seq": self._seq,
            "prev_hash": self._prev.hex(),
            "leaf_hash": leaf_hash.hex(),
            "receipt_hash": receipt_hash.hex(),
            "mandate_hash": mandate_hash.hex(),
            "entry_digest": digest.hex(),
            "tag": tag.hex(),
        }
        self.entries.append(entry)
        # advance the chain, ratchet the key forward, then wipe the old key
        self._prev = digest
        self._seq += 1
        nxt = _evolve(bytes(self._key))
        for i in range(len(self._key)):
            self._key[i] = 0
        self._key = bytearray(nxt)
        return entry

    def head(self) -> Dict[str, object]:
        """Anchorable summary: entry count + last digest. Anchor this (e.g. to
        Solana) to seal the chain against tail truncation."""
        return {"count": self._seq, "head_hash": self._prev.hex(), "session_id": self.session_id}


def verify_chain(
    master_secret: bytes,
    session_id: str,
    entries: Sequence[Dict[str, object]],
    *,
    leaves: Optional[Sequence[bytes]] = None,
    expected_head: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    """Replay the ratchet and verify every entry's chain link + tag.

    If ``leaves`` is given, also checks each stored ``leaf_hash`` against the
    real leaf bytes. If ``expected_head`` (a prior :meth:`FIRCChain.head`,
    typically anchored on-chain) is given, also checks count + head_hash to
    detect truncation / extension.

    Stops at the first failure: once a link or tag is wrong, every downstream
    epoch key derivation is meaningless.
    """
    key = bytearray(derive_seed(master_secret, session_id))
    prev = genesis_prev(session_id)
    failures: List[Dict[str, object]] = []
    verified = 0
    for i, e in enumerate(entries):
        row: Dict[str, object] = {"index": i, "seq": e.get("seq")}
        try:
            if int(e.get("seq", -1)) != i:
                row["error"] = "SEQ_GAP_OR_REORDER"
                failures.append(row)
                break
            if str(e.get("prev_hash", "")) != prev.hex():
                row["error"] = "CHAIN_LINK_MISMATCH"
                failures.append(row)
                break
            leaf_hash = bytes.fromhex(str(e.get("leaf_hash", "")))
            if leaves is not None:
                if i >= len(leaves) or hashlib.sha256(leaves[i]).digest() != leaf_hash:
                    row["error"] = "LEAF_HASH_MISMATCH"
                    failures.append(row)
                    break
            receipt_hash = bytes.fromhex(str(e.get("receipt_hash", "")))
            mandate_hash = bytes.fromhex(str(e.get("mandate_hash", "")))
            digest = _entry_digest(i, prev, leaf_hash, receipt_hash, mandate_hash)
            if digest.hex() != str(e.get("entry_digest", "")):
                row["error"] = "ENTRY_DIGEST_MISMATCH"
                failures.append(row)
                break
            expected_tag = _tag(bytes(key), digest)
            if not hmac.compare_digest(expected_tag.hex(), str(e.get("tag", ""))):
                row["error"] = "TAG_MISMATCH"
                failures.append(row)
                break
            verified += 1
            prev = digest
            nxt = _evolve(bytes(key))
            for j in range(len(key)):
                key[j] = 0
            key = bytearray(nxt)
        except Exception as exc:  # malformed / non-hex entry
            row["error"] = "MALFORMED: %s" % exc
            failures.append(row)
            break

    ok = (verified == len(entries)) and not failures
    result: Dict[str, object] = {
        "ok": ok,
        "verified": verified,
        "count": len(entries),
        "failures": failures,
    }
    if expected_head is not None:
        if failures:
            # inner verification already failed; the head check is meaningless
            head_ok = False
        else:
            head_ok = (
                int(expected_head.get("count", -1)) == len(entries)
                and str(expected_head.get("head_hash", "")) == prev.hex()
            )
            if not head_ok:
                failures.append({"error": "HEAD_MISMATCH_TRUNCATION_OR_EXTENSION"})
        result["head_ok"] = head_ok
        result["ok"] = bool(result["ok"] and head_ok)
    return result


if __name__ == "__main__":  # tiny self-demo (no I/O, no network)
    import json

    c = FIRCChain.from_master(b"demo-master-secret", "demo-session")
    for n in range(3):
        c.append(("action-%d" % n).encode(), receipt_hash=hashlib.sha256(("rx-%d" % n).encode()).digest())
    head = c.head()
    print(json.dumps({"head": head, "verify": verify_chain(b"demo-master-secret", "demo-session", c.entries, expected_head=head)}, indent=2))
