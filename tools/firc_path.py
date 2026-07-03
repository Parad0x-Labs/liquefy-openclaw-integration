#!/usr/bin/env python3
"""firc_path -- key-free Merkle inclusion proofs over a FIRC chain.

FIRC's head() seals only the tail (count + last entry_digest), so a single
interior paid action cannot be proven in isolation. firc_path builds a Merkle
tree over the chain's per-entry entry_digests and emits a logarithmic inclusion
proof, so ONE paid action (its leaf, receipt, mandate at position j) is provable
standalone against the anchored Merkle root -- KEY-FREE, with every other entry
withheld.

Scope (read before pitching):
* This is a MEMBERSHIP / POSITION proof, not a confidentiality (ZK) proof and
  not a tag-authenticity proof. It shows: "this entry_digest sits at position j
  in the chain committed by this root." It reveals nothing about the entries you
  do not disclose, but it does not hide the disclosed one.
* Per-entry HMAC authenticity stays with FIRC's keyed verifier; public
  authenticity of the ROOT itself comes from anchoring + the Ed25519 head
  cosignature tier, not from this proof alone.
* "Anchored" is confirmation-level, not finalized (a finality receipt is a
  separate build target).

Pure standard library (hashlib). Domain-separated and second-preimage-resistant
(distinct leaf/node prefixes; deterministic empty-leaf padding to a power of two
-- no duplicate-leaf ambiguity). verify_reveal recomputes the entry_digest via
FIRC's own formula so the disclosed fields are bound to the proven position.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Sequence

_DOMAIN = b"firc-path/v1"
_LEAF = b"\x00"
_NODE = b"\x01"
_EMPTY = hashlib.sha256(_DOMAIN + b"/empty-leaf").digest()


def _leaf_hash(entry_digest_hex: str) -> bytes:
    return hashlib.sha256(_LEAF + _DOMAIN + bytes.fromhex(entry_digest_hex)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_NODE + _DOMAIN + left + right).digest()


def _next_pow2(n: int) -> int:
    p = 1
    while p < n:
        p <<= 1
    return p


def _u64(n: int) -> bytes:
    return int(n).to_bytes(8, "big")


def _root_with_count(tree_root: bytes, count: int) -> bytes:
    # bind the EXACT entry count into the committed root, so a re-stamped count
    # (same power-of-two bucket) cannot reuse a valid proof
    return hashlib.sha256(_DOMAIN + b"/root" + tree_root + _u64(count)).digest()


def _levels(entry_digests: Sequence[str]) -> List[List[bytes]]:
    n = len(entry_digests)
    if n == 0:
        return [[_EMPTY]]
    pad = 1 if n <= 1 else _next_pow2(n)
    level = [_leaf_hash(d) for d in entry_digests] + [_EMPTY] * (pad - n)
    levels = [level]
    while len(level) > 1:
        level = [_node_hash(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
    return levels


def merkle_root(entry_digests: Sequence[str]) -> str:
    """Domain-separated, count-bound Merkle root over the chain's entry_digests."""
    levels = _levels(entry_digests)
    return _root_with_count(levels[-1][0], len(entry_digests)).hex()


def inclusion_proof(entry_digests: Sequence[str], index: int) -> Dict[str, object]:
    """Logarithmic audit path for the entry at `index`."""
    n = len(entry_digests)
    if not (0 <= index < n):
        raise IndexError("index out of range")
    levels = _levels(entry_digests)
    path: List[str] = []
    idx = index
    for lvl in range(len(levels) - 1):
        path.append(levels[lvl][idx ^ 1].hex())
        idx >>= 1
    return {
        "root": _root_with_count(levels[-1][0], n).hex(),
        "count": n,
        "index": index,
        "leaf_digest": str(entry_digests[index]),
        "audit_path": path,
    }


def verify_inclusion(root_hex: str, count: int, index: int, leaf_digest_hex: str, audit_path: Sequence[str]) -> bool:
    """KEY-FREE: recompute the count-bound root from a single leaf_digest + audit
    path and compare. False on any out-of-range / shape / value mismatch (fail
    closed). The exact count is bound into the root, so a re-stamped count is
    rejected even within the same power-of-two bucket."""
    if count < 1 or not (0 <= index < count):
        return False
    if len(leaf_digest_hex) != 64:  # FIRC entry_digests are 32-byte hex
        return False
    pad = 1 if count <= 1 else _next_pow2(count)
    depth = pad.bit_length() - 1
    if len(audit_path) != depth:
        return False
    try:
        h = _leaf_hash(leaf_digest_hex)
        for lvl in range(depth):
            sib = bytes.fromhex(audit_path[lvl])
            h = _node_hash(sib, h) if (index >> lvl) & 1 else _node_hash(h, sib)
        committed = _root_with_count(h, count)
    except ValueError:
        return False
    return committed.hex() == root_hex


def reveal(entries: Sequence[Dict[str, object]], index: int) -> Dict[str, object]:
    """Produce a standalone disclosure bundle for ONE entry: the Merkle root +
    audit path + the single entry dict. Every other entry stays withheld."""
    digests = [str(e.get("entry_digest", "")) for e in entries]
    proof = inclusion_proof(digests, index)
    return {
        "root": proof["root"],
        "count": proof["count"],
        "index": index,
        "entry": dict(entries[index]),
        "audit_path": proof["audit_path"],
    }


def verify_reveal(bundle: Dict[str, object], *, leaf: Optional[bytes] = None) -> Dict[str, object]:
    """KEY-FREE verification of a single revealed action against the anchored
    root. Checks (a) the disclosed fields recompute to the claimed entry_digest
    via FIRC's own formula, (b) seq == index, (c) Merkle inclusion at index, and
    (d optionally) sha256(leaf) == leaf_hash. ok requires all supplied checks."""
    import firc  # FIRC's entry_digest formula is the single source of truth

    try:
        entry = dict(bundle["entry"])  # type: ignore[index]
        root = str(bundle["root"])
        count = int(bundle["count"])
        index = int(bundle["index"])
        audit_path = list(bundle["audit_path"])  # type: ignore[arg-type]
        ed_claim = str(entry.get("entry_digest", ""))
        recomputed = firc._entry_digest(
            int(entry.get("seq", -1)),
            bytes.fromhex(str(entry.get("prev_hash", ""))),
            bytes.fromhex(str(entry.get("leaf_hash", ""))),
            bytes.fromhex(str(entry.get("receipt_hash", ""))),
            bytes.fromhex(str(entry.get("mandate_hash", ""))),
        ).hex()
    except Exception as exc:
        return {"ok": False, "error": "MALFORMED: %s" % exc,
                "digest_ok": False, "seq_ok": False, "position_ok": False}

    digest_ok = (recomputed == ed_claim)
    seq_ok = (int(entry.get("seq", -1)) == index)
    position_ok = verify_inclusion(root, count, index, ed_claim, audit_path)
    result: Dict[str, object] = {
        "digest_ok": digest_ok,
        "seq_ok": seq_ok,
        "position_ok": position_ok,
    }
    leaf_ok = None
    if leaf is not None:
        leaf_ok = (hashlib.sha256(leaf).hexdigest() == str(entry.get("leaf_hash", "")))
        result["leaf_ok"] = leaf_ok
    result["ok"] = bool(digest_ok and seq_ok and position_ok and (leaf_ok is not False))
    return result


if __name__ == "__main__":  # self-demo (needs firc on path; no network/IO)
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import firc  # type: ignore

    c = firc.FIRCChain.from_master(b"demo-master", "demo-session")
    for n in range(5):
        c.append(("action-%d" % n).encode(), receipt_hash=hashlib.sha256(("rx-%d" % n).encode()).digest())
    b = reveal(c.entries, 2)
    print(json.dumps({
        "revealed_index": b["index"], "count": b["count"], "root": b["root"][:16] + "...",
        "audit_path_len": len(b["audit_path"]),
        "verify": verify_reveal(b, leaf=b"action-2"),
    }, indent=2))
