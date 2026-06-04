#!/usr/bin/env python3
"""TERS -- Truncation-Evident Receipt Seal.

Folds an entire FIRC chain (see tools/firc.py) into ONE forward-secure
aggregate MAC, so dropping, adding, reordering, or altering any entry changes
the single sealed value. Where FIRC's ``head()`` seals the tail with a
(count, last-digest) pair, TERS produces one aggregate MAC plus a settlement
reconciliation -- the thing you anchor on-chain to prove "nothing was chopped
off, and the logged payments are exactly the payments that settled."

How it works
------------
* TERS derives its OWN forward-secure key schedule from (master_secret,
  session_id) -- a distinct HKDF info from FIRC, so the two MACs never share a
  key. The per-step key ratchets forward (``A_{j+1}=H("evolve"||A_j)``) and is
  wiped, FssAgg-style (Ma-Tsudik 2007).
* For each entry it folds ``agg <- HMAC(A_j, "/agg" || j || agg || entry_digest)``.
  Removing/adding/reordering/altering any entry changes ``agg``.
* It commits a sorted set of the entries' x402 ``receipt_hash`` values
  (``settlement_root``). ``verify_seal`` can then reconcile the logged receipt
  set against an independently observed on-chain settlement set -- surfacing a
  payment that settled but was never logged (an omission) or vice versa.

Honest scope
------------
* Symmetric / keyed model: anyone holding the seed can compute a seal, so the
  seal is only meaningful once the legitimate party ANCHORS it (e.g. on Solana).
  Truncation/alteration is caught by recomputing the aggregate over the
  presented entries and comparing to the anchored seal. Public, key-free
  aggregate *signatures* are a later tier.
* Settlement reconciliation compares the logged receipt set to a
  caller-provided settlement set; it does not itself read the chain.
* TERS seals the chain's SHAPE (via entry_digests) + payment set. Per-entry
  content integrity (leaf bytes, receipt/mandate binding, ordering) is FIRC's
  job -- run ``firc.verify_chain`` alongside this.
* Pure standard library (hashlib + hmac); zeroization is best-effort (CPython).
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Dict, List, Optional, Sequence

_DOMAIN = b"ters/v1"
_KEY_LEN = 32


def _u64(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("counter out of range")
    return n.to_bytes(8, "big")


def _lp(b: bytes) -> bytes:
    return _u64(len(b)) + b


def _h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    m.update(_lp(_DOMAIN))
    for p in parts:
        m.update(_lp(p))
    return m.digest()


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = _KEY_LEN) -> bytes:
    """RFC 5869 HKDF-SHA256."""
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


def _derive_seed(master_secret: bytes, session_id: str) -> bytes:
    return _hkdf_sha256(master_secret, session_id.encode("utf-8"), _DOMAIN + b"/seed", _KEY_LEN)


def _evolve(key: bytes) -> bytes:
    if len(key) != _KEY_LEN:
        raise ValueError("TERS internal: unexpected key length")
    return hashlib.sha256(_DOMAIN + b"/evolve" + key).digest()


def _settlement_root(receipt_hashes: Sequence[str]) -> bytes:
    """Commitment over the sorted unique non-empty receipt hashes (the logged
    payment set)."""
    uniq = sorted({rh for rh in receipt_hashes if rh})
    return _h(b"settle", _u64(len(uniq)), *[bytes.fromhex(rh) for rh in uniq])


def seal(master_secret: bytes, session_id: str, entries: Sequence[Dict[str, object]]) -> Dict[str, object]:
    """Compute the anchorable seal over a FIRC entry list.

    Returns ``{count, agg_mac, settlement_root, session_id}``. Anchor this
    (e.g. to Solana) -- verification recomputes it and compares. ``agg_mac`` is a
    finalization MAC binding count + the running forward-secure aggregate +
    settlement_root under the final epoch key, so that single keyed value
    commits the whole chain (empty chains included).
    """
    key = bytearray(_derive_seed(master_secret, session_id))
    agg = _h(b"agg-iv", session_id.encode("utf-8"))
    receipts: List[str] = []
    for j, e in enumerate(entries):
        ed = bytes.fromhex(str(e.get("entry_digest", "")))
        receipts.append(str(e.get("receipt_hash", "")))
        agg = hmac.new(bytes(key), _DOMAIN + b"/agg" + _lp(_u64(j)) + _lp(agg) + _lp(ed), hashlib.sha256).digest()
        nxt = _evolve(bytes(key))
        for i in range(len(key)):
            key[i] = 0
        key = bytearray(nxt)
    sroot = _settlement_root(receipts)
    # finalization: bind count + running aggregate + settlement set under the
    # final forward key, so ONE keyed value commits the whole chain (and an
    # empty chain is still authenticated, not a public constant).
    final = hmac.new(bytes(key), _DOMAIN + b"/final" + _lp(_u64(len(entries))) + _lp(agg) + _lp(sroot), hashlib.sha256).digest()
    for i in range(len(key)):
        key[i] = 0
    return {
        "count": len(entries),
        "agg_mac": final.hex(),
        "settlement_root": sroot.hex(),
        "session_id": session_id,
    }


def verify_seal(
    master_secret: bytes,
    session_id: str,
    entries: Sequence[Dict[str, object]],
    anchored_seal: Dict[str, object],
    *,
    settlements: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    """Recompute the seal over ``entries`` and compare to the anchored seal.

    Any truncation, extension, reorder, or entry_digest alteration flips
    ``agg_ok``/``count_ok``. If ``settlements`` (an independently observed set
    of on-chain settled receipt hashes) is given, also reconcile the logged
    payment set against it.
    """
    try:
        recomputed = seal(master_secret, session_id, entries)
    except Exception as exc:  # malformed (non-hex/odd) entry fields -> fail closed
        return {"ok": False, "malformed": True, "error": "MALFORMED: %s" % exc,
                "agg_ok": False, "count_ok": False, "settlement_root_ok": False}
    try:
        anchored_count = int(anchored_seal.get("count", -1))
    except (TypeError, ValueError):
        anchored_count = -2  # non-numeric anchored count never matches a real one
    count_ok = anchored_count == recomputed["count"]
    agg_ok = hmac.compare_digest(str(anchored_seal.get("agg_mac", "")), str(recomputed["agg_mac"]))
    sroot_ok = str(anchored_seal.get("settlement_root", "")) == recomputed["settlement_root"]
    result: Dict[str, object] = {
        "ok": bool(count_ok and agg_ok and sroot_ok),
        "count_ok": count_ok,
        "agg_ok": agg_ok,
        "settlement_root_ok": sroot_ok,
    }
    if settlements is not None:
        logged = {str(e.get("receipt_hash", "")) for e in entries if str(e.get("receipt_hash", ""))}
        settled = {s for s in settlements if s}
        settled_but_unlogged = sorted(settled - logged)  # settled on-chain, never logged => omission
        logged_but_unsettled = sorted(logged - settled)  # logged, not seen settled
        reconciled = not settled_but_unlogged and not logged_but_unsettled
        result["reconciled"] = reconciled
        result["settled_but_unlogged"] = settled_but_unlogged
        result["logged_but_unsettled"] = logged_but_unsettled
        result["ok"] = bool(result["ok"] and reconciled)
    return result


if __name__ == "__main__":  # tiny self-demo (no I/O, no network); needs firc on path
    import json
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import firc  # type: ignore

    c = firc.FIRCChain.from_master(b"demo-master", "demo-session")
    rx = [hashlib.sha256(("rx-%d" % i).encode()).digest() for i in range(3)]
    for i in range(3):
        c.append(("action-%d" % i).encode(), receipt_hash=rx[i])
    s = seal(b"demo-master", "demo-session", c.entries)
    settled = [r.hex() for r in rx]
    print(json.dumps({
        "seal": s,
        "verify": verify_seal(b"demo-master", "demo-session", c.entries, s, settlements=settled),
        "truncated": verify_seal(b"demo-master", "demo-session", c.entries[:2], s, settlements=settled),
    }, indent=2))
