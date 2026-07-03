#!/usr/bin/env python3
"""value_seal -- forward-secure value-conservation seal for vault payments.

TERS seals the chain shape + the SET of receipt hashes, but a receipt set is
amount-agnostic: 5 USDC vs 5000 USDC under the same receipt reconcile
identically. ValueSeal folds a SECOND forward-secure keyed accumulator over each
payment's (asset_id, amount, recipient) plus per-asset running totals into one
anchored MAC, so a single sealed value certifies the payment AMOUNTS and the
total spend per asset: "you cannot under-report what you paid."

How it works:
* Own forward-secure key schedule (distinct HKDF info from FIRC/TERS, no key
  reuse). For each payment item j: value_mac = HMAC(A_j, "/val" || j || prev ||
  item_digest); ratchet A_{j+1}=H("evolve"||A_j) and wipe A_j (FssAgg-style).
* Per-asset totals are arbitrary-precision integers (atomic units), committed in
  totals_root; a finalization MAC binds count + running mac + totals_root.
* verify_value_seal recomputes and compares; with an amount-carrying settlement
  feed it reconciles logged per-asset totals against what actually settled.

Honest scope:
* This is NOT a hiding/ZK/Pedersen commitment -- per-asset totals are committed
  in cleartext and MAC'd. No confidentiality is claimed.
* "Catches amount-substitution" against INTERNAL tampering always (a changed
  amount breaks the seal). Catching a lie agreed at seal-time needs the
  reconciliation feed to carry trustworthy/witnessed amounts.
* Symmetric / keyed model (like TERS): the seal must be anchored by the
  legitimate party; verification needs the seed. Public verification is a
  separate tier. Zeroization is best-effort (CPython).

Pure standard library (hashlib + hmac).
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Dict, List, Optional, Sequence

_DOMAIN = b"valueseal/v1"
_KEY_LEN = 32


def _u64(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("counter out of range")
    return n.to_bytes(8, "big")


def _int_bytes(n: int) -> bytes:
    """Minimal big-endian encoding of a non-negative arbitrary-precision int
    (0 -> empty); length-prefixed by the caller, so it is unambiguous."""
    if n < 0:
        raise ValueError("amount must be non-negative")
    return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


def _lp(b: bytes) -> bytes:
    return _u64(len(b)) + b


def _h(*parts: bytes) -> bytes:
    m = hashlib.sha256()
    m.update(_lp(_DOMAIN))
    for p in parts:
        m.update(_lp(p))
    return m.digest()


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = _KEY_LEN) -> bytes:
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
        raise ValueError("ValueSeal internal: unexpected key length")
    return hashlib.sha256(_DOMAIN + b"/evolve" + key).digest()


def _amount(item: Dict[str, object]) -> int:
    """Strict non-negative atomic-unit amount. Rejects float/bool and non-strict
    strings, because int(5.9)==5 would silently UNDER-REPORT a payment."""
    a = item.get("amount", 0)
    if isinstance(a, bool):
        raise ValueError("amount must be an integer, not bool")
    if isinstance(a, int):
        n = a
    elif isinstance(a, str):
        if a == "" or any(c not in "0123456789" for c in a):
            raise ValueError("amount must be a non-negative integer string")
        n = int(a)
    else:  # float, bytes, None, etc. -- never silently coerce
        raise ValueError("amount must be int or integer-string, got %s" % type(a).__name__)
    if n < 0:
        raise ValueError("amount must be non-negative")
    return n


def _item_digest(seq: int, item: Dict[str, object]) -> bytes:
    asset = str(item.get("asset_id", "")).encode("utf-8")
    recipient = str(item.get("recipient", "")).encode("utf-8")
    rh = str(item.get("receipt_hash", ""))
    receipt = bytes.fromhex(rh) if rh else b""
    return _h(b"item", _u64(seq), asset, _int_bytes(_amount(item)), recipient, receipt)


def _totals_root(totals: Dict[str, int]) -> bytes:
    parts: List[bytes] = [b"totals", _u64(len(totals))]
    for asset in sorted(totals):
        parts.append(asset.encode("utf-8"))
        parts.append(_int_bytes(totals[asset]))
    return _h(*parts)


def seal(master_secret: bytes, session_id: str, items: Sequence[Dict[str, object]]) -> Dict[str, object]:
    """Compute the anchorable value seal over payment items.

    Each item: {asset_id, amount (atomic int or int-string), recipient,
    receipt_hash?}. Returns {count, value_mac, totals, totals_root, session_id};
    value_mac is a finalization MAC binding count + the running forward-secure
    value accumulator + the per-asset totals root.
    """
    key = bytearray(_derive_seed(master_secret, session_id))
    vmac = _h(b"val-iv", session_id.encode("utf-8"))
    totals: Dict[str, int] = {}
    for j, item in enumerate(items):
        idg = _item_digest(j, item)
        vmac = hmac.new(bytes(key), _DOMAIN + b"/val" + _lp(_u64(j)) + _lp(vmac) + _lp(idg), hashlib.sha256).digest()
        asset = str(item.get("asset_id", ""))
        totals[asset] = totals.get(asset, 0) + _amount(item)
        nxt = _evolve(bytes(key))
        for i in range(len(key)):
            key[i] = 0
        key = bytearray(nxt)
    troot = _totals_root(totals)
    final = hmac.new(bytes(key), _DOMAIN + b"/final" + _lp(_u64(len(items))) + _lp(vmac) + _lp(troot), hashlib.sha256).digest()
    for i in range(len(key)):
        key[i] = 0
    return {
        "count": len(items),
        "value_mac": final.hex(),
        "totals": {a: str(t) for a, t in totals.items()},  # atomic units as strings (x402 convention, big-int safe)
        "totals_root": troot.hex(),
        "session_id": session_id,
    }


def verify_value_seal(
    master_secret: bytes,
    session_id: str,
    items: Sequence[Dict[str, object]],
    anchored_seal: Dict[str, object],
    *,
    settlements: Optional[Sequence[Dict[str, object]]] = None,
) -> Dict[str, object]:
    """Recompute the value seal over ``items`` and compare to the anchored seal.
    Any amount / asset / recipient / order / count change flips ``value_mac_ok``.
    With ``settlements`` (an amount-carrying observed feed) it reconciles logged
    per-asset totals against settled per-asset totals.
    """
    try:
        recomputed = seal(master_secret, session_id, items)
    except Exception as exc:  # malformed item -> fail closed
        return {"ok": False, "malformed": True, "error": "MALFORMED: %s" % exc,
                "value_mac_ok": False, "count_ok": False, "totals_root_ok": False}
    try:
        anchored_count = int(anchored_seal.get("count", -1))
    except (TypeError, ValueError):
        anchored_count = -2
    count_ok = anchored_count == recomputed["count"]
    value_mac_ok = hmac.compare_digest(str(anchored_seal.get("value_mac", "")), str(recomputed["value_mac"]))
    totals_root_ok = str(anchored_seal.get("totals_root", "")) == recomputed["totals_root"]
    result: Dict[str, object] = {
        "ok": bool(count_ok and value_mac_ok and totals_root_ok),
        "count_ok": count_ok,
        "value_mac_ok": value_mac_ok,
        "totals_root_ok": totals_root_ok,
    }
    if settlements is not None:
        logged = {a: int(t) for a, t in recomputed["totals"].items()}  # type: ignore[union-attr]
        settled: Dict[str, int] = {}
        try:
            for s in settlements:
                settled[str(s.get("asset_id", ""))] = settled.get(str(s.get("asset_id", "")), 0) + _amount(s)
        except ValueError:
            return {**result, "ok": False, "reconciled": False, "error": "MALFORMED_SETTLEMENT"}
        discrepancies: Dict[str, Dict[str, str]] = {}
        for asset in set(logged) | set(settled):
            lg, st = logged.get(asset, 0), settled.get(asset, 0)
            if lg != st:
                discrepancies[asset] = {"logged": str(lg), "settled": str(st)}
        reconciled = not discrepancies
        result["reconciled"] = reconciled
        result["asset_discrepancies"] = discrepancies
        result["ok"] = bool(result["ok"] and reconciled)
    return result


if __name__ == "__main__":  # self-demo (no IO, no network)
    import json

    items = [
        {"asset_id": "USDC", "amount": "1000000", "recipient": "alice", "receipt_hash": hashlib.sha256(b"r0").hexdigest()},
        {"asset_id": "USDC", "amount": "2500000", "recipient": "bob", "receipt_hash": hashlib.sha256(b"r1").hexdigest()},
        {"asset_id": "NULL", "amount": "42", "recipient": "carol", "receipt_hash": hashlib.sha256(b"r2").hexdigest()},
    ]
    s = seal(b"demo-master", "demo-session", items)
    settled_ok = [{"asset_id": "USDC", "amount": "3500000"}, {"asset_id": "NULL", "amount": "42"}]
    substituted = list(items)
    substituted[0] = {**items[0], "amount": "5000000000"}  # attacker inflates a paid amount
    print(json.dumps({
        "seal_totals": s["totals"],
        "verify_ok": verify_value_seal(b"demo-master", "demo-session", items, s, settlements=settled_ok),
        "amount_substituted": verify_value_seal(b"demo-master", "demo-session", substituted, s),
    }, indent=2))
