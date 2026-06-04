#!/usr/bin/env python3
"""dual_tier -- a public Ed25519 cosignature stapled over the keyed vault seal.

FIRC / TERS / value_seal are symmetric (keyed): only a holder of the master
secret can verify them. The parties who most need to verify -- a regulator,
payer, or counsel -- usually cannot. dual_tier adds a TIER-2 public attestation:
an Ed25519 signature over the anchored head (FIRC head + TERS seal + value
totals), verifiable by ANYONE holding the public key, with no master secret.

The two tiers are kept explicitly separate and labelled, so the symmetric tier-1
seal is never passed off as publicly verifiable:
  * tier1_keyed  -- the FIRC/TERS/value commitments (verifiable by a scoped
    key-holder / auditor only).
  * tier2_public -- an Ed25519 signature over the same anchored head, verifiable
    by anyone with the public key.

Honest scope:
* This ADDS an asymmetric attestation; it does NOT make the symmetric seals
  themselves public.
* tier-2 proves "the holder of public key P signed this anchored head." The
  AUTHORITY of P (that it is the agent's real Passport key) comes from anchoring
  P's fingerprint on-chain + out-of-band trust, NOT from this module.
* "Anchored" is confirmation-level, not finalized.
* NOT pure stdlib: needs the `cryptography` package (a pinned repo dependency;
  imported lazily so this module still imports without it).
"""
from __future__ import annotations

import json
from typing import Dict, Optional, Tuple

_DOMAIN = b"dual-tier/v1"


def _require_ed25519():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except Exception as exc:  # cryptography absent
        raise RuntimeError("dual_tier requires the 'cryptography' package for Ed25519") from exc
    return Ed25519PrivateKey, Ed25519PublicKey, InvalidSignature


def build_head(firc_head: Dict[str, object], ters_seal: Dict[str, object],
               value_seal: Optional[Dict[str, object]] = None) -> Dict[str, object]:
    """Assemble the canonical anchored head from the shipped seals' outputs."""
    head: Dict[str, object] = {
        "session_id": str(firc_head.get("session_id", ters_seal.get("session_id", ""))),
        "firc": {"count": int(firc_head.get("count", -1)), "head_hash": str(firc_head.get("head_hash", ""))},
        "ters": {"agg_mac": str(ters_seal.get("agg_mac", "")), "settlement_root": str(ters_seal.get("settlement_root", ""))},
    }
    if value_seal is not None:
        head["value"] = {"value_mac": str(value_seal.get("value_mac", "")), "totals_root": str(value_seal.get("totals_root", ""))}
    return head


def _head_message(head: Dict[str, object]) -> bytes:
    # canonical, order-independent encoding of the head, domain-separated
    # strict JSON (allow_nan=False) so a third-party verifier in any language
    # reproduces the exact signed bytes; ensure_ascii avoids UTF-8 ambiguity
    canon = json.dumps(head, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    return _DOMAIN + b"/head" + canon


def generate_keypair() -> Tuple[str, str]:
    """Return (private_key_hex, public_key_hex) raw Ed25519 keys."""
    Ed25519PrivateKey, _pub, _inv = _require_ed25519()
    sk = Ed25519PrivateKey.generate()
    return (sk.private_bytes_raw().hex(), sk.public_key().public_bytes_raw().hex())


def public_key_of(private_key_hex: str) -> str:
    Ed25519PrivateKey, _pub, _inv = _require_ed25519()
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    return sk.public_key().public_bytes_raw().hex()


def cosign(private_key_hex: str, head: Dict[str, object]) -> Dict[str, object]:
    """Tier-2: produce a public Ed25519 cosignature over the anchored head."""
    Ed25519PrivateKey, _pub, _inv = _require_ed25519()
    sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    sig = sk.sign(_head_message(head))
    return {
        "tier": "public-ed25519-v1",
        "alg": "Ed25519",
        "public_key": sk.public_key().public_bytes_raw().hex(),
        "signature": sig.hex(),
        "head": head,
    }


def verify_cosignature(public_key_hex: str, head: Dict[str, object], signature_hex: str) -> bool:
    """PUBLIC, key-free (no master secret): verify the Ed25519 cosignature over
    the head against a public key. Fail-closed on any bad input."""
    _sk, Ed25519PublicKey, InvalidSignature = _require_ed25519()
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(bytes.fromhex(signature_hex), _head_message(head))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def staple(tier1_keyed: Dict[str, object], head: Dict[str, object], cosig: Dict[str, object]) -> Dict[str, object]:
    """Assemble the dual-tier bundle with the two tiers explicitly separated."""
    return {
        "schema": "vault.dual-tier.v1",
        "head": head,
        "tier1_keyed": tier1_keyed,
        "tier2_public": {"alg": "Ed25519", "public_key": str(cosig.get("public_key", "")), "signature": str(cosig.get("signature", ""))},
        "note": "tier1_keyed verifies only with the master secret (scoped auditor); tier2_public verifies with the Ed25519 public key (anyone). tier2 does not make tier1 public.",
    }


if __name__ == "__main__":  # self-demo (needs cryptography)
    sk_hex, pk_hex = generate_keypair()
    head = build_head(
        {"session_id": "demo", "count": 3, "head_hash": "ab" * 32},
        {"agg_mac": "cd" * 32, "settlement_root": "ef" * 32},
    )
    cs = cosign(sk_hex, head)
    tampered = dict(head)
    tampered["firc"] = {"count": 999, "head_hash": "00" * 32}
    print(json.dumps({
        "public_verify_ok": verify_cosignature(pk_hex, head, cs["signature"]),
        "tamper_rejected": verify_cosignature(pk_hex, tampered, cs["signature"]),
        "wrong_key_rejected": verify_cosignature(generate_keypair()[1], head, cs["signature"]),
    }, indent=2))
