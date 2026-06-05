#!/usr/bin/env python3
"""disclosure_envelope -- a self-describing, honest-by-construction disclosure
bundle for the OpenClaw vault.

A vault hands a third party ONE envelope that declares exactly which verification
tiers it carries; verify_envelope() checks each with the already-shipped verifier
and REFUSES to over-claim:

  * public_cosign  -- Ed25519 signature over the anchored head (dual_tier):
                      PUBLIC -- anyone with the key verifies, no master secret.
  * single_action  -- a key-free Merkle reveal of one paid action (firc_path).
  * keyed_seal     -- the symmetric FIRC/TERS commitments: verifiable only by a
                      key-holder (skipped unless master_secret + entries given).
  * zk_proof       -- a status enum {none | commitment_placeholder | groth16}.
                      zk_verified is True ONLY when a real ZK verifier validates.
                      None is wired today, so it stays False and the envelope
                      SAYS SO: a commitment_placeholder is HIDING, not
                      zero-knowledge; the groth16 slot is reserved (the dark-null
                      bundle path is a serializer with no verifier today).

ok means "every tier actually CHECKED passed"; skipped tiers (e.g. keyed with no
key) are reported, not silently treated as passing, and zk never contributes a
positive.

Pure standard library, except the public_cosign tier (lazy-imports dual_tier,
which uses the pinned cryptography Ed25519 backend). Composes only shipped,
merged modules; adds no new crypto. "Anchored" is confirmation-level, not
finalized; a public key's authority comes from anchoring + out-of-band trust.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence

SCHEMA = "vault.disclosure-envelope.v1"
ZK_NONE = "none"
ZK_PLACEHOLDER = "commitment_placeholder"
ZK_GROTH16 = "groth16"
_ZK_STATUSES = (ZK_NONE, ZK_PLACEHOLDER, ZK_GROTH16)


def build_envelope(
    session_id: object,
    head: object,
    *,
    public_cosign: Optional[Dict[str, object]] = None,
    single_action: Optional[Dict[str, object]] = None,
    keyed_seal: Optional[Dict[str, object]] = None,
    zk_proof: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    """Assemble a disclosure envelope from whichever tiers are available."""
    tiers: Dict[str, object] = {}
    if public_cosign is not None:
        tiers["public_cosign"] = {
            "alg": "Ed25519",
            "public_key": str(public_cosign.get("public_key", "")),
            "signature": str(public_cosign.get("signature", "")),
        }
    if single_action is not None:
        tiers["single_action"] = single_action  # a firc_path reveal bundle
    if keyed_seal is not None:
        tiers["keyed_seal"] = keyed_seal
    zk: Dict[str, object] = {"status": ZK_NONE}
    if zk_proof is not None:
        st = str(zk_proof.get("status", ZK_NONE))
        zk = dict(zk_proof)
        zk["status"] = st if st in _ZK_STATUSES else ZK_NONE
    return {"schema": SCHEMA, "session_id": str(session_id), "head": head, "tiers": tiers, "zk_proof": zk}


def _verify_zk(zk: Dict[str, object]) -> Dict[str, object]:
    """zk_verified is True ONLY when a real verifier validates. None is wired."""
    if not isinstance(zk, dict):
        return {"status": "unknown", "zk_verified": False, "note": "malformed zk_proof (not an object) -- not verified"}
    status = str(zk.get("status", ZK_NONE))
    if status == ZK_NONE:
        return {"status": ZK_NONE, "zk_verified": False, "note": "no zk proof present"}
    if status == ZK_PLACEHOLDER:
        return {"status": ZK_PLACEHOLDER, "zk_verified": False,
                "note": "commitment placeholder is HIDING, not zero-knowledge; not verified as ZK"}
    if status == ZK_GROTH16:
        return {"status": ZK_GROTH16, "zk_verified": False,
                "note": "groth16 slot reserved; no verifier wired (dark-null bundle path is serializer-only) -- not verified"}
    return {"status": status, "zk_verified": False, "note": "unknown zk status -- not verified"}


def verify_envelope(
    envelope: Dict[str, object],
    *,
    trusted_public_key: Optional[str] = None,
    master_secret: Optional[bytes] = None,
    entries: Optional[Sequence[Dict[str, object]]] = None,
    leaf: Optional[bytes] = None,
) -> Dict[str, object]:
    """Verify each tier the envelope carries with its shipped verifier, honestly.

    A tier is True (passed), False (failed), or None (skipped -- not checkable
    with what was provided). ``ok`` is True iff at least one tier was checked and
    every checked tier passed. zk is reported but never makes ``ok`` True.
    """
    if not isinstance(envelope, dict) or envelope.get("schema") != SCHEMA:
        return {"ok": False, "error": "BAD_ENVELOPE_SCHEMA"}
    head = envelope.get("head")
    tiers = envelope.get("tiers", {}) or {}
    results: Dict[str, object] = {}
    notes: List[str] = []
    cosign_trusted: Optional[bool] = None  # None=no cosign tier; False=own-key; True=trusted-key

    if "public_cosign" in tiers:
        try:
            import dual_tier  # lazy: needs cryptography
            t = tiers["public_cosign"]
            cosign_trusted = trusted_public_key is not None
            pk = trusted_public_key if trusted_public_key is not None else str(t.get("public_key", ""))
            if trusted_public_key is None:
                notes.append("public_cosign: no trusted key supplied; used the envelope's own key "
                             "(the key's authority is out-of-band / anchored, not proven here)")
            results["public_cosign"] = bool(dual_tier.verify_cosignature(pk, head, str(t.get("signature", ""))))
        except Exception as exc:
            results["public_cosign"] = False
            notes.append("public_cosign: %s" % exc)

    if "single_action" in tiers:
        try:
            import firc_path
            results["single_action"] = bool(firc_path.verify_reveal(tiers["single_action"], leaf=leaf).get("ok"))
        except Exception as exc:
            results["single_action"] = False
            notes.append("single_action: %s" % exc)

    if "keyed_seal" in tiers:
        if master_secret is not None and entries is not None:
            try:
                import vault_evidence
                ks = tiers["keyed_seal"]
                res = vault_evidence.verify_evidence(
                    master_secret, str(envelope.get("session_id", "")), entries,
                    firc_head=ks.get("firc_head"), ters_seal=ks.get("ters_seal"),
                )
                results["keyed_seal"] = bool(res.get("ok"))
            except Exception as exc:
                results["keyed_seal"] = False
                notes.append("keyed_seal: %s" % exc)
        else:
            results["keyed_seal"] = None
            notes.append("keyed_seal: skipped (no master_secret/entries -- verifiable only by a key-holder)")

    zk = _verify_zk(envelope.get("zk_proof", {"status": ZK_NONE}))

    checked = [v for v in results.values() if v is not None]
    ok = bool(checked) and all(checked)
    return {
        "ok": ok,
        "results": results,
        "verified_tiers": [k for k, v in results.items() if v is True],
        "failed_tiers": [k for k, v in results.items() if v is False],
        "skipped_tiers": [k for k, v in results.items() if v is None],
        "cosign_trusted_key": cosign_trusted,  # False = signature valid but key authority unproven (self-asserted)
        "zk": zk,
        "zk_verified": zk["zk_verified"],  # always False today -- no real ZK verifier wired
        "notes": notes,
    }
