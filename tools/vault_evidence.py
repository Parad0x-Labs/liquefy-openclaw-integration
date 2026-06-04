#!/usr/bin/env python3
"""vault_evidence -- unified FIRC + TERS evidence verification for the OpenClaw vault.

One entry point that runs both vault primitives over an agent's receipt log:
  * firc.verify_chain  -- per-entry integrity, chain linkage, optional tail seal
  * ters.verify_seal   -- one-value truncation seal + settlement reconciliation

Use anchor_values() to produce the two anchorable commitments (the FIRC head and
the TERS seal) for a chain, and verify_evidence() to check a presented log
against them in a single call.

Pure standard library; composes tools/firc.py + tools/ters.py (no new crypto).
Honest scope is inherited from those modules: symmetric/keyed verifier;
truncation detection needs the anchored head/seal; zeroization is best-effort.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import firc  # type: ignore
import ters  # type: ignore


def anchor_values(master_secret: bytes, session_id: str, entries: Sequence[Dict[str, object]]) -> Dict[str, object]:
    """Produce the two anchorable commitments for a chain: the FIRC head
    (count + last entry digest) and the TERS seal (aggregate + settlement_root).
    Anchor both (e.g. to Solana) -- verify_evidence checks a log against them.
    Raises ValueError if any entry lacks a 32-byte-hex entry_digest."""
    for i, e in enumerate(entries):
        ed = str(e.get("entry_digest", ""))
        try:
            valid = len(bytes.fromhex(ed)) == 32
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("malformed entry %d: entry_digest must be 32-byte hex" % i)
    if entries:
        head_hash = str(entries[-1].get("entry_digest", ""))
    else:
        head_hash = firc.genesis_prev(session_id).hex()
    firc_head = {"count": len(entries), "head_hash": head_hash, "session_id": session_id}
    ters_seal = ters.seal(master_secret, session_id, entries)
    return {"firc_head": firc_head, "ters_seal": ters_seal}


def verify_evidence(
    master_secret: bytes,
    session_id: str,
    entries: Sequence[Dict[str, object]],
    *,
    leaves: Optional[Sequence[bytes]] = None,
    firc_head: Optional[Dict[str, object]] = None,
    ters_seal: Optional[Dict[str, object]] = None,
    settlements: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    """Run FIRC chain verification and (if a seal is given) TERS seal
    verification over ``entries``, then combine into one verdict.

    ``ok`` is True only if every supplied check passes. The per-module results
    are returned under ``firc`` and ``ters`` for detail.
    """
    firc_res = firc.verify_chain(master_secret, session_id, entries, leaves=leaves, expected_head=firc_head)
    checks: List[str] = ["firc.verify_chain"]
    ok = bool(firc_res.get("ok"))

    ters_res: Optional[Dict[str, object]] = None
    if ters_seal is not None:
        ters_res = ters.verify_seal(master_secret, session_id, entries, ters_seal, settlements=settlements)
        checks.append("ters.verify_seal")
        ok = ok and bool(ters_res.get("ok"))

    failed: List[str] = []
    if not firc_res.get("ok"):
        failed.append("firc")
    if ters_res is not None and not ters_res.get("ok"):
        failed.append("ters")

    return {
        "ok": ok,
        "anchored": bool(firc_head is not None or ters_seal is not None),
        "checks": checks,
        "failed": failed,
        "entries": len(entries),
        "firc": firc_res,
        "ters": ters_res,
    }


# --------------------------------------------------------------------------- CLI

def _load_key(key_hex: Optional[str]) -> Optional[bytes]:
    if key_hex:
        return bytes.fromhex(key_hex)
    env = os.environ.get("VAULT_EVIDENCE_KEY")
    if env:
        return bytes.fromhex(env)
    return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    p = argparse.ArgumentParser(prog="vault_evidence", description="Verify OpenClaw vault evidence (FIRC + TERS).")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, helptext in (("verify", "verify an evidence bundle JSON"),
                           ("anchor", "produce anchorable commitments for a chain bundle JSON")):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("--bundle", required=True, help="path to the bundle JSON")
        sp.add_argument("--key-hex", help="master secret as hex (or set $VAULT_EVIDENCE_KEY)")

    ns = p.parse_args(argv)
    try:
        key = _load_key(ns.key_hex)
        if key is None:
            print(json.dumps({"ok": False, "error": "NO_KEY: pass --key-hex or set $VAULT_EVIDENCE_KEY"}))
            return 2
        try:
            raw = Path(ns.bundle).read_text(encoding="utf-8")
        except OSError:
            # never echo the (caller-supplied, possibly private) path
            print(json.dumps({"ok": False, "error": "BUNDLE_UNREADABLE"}))
            return 2
        bundle = json.loads(raw)
        session_id = str(bundle.get("session_id", ""))
        entries = bundle.get("entries", []) or []

        if ns.cmd == "anchor":
            print(json.dumps(anchor_values(key, session_id, entries), indent=2))
            return 0

        leaves_hex = bundle.get("leaves")
        leaves = [bytes.fromhex(x) for x in leaves_hex] if leaves_hex else None
        res = verify_evidence(
            key, session_id, entries,
            leaves=leaves,
            firc_head=bundle.get("firc_head"),
            ters_seal=bundle.get("ters_seal"),
            settlements=bundle.get("settlements"),
        )
        print(json.dumps(res, indent=2))
        return 0 if res["ok"] else 2
    except Exception as exc:  # fail closed on any bad input
        print(json.dumps({"ok": False, "error": "INVALID_INPUT: %s" % exc}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
