#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from common_signing import sign_vault_artifacts, verify_vault_signature


CLI_SCHEMA_VERSION = "liquefy.sign.cli.v1"


def _emit(payload: dict, *, enabled_json: bool, json_file: Path | None) -> None:
    if json_file:
        json_file.parent.mkdir(parents=True, exist_ok=True)
        json_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if os.name != "nt":
            try:
                json_file.chmod(0o600)
            except OSError:
                pass
    if enabled_json:
        print(json.dumps(payload, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description="Sign or verify Liquefy vault proof artifacts.")
    sub = ap.add_subparsers(dest="command", required=True)

    p_sign = sub.add_parser("sign")
    p_sign.add_argument("vault_dir")
    p_sign.add_argument("--key-path", default=None)
    p_sign.add_argument(
        "--algorithm",
        default="ed25519",
        help="ed25519 (default, publicly verifiable) or hmac (local-only/legacy)",
    )
    p_sign.add_argument("--json", action="store_true")
    p_sign.add_argument("--json-file", default=None)

    p_verify = sub.add_parser("verify-signature")
    p_verify.add_argument("vault_dir")
    p_verify.add_argument("--key-path", default=None, help="HMAC (legacy) secret key path")
    p_verify.add_argument(
        "--public-key",
        default=None,
        help="Ed25519 public key (hex) or path to a pubkey file — verify with no secret",
    )
    p_verify.add_argument(
        "--key-fingerprint",
        default=None,
        help="Expected signing-key fingerprint (e.g. from the on-chain anchor) to bind against",
    )
    p_verify.add_argument("--json", action="store_true")
    p_verify.add_argument("--json-file", default=None)

    args = ap.parse_args()
    json_file = Path(args.json_file).resolve() if args.json_file else None
    vault_dir = Path(args.vault_dir).expanduser().resolve()
    key_path = Path(args.key_path).expanduser().resolve() if args.key_path else None

    if args.command == "sign":
        result = sign_vault_artifacts(vault_dir, key_path=key_path, algorithm=args.algorithm)
        payload = {
            "schema_version": CLI_SCHEMA_VERSION,
            "tool": "liquefy_sign",
            "command": "sign",
            "ok": True,
            "result": result,
        }
        _emit(payload, enabled_json=args.json, json_file=json_file)
        if not args.json:
            print(f"[sign] OK vault={vault_dir}")
            print(f"  algorithm={result.get('algorithm')}")
            print(f"  signature={result.get('signature_path')}")
            if result.get("algorithm") == "Ed25519":
                print(f"  public_key={result.get('public_key')}")
                print(f"  public_key_file={result.get('public_key_path')}")
                print(f"  key_fingerprint={result.get('key_fingerprint')}  (publish / anchor this)")
        return

    result = verify_vault_signature(
        vault_dir,
        key_path=key_path,
        public_key=args.public_key,
        expected_key_fingerprint=args.key_fingerprint,
    )
    payload = {
        "schema_version": CLI_SCHEMA_VERSION,
        "tool": "liquefy_sign",
        "command": "verify-signature",
        "ok": bool(result.get("ok", False)),
        "result": result,
    }
    _emit(payload, enabled_json=args.json, json_file=json_file)
    if not args.json:
        print(f"[verify-signature] {'PASS' if payload['ok'] else 'FAIL'} vault={vault_dir}")
        if result.get("algorithm"):
            verifiability = "public-key only" if result.get("publicly_verifiable") else "requires secret key"
            print(f"  algorithm={result.get('algorithm')} ({verifiability})")
        if result.get("error"):
            print(f"  error={result.get('error')}")
    if not payload["ok"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
