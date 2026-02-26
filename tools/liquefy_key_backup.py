#!/usr/bin/env python3
"""
liquefy_key_backup.py
=====================
Encryption key backup and recovery for disaster scenarios.

If your machine dies and you only had LIQUEFY_SECRET as an env var,
your encrypted cloud backups are unrecoverable. This tool prevents that.

Modes:
    export    — export encryption key to a backup file (encrypted with a passphrase)
    recover   — recover encryption key from a backup file
    card      — generate a printable recovery card (text)
    verify    — verify a backup file can be decrypted

Usage:
    python tools/liquefy_key_backup.py export --output key_backup.enc
    python tools/liquefy_key_backup.py recover --input key_backup.enc
    python tools/liquefy_key_backup.py card --output RECOVERY_CARD.txt
    python tools/liquefy_key_backup.py verify --input key_backup.enc
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = REPO_ROOT / "api"
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

BACKUP_MAGIC = b"LKEY"
BACKUP_VERSION = 1


def _get_secret() -> str:
    """Get LIQUEFY_SECRET from environment."""
    secret = os.environ.get("LIQUEFY_SECRET", "")
    if not secret:
        print("ERROR: LIQUEFY_SECRET env var not set. Nothing to back up.")
        print("  Set it first: export LIQUEFY_SECRET=\"your-secret\"")
        sys.exit(1)
    return secret


def _derive_wrap_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a wrapping key from a user passphrase."""
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt_key(secret: str, passphrase: str) -> bytes:
    """Encrypt the master secret with a passphrase-derived key."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    salt = os.urandom(16)
    wrap_key = _derive_wrap_key(passphrase, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(wrap_key)

    plaintext = secret.encode("utf-8")
    aad = BACKUP_MAGIC + bytes([BACKUP_VERSION])
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)

    payload = {
        "magic": base64.b64encode(BACKUP_MAGIC).decode(),
        "version": BACKUP_VERSION,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "created": datetime.now(timezone.utc).isoformat(),
        "key_fingerprint": hashlib.sha256(plaintext).hexdigest()[:16],
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def _decrypt_key(backup_data: bytes, passphrase: str) -> str:
    """Decrypt the master secret from a backup file."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    payload = json.loads(backup_data.decode("utf-8"))

    if payload.get("version") != BACKUP_VERSION:
        raise ValueError(f"Unsupported backup version: {payload.get('version')}")

    salt = base64.b64decode(payload["salt"])
    nonce = base64.b64decode(payload["nonce"])
    ciphertext = base64.b64decode(payload["ciphertext"])

    wrap_key = _derive_wrap_key(passphrase, salt)
    aad = BACKUP_MAGIC + bytes([BACKUP_VERSION])
    aesgcm = AESGCM(wrap_key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, aad)
    except Exception:
        raise ValueError("Decryption failed — wrong passphrase or corrupted backup")

    return plaintext.decode("utf-8")


def cmd_export(args: argparse.Namespace) -> int:
    secret = _get_secret()

    print("  Create a passphrase to protect your backup.")
    print("  Store this passphrase separately (password manager, paper, etc.)")
    print()
    passphrase = getpass.getpass("  Passphrase: ")
    if len(passphrase) < 8:
        print("ERROR: Passphrase must be at least 8 characters.")
        return 1
    confirm = getpass.getpass("  Confirm: ")
    if passphrase != confirm:
        print("ERROR: Passphrases don't match.")
        return 1

    encrypted = _encrypt_key(secret, passphrase)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encrypted)

    if os.name != "nt":
        try:
            output.chmod(0o600)
        except OSError:
            pass

    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:16]
    print()
    print(f"  Key backup saved: {output}")
    print(f"  Key fingerprint: {fingerprint}")
    print()
    print("  IMPORTANT:")
    print("  1. Store this file OFF your main machine (USB, cloud, safe)")
    print("  2. Remember your passphrase — without it, backup is useless")
    print("  3. The backup file + passphrase = full key recovery")
    return 0


def cmd_recover(args: argparse.Namespace) -> int:
    backup_path = Path(args.input)
    if not backup_path.exists():
        print(f"ERROR: Backup file not found: {backup_path}")
        return 1

    backup_data = backup_path.read_bytes()
    passphrase = getpass.getpass("  Passphrase: ")

    try:
        secret = _decrypt_key(backup_data, passphrase)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 1

    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:16]
    print()
    print(f"  Key recovered successfully.")
    print(f"  Fingerprint: {fingerprint}")
    print()
    print("  To restore, set this environment variable:")
    print()
    if os.name == "nt":
        print(f'  $env:LIQUEFY_SECRET="{secret}"')
    else:
        print(f'  export LIQUEFY_SECRET="{secret}"')
    print()
    print("  Then run: make cloud-pull VAULT=./vault BUCKET=your-bucket")
    return 0


def cmd_card(args: argparse.Namespace) -> int:
    secret = _get_secret()
    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:16]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    chunks = [secret[i:i+8] for i in range(0, len(secret), 8)]
    formatted_secret = "  ".join(chunks)

    card = f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║              LIQUEFY ENCRYPTION RECOVERY CARD                ║
║                                                              ║
║  Generated: {now:<46s} ║
║  Fingerprint: {fingerprint:<44s} ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  MASTER SECRET:                                              ║
║                                                              ║
║  {formatted_secret:<60s} ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  TO RECOVER:                                                 ║
║                                                              ║
║  1. Install Liquefy on new machine                           ║
║  2. Set env var:                                             ║
║     export LIQUEFY_SECRET="<secret above>"                   ║
║  3. Pull from cloud:                                         ║
║     make cloud-pull VAULT=./vault BUCKET=your-bucket         ║
║                                                              ║
║  KEEP THIS CARD IN A SAFE PLACE.                             ║
║  Anyone with this secret can decrypt your vaults.            ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

    if args.output:
        output = Path(args.output)
        output.write_text(card, encoding="utf-8")
        if os.name != "nt":
            try:
                output.chmod(0o600)
            except OSError:
                pass
        print(f"  Recovery card saved: {output}")
        print("  Print it. Store it in a safe. Do NOT leave it on your desktop.")
    else:
        print(card)

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    backup_path = Path(args.input)
    if not backup_path.exists():
        print(f"ERROR: Backup file not found: {backup_path}")
        return 1

    backup_data = backup_path.read_bytes()
    passphrase = getpass.getpass("  Passphrase: ")

    try:
        secret = _decrypt_key(backup_data, passphrase)
    except ValueError as e:
        print(f"  VERIFY: FAIL — {e}")
        return 1

    fingerprint = hashlib.sha256(secret.encode()).hexdigest()[:16]

    current = os.environ.get("LIQUEFY_SECRET", "")
    if current and current == secret:
        print(f"  VERIFY: PASS — matches current LIQUEFY_SECRET (fingerprint: {fingerprint})")
    elif current:
        current_fp = hashlib.sha256(current.encode()).hexdigest()[:16]
        print(f"  VERIFY: DECRYPTED OK but does NOT match current LIQUEFY_SECRET")
        print(f"    Backup fingerprint:  {fingerprint}")
        print(f"    Current fingerprint: {current_fp}")
    else:
        print(f"  VERIFY: PASS — backup decrypts successfully (fingerprint: {fingerprint})")

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-key-backup",
        description="Backup and recover Liquefy encryption keys.",
    )
    sub = parser.add_subparsers(dest="command")

    p_export = sub.add_parser("export", help="Export encryption key to backup file")
    p_export.add_argument("--output", default="liquefy_key_backup.enc", help="Output file")

    p_recover = sub.add_parser("recover", help="Recover key from backup file")
    p_recover.add_argument("--input", required=True, help="Backup file path")

    p_card = sub.add_parser("card", help="Generate printable recovery card")
    p_card.add_argument("--output", help="Output file (omit for stdout)")

    p_verify = sub.add_parser("verify", help="Verify backup file")
    p_verify.add_argument("--input", required=True, help="Backup file path")

    args = parser.parse_args()
    commands = {"export": cmd_export, "recover": cmd_recover, "card": cmd_card, "verify": cmd_verify}

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
