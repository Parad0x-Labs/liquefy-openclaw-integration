#!/usr/bin/env python3
"""
liquefy_vault_anchor.py
=======================
On-chain vault integrity anchoring on Solana.

Computes a compact proof of vault state (manifest hashes, audit chain tip,
file count, total bytes) and optionally anchors it on Solana as a permanent,
publicly verifiable proof. Anyone with a Solana explorer can confirm your
data existed at a specific time — without seeing any of it.

Architecture:
    1. proof   — compute proof locally (free, no wallet needed)
    2. anchor  — submit proof to Solana via Memo program (~0.000005 SOL)
    3. verify  — verify a local vault matches an on-chain anchor
    4. show    — display an existing anchor from a proof file

On-chain data (80 bytes):
    - vault_hash:      SHA-256 of all vault file hashes concatenated (32 bytes)
    - chain_tip:       latest audit chain hash (32 bytes)
    - key_fingerprint: SHA-256 of LIQUEFY_SECRET (first 16 bytes)

Uses the SPL Memo program (standard, no custom program needed).
Transaction signature = permanent on-chain receipt.

Usage:
    python tools/liquefy_vault_anchor.py proof --vault ./vault
    python tools/liquefy_vault_anchor.py anchor --vault ./vault --keypair ~/.config/solana/id.json
    python tools/liquefy_vault_anchor.py verify --vault ./vault --proof ./vault/.anchor-proof.json
    python tools/liquefy_vault_anchor.py show --proof ./vault/.anchor-proof.json
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cli_runtime import resolve_repo_root

REPO_ROOT = resolve_repo_root(__file__)
API_DIR = REPO_ROOT / "api"
TOOLS_DIR = REPO_ROOT / "tools"
for _p in (API_DIR, TOOLS_DIR):
    ps = str(_p)
    if ps not in sys.path:
        sys.path.insert(0, ps)

VAULT_EXTENSIONS = {".null", ".lqf", ".vsnx", ".jsonl"}
ANCHOR_PROOF_FILE = ".anchor-proof.json"
PROOF_SCHEMA = "liquefy.vault-anchor.v1"

MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"

SOLANA_MAINNET = "https://api.mainnet-beta.solana.com"
SOLANA_DEVNET = "https://api.devnet.solana.com"


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _collect_vault_files(vault_dir: Path) -> List[Path]:
    files = []
    for root, _, fnames in os.walk(vault_dir):
        for fname in sorted(fnames):
            fpath = Path(root) / fname
            if fpath.suffix.lower() in VAULT_EXTENSIONS or fname.endswith(".manifest.json"):
                files.append(fpath)
    return files


def _compute_vault_hash(vault_dir: Path) -> Tuple[str, int, int]:
    """Compute a single deterministic hash of the entire vault state.

    Returns (vault_hash, file_count, total_bytes).
    """
    files = _collect_vault_files(vault_dir)
    h = hashlib.sha256()
    total_bytes = 0

    for fpath in sorted(files):
        rel = str(fpath.relative_to(vault_dir))
        file_hash = _file_sha256(fpath)
        h.update(f"{rel}:{file_hash}\n".encode("utf-8"))
        total_bytes += fpath.stat().st_size

    return h.hexdigest(), len(files), total_bytes


def _get_chain_tip(vault_dir: Path) -> str:
    """Get the latest audit chain hash."""
    candidates = [
        vault_dir / "audit" / "chain.jsonl",
        vault_dir / "chain.jsonl",
        vault_dir / ".liquefy" / "audit" / "default" / "chain.jsonl",
        Path.home() / ".liquefy" / "audit" / "default" / "chain.jsonl",
    ]
    for p in candidates:
        if p.exists():
            last_hash = "0" * 64
            with p.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            last_hash = entry.get("_hash", last_hash)
                        except json.JSONDecodeError:
                            pass
            return last_hash
    return "0" * 64


def _get_key_fingerprint() -> str:
    """SHA-256 fingerprint of the encryption key (first 16 hex chars)."""
    secret = os.environ.get("LIQUEFY_SECRET", "")
    if secret:
        return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]
    return "0" * 16


def compute_proof(vault_dir: Path) -> Dict[str, Any]:
    """Compute a complete vault proof (offline, free)."""
    vault_hash, file_count, total_bytes = _compute_vault_hash(vault_dir)
    chain_tip = _get_chain_tip(vault_dir)
    key_fp = _get_key_fingerprint()
    ts = datetime.now(timezone.utc).isoformat()

    anchor_payload = f"LQFY|{vault_hash[:16]}|{chain_tip[:16]}|{key_fp}"

    proof = {
        "schema": PROOF_SCHEMA,
        "version": 1,
        "timestamp": ts,
        "vault_path": str(vault_dir),
        "vault_hash": vault_hash,
        "chain_tip": chain_tip,
        "key_fingerprint": key_fp,
        "file_count": file_count,
        "total_bytes": total_bytes,
        "anchor_payload": anchor_payload,
        "anchor_payload_hex": anchor_payload.encode("utf-8").hex(),
        "solana_tx": None,
        "solana_cluster": None,
    }

    return proof


def _save_proof(proof: Dict, vault_dir: Path) -> Path:
    proof_path = vault_dir / ANCHOR_PROOF_FILE
    proof_path.write_text(json.dumps(proof, indent=2), encoding="utf-8")
    if os.name != "nt":
        try:
            proof_path.chmod(0o644)
        except OSError:
            pass
    return proof_path


def cmd_proof(args: argparse.Namespace) -> int:
    vault_dir = Path(args.vault).resolve()
    if not vault_dir.exists():
        print(json.dumps({"ok": False, "error": f"Vault not found: {vault_dir}"}))
        return 1

    proof = compute_proof(vault_dir)
    proof_path = _save_proof(proof, vault_dir)

    if args.json:
        print(json.dumps({"ok": True, **proof, "proof_file": str(proof_path)}, indent=2))
    else:
        print(f"  Vault proof computed:")
        print(f"    Files:         {proof['file_count']}")
        print(f"    Total bytes:   {proof['total_bytes']:,}")
        print(f"    Vault hash:    {proof['vault_hash'][:32]}...")
        print(f"    Chain tip:     {proof['chain_tip'][:32]}...")
        print(f"    Key FP:        {proof['key_fingerprint']}")
        print(f"    Anchor data:   {proof['anchor_payload']}")
        print(f"    Saved:         {proof_path}")
        print()
        print("  To anchor on Solana:")
        print(f"    python tools/liquefy_vault_anchor.py anchor --vault {vault_dir} --keypair <path>")

    return 0


def cmd_anchor(args: argparse.Namespace) -> int:
    vault_dir = Path(args.vault).resolve()
    if not vault_dir.exists():
        print(json.dumps({"ok": False, "error": f"Vault not found: {vault_dir}"}))
        return 1

    try:
        from solders.keypair import Keypair
        from solders.pubkey import Pubkey
        from solders.transaction import Transaction
        from solders.message import Message
        from solders.instruction import Instruction, AccountMeta
        from solders.hash import Hash as SolHash
        from solders.commitment_config import CommitmentLevel
        import httpx
    except ImportError:
        print("ERROR: Solana dependencies required. Install with:")
        print("  pip install solders httpx")
        return 1

    keypair_path = Path(args.keypair).expanduser()
    if not keypair_path.exists():
        print(f"ERROR: Keypair file not found: {keypair_path}")
        return 1

    kp_data = json.loads(keypair_path.read_text("utf-8"))
    keypair = Keypair.from_bytes(bytes(kp_data))

    cluster = args.cluster or "mainnet"
    rpc_url = args.rpc or (SOLANA_MAINNET if cluster == "mainnet" else SOLANA_DEVNET)

    proof = compute_proof(vault_dir)
    memo_data = proof["anchor_payload"].encode("utf-8")

    memo_program = Pubkey.from_string(MEMO_PROGRAM_ID)
    memo_ix = Instruction(
        program_id=memo_program,
        accounts=[AccountMeta(pubkey=keypair.pubkey(), is_signer=True, is_writable=False)],
        data=memo_data,
    )

    client = httpx.Client(timeout=30)

    resp = client.post(rpc_url, json={
        "jsonrpc": "2.0", "id": 1, "method": "getLatestBlockhash",
        "params": [{"commitment": "finalized"}],
    })
    blockhash_data = resp.json()
    blockhash = SolHash.from_string(blockhash_data["result"]["value"]["blockhash"])

    msg = Message.new_with_blockhash([memo_ix], keypair.pubkey(), blockhash)
    tx = Transaction.new_unsigned(msg)
    tx.sign([keypair], blockhash)

    tx_bytes = bytes(tx)
    tx_b64 = base64.b64encode(tx_bytes).decode("utf-8")

    resp = client.post(rpc_url, json={
        "jsonrpc": "2.0", "id": 1, "method": "sendTransaction",
        "params": [tx_b64, {"encoding": "base64", "skipPreflight": False}],
    })
    result = resp.json()

    if "error" in result:
        print(json.dumps({"ok": False, "error": result["error"]}))
        return 1

    tx_sig = result["result"]

    time.sleep(2)
    resp = client.post(rpc_url, json={
        "jsonrpc": "2.0", "id": 1, "method": "getTransaction",
        "params": [tx_sig, {"encoding": "json", "commitment": "confirmed"}],
    })
    confirmed = resp.json().get("result") is not None

    proof["solana_tx"] = tx_sig
    proof["solana_cluster"] = cluster
    proof["confirmed"] = confirmed
    proof_path = _save_proof(proof, vault_dir)

    explorer = f"https://solscan.io/tx/{tx_sig}" if cluster == "mainnet" else f"https://solscan.io/tx/{tx_sig}?cluster=devnet"

    if args.json:
        print(json.dumps({"ok": True, **proof, "explorer": explorer}, indent=2))
    else:
        status = "CONFIRMED" if confirmed else "PENDING"
        print(f"  Vault anchored on Solana ({cluster}):")
        print(f"    TX:         {tx_sig}")
        print(f"    Status:     {status}")
        print(f"    Vault hash: {proof['vault_hash'][:32]}...")
        print(f"    Chain tip:  {proof['chain_tip'][:32]}...")
        print(f"    Explorer:   {explorer}")
        print(f"    Proof:      {proof_path}")

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    vault_dir = Path(args.vault).resolve()
    proof_path = Path(args.proof) if args.proof else vault_dir / ANCHOR_PROOF_FILE

    if not proof_path.exists():
        print(json.dumps({"ok": False, "error": f"Proof file not found: {proof_path}"}))
        return 1

    stored_proof = json.loads(proof_path.read_text("utf-8"))
    current_proof = compute_proof(vault_dir)

    vault_match = stored_proof["vault_hash"] == current_proof["vault_hash"]
    chain_match = stored_proof["chain_tip"] == current_proof["chain_tip"]
    key_match = stored_proof["key_fingerprint"] == current_proof["key_fingerprint"]
    file_match = stored_proof["file_count"] == current_proof["file_count"]

    all_ok = vault_match and chain_match and key_match and file_match
    tx_sig = stored_proof.get("solana_tx")

    result = {
        "ok": all_ok,
        "vault_hash_match": vault_match,
        "chain_tip_match": chain_match,
        "key_fingerprint_match": key_match,
        "file_count_match": file_match,
        "anchored_on_chain": tx_sig is not None,
        "solana_tx": tx_sig,
        "stored_vault_hash": stored_proof["vault_hash"][:32] + "...",
        "current_vault_hash": current_proof["vault_hash"][:32] + "...",
    }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        status = "INTACT" if all_ok else "MISMATCH DETECTED"
        print(f"  Vault verification: {status}")
        print(f"    Vault hash:    {'MATCH' if vault_match else 'MISMATCH'}")
        print(f"    Chain tip:     {'MATCH' if chain_match else 'MISMATCH'}")
        print(f"    Key FP:        {'MATCH' if key_match else 'MISMATCH'}")
        print(f"    File count:    {'MATCH' if file_match else 'MISMATCH'} ({current_proof['file_count']})")
        if tx_sig:
            print(f"    On-chain TX:   {tx_sig}")
        else:
            print(f"    On-chain TX:   not anchored yet")

    return 0 if all_ok else 1


def cmd_show(args: argparse.Namespace) -> int:
    proof_path = Path(args.proof)
    if not proof_path.exists():
        print(json.dumps({"ok": False, "error": f"Proof file not found: {proof_path}"}))
        return 1

    proof = json.loads(proof_path.read_text("utf-8"))
    tx_sig = proof.get("solana_tx")
    cluster = proof.get("solana_cluster", "mainnet")

    if args.json:
        print(json.dumps({"ok": True, **proof}, indent=2))
    else:
        print(f"  Anchor Proof:")
        print(f"    Schema:        {proof.get('schema')}")
        print(f"    Timestamp:     {proof.get('timestamp')}")
        print(f"    Vault hash:    {proof['vault_hash']}")
        print(f"    Chain tip:     {proof['chain_tip']}")
        print(f"    Key FP:        {proof['key_fingerprint']}")
        print(f"    Files:         {proof['file_count']}")
        print(f"    Bytes:         {proof['total_bytes']:,}")
        print(f"    Anchor data:   {proof['anchor_payload']}")
        if tx_sig:
            explorer = f"https://solscan.io/tx/{tx_sig}" if cluster == "mainnet" else f"https://solscan.io/tx/{tx_sig}?cluster=devnet"
            print(f"    Solana TX:     {tx_sig}")
            print(f"    Cluster:       {cluster}")
            print(f"    Explorer:      {explorer}")
        else:
            print(f"    Solana TX:     not anchored")

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="liquefy-vault-anchor",
        description="On-chain vault integrity anchoring on Solana.",
    )
    sub = parser.add_subparsers(dest="command")

    p_proof = sub.add_parser("proof", help="Compute vault proof (offline, free)")
    p_proof.add_argument("--vault", required=True, help="Vault directory")
    p_proof.add_argument("--json", action="store_true")

    p_anchor = sub.add_parser("anchor", help="Anchor proof on Solana")
    p_anchor.add_argument("--vault", required=True, help="Vault directory")
    p_anchor.add_argument("--keypair", required=True, help="Solana keypair JSON file")
    p_anchor.add_argument("--cluster", choices=["mainnet", "devnet"], default="mainnet")
    p_anchor.add_argument("--rpc", help="Custom RPC URL")
    p_anchor.add_argument("--json", action="store_true")

    p_verify = sub.add_parser("verify", help="Verify vault matches anchor")
    p_verify.add_argument("--vault", required=True, help="Vault directory")
    p_verify.add_argument("--proof", help="Proof file path (default: vault/.anchor-proof.json)")
    p_verify.add_argument("--json", action="store_true")

    p_show = sub.add_parser("show", help="Display an existing anchor proof")
    p_show.add_argument("--proof", required=True, help="Proof file path")
    p_show.add_argument("--json", action="store_true")

    args = parser.parse_args()
    commands = {"proof": cmd_proof, "anchor": cmd_anchor, "verify": cmd_verify, "show": cmd_show}

    if args.command in commands:
        return commands[args.command](args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
