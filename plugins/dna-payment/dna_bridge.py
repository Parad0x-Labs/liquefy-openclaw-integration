#!/usr/bin/env python3
"""
dna_bridge.py — DNA x402 payment receipt archiver + per-receipt Solana anchor.

Responsibilities:
  1. cmd_archive(): compress receipts via Liquefy, write receipts.jsonl, call
     liquefy_vault_anchor.py for vault-level anchoring, then (if SOLANA_KEYPAIR
     is present) call cmd_anchor_receipts() for per-receipt SPL-Memo anchoring.
  2. cmd_anchor_receipts(): SHA-256 each JSONL line, send each hash as an
     on-chain SPL-Memo transaction, return structured results.

Environment variables:
  SOLANA_KEYPAIR   JSON array of 64 bytes (base-10 ints).  Required for
                   per-receipt anchoring; if absent anchoring is skipped.
  SOLANA_RPC_URL   Optional override; defaults to mainnet-beta.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_RPC_URL = "https://api.mainnet-beta.solana.com"
EXPLORER_BASE   = "https://explorer.solana.com/tx"

# Path to the vault-level anchor helper that lives next to this plugin.
_PLUGIN_DIR          = Path(__file__).parent
VAULT_ANCHOR_SCRIPT  = _PLUGIN_DIR / "liquefy_vault_anchor.py"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _receipt_sha256(line: str) -> str:
    """Return hex SHA-256 of the UTF-8 bytes of a JSONL receipt line."""
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


def _keypair_from_env() -> list[int] | None:
    """Parse SOLANA_KEYPAIR env var.  Returns None if not set."""
    raw = os.environ.get("SOLANA_KEYPAIR", "").strip()
    if not raw:
        return None
    try:
        kp = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"SOLANA_KEYPAIR is not valid JSON: {exc}") from exc
    if not isinstance(kp, list) or len(kp) != 64:
        raise ValueError(
            f"SOLANA_KEYPAIR must be a JSON array of exactly 64 ints, got {len(kp) if isinstance(kp, list) else type(kp).__name__}"
        )
    return kp


def _write_keypair_file(keypair: list[int]) -> Path:
    """Write keypair JSON to a temp file; caller is responsible for cleanup."""
    fd, path = tempfile.mkstemp(suffix=".json", prefix="sol_kp_")
    with os.fdopen(fd, "w") as fh:
        json.dump(keypair, fh)
    return Path(path)


def _send_spl_memo(memo_hex: str, keypair_path: Path, rpc_url: str) -> dict:
    """
    Submit a single SPL-Memo transaction containing memo_hex via the Solana CLI.

    Returns dict with keys: solana_tx, slot, explorer_url.
    Raises RuntimeError on CLI failure.
    """
    cmd = [
        "solana", "transfer",
        "--from", str(keypair_path),
        "--url", rpc_url,
        "--with-memo", memo_hex,
        # zero-lamport self-transfer to carry the memo
        str(_pubkey_from_keypair_file(keypair_path)),
        "0",
        "--allow-unfunded-recipient",
        "--output", "json",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "solana CLI not found on PATH — install Solana tools to use per-receipt anchoring"
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("solana CLI timed out after 60 s")

    if result.returncode != 0:
        raise RuntimeError(
            f"solana CLI exited {result.returncode}: {result.stderr.strip()}"
        )

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        # Fallback: the CLI may print raw signature on stdout in older versions.
        sig = result.stdout.strip()
        return {
            "solana_tx":    sig,
            "slot":         None,
            "explorer_url": f"{EXPLORER_BASE}/{sig}",
        }

    sig  = data.get("signature") or data.get("result") or ""
    slot = data.get("slot")
    return {
        "solana_tx":    sig,
        "slot":         slot,
        "explorer_url": f"{EXPLORER_BASE}/{sig}",
    }


def _pubkey_from_keypair_file(keypair_path: Path) -> str:
    """Return the base-58 pubkey string for a keypair file via solana-keygen."""
    result = subprocess.run(
        ["solana-keygen", "pubkey", str(keypair_path)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"solana-keygen pubkey failed: {result.stderr.strip()}"
        )
    return result.stdout.strip()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def cmd_anchor_receipts(
    receipts_jsonl_path: str,
    rpc_url: str | None = None,
) -> list[dict]:
    """
    Anchor each receipt hash individually on Solana via SPL Memo.

    For every non-empty line in receipts_jsonl_path:
      - Compute SHA-256 of the line's UTF-8 bytes.
      - Submit an SPL-Memo transaction carrying that hex digest.
      - Record the result regardless of per-receipt success/failure.

    Returns a list of dicts, one per receipt line:
      {
          "receipt_id":   str | int,   # from the receipt JSON, or line index
          "receipt_hash": str,         # hex SHA-256
          "solana_tx":    str | None,
          "slot":         int | None,
          "explorer_url": str | None,
          "error":        str | None,  # set only on failure
      }

    Fails gracefully per-receipt — a single anchor failure does not abort
    the batch.

    Requires: SOLANA_KEYPAIR env var (JSON array of 64 bytes).
    """
    rpc = rpc_url or os.environ.get("SOLANA_RPC_URL", DEFAULT_RPC_URL)
    keypair = _keypair_from_env()
    if keypair is None:
        raise EnvironmentError(
            "SOLANA_KEYPAIR env var not set — cannot anchor receipts"
        )

    kp_file = _write_keypair_file(keypair)
    results: list[dict] = []
    try:
        with open(receipts_jsonl_path, "r", encoding="utf-8") as fh:
            for idx, raw_line in enumerate(fh):
                line = raw_line.rstrip("\n")
                if not line:
                    continue

                # Parse for receipt_id; fall back to line index.
                receipt_id: Any = idx
                try:
                    obj = json.loads(line)
                    receipt_id = obj.get("receiptId", obj.get("receipt_id", idx))
                except (json.JSONDecodeError, AttributeError):
                    pass

                receipt_hash = _receipt_sha256(line)
                entry: dict = {
                    "receipt_id":   receipt_id,
                    "receipt_hash": receipt_hash,
                    "solana_tx":    None,
                    "slot":         None,
                    "explorer_url": None,
                    "error":        None,
                }

                try:
                    tx_info = _send_spl_memo(
                        memo_hex=receipt_hash,
                        keypair_path=kp_file,
                        rpc_url=rpc,
                    )
                    entry["solana_tx"]    = tx_info["solana_tx"]
                    entry["slot"]         = tx_info["slot"]
                    entry["explorer_url"] = tx_info["explorer_url"]
                except Exception as exc:  # noqa: BLE001
                    entry["error"] = str(exc)

                results.append(entry)
    finally:
        try:
            kp_file.unlink()
        except OSError:
            pass

    return results


def cmd_archive(
    receipts: list[dict],
    output_dir: str,
    rpc_url: str | None = None,
) -> dict:
    """
    Archive a batch of x402 receipts.

    Steps:
      1. Write receipts.jsonl to output_dir.
      2. Call liquefy_vault_anchor.py for vault-level (whole-blob) anchoring.
      3. If SOLANA_KEYPAIR is set, call cmd_anchor_receipts() for per-receipt
         on-chain SPL-Memo anchoring.
      4. Return a manifest dict with all results.

    Returns:
      {
          "receipts_jsonl":     str,           # absolute path
          "vault_anchor":       dict | None,   # result from liquefy_vault_anchor
          "per_receipt_anchors": list[dict],   # from cmd_anchor_receipts, or []
          "anchored_at":        float,         # unix timestamp
      }
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    receipts_jsonl_path = out / "receipts.jsonl"

    # ── Step 1: write receipts.jsonl ─────────────────────────────────────────
    with open(receipts_jsonl_path, "w", encoding="utf-8") as fh:
        for r in receipts:
            fh.write(json.dumps(r, separators=(",", ":")) + "\n")

    manifest: dict = {
        "receipts_jsonl":      str(receipts_jsonl_path),
        "vault_anchor":        None,
        "per_receipt_anchors": [],
        "anchored_at":         time.time(),
    }

    # ── Step 2: vault-level anchor via liquefy_vault_anchor.py ──────────────
    if VAULT_ANCHOR_SCRIPT.exists():
        try:
            vault_result = subprocess.run(
                [sys.executable, str(VAULT_ANCHOR_SCRIPT), str(receipts_jsonl_path)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if vault_result.returncode == 0:
                try:
                    manifest["vault_anchor"] = json.loads(vault_result.stdout)
                except json.JSONDecodeError:
                    manifest["vault_anchor"] = {"raw_output": vault_result.stdout.strip()}
            else:
                manifest["vault_anchor"] = {
                    "error": vault_result.stderr.strip() or vault_result.stdout.strip()
                }
        except Exception as exc:  # noqa: BLE001
            manifest["vault_anchor"] = {"error": str(exc)}
    else:
        manifest["vault_anchor"] = {
            "skipped": True,
            "reason":  f"liquefy_vault_anchor.py not found at {VAULT_ANCHOR_SCRIPT}",
        }

    # ── Step 3: per-receipt anchoring (only if keypair available) ───────────
    keypair_present = bool(os.environ.get("SOLANA_KEYPAIR", "").strip())
    if keypair_present:
        try:
            per_receipt = cmd_anchor_receipts(
                receipts_jsonl_path=str(receipts_jsonl_path),
                rpc_url=rpc_url,
            )
            manifest["per_receipt_anchors"] = per_receipt
        except Exception as exc:  # noqa: BLE001
            manifest["per_receipt_anchors"] = [{"error": str(exc)}]

    return manifest


# ---------------------------------------------------------------------------
# CLI entry-point (optional convenience)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="DNA x402 bridge: archive receipts and anchor on Solana."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_archive = sub.add_parser("archive", help="Archive receipt batch from JSON file")
    p_archive.add_argument("receipts_json", help="Path to JSON file containing list of receipts")
    p_archive.add_argument("output_dir",    help="Directory to write receipts.jsonl and manifest")
    p_archive.add_argument("--rpc",         help="Solana RPC URL override", default=None)

    p_anchor = sub.add_parser("anchor-receipts", help="Anchor existing receipts.jsonl on Solana")
    p_anchor.add_argument("receipts_jsonl", help="Path to receipts.jsonl")
    p_anchor.add_argument("--rpc",          help="Solana RPC URL override", default=None)

    args = parser.parse_args()

    if args.cmd == "archive":
        with open(args.receipts_json, "r", encoding="utf-8") as f:
            receipt_list = json.load(f)
        result = cmd_archive(receipt_list, args.output_dir, rpc_url=args.rpc)
        print(json.dumps(result, indent=2))

    elif args.cmd == "anchor-receipts":
        result = cmd_anchor_receipts(args.receipts_jsonl, rpc_url=args.rpc)
        print(json.dumps(result, indent=2))
