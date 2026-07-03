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
  SOLANA_RPC_URL   Optional override; defaults to https://solana-rpc.publicnode.com.
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

DEFAULT_RPC_URL = "https://solana-rpc.publicnode.com"
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
# Telemetry / audit helpers
# ---------------------------------------------------------------------------

# Event kinds that indicate an error condition.
_ERROR_KINDS: frozenset[str] = frozenset({
    "GUARD_RECEIPT_INVALID",
    "GUARD_VALIDATION_FAILED",
    "PAYMENT_FAILED",
    "RECEIPT_REJECTED",
    "SIG_MISMATCH",
    "AUTH_FAILED",
})

# Event kinds that are receipt-domain events.
_RECEIPT_KINDS: frozenset[str] = frozenset({
    "GUARD_RECEIPT_INVALID",
    "GUARD_VALIDATION_FAILED",
    "PAYMENT_VERIFIED",
    "PAYMENT_FAILED",
    "RECEIPT_REJECTED",
})


def audit_to_telemetry(audit: dict) -> dict:
    """
    Map a raw audit-log record to a normalised telemetry record.

    Input fields (all optional except ``kind``):
        kind       — event kind string (e.g. "GUARD_RECEIPT_INVALID")
        ts         — ISO-8601 timestamp string
        traceId    — trace identifier
        shopId     — seller/shop identifier
        receiptId  — receipt identifier
        mint       — token mint symbol (e.g. "USDC")
        errorCode  — error code string

    Returns a dict with:
        event_type — same as ``kind``
        severity   — "error" for error-class events, "info" otherwise
        domain     — "receipt" for receipt-related events, "payment" otherwise
        tags       — list of "key:value" strings
        ts         — forwarded timestamp (if present)
        trace_id   — forwarded traceId (if present)
    """
    kind = audit.get("kind", "")

    severity = "error" if kind in _ERROR_KINDS else "info"
    domain = "receipt" if kind in _RECEIPT_KINDS else "payment"

    tags: list[str] = []
    if audit.get("shopId"):
        tags.append(f"shop:{audit['shopId']}")
    if audit.get("mint"):
        tags.append(f"mint:{audit['mint']}")
    if audit.get("errorCode"):
        tags.append(f"error:{audit['errorCode']}")
    if audit.get("receiptId"):
        tags.append(f"receipt:{audit['receiptId']}")

    record: dict = {
        "event_type": kind,
        "severity":   severity,
        "domain":     domain,
        "tags":       tags,
    }
    if audit.get("ts"):
        record["ts"] = audit["ts"]
    if audit.get("traceId"):
        record["trace_id"] = audit["traceId"]

    return record


# ---------------------------------------------------------------------------
# HTTP helpers (thin wrappers — easily monkeypatched in tests)
# ---------------------------------------------------------------------------

def fetch_text(url: str) -> str:
    """Fetch a URL and return the response body as a string."""
    import urllib.request  # lazy import — not needed for archiving
    with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310
        return resp.read().decode("utf-8")


def fetch_json(url: str) -> Any:
    """Fetch a URL and return the JSON-parsed response body."""
    return json.loads(fetch_text(url))


# ---------------------------------------------------------------------------
# Export command
# ---------------------------------------------------------------------------

def cmd_export(args: Any) -> bool:
    """
    Export audit events and the latest receipt from a DNA server.

    Reads from:
        {args.server}/audit/log    — newline-delimited JSON audit records
        {args.server}/receipt/latest — single JSON receipt object

    Writes to args.out/:
        telemetry.jsonl      — one normalised telemetry record per audit line
        receipts.jsonl       — one line per receipt fetched
        manifest.json        — summary with proof_artifact_count

    Returns True on success.
    """
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    server = args.server.rstrip("/")

    # ── Fetch audit log ──────────────────────────────────────────────────────
    raw_audit = fetch_text(f"{server}/audit/log")
    audit_records: list[dict] = []
    for line in raw_audit.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            audit_records.append(json.loads(line))
        except json.JSONDecodeError:
            pass

    # ── Fetch latest receipt ─────────────────────────────────────────────────
    receipt = fetch_json(f"{server}/receipt/latest")

    # ── Write telemetry.jsonl ────────────────────────────────────────────────
    telemetry_path = out / "telemetry.jsonl"
    with open(telemetry_path, "w", encoding="utf-8") as fh:
        for rec in audit_records:
            tel = audit_to_telemetry(rec)
            fh.write(json.dumps(tel, separators=(",", ":")) + "\n")

    # ── Write receipts.jsonl ─────────────────────────────────────────────────
    receipts_path = out / "receipts.jsonl"
    with open(receipts_path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(receipt, separators=(",", ":")) + "\n")

    # ── Write manifest.json ──────────────────────────────────────────────────
    manifest = {
        "server":               server,
        "telemetry_count":      len(audit_records),
        "proof_artifact_count": 1,  # one receipt fetched
        "exported_at":          time.time(),
    }
    manifest_path = out / "manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)

    return True


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
