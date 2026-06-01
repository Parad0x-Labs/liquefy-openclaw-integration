"""
Dark Null Bridge Plugin
=======================
Archives Dark Null Protocol settlement data (ZK proofs, nullifier records,
withdrawal events) into Liquefy TraceVaults and optionally anchors them on
Solana via a memo-program receipt_anchor transaction.

Program addresses
-----------------
dark_bn254_gate     : GCptvBYF8S6eVYoh15B7WAESc54FUHCpN1Ui6aHeQYZd
dark_shielded_pool  : (pending audit)
dark_semaphore      : Ev7HEFhhKTXk6kS2Y6ssbUcK9C7E6yZ589jJNjUrQV5p
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Program registry
# ---------------------------------------------------------------------------

DARK_NULL_PROGRAMS: dict[str, str] = {
    "dark_bn254_gate": "GCptvBYF8S6eVYoh15B7WAESc54FUHCpN1Ui6aHeQYZd",
    "dark_shielded_pool": "(pending audit)",
    "dark_semaphore": "Ev7HEFhhKTXk6kS2Y6ssbUcK9C7E6yZ589jJNjUrQV5p",
}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class DarkNullEvent:
    """Represents one settlement event emitted by the Dark Null Protocol."""

    event_type: str       # "deposit" | "withdraw" | "nullifier_spent"
    nullifier_hash: str   # hex-encoded 32-byte nullifier
    merkle_root: str      # hex-encoded 32-byte Merkle root at time of event
    amount_atomic: int    # token amount in smallest denomination (e.g. lamports)
    receiver_token: str   # base58 SPL token account that received the funds
    slot: int             # Solana slot at which the event was confirmed
    proof_bytes_hex: str  # hex-encoded 256-byte Groth16 proof (A‖B‖C)
    timestamp: float      # Unix epoch float


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _liquefy_paths() -> None:
    """Ensure the sibling liquefy clone is on sys.path."""
    plugin_root = Path(__file__).resolve().parents[2]           # …/liquefy-openclaw-integration
    clone_root = plugin_root.parent                              # …/.clone
    liquefy_src = clone_root / "liquefy" / "src"
    liquefy_engines = clone_root / "liquefy" / "engines"
    for _p in (
        liquefy_src,
        liquefy_engines,
        liquefy_engines / "json_codec",
        liquefy_engines / "security_compliance",
    ):
        if _p.exists() and str(_p) not in sys.path:
            sys.path.insert(0, str(_p))


def _derive_aes_key(secret: bytes | None = None) -> bytes:
    """Return a 32-byte AES-256 key.

    Priority:
    1. *secret* argument (caller-supplied raw bytes — will be SHA-256 stretched)
    2. ``LIQUEFY_VAULT_KEY`` environment variable
    3. Dev-only deterministic fallback (must be replaced in production)
    """
    if secret is not None:
        return hashlib.sha256(secret).digest()
    env_key = os.environ.get("LIQUEFY_VAULT_KEY")
    if env_key:
        return hashlib.sha256(env_key.encode()).digest()
    # Dev fallback — DO NOT use in production
    return hashlib.sha256(b"liquefy-openclaw-dark-null-dev-only-insecure").digest()


def tracevault_pack(records: list[dict], vault_path: Path, aes_key: bytes) -> None:
    """Compress then AES-256-GCM encrypt *records* and write to *vault_path*.

    Delegates to ``liquefy.compress_encrypted`` so the vault is both columnar-
    compressed and authenticated-encrypted in a single pass.
    """
    _liquefy_paths()
    from liquefy import compress_encrypted  # type: ignore  # sibling clone

    jsonl = "\n".join(json.dumps(r, separators=(",", ":")) for r in records)
    blob = compress_encrypted(jsonl.encode("utf-8"), aes_key)
    vault_path.parent.mkdir(parents=True, exist_ok=True)
    vault_path.write_bytes(blob)


def liquefy_vault_anchor(vault_path: Path, rpc_url: str | None = None) -> str:
    """Anchor the SHA-256 hash of *vault_path* on Solana via the Memo program.

    Reads the payer keypair from ``SOLANA_PAYER_KEYPAIR_PATH`` (JSON byte-array
    format produced by ``solana-keygen``).  Falls back to the standard CLI
    location ``~/.config/solana/id.json``.

    Returns the transaction signature string.
    Raises ``RuntimeError`` with a descriptive message on failure.
    """
    vault_hash = hashlib.sha256(vault_path.read_bytes()).digest()

    try:
        import urllib.request

        from solders.hash import Hash  # type: ignore
        from solders.instruction import AccountMeta, Instruction  # type: ignore
        from solders.keypair import Keypair  # type: ignore
        from solders.pubkey import Pubkey  # type: ignore
        from solders.transaction import Transaction  # type: ignore

        MEMO_PROGRAM = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")

        keypair_path = os.environ.get(
            "SOLANA_PAYER_KEYPAIR_PATH",
            str(Path.home() / ".config" / "solana" / "id.json"),
        )
        secret = json.loads(Path(keypair_path).read_text(encoding="utf-8"))
        payer = Keypair.from_bytes(bytes(secret))

        rpc = rpc_url or os.environ.get(
            "SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"
        )

        # --- fetch recent blockhash ----------------------------------------
        req_body = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "getLatestBlockhash",
            "params": [{"commitment": "finalized"}],
        }).encode()
        req = urllib.request.Request(
            rpc, data=req_body, headers={"Content-Type": "application/json"}
        )
        resp = json.loads(urllib.request.urlopen(req, timeout=15).read())
        blockhash = Hash.from_string(resp["result"]["value"]["blockhash"])

        # --- build memo instruction carrying vault hash (base64-encoded) ----
        memo_data = base64.b64encode(vault_hash).decode("ascii")
        ix = Instruction(
            MEMO_PROGRAM,
            memo_data.encode("utf-8"),
            [AccountMeta(payer.pubkey(), is_signer=True, is_writable=False)],
        )
        tx = Transaction([payer], [ix], blockhash)

        # --- send transaction -----------------------------------------------
        send_body = json.dumps({
            "jsonrpc": "2.0", "id": 1,
            "method": "sendTransaction",
            "params": [
                base64.b64encode(bytes(tx)).decode("ascii"),
                {"encoding": "base64"},
            ],
        }).encode()
        req2 = urllib.request.Request(
            rpc, data=send_body, headers={"Content-Type": "application/json"}
        )
        resp2 = json.loads(urllib.request.urlopen(req2, timeout=15).read())
        return resp2["result"]

    except Exception as exc:
        raise RuntimeError(
            f"liquefy_vault_anchor: Solana anchor failed for {vault_path.name}: {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# cmd_archive
# ---------------------------------------------------------------------------

def cmd_archive(
    events_dir: str,
    output_dir: str,
    anchor: bool = False,
    aes_key: bytes | None = None,
) -> dict:
    """Read Dark Null settlement events, pack into a TraceVault, optionally anchor.

    Parameters
    ----------
    events_dir:
        Directory containing ``dark_null_events.jsonl``.  Each line must be a
        JSON object that can be deserialised into a :class:`DarkNullEvent`.
    output_dir:
        Destination directory for the ``.vault`` file.
    anchor:
        When ``True``, call :func:`liquefy_vault_anchor` after packing.
    aes_key:
        Optional raw bytes used as the AES-256 encryption secret.  If omitted
        the key is derived from the ``LIQUEFY_VAULT_KEY`` environment variable
        or the built-in dev fallback.

    Returns
    -------
    dict
        ``{ vault_path, event_count }`` — plus ``anchor_tx`` when *anchor* is
        ``True``.
    """
    events_path = Path(events_dir) / "dark_null_events.jsonl"
    if not events_path.exists():
        raise FileNotFoundError(f"events file not found: {events_path}")

    raw_events: list[dict] = []
    with events_path.open(encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw_events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {lineno} of {events_path}: {exc}") from exc

    # Map to the canonical liquefy.dark-null.telemetry.v1 schema
    mapped: list[dict] = [
        {
            "schema": "liquefy.dark-null.telemetry.v1",
            "event_type": r.get("event_type", ""),
            "nullifier_hash": r.get("nullifier_hash", ""),
            "merkle_root": r.get("merkle_root", ""),
            "amount_atomic": int(r.get("amount_atomic", 0)),
            "receiver_token": r.get("receiver_token", ""),
            "slot": int(r.get("slot", 0)),
            "proof_bytes_hex": r.get("proof_bytes_hex", ""),
            "timestamp": float(r.get("timestamp", 0.0)),
        }
        for r in raw_events
    ]

    key = _derive_aes_key(aes_key)
    vault_name = f"dark_null_{int(time.time())}.vault"
    vault_path = Path(output_dir) / vault_name
    tracevault_pack(mapped, vault_path, key)

    result: dict = {
        "vault_path": str(vault_path),
        "event_count": len(mapped),
    }
    if anchor:
        result["anchor_tx"] = liquefy_vault_anchor(vault_path)

    return result


# ---------------------------------------------------------------------------
# cmd_export_proof_bundle
# ---------------------------------------------------------------------------

def cmd_export_proof_bundle(
    proof_bytes_hex: str,
    public_inputs: list,
    output_dir: str,
) -> dict:
    """Serialize a raw Groth16 proof and its public inputs to ``proof_bundle.json``.

    Parameters
    ----------
    proof_bytes_hex:
        Hex-encoded 256-byte Groth16 proof in A‖B‖C groth16-solana format
        (64 bytes pi_a ‖ 128 bytes pi_b ‖ 64 bytes pi_c, big-endian limbs).
    public_inputs:
        Ordered list of public inputs matching the circuit's ``n_public``
        declaration.  Each entry may be an ``int``, a hex string, or a
        decimal string.
    output_dir:
        Directory where ``proof_bundle.json`` will be written.

    Returns
    -------
    dict
        ``{ bundle_path, bundle_hash }`` where *bundle_hash* is the hex-encoded
        SHA-256 digest of the serialised bundle file.
    """
    # Normalise proof bytes
    hex_clean = proof_bytes_hex.lstrip("0x").lower()
    if len(hex_clean) != 512:
        raise ValueError(
            f"proof_bytes_hex must encode exactly 256 bytes (512 hex chars); "
            f"got {len(hex_clean)} hex chars"
        )

    bundle = {
        "schema": "liquefy.dark-null.proof-bundle.v1",
        "proof_bytes_hex": hex_clean,
        "public_inputs": [
            (hex(v) if isinstance(v, int) else str(v)) for v in public_inputs
        ],
        "exported_at": time.time(),
        "curve": "bn254",
        "protocol": "groth16",
    }

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    bundle_path = out_path / "proof_bundle.json"
    bundle_path.write_text(
        json.dumps(bundle, indent=2, separators=(",", ": ")), encoding="utf-8"
    )

    bundle_hash = hashlib.sha256(bundle_path.read_bytes()).hexdigest()

    return {
        "bundle_path": str(bundle_path),
        "bundle_hash": bundle_hash,
    }


# ---------------------------------------------------------------------------
# Plugin manifest
# ---------------------------------------------------------------------------

PLUGIN_MANIFEST: dict = {
    "plugin_id": "dark-null",
    "version": "0.1.0",
    "schema_namespace": "liquefy.dark-null.telemetry.v1",
    "description": (
        "Archives Dark Null Protocol ZK settlement data (ZK proofs, nullifier records, "
        "withdrawal events) into AES-256-GCM encrypted Liquefy TraceVaults. "
        "Optional on-chain anchoring via receipt_anchor (Solana Memo program)."
    ),
    "commands": {
        "archive": "cmd_archive",
        "export_proof_bundle": "cmd_export_proof_bundle",
    },
    "programs": DARK_NULL_PROGRAMS,
    "requires": ["liquefy", "solders", "cryptography"],
    "event_input_file": "dark_null_events.jsonl",
    "vault_extension": ".vault",
    "proof_bundle_file": "proof_bundle.json",
}
