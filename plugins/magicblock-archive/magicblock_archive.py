"""
magicblock_archive.py — MagicBlock Ephemeral Rollup session archiving plugin for openclaw-vault.

Gap filled: MagicBlock Ephemeral Rollups commit final state to Solana but produce no durable
transaction log. Sessions are described as "auditable" but nothing is archived. This plugin
archives ER session logs: compresses, optionally encrypts, hashes, and folds a 32-byte
session commitment into the on-chain receipt_anchor accumulator. x402 session playback
pricing is included.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MAGICBLOCK_RPC: str = os.environ.get("MAGICBLOCK_RPC", "https://devnet.magicblock.app")

# receipt_anchor program (web0/Parad0x, mainnet-beta) — folds a 32-byte session
# commitment into a rolling on-chain accumulator: root_n = sha256(root_{n-1} || anchor_n).
RECEIPT_ANCHOR_PROGRAM = "6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN"

# Hour-bucket accumulator parameters (mirror programs/receipt_anchor processor.rs).
BUCKET_WINDOW_SECONDS = 3600
INSTRUCTION_VERSION_V1 = 0x01
FLAG_HAS_BUCKET_ID = 0x01


# ---------------------------------------------------------------------------
# 1. fetch_session_log
# ---------------------------------------------------------------------------

def fetch_session_log(session_id: str, er_rpc_url: str = None) -> list[dict]:
    """Fetch transaction history for an Ephemeral Rollup session.

    Queries the ER validator RPC for all transactions associated with
    *session_id*.  Each entry is normalised to a common shape so callers
    do not need to parse raw Solana RPC responses.

    Parameters
    ----------
    session_id:
        The public key (base-58) or opaque identifier for the ER session
        account.
    er_rpc_url:
        Override the RPC endpoint.  Defaults to ``MAGICBLOCK_RPC``.

    Returns
    -------
    list[dict]
        Each dict contains:
        ``slot`` (int), ``signature`` (str), ``action_type`` (str),
        ``accounts`` (list[str]), ``data_hex`` (str).
    """
    import urllib.request
    import urllib.error

    rpc_url = er_rpc_url or MAGICBLOCK_RPC

    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getSignaturesForAddress",
        "params": [
            session_id,
            {"limit": 1000, "commitment": "confirmed"},
        ],
    }).encode()

    req = urllib.request.Request(
        rpc_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = json.loads(resp.read())
    except urllib.error.URLError as exc:
        raise RuntimeError(f"ER RPC unreachable at {rpc_url}: {exc}") from exc

    if "error" in body:
        raise RuntimeError(f"ER RPC error: {body['error']}")

    raw_sigs: list[dict] = body.get("result", [])

    # For each signature fetch the full transaction to extract accounts/data.
    entries: list[dict] = []
    for sig_info in raw_sigs:
        signature = sig_info.get("signature", "")
        slot = sig_info.get("slot", 0)

        tx_payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTransaction",
            "params": [
                signature,
                {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0},
            ],
        }).encode()

        tx_req = urllib.request.Request(
            rpc_url,
            data=tx_payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(tx_req, timeout=15) as tx_resp:
                tx_body = json.loads(tx_resp.read())
        except urllib.error.URLError:
            # Best-effort: include a stub entry if transaction fetch fails.
            entries.append({
                "slot": slot,
                "signature": signature,
                "action_type": "unknown",
                "accounts": [],
                "data_hex": "",
            })
            continue

        tx = tx_body.get("result") or {}
        message = (tx.get("transaction") or {}).get("message") or {}
        account_keys: list[str] = [
            (k.get("pubkey") if isinstance(k, dict) else k)
            for k in message.get("accountKeys", [])
        ]

        # Extract instruction data (first instruction only for action_type heuristic).
        instructions = message.get("instructions", [])
        data_hex = ""
        action_type = "tx"
        if instructions:
            first_ix = instructions[0]
            raw_data = first_ix.get("data", "")
            if isinstance(raw_data, str):
                data_hex = raw_data
            # Heuristic: derive action_type from program / parsed type when available.
            parsed = first_ix.get("parsed")
            if isinstance(parsed, dict):
                action_type = parsed.get("type", "tx")
            elif first_ix.get("program"):
                action_type = first_ix["program"]

        entries.append({
            "slot": slot,
            "signature": signature,
            "action_type": action_type,
            "accounts": account_keys,
            "data_hex": data_hex,
        })

    return entries


# ---------------------------------------------------------------------------
# 2. archive_session
# ---------------------------------------------------------------------------

def archive_session(
    session_id: str,
    aes_key: bytes = None,
    anchor: bool = False,
    er_rpc_url: str = None,
    output_dir: str = None,
) -> dict:
    """Fetch, compress, optionally encrypt, hash, and optionally anchor a session.

    Parameters
    ----------
    session_id:
        ER session public key / identifier.
    aes_key:
        32-byte key for AES-256-GCM encryption.  If ``None`` the archive is
        stored unencrypted.
    anchor:
        When ``True`` fold a 32-byte commitment binding the session id and
        archive hash into the on-chain ``receipt_anchor`` accumulator so it
        becomes immutably timestamped on Solana.
    er_rpc_url:
        Override ER RPC endpoint.
    output_dir:
        Directory where the archive file is written.  Defaults to cwd.

    Returns
    -------
    dict
        ``session_id``, ``action_count``, ``compressed_bytes``,
        ``archive_hash``, ``archive_path``, ``solana_tx`` (str or None), and —
        when anchored — ``anchor_commitment`` (hex of the 32-byte value folded
        on-chain) and ``anchor_bucket_id`` (int) so the anchor can be
        reproduced and verified against the live bucket.
    """
    try:
        import zstandard as zstd
    except ImportError as exc:
        raise ImportError(
            "zstandard is required: pip install zstandard"
        ) from exc

    # --- fetch ---
    log = fetch_session_log(session_id, er_rpc_url=er_rpc_url)

    # --- serialise to JSONL ---
    jsonl_bytes = b"\n".join(json.dumps(entry).encode() for entry in log)

    # --- compress ---
    cctx = zstd.ZstdCompressor(level=19)
    compressed: bytes = cctx.compress(jsonl_bytes)

    # --- optionally encrypt ---
    if aes_key is not None:
        if len(aes_key) != 32:
            raise ValueError("aes_key must be exactly 32 bytes for AES-256-GCM")
        compressed = _aes256_gcm_encrypt(aes_key, compressed)

    # --- hash (over the final blob, post-encryption if any) ---
    archive_hash = hashlib.sha256(compressed).hexdigest()

    # --- write to disk ---
    out_dir = Path(output_dir) if output_dir else Path.cwd()
    out_dir.mkdir(parents=True, exist_ok=True)
    suffix = ".zst.enc" if aes_key else ".zst"
    archive_path = out_dir / f"session_{session_id}{suffix}"
    archive_path.write_bytes(compressed)

    # --- optionally anchor on Solana ---
    solana_tx: Optional[str] = None
    anchor_commitment: Optional[str] = None
    anchor_bucket_id: Optional[int] = None
    if anchor:
        commitment = _session_commitment(session_id, archive_hash)
        anchor_commitment = commitment.hex()
        solana_tx, anchor_bucket_id = _anchor_receipt(commitment)

    return {
        "session_id": session_id,
        "action_count": len(log),
        "compressed_bytes": len(compressed),
        "archive_hash": archive_hash,
        "archive_path": str(archive_path),
        "solana_tx": solana_tx,
        "anchor_commitment": anchor_commitment,
        "anchor_bucket_id": anchor_bucket_id,
    }


# ---------------------------------------------------------------------------
# 3. verify_archive
# ---------------------------------------------------------------------------

def verify_archive(archive_path: str, expected_hash: str) -> bool:
    """Verify the integrity of an archive file.

    Parameters
    ----------
    archive_path:
        Absolute or relative path to the archive (compressed blob).
    expected_hash:
        Hex-encoded SHA-256 digest to compare against.

    Returns
    -------
    bool
        ``True`` if the recomputed digest matches *expected_hash*.
    """
    path = Path(archive_path)
    if not path.exists():
        raise FileNotFoundError(f"Archive not found: {archive_path}")

    data = path.read_bytes()
    actual_hash = hashlib.sha256(data).hexdigest()
    return actual_hash == expected_hash


# ---------------------------------------------------------------------------
# 4. x402_session_playback_url
# ---------------------------------------------------------------------------

def x402_session_playback_url(
    session_id: str,
    archive_hash: str,
    price_usdc: float = 0.01,
) -> str:
    """Return a formatted x402 endpoint description for session playback.

    The caller (deployer) is responsible for standing up the actual HTTP
    endpoint that enforces the x402 payment.  This function returns only the
    canonical URL string so it can be stored in metadata or passed to clients.

    Parameters
    ----------
    session_id:
        ER session identifier.
    archive_hash:
        SHA-256 hex digest of the archived blob (as returned by
        :func:`archive_session`).
    price_usdc:
        Price in USDC to access the session playback.  Defaults to $0.01.

    Returns
    -------
    str
        Formatted x402 URL, e.g.
        ``x402://session/abc123?archive=deadbeef...&price=0.01USDC``
    """
    return (
        f"x402://session/{session_id}"
        f"?archive={archive_hash}"
        f"&price={price_usdc}USDC"
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _aes256_gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt *plaintext* with AES-256-GCM.

    Output layout: ``nonce (12 bytes) || tag (16 bytes) || ciphertext``.

    Uses the standard library ``cryptography`` package when available,
    falling back to a pure-Python path via ``pycryptodome`` (Crypto.Cipher).
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import secrets as _sec
        nonce = _sec.token_bytes(12)
        aesgcm = AESGCM(key)
        # cryptography appends tag to ciphertext
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        # Reformat to nonce || tag || ciphertext for explicit layout
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
        return nonce + tag + ciphertext
    except ImportError:
        pass

    try:
        from Crypto.Cipher import AES as _AES
        import secrets as _sec
        nonce = _sec.token_bytes(12)
        cipher = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + tag + ciphertext
    except ImportError as exc:
        raise ImportError(
            "AES-256-GCM requires either 'cryptography' or 'pycryptodome': "
            "pip install cryptography"
        ) from exc


def _aes256_gcm_decrypt(key: bytes, blob: bytes) -> bytes:
    """Decrypt a blob produced by :func:`_aes256_gcm_encrypt`."""
    nonce = blob[:12]
    tag = blob[12:28]
    ciphertext = blob[28:]

    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except ImportError:
        pass

    from Crypto.Cipher import AES as _AES
    cipher = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    cipher.verify(tag)
    return plaintext


def _session_commitment(session_id: str, archive_hash: str) -> bytes:
    """Return the 32-byte commitment anchored on-chain for a session.

    Binds the session id and the archive's SHA-256 so the anchored value is
    reproducible by anyone who knows both::

        commitment = sha256("openclaw-vault:session:{session_id}:sha256:{archive_hash}")

    receipt_anchor stores only this 32-byte value (it is opaque on-chain); a
    verifier reproduces it from ``session_id`` + ``archive_hash`` and checks it
    against the bucket's ordered anchor list.
    """
    preimage = f"openclaw-vault:session:{session_id}:sha256:{archive_hash}"
    return hashlib.sha256(preimage.encode()).digest()


def _build_anchor_single_data(anchor32: bytes, bucket_id: int) -> bytes:
    """Encode a receipt_anchor ``AnchorSingle`` instruction.

    Native program — no Anchor 8-byte discriminator. Layout mirrors
    ``programs/receipt_anchor`` instruction.rs::

        version(1) | flags(1) | anchor32(32) | bucket_id(u64 LE)   # 42 bytes

    The explicit bucket id (``FLAG_HAS_BUCKET_ID``) makes the client-derived PDA
    and the program's stored bucket id agree, avoiding an hour-boundary race.
    """
    if len(anchor32) != 32:
        raise ValueError("anchor must be exactly 32 bytes")
    return (
        bytes([INSTRUCTION_VERSION_V1, FLAG_HAS_BUCKET_ID])
        + anchor32
        + int(bucket_id).to_bytes(8, "little")
    )


def _anchor_receipt(
    anchor32: bytes,
    solana_rpc: str = "https://solana-rpc.publicnode.com",
) -> tuple[str, int]:
    """Fold *anchor32* into the live mainnet ``receipt_anchor`` accumulator.

    Builds the ``AnchorSingle`` instruction for the current hour bucket and
    submits it with the env-supplied fee-payer.  After it lands, the bucket root
    becomes ``sha256(prevRoot || anchor32)``.

    In a production deployment the fee-payer keypair would be loaded from a
    secrets manager.  Here we read it from ``SOLANA_FEE_PAYER_KEY_HEX`` and use
    the ``solders`` / ``solana-py`` stack when available, raising a clear error
    otherwise.

    Returns
    -------
    tuple[str, int]
        The transaction signature and the hour bucket id the anchor was folded
        into (needed, with the bucket's ordered anchor list, to later verify
        inclusion against the live bucket).
    """
    import time

    try:
        from solders.keypair import Keypair  # type: ignore
        from solders.pubkey import Pubkey  # type: ignore
        from solders.transaction import Transaction  # type: ignore
        from solders.instruction import Instruction, AccountMeta  # type: ignore
        from solders.message import Message  # type: ignore
        from solana.rpc.api import Client  # type: ignore
        from solana.rpc.types import TxOpts  # type: ignore
    except ImportError as exc:
        raise ImportError(
            "Solana anchoring requires 'solders' and 'solana': "
            "pip install solders solana"
        ) from exc

    raw_key_hex = os.environ.get("SOLANA_FEE_PAYER_KEY_HEX", "")
    if not raw_key_hex:
        raise EnvironmentError(
            "Set SOLANA_FEE_PAYER_KEY_HEX (64-byte hex) to anchor on Solana."
        )
    payer = Keypair.from_bytes(bytes.fromhex(raw_key_hex))

    # Hour bucket for "now"; passed explicitly so the derived PDA and the
    # program's stored bucket id agree (mirrors agent-reputation's WRITE path).
    bucket_id = int(time.time()) // BUCKET_WINDOW_SECONDS

    program_id = Pubkey.from_string(RECEIPT_ANCHOR_PROGRAM)
    bucket_pda, _bump = Pubkey.find_program_address(
        [b"bucket", bucket_id.to_bytes(8, "little")], program_id
    )
    system_program = Pubkey.from_string("11111111111111111111111111111111")

    ix = Instruction(
        program_id=program_id,
        accounts=[
            # Payer must be a writable signer: it pays fees and funds bucket
            # rent on first use of the hour bucket.
            AccountMeta(pubkey=payer.pubkey(), is_signer=True, is_writable=True),
            AccountMeta(pubkey=bucket_pda, is_signer=False, is_writable=True),
            AccountMeta(pubkey=system_program, is_signer=False, is_writable=False),
        ],
        data=_build_anchor_single_data(anchor32, bucket_id),
    )

    client = Client(solana_rpc)
    recent_blockhash = client.get_latest_blockhash().value.blockhash
    msg = Message.new_with_blockhash([ix], payer.pubkey(), recent_blockhash)
    tx = Transaction([payer], msg, recent_blockhash)
    result = client.send_transaction(tx, opts=TxOpts(skip_preflight=False))
    return str(result.value), bucket_id
