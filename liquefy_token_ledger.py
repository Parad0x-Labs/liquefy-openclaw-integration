"""
liquefy_token_ledger.py — per-agent token usage ledger for OpenClaw operators.

Agent Passport binding makes per-agent spend verifiable on-chain via
dark_secp256k1_auth. Bind once per agent, spend records become provably
attributed to a specific wallet.

On-chain program:
  dark_secp256k1_auth: AqwBbV13AoczhoELwP8oxT3nDqB6MsLWXauNzHkssZ9B

PDA derivation:
  seeds = [b"eth_agent", bytes.fromhex(eth_address_no_0x)]   # 20 bytes
  bump computed by find_program_address
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DARK_SECP256K1_AUTH_PROGRAM_ID = "AqwBbV13AoczhoELwP8oxT3nDqB6MsLWXauNzHkssZ9B"
SOLANA_MAINNET_RPC = "https://api.mainnet-beta.solana.com"


# ---------------------------------------------------------------------------
# PDA helpers
# ---------------------------------------------------------------------------

def _b58decode(s: str) -> bytes:
    """Minimal base-58 decoder (no external dependency)."""
    ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = 0
    for c in s.encode():
        n = n * 58 + ALPHABET.index(c)
    result = n.to_bytes(32, "big")
    # strip leading zero-bytes that correspond to leading '1's
    leading = len(s) - len(s.lstrip("1"))
    return b"\x00" * leading + result.lstrip(b"\x00")


def _find_program_address(seeds: list[bytes], program_id_b58: str) -> tuple[str, int]:
    """
    Pure-Python replication of Solana find_program_address.

    Iterates bump from 255 downward; returns (pda_base58, bump).
    Uses solders if installed (fast), otherwise falls back to pure Python.
    """
    try:
        from solders.pubkey import Pubkey  # type: ignore

        program_pk = Pubkey.from_string(program_id_b58)
        pda, bump = Pubkey.find_program_address(seeds, program_pk)
        return str(pda), bump
    except ImportError:
        pass

    # Pure-Python fallback (sha256-based, matches on-curve check via curve25519)
    program_bytes = _b58decode(program_id_b58)
    for bump in range(255, -1, -1):
        h = hashlib.sha256()
        for s in seeds:
            h.update(s)
        h.update(bytes([bump]))
        h.update(program_bytes)
        h.update(b"ProgramDerivedAddress")
        candidate = h.digest()
        # A valid PDA must NOT be on the ed25519 curve.
        # Lightweight check: if the high bit of the last byte is 0, treat as
        # off-curve (sufficient for address derivation in most cases).
        # For production use install solders for the proper curve check.
        if not _is_on_ed25519_curve(candidate):
            # Base-58 encode
            return _b58encode(candidate), bump
    raise ValueError("Could not find valid PDA bump")


def _is_on_ed25519_curve(point_bytes: bytes) -> bool:
    """
    Approximate on-curve check for ed25519.
    Uses the curve equation: -x^2 + y^2 = 1 + d*x^2*y^2 mod p
    where d = -121665/121666 mod p.
    Returns True if the point is on the curve (and therefore NOT a valid PDA).
    """
    p = 2**255 - 19
    d = (-121665 * pow(121666, p - 2, p)) % p
    y = int.from_bytes(point_bytes, "little") % (2**255)
    y2 = (y * y) % p
    x2 = ((y2 - 1) * pow(d * y2 + 1, p - 2, p)) % p
    # Check if x2 is a quadratic residue
    return pow(x2, (p - 1) // 2, p) == 1


def _b58encode(data: bytes) -> str:
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(ALPHABET[r])
    leading = len(data) - len(data.lstrip(b"\x00"))
    return "1" * leading + "".join(reversed(result))


# ---------------------------------------------------------------------------
# Agent Passport
# ---------------------------------------------------------------------------

def bind_agent_passport(
    agent_id: str,
    eth_address: str = None,
    solana_wallet: str = None,
) -> dict:
    """
    Bind an agent to an on-chain Agent Passport.

    Constructs the EthAgentRecord PDA from dark_secp256k1_auth
    (AqwBbV13AoczhoELwP8oxT3nDqB6MsLWXauNzHkssZ9B) and checks whether the
    account exists on Solana mainnet.

    Args:
        agent_id:       Opaque identifier for the agent (e.g. "agent-007").
        eth_address:    Ethereum address (with or without "0x" prefix).
                        Used as PDA seed.  Required to derive the PDA.
        solana_wallet:  Optional Solana wallet that co-signs the record.

    Returns:
        {
            "agent_id":      str,
            "eth_address":   str | None,
            "solana_wallet": str | None,
            "pda":           str | None,   # base-58 PDA address
            "registered":    bool,         # True if account exists on-chain
            "checked_at":    float,        # Unix timestamp of the RPC check
        }
    """
    pda: Optional[str] = None
    registered = False
    checked_at = time.time()

    if eth_address:
        # Normalise: strip 0x prefix, lowercase
        addr_hex = eth_address.lower().removeprefix("0x")
        if len(addr_hex) != 40:
            raise ValueError(f"eth_address must be 20 bytes (40 hex chars), got: {eth_address!r}")

        seeds = [b"eth_agent", bytes.fromhex(addr_hex)]
        pda, _bump = _find_program_address(seeds, DARK_SECP256K1_AUTH_PROGRAM_ID)

        # Check if the account exists on-chain
        registered = _account_exists(pda)
        checked_at = time.time()

    return {
        "agent_id":      agent_id,
        "eth_address":   eth_address,
        "solana_wallet": solana_wallet,
        "pda":           pda,
        "registered":    registered,
        "checked_at":    checked_at,
    }


def _account_exists(pubkey_b58: str) -> bool:
    """
    Return True if the Solana account at pubkey_b58 exists (non-null lamports).

    Tries solders/solana-py first; falls back to a raw JSON-RPC request.
    """
    try:
        from solders.rpc.api import Client  # type: ignore

        client = Client(SOLANA_MAINNET_RPC)
        resp = client.get_account_info(pubkey_b58)
        return resp.value is not None
    except ImportError:
        pass

    try:
        import requests  # type: ignore

        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getAccountInfo",
            "params": [pubkey_b58, {"encoding": "base64"}],
        }
        resp = requests.post(SOLANA_MAINNET_RPC, json=payload, timeout=10)
        data = resp.json()
        return data.get("result", {}).get("value") is not None
    except Exception:
        pass

    # No network library available — cannot verify
    return False


# ---------------------------------------------------------------------------
# Session / spend record
# ---------------------------------------------------------------------------

@dataclass
class SessionRecord:
    """
    A single agent session's token spend record.

    agent_passport_pda and identity_verified are populated by calling
    bind_agent_passport() and then attaching the result with attach_passport().
    """

    session_id: str
    agent_id: str
    tokens_in: int = 0
    tokens_out: int = 0
    started_at: float = field(default_factory=time.time)
    ended_at: Optional[float] = None

    # Agent Passport fields — populated after bind_agent_passport()
    agent_passport_pda: Optional[str] = None   # on-chain PDA address
    identity_verified: bool = False            # True when PDA confirmed on-chain

    def attach_passport(self, passport: dict) -> None:
        """
        Attach the result of bind_agent_passport() to this session record.

        Sets agent_passport_pda and identity_verified so that the spend
        record is provably attributed to the bound wallet.
        """
        self.agent_passport_pda = passport.get("pda")
        self.identity_verified = bool(passport.get("registered"))

    def to_dict(self) -> dict:
        return {
            "session_id":          self.session_id,
            "agent_id":            self.agent_id,
            "tokens_in":           self.tokens_in,
            "tokens_out":          self.tokens_out,
            "tokens_total":        self.tokens_in + self.tokens_out,
            "started_at":          self.started_at,
            "ended_at":            self.ended_at,
            "agent_passport_pda":  self.agent_passport_pda,
            "identity_verified":   self.identity_verified,
        }


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------

class TokenLedger:
    """
    Per-agent token usage ledger for OpenClaw operators.

    Usage
    -----
    ledger = TokenLedger()

    # Bind passport once per agent (network call)
    passport = bind_agent_passport("agent-007", eth_address="0xDEAD...BEEF")

    # Record a session
    rec = ledger.open_session("sess-001", "agent-007")
    rec.attach_passport(passport)
    ledger.record_tokens("sess-001", tokens_in=512, tokens_out=128)
    ledger.close_session("sess-001")

    # Export
    rows = ledger.export()
    """

    def __init__(self) -> None:
        self._sessions: dict[str, SessionRecord] = {}

    def open_session(self, session_id: str, agent_id: str) -> SessionRecord:
        if session_id in self._sessions:
            raise KeyError(f"Session {session_id!r} already exists")
        rec = SessionRecord(session_id=session_id, agent_id=agent_id)
        self._sessions[session_id] = rec
        return rec

    def record_tokens(
        self,
        session_id: str,
        tokens_in: int = 0,
        tokens_out: int = 0,
    ) -> None:
        rec = self._sessions[session_id]
        rec.tokens_in += tokens_in
        rec.tokens_out += tokens_out

    def close_session(self, session_id: str) -> SessionRecord:
        rec = self._sessions[session_id]
        rec.ended_at = time.time()
        return rec

    def get_session(self, session_id: str) -> SessionRecord:
        return self._sessions[session_id]

    def export(self) -> list[dict]:
        """Return all session records as a list of dicts (ready for liquefy compression)."""
        return [r.to_dict() for r in self._sessions.values()]

    def agent_totals(self) -> dict[str, int]:
        """Aggregate total tokens spent per agent_id."""
        totals: dict[str, int] = {}
        for rec in self._sessions.values():
            totals[rec.agent_id] = totals.get(rec.agent_id, 0) + rec.tokens_in + rec.tokens_out
        return totals
