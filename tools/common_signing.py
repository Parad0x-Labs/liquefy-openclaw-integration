#!/usr/bin/env python3
"""
common_signing.py — sign and verify Liquefy vault proof artifacts.

Two signing paths are supported:

* ``Ed25519`` (default) — an *asymmetric* digital signature. The canonical
  manifest of signed files is signed with a private key; verification needs
  ONLY the public key. This is what makes a vault *publicly verifiable*: a
  third party can confirm a signature with nothing but the published public
  key (and, ideally, the key fingerprint anchored on-chain). No secret is ever
  required to verify.

* ``HMAC-SHA256`` (legacy / local-only) — a *symmetric* MAC. Verification
  requires the same secret key used to sign, so it proves integrity only to a
  holder of that secret. Kept for backward compatibility and air-gapped local
  workflows; it is NOT publicly verifiable and must not be claimed as such.

Schema versions in ``signature.json``:
    v1 — HMAC-SHA256 only (legacy). Unchanged, still emitted for HMAC.
    v2 — Ed25519. Adds ``public_key``, ``key_fingerprint``, ``manifest_sha256``
         and ``manifest_signature``. ``verify_vault_signature`` auto-detects the
         algorithm, so both schema versions are supported.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Union


DEFAULT_SIGNED = ("tracevault_index.json", "vault_manifest.json", "run_metadata.json", "AI_SUMMARY.json")

# Algorithm identifiers, as written to / read from signature.json["algorithm"].
ALG_HMAC = "HMAC-SHA256"
ALG_ED25519 = "Ed25519"

# signature.json schema_version values.
SCHEMA_V1 = "v1"  # HMAC-SHA256 (legacy, local-only)
SCHEMA_V2 = "v2"  # Ed25519 (asymmetric, publicly verifiable)

# Ed25519 is the default for anything that claims to be *publicly* verifiable.
DEFAULT_ALGORITHM = ALG_ED25519


# ── Ed25519 backend (cryptography is a pinned dependency; degrade gracefully) ──
try:  # pragma: no cover - exercised indirectly
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _HAVE_ED25519 = True
except Exception:  # pragma: no cover - only when cryptography is absent
    _HAVE_ED25519 = False

    class InvalidSignature(Exception):  # type: ignore[no-redef]
        pass


def _require_ed25519() -> None:
    if not _HAVE_ED25519:
        raise RuntimeError(
            "Ed25519 signing requires the 'cryptography' package "
            "(pip install cryptography). Pass algorithm='HMAC-SHA256' for a "
            "local-only/legacy signature if you cannot install it."
        )


def _normalize_algorithm(algorithm: object, *, allow_unknown: bool = False) -> str:
    a = str(algorithm or "").strip().lower()
    if a in ("ed25519", "ed-25519", "eddsa"):
        return ALG_ED25519
    if a in ("hmac", "hmac-sha256", "hmacsha256", "hmac_sha256"):
        return ALG_HMAC
    if allow_unknown:
        return a or ALG_HMAC
    raise ValueError(
        f"Unsupported signing algorithm {algorithm!r}; use 'Ed25519' or 'HMAC-SHA256'."
    )


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _default_key_path() -> Path:
    """Default path for the HMAC (symmetric) secret key."""
    env = os.environ.get("LIQUEFY_SIGNING_KEY_PATH")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / ".liquefy" / "signing.key").resolve()


def _default_ed25519_key_path() -> Path:
    """Default path for the Ed25519 private key (32-byte raw seed)."""
    env = os.environ.get("LIQUEFY_ED25519_KEY_PATH")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / ".liquefy" / "signing_ed25519.key").resolve()


def _ensure_key(key_path: Optional[Path] = None) -> Path:
    """Ensure an HMAC secret key exists (32 random bytes).

    Treats a 0-byte file as missing so a writability probe that touched the
    path (or a prior interrupted run) can never leave us signing with an empty
    key."""
    kp = Path(key_path).resolve() if key_path else _default_key_path()
    kp.parent.mkdir(parents=True, exist_ok=True)
    if (not kp.exists()) or kp.stat().st_size == 0:
        kp.write_bytes(secrets.token_bytes(32))
        if os.name != "nt":
            try:
                kp.chmod(0o600)
            except OSError:
                pass
    return kp


def _ensure_ed25519_key(key_path: Optional[Path] = None) -> Path:
    """Ensure an Ed25519 private key exists (32-byte raw seed).

    A 0-byte file is treated as missing and (re)generated; a non-empty file of
    the wrong size is left untouched so a user's misplaced key is never silently
    overwritten (``_load_ed25519_private`` raises a clear error for it)."""
    kp = Path(key_path).resolve() if key_path else _default_ed25519_key_path()
    kp.parent.mkdir(parents=True, exist_ok=True)
    if (not kp.exists()) or kp.stat().st_size == 0:
        _require_ed25519()
        priv = Ed25519PrivateKey.generate()
        kp.write_bytes(priv.private_bytes_raw())
        if os.name != "nt":
            try:
                kp.chmod(0o600)
            except OSError:
                pass
    return kp


def _resolve_key_path_for_vault(
    vault_dir: Path,
    key_path: Optional[Path] = None,
    *,
    default_path: Optional[Path] = None,
    local_name: str = "signing.key",
) -> Path:
    if key_path is not None:
        return Path(key_path).resolve()
    primary = default_path if default_path is not None else _default_key_path()
    try:
        primary.parent.mkdir(parents=True, exist_ok=True)
        if primary.exists():
            return primary
        # Probe writability WITHOUT creating the key file itself — touching
        # `primary` here would leave an empty file that _ensure_* would then
        # mistake for an existing key.
        probe = primary.parent / (primary.name + ".probe")
        with open(probe, "wb"):
            pass
        probe.unlink()
        return primary
    except Exception:
        # NOTE: this fallback writes the *private/secret* key under the vault.
        # Only the public key (signing_pubkey.ed25519) and signature.json are
        # meant to be published — never the ``*.key`` file. Secret-file globs
        # in docs/policy.md already exclude ``*.key`` from any vault export.
        local = (Path(vault_dir).resolve() / ".liquefy" / local_name).resolve()
        local.parent.mkdir(parents=True, exist_ok=True)
        return local


def _read_key(key_path: Optional[Path] = None) -> bytes:
    kp = _ensure_key(key_path)
    return kp.read_bytes()


def _load_ed25519_private(key_path: Path) -> "Ed25519PrivateKey":
    _require_ed25519()
    raw = Path(key_path).read_bytes()
    if len(raw) != 32:
        raise ValueError(
            f"Ed25519 private key at {key_path} must be 32 raw bytes, got {len(raw)}."
        )
    return Ed25519PrivateKey.from_private_bytes(raw)


def _coerce_public_key_bytes(public_key: Union[str, bytes, Path]) -> bytes:
    """Accept a 32-byte Ed25519 public key as raw bytes, a hex string, or a
    path to a file containing the hex string."""
    if isinstance(public_key, (bytes, bytearray)):
        return bytes(public_key)
    if isinstance(public_key, Path):
        return bytes.fromhex(public_key.read_text(encoding="utf-8").strip())
    if isinstance(public_key, str):
        s = public_key.strip()
        candidate = Path(s)
        try:
            if candidate.exists() and candidate.is_file():
                s = candidate.read_text(encoding="utf-8").strip()
        except OSError:
            pass
        return bytes.fromhex(s)
    raise TypeError(f"Unsupported public_key type: {type(public_key)!r}")


def _key_fingerprint(public_key_bytes: bytes) -> str:
    """Short, stable fingerprint of an Ed25519 public key.

    First 16 hex chars of SHA-256(public_key). This is what gets bound to the
    on-chain anchor so a verifier can confirm the published public key is the
    one the owner committed to."""
    return hashlib.sha256(public_key_bytes).hexdigest()[:16]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sign_bytes(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _collect_entries(vault_dir: Path, signed_files: Iterable[str]) -> List[Dict[str, object]]:
    entries: List[Dict[str, object]] = []
    for rel in signed_files:
        p = vault_dir / rel
        if not p.exists() or not p.is_file():
            continue
        entries.append({"path": rel, "bytes": p.stat().st_size, "sha256": _sha256_file(p)})
    entries.sort(key=lambda x: str(x["path"]))
    return entries


def _canonical_manifest_bytes(entries: Iterable[Dict[str, object]]) -> bytes:
    """Deterministic byte representation of the signed-file manifest.

    Independent of key ordering / whitespace so signer and verifier always hash
    the exact same bytes. This is what the Ed25519 signature covers."""
    canon = [
        {"path": str(e["path"]), "bytes": int(e["bytes"]), "sha256": str(e["sha256"])}
        for e in sorted(entries, key=lambda x: str(x["path"]))
    ]
    return json.dumps(canon, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _write_signature(vault_dir: Path, payload: Dict[str, object], *, private: bool) -> Path:
    sig_dir = vault_dir / ".liquefy"
    sig_dir.mkdir(parents=True, exist_ok=True)
    sig_path = sig_dir / "signature.json"
    sig_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    if os.name != "nt":
        try:
            # HMAC signatures are local artifacts (0600). Ed25519 signatures are
            # meant to be published, so leave them world-readable (0644).
            sig_path.chmod(0o600 if private else 0o644)
        except OSError:
            pass
    return sig_path


# ── HMAC-SHA256 (legacy, local-only) ──────────────────────────────────────


def _sign_hmac(vault_dir: Path, *, key_path: Optional[Path], signed_files: Iterable[str]) -> Dict[str, object]:
    key_file = _resolve_key_path_for_vault(vault_dir, key_path)
    key = _read_key(key_file)
    key_id = hashlib.sha256(key).hexdigest()[:16]

    entries: List[Dict[str, object]] = []
    for rel in signed_files:
        p = vault_dir / rel
        if not p.exists() or not p.is_file():
            continue
        raw = p.read_bytes()
        entries.append(
            {
                "path": rel,
                "bytes": len(raw),
                "sha256": _sha256_file(p),
                "hmac_sha256": _sign_bytes(key, raw),
            }
        )

    entries.sort(key=lambda x: str(x["path"]))
    payload = {
        "schema": "liquefy.signature",
        "schema_version": SCHEMA_V1,
        "generated_at_utc": _utc_now(),
        "algorithm": ALG_HMAC,
        "key_id": key_id,
        "key_path": str(key_file),
        "signed_files": entries,
    }
    sig_path = _write_signature(vault_dir, payload, private=True)
    return {"signature_path": str(sig_path), **payload}


def _verify_hmac(vault_dir: Path, sig: Dict[str, object], sig_path: Path, *, key_path: Optional[Path]) -> Dict[str, object]:
    resolved_key_path = None
    if key_path is not None:
        resolved_key_path = Path(key_path).resolve()
    else:
        sig_key = sig.get("key_path")
        if isinstance(sig_key, str) and sig_key.strip():
            resolved_key_path = Path(sig_key).expanduser().resolve()
    key = _read_key(resolved_key_path)
    checks: List[Dict[str, object]] = []
    ok = True
    for row in sig.get("signed_files", []):
        rel = str(row.get("path", ""))
        p = vault_dir / rel
        exists = p.exists() and p.is_file()
        check = {"path": rel, "exists": exists, "ok": False}
        if not exists:
            ok = False
            checks.append(check)
            continue
        raw = p.read_bytes()
        sha = _sha256_file(p)
        mac = _sign_bytes(key, raw)
        check["sha256_ok"] = sha == str(row.get("sha256", ""))
        check["signature_ok"] = hmac.compare_digest(mac, str(row.get("hmac_sha256", "")))
        check["ok"] = bool(check["sha256_ok"] and check["signature_ok"])
        if not check["ok"]:
            ok = False
        checks.append(check)
    return {
        "ok": ok,
        "algorithm": sig.get("algorithm"),
        "key_id": sig.get("key_id"),
        "publicly_verifiable": False,
        "signature_path": str(sig_path),
        "checks": checks,
    }


# ── Ed25519 (asymmetric, publicly verifiable) ─────────────────────────────


def _sign_ed25519(vault_dir: Path, *, key_path: Optional[Path], signed_files: Iterable[str]) -> Dict[str, object]:
    _require_ed25519()
    key_file = _resolve_key_path_for_vault(
        vault_dir,
        key_path,
        default_path=_default_ed25519_key_path(),
        local_name="signing_ed25519.key",
    )
    key_file = _ensure_ed25519_key(key_file)
    priv = _load_ed25519_private(key_file)
    pub_bytes = priv.public_key().public_bytes_raw()
    pub_hex = pub_bytes.hex()
    key_fp = _key_fingerprint(pub_bytes)

    entries = _collect_entries(vault_dir, signed_files)
    manifest = _canonical_manifest_bytes(entries)
    manifest_sha256 = hashlib.sha256(manifest).hexdigest()
    manifest_signature = priv.sign(manifest).hex()

    payload = {
        "schema": "liquefy.signature",
        "schema_version": SCHEMA_V2,
        "generated_at_utc": _utc_now(),
        "algorithm": ALG_ED25519,
        # key_id retained for back-compat with v1 consumers; equals the
        # fingerprint of the public key.
        "key_id": key_fp,
        "key_fingerprint": key_fp,
        "public_key": pub_hex,
        "public_key_encoding": "ed25519-raw-hex",
        "manifest_sha256": manifest_sha256,
        "manifest_signature": manifest_signature,
        "signed_files": entries,
    }
    sig_path = _write_signature(vault_dir, payload, private=False)

    # Publish the PUBLIC key next to the vault so anyone can verify without a secret.
    pub_path = sig_path.parent / "signing_pubkey.ed25519"
    pub_path.write_text(pub_hex + "\n", encoding="utf-8")
    if os.name != "nt":
        try:
            pub_path.chmod(0o644)
        except OSError:
            pass

    return {"signature_path": str(sig_path), "public_key_path": str(pub_path), **payload}


def _verify_ed25519(
    vault_dir: Path,
    sig: Dict[str, object],
    sig_path: Path,
    *,
    public_key: Optional[Union[str, bytes, Path]] = None,
    expected_key_fingerprint: Optional[str] = None,
) -> Dict[str, object]:
    if not _HAVE_ED25519:
        return {"ok": False, "error": "ED25519_UNAVAILABLE: pip install cryptography", "checks": []}

    # Resolve the public key. Priority:
    #   1. caller-supplied trusted key (best — fetched out-of-band / on-chain)
    #   2. public key embedded in signature.json (integrity; pair with the
    #      anchored fingerprint for authenticity)
    pub_source = "embedded"
    pub_bytes: Optional[bytes] = None
    if public_key is not None:
        try:
            pub_bytes = _coerce_public_key_bytes(public_key)
        except (ValueError, OSError, TypeError) as exc:
            return {"ok": False, "error": f"PUBLIC_KEY_DECODE_ERROR: {exc}", "checks": []}
        pub_source = "provided"
    else:
        emb = sig.get("public_key")
        if isinstance(emb, str) and emb.strip():
            try:
                pub_bytes = bytes.fromhex(emb.strip())
            except ValueError:
                return {"ok": False, "error": "PUBLIC_KEY_DECODE_ERROR", "checks": []}

    if not pub_bytes or len(pub_bytes) != 32:
        return {"ok": False, "error": "PUBLIC_KEY_MISSING_OR_INVALID", "checks": []}

    try:
        pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    except Exception as exc:  # noqa: BLE001 - surface as structured error
        return {"ok": False, "error": f"PUBLIC_KEY_INVALID: {exc}", "checks": []}

    computed_fp = _key_fingerprint(pub_bytes)

    # The fingerprint recorded inside signature.json must match the key it ships.
    sig_fp = sig.get("key_fingerprint")
    if isinstance(sig_fp, str) and sig_fp.strip():
        sig_fp_ok = sig_fp.strip().lower() == computed_fp
    else:
        sig_fp_ok = True

    # Optional binding to an externally trusted fingerprint (e.g. the value
    # anchored on Solana). When supplied, the key MUST match it.
    fingerprint_matches_expected: Optional[bool] = None
    if expected_key_fingerprint is not None:
        fingerprint_matches_expected = (
            str(expected_key_fingerprint).strip().lower() == computed_fp
        )

    # Per-file integrity: recompute each file's SHA-256 and compare to the
    # manifest. Pinpoints which file changed.
    entries = sig.get("signed_files", []) or []
    checks: List[Dict[str, object]] = []
    files_ok = True
    for row in entries:
        rel = str(row.get("path", ""))
        p = vault_dir / rel
        exists = p.exists() and p.is_file()
        check = {"path": rel, "exists": exists, "ok": False}
        if not exists:
            files_ok = False
            checks.append(check)
            continue
        sha = _sha256_file(p)
        check["sha256_ok"] = sha == str(row.get("sha256", ""))
        if not check["sha256_ok"]:
            files_ok = False
        check["ok"] = bool(check["sha256_ok"])
        checks.append(check)

    # Authenticity: verify the Ed25519 signature over the canonical manifest.
    # If an attacker edits a file AND rewrites its manifest entry to match, the
    # per-file SHA check passes but the manifest bytes change — and they cannot
    # re-sign without the private key, so this verification fails.
    manifest = _canonical_manifest_bytes(entries)
    computed_manifest_sha = hashlib.sha256(manifest).hexdigest()
    stored_manifest_sha = str(sig.get("manifest_sha256", ""))
    manifest_sha_ok = (computed_manifest_sha == stored_manifest_sha) if stored_manifest_sha else True

    signature_ok = False
    try:
        pub.verify(bytes.fromhex(str(sig.get("manifest_signature", ""))), manifest)
        signature_ok = True
    except (InvalidSignature, ValueError):
        signature_ok = False

    # Fold the manifest-signature verdict into each per-file check so consumers
    # that only inspect ``checks`` still see a failure when the signature breaks.
    for c in checks:
        c["signature_ok"] = signature_ok
        c["ok"] = bool(c.get("ok") and signature_ok)

    overall = bool(
        files_ok
        and signature_ok
        and manifest_sha_ok
        and sig_fp_ok
        and (fingerprint_matches_expected is not False)
    )

    return {
        "ok": overall,
        "algorithm": ALG_ED25519,
        "key_id": sig.get("key_id", computed_fp),
        "key_fingerprint": computed_fp,
        "key_fingerprint_matches_signature": sig_fp_ok,
        "key_fingerprint_matches_expected": fingerprint_matches_expected,
        "public_key": pub_bytes.hex(),
        "public_key_source": pub_source,
        "publicly_verifiable": True,
        "manifest_signature_ok": signature_ok,
        "manifest_sha256_ok": manifest_sha_ok,
        "signature_path": str(sig_path),
        "checks": checks,
    }


# ── Public API ─────────────────────────────────────────────────────────────


def sign_vault_artifacts(
    vault_dir: Path,
    *,
    key_path: Optional[Path] = None,
    signed_files: Iterable[str] = DEFAULT_SIGNED,
    algorithm: str = DEFAULT_ALGORITHM,
) -> Dict[str, object]:
    """Sign the vault's proof artifacts and write ``.liquefy/signature.json``.

    algorithm:
        ``"Ed25519"`` (default) — asymmetric, publicly verifiable. Also writes
            ``.liquefy/signing_pubkey.ed25519`` (the public key) for third parties.
        ``"HMAC-SHA256"`` — legacy symmetric MAC, verifiable only by a holder of
            the secret key. Use for local/air-gapped integrity only.
    """
    vault_dir = Path(vault_dir).resolve()
    alg = _normalize_algorithm(algorithm)
    if alg == ALG_ED25519:
        return _sign_ed25519(vault_dir, key_path=key_path, signed_files=signed_files)
    return _sign_hmac(vault_dir, key_path=key_path, signed_files=signed_files)


def verify_vault_signature(
    vault_dir: Path,
    *,
    key_path: Optional[Path] = None,
    public_key: Optional[Union[str, bytes, Path]] = None,
    expected_key_fingerprint: Optional[str] = None,
) -> Dict[str, object]:
    """Verify ``.liquefy/signature.json``, auto-detecting the algorithm.

    Ed25519 (v2): verification uses ONLY a public key — never a secret.
        public_key: a trusted Ed25519 public key (hex, raw bytes, or a path to a
            file containing the hex). If omitted, the public key embedded in
            signature.json is used (good for local integrity; pair it with
            ``expected_key_fingerprint`` for authenticity).
        expected_key_fingerprint: bind verification to a fingerprint obtained
            out-of-band, e.g. the one anchored on Solana. Verification fails if
            the signing key does not match it.

    HMAC-SHA256 (v1): legacy path. ``key_path`` (or the path recorded in the
        signature) supplies the secret key. Not publicly verifiable.
    """
    vault_dir = Path(vault_dir).resolve()
    sig_path = vault_dir / ".liquefy" / "signature.json"
    if not sig_path.exists():
        return {"ok": False, "error": "SIGNATURE_NOT_FOUND", "checks": []}
    try:
        sig = json.loads(sig_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - structured error for callers
        return {"ok": False, "error": f"SIGNATURE_PARSE_ERROR: {exc}", "checks": []}

    algorithm = _normalize_algorithm(sig.get("algorithm", ALG_HMAC), allow_unknown=True)
    if algorithm == ALG_ED25519:
        return _verify_ed25519(
            vault_dir,
            sig,
            sig_path,
            public_key=public_key,
            expected_key_fingerprint=expected_key_fingerprint,
        )
    if algorithm == ALG_HMAC:
        return _verify_hmac(vault_dir, sig, sig_path, key_path=key_path)
    return {
        "ok": False,
        "error": f"UNSUPPORTED_ALGORITHM: {sig.get('algorithm')!r}",
        "checks": [],
    }
