# Verify a Vault Signature

A signed vault carries `.liquefy/signature.json`. There are two signing modes,
and they have **different trust properties** — be precise about which one a vault
uses before claiming it is "publicly verifiable."

| Mode | Primitive | Who can verify | Use for |
|---|---|---|---|
| **Ed25519** (default) | Asymmetric digital signature | **Anyone** — needs only the public key, no secret | Anything published / shared / claimed publicly verifiable |
| **HMAC-SHA256** (legacy) | Symmetric MAC | Only a holder of the **secret signing key** | Local / air-gapped integrity checks |

> HMAC is a *symmetric* MAC: verifying it requires the same secret used to sign,
> so a third party **cannot** verify an HMAC-signed vault. Do not describe an
> HMAC-only vault as publicly verifiable. Ed25519 is the default precisely so the
> public claim holds.

## What is signed

The signer builds a **canonical manifest** — the sorted list of
`{path, bytes, sha256}` for each signed artifact — and signs those exact bytes
with the Ed25519 private key. Verification then does two independent checks:

1. **Per-file integrity** — recompute each file's SHA-256 and compare it to the
   manifest. Pinpoints *which* file changed.
2. **Authenticity** — verify the Ed25519 signature over the canonical manifest
   with the public key. If an attacker edits a file *and* rewrites its manifest
   entry to match, the per-file check passes — but the manifest bytes changed and
   they cannot re-sign without the private key, so this check fails.

## Verify with only the public key

The public key is published next to the vault at
`.liquefy/signing_pubkey.ed25519` and embedded in `signature.json`
(`public_key`, hex). No secret is ever needed to verify.

```bash
# Verify using the public key published with the vault
python tools/liquefy_sign.py verify-signature ./vault \
    --public-key ./vault/.liquefy/signing_pubkey.ed25519

# Or paste the public key hex directly
python tools/liquefy_sign.py verify-signature ./vault --public-key <pubkey-hex>
```

Exit code `0` = PASS, `1` = FAIL. Add `--json` for machine-readable output
(`ok`, `manifest_signature_ok`, per-file `checks`, `key_fingerprint`).

### Pin the key to the on-chain anchor (authenticity)

The embedded public key proves *integrity* but not *authenticity* on its own — an
attacker who replaces the vault could also replace the key. To close that gap, the
key's **fingerprint** (`SHA-256(public_key)[:16]`) is anchored on Solana by
`liquefy_vault_anchor.py`. A verifier reads the fingerprint from the immutable
on-chain memo and binds verification to it:

```bash
python tools/liquefy_sign.py verify-signature ./vault \
    --public-key ./vault/.liquefy/signing_pubkey.ed25519 \
    --key-fingerprint <fingerprint-from-the-on-chain-anchor>
```

If the signing key does not match the anchored fingerprint, verification fails —
so an attacker cannot substitute their own key.

## Programmatic use

```python
from common_signing import sign_vault_artifacts, verify_vault_signature

# Sign (Ed25519 is the default)
info = sign_vault_artifacts("./vault")
public_key = info["public_key"]          # publish this
fingerprint = info["key_fingerprint"]    # anchor this on-chain

# Verify with ONLY the public key — no secret required
result = verify_vault_signature("./vault", public_key=public_key,
                                expected_key_fingerprint=fingerprint)
assert result["ok"] is True
```

## Schema versions

`signature.json` carries `schema_version`:

- **`v2`** — Ed25519. Adds `public_key`, `key_fingerprint`, `manifest_sha256`,
  `manifest_signature`. Each `signed_files` entry is `{path, bytes, sha256}`.
- **`v1`** — HMAC-SHA256 (legacy). Each `signed_files` entry additionally carries
  `hmac_sha256`, plus a top-level `key_path`/`key_id`.

`verify_vault_signature()` auto-detects the algorithm from `signature.json`, so
both schema versions are supported by the same verifier.
