# Threat Model (Concise)

## Assets We Protect

- Original data confidentiality (encrypted vault blobs)
- Data integrity / authenticity of encrypted payloads
- Byte-perfect restoration correctness
- Operator secrets in OpenClaw/TraceVault workspaces (denylist-protected by default)
- Local filesystem boundaries during pack/restore

## Trust Boundaries

- Untrusted inputs:
  - files inside a workspace/run directory
  - `tracevault_index.json` and archive blobs during restore
  - CLI arguments and policy files
- Trusted inputs:
  - `LIQUEFY_SECRET` / explicit encryption secret
  - local filesystem permissions (subject to wrapper checks)

## Main Threats

### 1. Secret Leakage
- Risk: packing `.env`, key files, credentials, `openclaw.json`
- Mitigations:
  - strict denylist defaults
  - phrase-gated risky override
  - JSON/report risk summaries
  - output permission hardening

### 2. Path Traversal / Filesystem Escape
- Risk: malicious restore index writes outside `--out`
- Mitigations:
  - restore target path normalization and boundary checks
  - absolute path / `..` rejection
  - symlink escape rejection for resolved targets
  - pack/openclaw scan skips symlinked files by default

### 3. Crypto Tampering
- Risk: header/ciphertext modification
- Mitigations:
  - AES-GCM AEAD
  - header included as AAD
  - tenant-isolated PBKDF2-derived keys
  - no plaintext audit metadata in blob

### 4. DoS / Parser Abuse
- Risk: malformed blobs, truncated blobs, absurd lengths
- Mitigations:
  - strict blob header parsing
  - `MAX_AUDIT_LEN` cap
  - explicit errors on invalid lengths/magic/KDF/version
  - fuzz/smoke harness for `unseal()` parsing

## Non-Goals (Current)

- Protection against a fully compromised host OS
- Key storage in OS keychain/HSM (future improvement)
- Formal cryptographic proofs
- Full-blown coverage-guided fuzzing across every engine parser (nightly parser smoke exists; deeper fuzzing planned)
