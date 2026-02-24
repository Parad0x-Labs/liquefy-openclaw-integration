# Verify Downloads

Liquefy release binaries are published with a `SHA256SUMS.txt` file in GitHub Releases.

Use it to verify that the file you downloaded matches the release artifact exactly.

## 1) Download the binary and `SHA256SUMS.txt`

Download from the official repository releases page:

- `Parad0x-Labs/liquefy-openclaw-integration`

Make sure both files are in the same directory:

- `liquefy-<platform>`
- `SHA256SUMS.txt`

## 2) Verify the checksum

### macOS / Linux (`shasum`)

```bash
shasum -a 256 liquefy-macos-universal2
grep "liquefy-macos-universal2" SHA256SUMS.txt
```

The hash values must match exactly.

### Linux (`sha256sum`)

```bash
sha256sum liquefy-linux-x64
grep "liquefy-linux-x64" SHA256SUMS.txt
```

### Windows (PowerShell)

```powershell
Get-FileHash .\liquefy-windows-x64.exe -Algorithm SHA256
Select-String "liquefy-windows-x64.exe" .\SHA256SUMS.txt
```

## 3) If the checksum does not match

- Do not run the file.
- Delete the download.
- Re-download from the official GitHub release page.

## What this verifies (and what it does not)

- `SHA256SUMS.txt` verifies file integrity (the binary was not corrupted/modified after release packaging).
- It does not by itself prove publisher identity.

For now, use:

- the official GitHub repo/releases page
- checksums from the same release

Future hardening can add signed tags and signed release artifacts.
