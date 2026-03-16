# DNA Payment Bridge — Liquefy Plugin

Bridges [DNA x402](https://github.com/Parad0x-Labs/dna-x402) micropayment audit logs and signed receipts into Liquefy vaults as verifiable proof artifacts.

This plugin is not the DNA x402 payment rail itself. It consumes exported audit
events and signed receipts from a running DNA server and archives them into
Liquefy. Protocol concerns like off-chain balance signatures, dispute/slashing
logic, challenge periods, and Solana RPC transaction sequencing belong in the
upstream `dna-x402` codebase, not in this bridge plugin.

## What This Does

- Exports DNA payment audit events as Liquefy telemetry (NDJSON)
- Converts signed payment receipts into proof artifacts
- Carries DNA Guard events for spend blocks, replay alerts, validation failures, disputes, and receipt verification state
- Packs everything into `.null` vaults with bit-perfect verification

## What This Does Not Do

- Does not settle or net payments itself
- Does not maintain off-chain state channels
- Does not implement challenge/slashing logic
- Does not broadcast or bundle Solana transactions
- Does not validate that the upstream DNA service's protocol model is sound

## Quick Start

### Export DNA Payments to Vault

```bash
# Quick health / audit summary
python plugins/dna-payment/dna_bridge.py status --server http://localhost:8080

# From the DNA x402 project:
curl -s http://localhost:8080/admin/audit/export | \
  npx tsx src/bridge/liquefy/cli.ts --stdin --out ./vault-staging/payments

# Pack with Liquefy:
python tools/tracevault_pack.py ./vault-staging/payments --org dna --out ./vault/dna-payments --json

# Or use the Python bridge directly from this repo:
python plugins/dna-payment/dna_bridge.py archive \
  --server http://localhost:8080 \
  --out ./vault-staging/dna-export \
  --vault-out ./vault/dna-payments
```

### Python Integration

```python
#!/usr/bin/env python3
"""Export DNA payment data and pack into a Liquefy vault."""
import subprocess
import json
import sys
import os
from pathlib import Path

DNA_SERVER = os.getenv("DNA_SERVER", "http://localhost:8080")
LIQUEFY_ROOT = os.getenv("LIQUEFY_ROOT", str(Path(__file__).parent.parent.parent))
VAULT_OUT = os.getenv("VAULT_OUT", "./vault/dna-payments")
STAGING = "./vault-staging/dna-export"

def export_dna():
    """Fetch audit logs from DNA server and convert to Liquefy format."""
    import urllib.request
    
    # Fetch audit export
    req = urllib.request.Request(f"{DNA_SERVER}/admin/audit/export")
    with urllib.request.urlopen(req) as resp:
        audit_ndjson = resp.read().decode()
    
    # Write to staging
    os.makedirs(STAGING, exist_ok=True)
    with open(f"{STAGING}/telemetry.jsonl", "w") as f:
        for line in audit_ndjson.strip().split("\n"):
            if line.strip():
                entry = json.loads(line)
                record = {
                    "_schema": "liquefy.dna.telemetry.v1",
                    "_source": "dna-x402",
                    "ts": entry.get("ts", ""),
                    "event_type": entry.get("kind", "unknown"),
                    "trace_id": entry.get("traceId"),
                    "severity": "info",
                    "domain": "payment",
                    "tags": [f"kind:{entry.get('kind', '')}"],
                    "fields": entry,
                }
                f.write(json.dumps(record) + "\n")
    
    print(f"Exported to {STAGING}/telemetry.jsonl")
    return STAGING

def pack_vault(staging_dir):
    """Pack staging directory into a .null vault."""
    cmd = [
        sys.executable,
        f"{LIQUEFY_ROOT}/tools/tracevault_pack.py",
        staging_dir,
        "--org", "dna",
        "--out", VAULT_OUT,
        "--json",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        print(f"Vault packed: {VAULT_OUT}")
        return json.loads(result.stdout)
    else:
        print(f"Pack failed: {result.stderr}", file=sys.stderr)
        return None

if __name__ == "__main__":
    staging = export_dna()
    pack_vault(staging)
```

## Output Structure

```
vault-staging/dna-export/
├── manifest.json          # Run metadata (payments, mints, totals)
├── telemetry.jsonl        # Audit events in Liquefy telemetry format
├── receipts.jsonl         # Proof artifacts (NDJSON bulk)
└── proofs/
    ├── <receiptId-1>.json # Individual signed receipt
    ├── <receiptId-2>.json
    └── ...
```

## Schemas

### Telemetry Record (`liquefy.dna.telemetry.v1`)

```json
{
  "_schema": "liquefy.dna.telemetry.v1",
  "_source": "dna-x402",
  "ts": "2026-02-25T14:10:34.796Z",
  "event_type": "PAYMENT_VERIFIED",
  "trace_id": null,
  "severity": "info",
  "domain": "payment",
  "tags": ["kind:PAYMENT_VERIFIED", "settlement:netting"],
  "fields": { "amount_atomic": "1000", "mint": "USDC" }
}
```

DNA Guard examples:
- `GUARD_SPEND_BLOCKED` -> `payment` domain, `warn` severity
- `GUARD_REPLAY_ALERT` -> `receipt` domain, `warn` severity
- `GUARD_VALIDATION_FAILED` / `GUARD_DISPUTE_TAGGED` -> `receipt` domain
- `GUARD_RECEIPT_VERIFIED` / `GUARD_RECEIPT_INVALID` -> receipt verification trail
- `GUARD_FAIL_OPEN` / `GUARD_RUNTIME_ERROR` -> `system` domain

### Proof Artifact (`liquefy.dna.proof.v1`)

```json
{
  "_schema": "liquefy.dna.proof.v1",
  "_source": "dna-x402",
  "artifact_type": "signed_receipt",
  "receipt_id": "abc-123",
  "chain_position": 1,
  "ts": "2026-02-25T14:10:34.796Z",
  "integrity": {
    "signer_pubkey": "...",
    "signature": "...",
    "receipt_hash": "...",
    "prev_hash": "..."
  },
  "payment": {
    "settlement": "transfer",
    "amount_atomic": "5000",
    "tx_signature": "5YkC97Lz..."
  }
}
```

## Live Sidecar Mode

For real-time archival, DNA's server can stream events to a Liquefy vault directory as they happen:

```typescript
import { LiquefySidecar } from "dna-x402";

const sidecar = new LiquefySidecar({
  outDir: "./vault-live",
  cluster: "mainnet-beta",
});
sidecar.attachAuditLogger(auditLogger);
sidecar.startPeriodicFlush(); // flushes every 5 minutes
```
