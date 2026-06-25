---
name: Agent Passport
description: On-chain identity for OpenClaw agents — .null name, ETH↔Solana binding, verifiable agent identity without touching private keys
tags: identity, solana, web0, null, reputation, passport
requires_openclaw: ">=2026.6.1"
license: MIT
metadata:
  author: Parad0x-Labs
---

# Agent Passport

Gives an OpenClaw agent a verifiable on-chain identity backed by the web0 stack
on Solana. The agent can prove who it is (or confirm who another agent is) without
ever holding or requesting private keys.

## What it does

- Reads `solanaWallet`, `ethAddress`, and `nullName` from plugin config
- Derives PDAs for the live on-chain identity programs (`dark_secp256k1_auth`,
  `dark_secp256r1_vault`) and checks whether the accounts exist
- Returns the agent's full identity record so it can be injected into conversation
  context, payment routing, or audit trails
- Can also verify a DIFFERENT agent's identity by their wallet or ETH address

## Tools exposed

### `get_agent_passport`

Returns this agent's on-chain identity record:

```json
{
  "null_name": "myagent.null",
  "solana_wallet": "...",
  "eth_address": "0x...",
  "eth_binding_pda": "...",
  "eth_binding_registered": true,
  "webauthn_vault_registered": false,
  "network": "solana-mainnet",
  "programs": {
    "dark_secp256k1_auth": "AqwBbV13AoczhoELwP8oxT3nDqB6MsLWXauNzHkssZ9B",
    "dark_secp256r1_vault": "3hbbtjeSrTVYXq6eRwjeofDe2DCPh3n8cfN6kZcQfewi",
    "receipt_anchor": "6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN"
  }
}
```

No parameters required — reads from plugin config.

### `verify_agent_identity`

Verifies a DIFFERENT agent's on-chain identity. Supply at least one of:
- `target_solana_wallet` — base58 Solana public key
- `target_eth_address` — hex ETH address
- `target_null_name` — .null name (informational; not resolved on-chain yet)

Returns whether the ETH binding and/or Solana wallet PDAs are registered on-chain.

## Trust model

- **Read-only.** Both tools only query on-chain account existence — no transactions,
  no signing, no private key access of any kind.
- **Public RPC only.** Uses `https://solana-rpc.publicnode.com` by default
  (never `api.mainnet-beta.solana.com`). Override with `rpcUrl` in config.
- **No secrets in config.** `solanaWallet` and `ethAddress` are public keys/addresses.
  Private keys belong in the host signer, not here.
- **PDA derivation is deterministic.** Seeds are the same ones the on-chain programs
  use — no external oracle needed.

## Current status

ETH↔Solana binding (`dark_secp256k1_auth`) and WebAuthn P-256 vault
(`dark_secp256r1_vault`) are live on mainnet. .null name resolution wiring comes
with the null-resolver deployment — `nullName` is surfaced from config as-is
until then.
