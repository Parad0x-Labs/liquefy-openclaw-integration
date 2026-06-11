# @parad0x_labs/mcp-server

Exposes the Parad0x Labs stack as MCP tools. Works with Claude Desktop, Cursor, Windsurf, and any MCP-compatible agent runtime.

## Tools

| Tool | Description |
|---|---|
| `x402_get_quote` | Get a payment quote for an x402-gated API endpoint |
| `anchor_receipt` | Anchor a 32-byte receipt hash on Solana mainnet via `receipt_anchor` |
| `lookup_passport` | Check if an ETH address or Solana wallet has a verified Dark Passport binding |
| `build_outcome_receipt` | Build a signed outcome receipt with PnL, accuracy, or delivery result |
| `compress_receipts` | Compress a batch of receipts (Liquefy format, 83x typical ratio) |
| `get_stack_status` | Discover all live Parad0x Labs mainnet program addresses |

## Install

```bash
npm install -g @parad0x_labs/mcp-server
```

Or use directly via `npx` without installing.

## Claude Desktop config

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "parad0x": {
      "command": "npx",
      "args": ["-y", "@parad0x_labs/mcp-server"],
      "env": {
        "SOLANA_RPC_URL": "https://api.mainnet-beta.solana.com",
        "SOLANA_KEYPAIR": "[1,2,3,...]"
      }
    }
  }
}
```

`SOLANA_KEYPAIR` is a JSON array of 64 bytes (the standard Solana keypair format output by `solana-keygen`). Without it, `anchor_receipt` runs in dry-run mode and returns a mock transaction for format inspection.

## Cursor / Windsurf config

Add to `.cursor/mcp.json` or `.windsurf/mcp.json` in your project root:

```json
{
  "mcpServers": {
    "parad0x": {
      "command": "npx",
      "args": ["-y", "@parad0x_labs/mcp-server"],
      "env": {
        "SOLANA_RPC_URL": "https://api.mainnet-beta.solana.com"
      }
    }
  }
}
```

## Build from source

```bash
cd packages/mcp-server
npm install
npm run build
npm start
```

## Env vars

| Variable | Default | Description |
|---|---|---|
| `SOLANA_RPC_URL` | `https://api.mainnet-beta.solana.com` | Solana RPC endpoint |
| `SOLANA_KEYPAIR` | _(unset)_ | JSON array of 64 bytes — enables real transaction submission |

## Programs (mainnet)

| Program | Address |
|---|---|
| receipt_anchor | `6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN` |
| dark_secp256r1_vault | `3hbbtjeSrTVYXq6eRwjeofDe2DCPh3n8cfN6kZcQfewi` |
| dark_secp256k1_auth | `AqwBbV13AoczhoELwP8oxT3nDqB6MsLWXauNzHkssZ9B` |
| dark_bn254_gate | `GCptvBYF8S6eVYoh15B7WAESc54FUHCpN1Ui6aHeQYZd` |
| dark_semaphore | `Ev7HEFhhKTXk6kS2Y6ssbUcK9C7E6yZ589jJNjUrQV5p` |
| null_token | `8EeDdvCRmFAzVD4takkBrNNwkeUTUQh4MscRK5Fzpump` |
