---
name: parad0x-mcp-server
description: MCP server exposing the full Parad0x Labs stack — x402 payment quotes, on-chain receipt anchoring on Solana mainnet-beta, Dark Passport lookup, outcome receipts, receipt compression, and live program discovery. Runs over stdio, works with Claude Desktop and any MCP client.
license: MIT
metadata:
  author: Parad0x-Labs
---

# Parad0x Labs MCP Server

Exposes the Parad0x Labs web0 stack as MCP tools. Works with Claude Desktop,
Cursor, Windsurf, and any MCP-compatible agent runtime.

## When to use

- Your agent needs to quote, pay, or verify an x402-gated API call.
- You want to anchor a receipt hash on Solana mainnet-beta.
- You need to look up whether a wallet or ETH address has a verified Dark Passport.
- You want to compress a batch of receipts or check live program addresses.

## Tools

| Tool | Does |
|---|---|
| `x402_get_quote` | Get a payment quote for an x402-gated API endpoint |
| `anchor_receipt` | Anchor a 32-byte receipt hash on Solana mainnet-beta via `receipt_anchor` |
| `lookup_passport` | Check if an ETH address or Solana wallet has a verified Dark Passport binding |
| `build_outcome_receipt` | Build a signed outcome receipt with PnL, accuracy, or delivery result |
| `compress_receipts` | Compress a batch of receipts (Liquefy format) |
| `get_stack_status` | Discover Parad0x Labs mainnet-beta program addresses |

## Install

```bash
npm install -g @parad0x_labs/mcp-server
```

Or use directly without installing:

```bash
npx @parad0x_labs/mcp-server
```

## Claude Desktop config

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "parad0x": {
      "command": "npx",
      "args": ["-y", "@parad0x_labs/mcp-server"],
      "env": {
        "SOLANA_RPC_URL": "https://solana-rpc.publicnode.com"
      }
    }
  }
}
```

## Source

github.com/Parad0x-Labs/openclaw-skills/tree/main/skills/mcp-server
