/**
 * Canonical x402 / Solana constants — VENDORED from the DNA x402 SDK so this
 * skill has no unpublished @parad0x_labs/* runtime dependency. These are public
 * addresses and protocol identifiers, not secrets.
 *
 * Source of truth: packages/null-miner-sdk/src/x402/index.ts and
 * packages/liquefy-receipts/src/anchor.ts (github.com/Parad0x-Labs/dna-x402).
 */

export type SolanaNetwork = "solana-mainnet" | "solana-devnet";

/** USDC SPL mint per network */
export const USDC_MINT: Record<SolanaNetwork, string> = {
  "solana-mainnet": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "solana-devnet": "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr",
};

/** USDC has 6 decimals */
export const USDC_DECIMALS = 6;

/** $NULL token mint (Token-2022, mainnet) */
export const NULL_TOKEN = "8EeDdvCRmFAzVD4takkBrNNwkeUTUQh4MscRK5Fzpump";

/** x402 protocol version this skill speaks */
export const X402_VERSION = 1;

/** Memo prefix stamped on payments */
export const MEMO_PREFIX = "null-miner-v1";

/** receipt_anchor program (deployed on mainnet) */
export const RECEIPT_ANCHOR_PROGRAM_ID: Record<SolanaNetwork, string | null> = {
  "solana-mainnet": "6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN",
  "solana-devnet": null, // devnet anchor program pending
};

/** Default public RPC endpoints (override in config for a private RPC) */
export const DEFAULT_RPC: Record<SolanaNetwork, string> = {
  "solana-mainnet": "https://api.mainnet-beta.solana.com",
  "solana-devnet": "https://api.devnet.solana.com",
};

/** Memo program (used to stamp the receipt hash on-chain alongside the transfer) */
export const MEMO_PROGRAM_ID = "MemoSq4gq7ZNgPgvNXm4VuMcUiNeAg2gZh2sZjEDLpZ";

/** USDC atomic-unit conversions */
export function usdcToAtomic(usdc: number): number {
  return Math.round(usdc * 10 ** USDC_DECIMALS);
}

export function atomicToUsdc(atomic: number): number {
  return atomic / 10 ** USDC_DECIMALS;
}
