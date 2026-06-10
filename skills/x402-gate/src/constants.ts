/**
 * Canonical x402 / Solana constants — VENDORED from the DNA x402 SDK so this
 * skill has no unpublished @parad0x_labs/* runtime dependency. These are public
 * addresses and protocol identifiers, not secrets. Kept byte-identical to the
 * paying side (openclaw-x402-pay) so receipt hashes match across the loop.
 */

export type SolanaNetwork = "solana-mainnet" | "solana-devnet";

export const USDC_MINT: Record<SolanaNetwork, string> = {
  "solana-mainnet": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "solana-devnet": "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr",
};

export const USDC_DECIMALS = 6;
export const NULL_TOKEN = "8EeDdvCRmFAzVD4takkBrNNwkeUTUQh4MscRK5Fzpump";
export const X402_VERSION = 1;
export const MEMO_PREFIX = "null-miner-v1";

export const RECEIPT_ANCHOR_PROGRAM_ID: Record<SolanaNetwork, string | null> = {
  "solana-mainnet": "6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN",
  "solana-devnet": null,
};

export const DEFAULT_RPC: Record<SolanaNetwork, string> = {
  "solana-mainnet": "https://api.mainnet-beta.solana.com",
  "solana-devnet": "https://api.devnet.solana.com",
};

export function usdcToAtomic(usdc: number): number {
  return Math.round(usdc * 10 ** USDC_DECIMALS);
}

export function atomicToUsdc(atomic: number): number {
  return atomic / 10 ** USDC_DECIMALS;
}
