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

/** Default public RPC endpoints (override in config for a private RPC) */
export const DEFAULT_RPC: Record<SolanaNetwork, string> = {
  "solana-mainnet": "https://api.mainnet-beta.solana.com",
  "solana-devnet": "https://api.devnet.solana.com",
};

/** Memo program (used to stamp the receipt hash on-chain alongside the transfer) */
export const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/** Priority fee (micro-lamports per compute unit) so a payment lands under
 *  mainnet congestion. Fixed local value — NOT taken from the untrusted 402
 *  challenge, so a malicious server cannot inflate the payer's SOL fee. */
export const DEFAULT_PRIORITY_FEE_MICRO_LAMPORTS = 50_000;

/** Compute-unit cap for a payment tx (ATA-create + transfer + memo), so the
 *  priority fee stays bounded and predictable. */
export const PAYMENT_COMPUTE_UNIT_LIMIT = 60_000;

/** USDC atomic-unit conversions */
export function usdcToAtomic(usdc: number): number {
  return Math.round(usdc * 10 ** USDC_DECIMALS);
}

export function atomicToUsdc(atomic: number): number {
  return atomic / 10 ** USDC_DECIMALS;
}
