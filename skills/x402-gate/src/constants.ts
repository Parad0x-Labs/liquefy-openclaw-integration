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

/** SPL Memo program — the receipt memo must originate from THIS program for the
 *  binding to be program-attested (not just a string in the logs). */
export const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/** Domain tag prepended to the presenter-auth nonce before the payer key signs it
 *  (see x402-pay). MUST stay byte-identical to the paying side. */
export const PRESENTER_AUTH_DOMAIN = "x402-presenter-auth:v1:";

/** Default public RPC endpoint(s). DEVNET ONLY by design: on mainnet the gate
 *  requires an explicit rpcUrl (it is the trusted settlement oracle), so there is
 *  no public-mainnet default to silently fall back to. */
export const DEFAULT_RPC: Partial<Record<SolanaNetwork, string>> = {
  "solana-devnet": "https://api.devnet.solana.com",
};

export function usdcToAtomic(usdc: number): number {
  return Math.round(usdc * 10 ** USDC_DECIMALS);
}

export function atomicToUsdc(atomic: number): number {
  return atomic / 10 ** USDC_DECIMALS;
}
