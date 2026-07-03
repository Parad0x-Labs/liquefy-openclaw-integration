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

/**
 * Protocol fee, in basis points (1 bp = 0.01%). 5 bps = 0.05%, enforced at
 * settlement: the gate refuses to serve unless the treasury was credited at least
 * this fee in the same tx. PINNED here — NEVER read from the (untrusted) challenge
 * `extra.platformFeePct`. Kept byte-identical to the paying side so the fee the
 * buyer builds matches the fee the gate requires.
 */
export const PROTOCOL_FEE_BPS = 5;

/** Basis-point denominator (10000 bps = 100%). */
export const BPS_DENOMINATOR = 10_000;

/**
 * Protocol-fee treasury — the Squads multisig credited by the fee leg. Non-custodial:
 * the gate verifies the on-chain credit to THIS address; it never holds funds. PINNED
 * on both sides, NEVER taken from the challenge `extra.platformWallet`.
 */
export const PROTOCOL_FEE_TREASURY = "9M949AfyYCHp9hUk7crZZx3N6Y8sigyWBN6RM6tFq1q5";

/**
 * Protocol fee (atomic USDC units) for a payment of `amountAtomic`. Rounded UP so a
 * positive payment ALWAYS owes a positive fee (>= 1 atomic). BigInt-exact. MUST stay
 * byte-identical to the paying side.
 */
export function protocolFeeAtomic(amountAtomic: bigint): bigint {
  if (amountAtomic <= 0n) return 0n;
  const bps = BigInt(PROTOCOL_FEE_BPS);
  const denom = BigInt(BPS_DENOMINATOR);
  return (amountAtomic * bps + (denom - 1n)) / denom; // ceil(amount * bps / 10000)
}

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
