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

/**
 * Protocol fee, in basis points (1 bp = 0.01%). 5 bps = 0.05%, captured on every
 * marketplace payment as a SECOND transfer leg in the same atomic tx.
 *
 * PINNED here — NEVER read from the (untrusted) 402 challenge `extra.platformFeePct`.
 * A greedy seller can't zero it from the challenge, and a malicious challenge can't
 * inflate or redirect it. MUST stay byte-identical to the gate side (which enforces
 * the same fee at settlement), or a payment this side builds would be rejected there.
 */
export const PROTOCOL_FEE_BPS = 5;

/** Basis-point denominator (10000 bps = 100%). */
export const BPS_DENOMINATOR = 10_000;

/**
 * Protocol-fee treasury — the Squads multisig that receives the fee leg directly
 * on-chain. Non-custodial: funds settle straight to this address in the buyer's own
 * atomic tx; no intermediary ever holds them. PINNED on both sides, NEVER taken from
 * the challenge `extra.platformWallet`.
 */
export const PROTOCOL_FEE_TREASURY = "9M949AfyYCHp9hUk7crZZx3N6Y8sigyWBN6RM6tFq1q5";

/**
 * Protocol fee (atomic USDC units) for a payment of `amountAtomic`. Rounded UP, so a
 * positive payment ALWAYS carries a positive fee (>= 1 atomic unit) — the fee can
 * never round to zero and become a free ride. BigInt-exact (no float drift).
 */
export function protocolFeeAtomic(amountAtomic: bigint): bigint {
  if (amountAtomic <= 0n) return 0n;
  const bps = BigInt(PROTOCOL_FEE_BPS);
  const denom = BigInt(BPS_DENOMINATOR);
  return (amountAtomic * bps + (denom - 1n)) / denom; // ceil(amount * bps / 10000)
}

/** x402 protocol version this skill speaks */
export const X402_VERSION = 1;

/** Memo prefix stamped on payments */
export const MEMO_PREFIX = "null-miner-v1";

/** Domain tag prepended to the presenter-auth nonce before the payer key signs it,
 *  so the wallet never signs attacker-chosen raw bytes (no cross-protocol oracle).
 *  MUST stay byte-identical to the gate side. */
export const PRESENTER_AUTH_DOMAIN = "x402-presenter-auth:v1:";

/** Default public RPC endpoint(s). DEVNET ONLY by design: mainnet has NO default
 *  so a real-money payment never silently falls back to the public mainnet RPC (a
 *  third-party observer, and unreliable) — mainnet requires an explicit private
 *  rpcUrl in config. */
export const DEFAULT_RPC: Partial<Record<SolanaNetwork, string>> = {
  "solana-devnet": "https://api.devnet.solana.com",
};

/** Memo program (used to stamp the receipt hash on-chain alongside the transfer) */
export const MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

/** Priority fee (micro-lamports per compute unit) so a payment lands under
 *  mainnet congestion. Fixed local value — NOT taken from the untrusted 402
 *  challenge, so a malicious server cannot inflate the payer's SOL fee. */
export const DEFAULT_PRIORITY_FEE_MICRO_LAMPORTS = 50_000;

/** Compute-unit cap for a payment tx — now two legs: 2× idempotent ATA-create +
 *  2× transferChecked (seller + protocol-fee treasury) + memo — so the priority fee
 *  stays bounded and predictable. Headroom over the worst case (both ATAs needing
 *  creation); the priority fee is price × this limit, ~0.00001 SOL, negligible. */
export const PAYMENT_COMPUTE_UNIT_LIMIT = 200_000;

/** USDC atomic-unit conversions */
export function usdcToAtomic(usdc: number): number {
  return Math.round(usdc * 10 ** USDC_DECIMALS);
}

export function atomicToUsdc(atomic: number): number {
  return atomic / 10 ** USDC_DECIMALS;
}
