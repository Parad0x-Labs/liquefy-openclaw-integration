/**
 * x402 challenge + payment types. Mirrors the wire format produced by the DNA
 * x402 server (`createPaymentRequirement`) so this client can parse a real 402
 * response from any null-miner / x402 endpoint.
 */

import type { SolanaNetwork } from "./constants";

/** One acceptable payment method inside a 402 response. */
export interface X402PaymentRequirement {
  scheme: "exact";
  network: SolanaNetwork;
  /** Atomic units (USDC = 6 decimals), as a string on the wire */
  maxAmountRequired: string;
  resource: string;
  description: string;
  memoPrefix: string;
  /** Recipient address (base58) */
  payTo: string;
  /** Asset mint (USDC) base58 */
  asset: string;
  extra?: {
    platformWallet?: string;
    platformFeePct?: number;
    anchorReceipt?: boolean;
    passportId?: string;
    platformId?: string;
    nullifierSeed?: string;
  };
}

/** Full body of an HTTP 402 response. */
export interface X402Challenge {
  x402Version: number;
  accepts: X402PaymentRequirement[];
  /** Presenter-auth nonce the payer must sign (set by gates that require it). */
  nonce?: string;
}

/** A signer the agent owner controls. The skill NEVER holds the private key —
 *  it builds an unsigned transaction and hands it to `signTransaction`. */
export interface X402Signer {
  /** Solana public key (base58) of the paying wallet */
  publicKey: string;
  /**
   * Sign a fully-built Solana transaction and return it signed.
   * Implemented by the agent owner (wallet adapter, hardware signer, KMS, …).
   * The transaction is NOT broadcast here — the skill broadcasts after signing.
   */
  signTransaction: (txBase64: string) => Promise<string>;
  /**
   * Sign an arbitrary UTF-8 message with the wallet key, returning a base64
   * ed25519 signature. Required only for gates that use presenter-auth (they
   * issue a nonce the payer must sign to prove key control).
   */
  signMessage?: (message: string) => Promise<string>;
}

/** Result of a completed x402 payment + resource fetch. */
export interface X402PayResult {
  ok: boolean;
  /** The resource body returned after payment (text) */
  body?: string;
  status: number;
  /** Solana transaction signature of the payment, if paid */
  paymentSignature?: string;
  /** SHA-256 receipt hash (hex) of the payment */
  receiptHash?: string;
  amountUsdc?: number;
  payTo?: string;
  network?: SolanaNetwork;
  error?: string;
  /** Capability token returned by the gate — reuse this resource within its scope
   *  without paying again (the client also caches it automatically). */
  capability?: string;
  /** True when access was served by reusing a cached capability (no new payment). */
  reusedCapability?: boolean;
  /** True when the payment's on-chain confirmation was ambiguous: the tx may have
   *  landed (see paymentSignature). Do NOT retry-pay without checking the signature. */
  pending?: boolean;
}

export interface X402PayConfig {
  /** Hard per-payment cap — refuse any single challenge above this many USDC. */
  maxAmountUsdc: number;
  /** Allow real-money mainnet payments. Default false (opt-in). */
  allowMainnet: boolean;
  /** Optional cumulative cap across this process's lifetime (defense vs a
   *  malicious endpoint draining the wallet one capped payment at a time). */
  maxTotalUsdc?: number;
  /** Optional recipient allowlist — if set, refuse to pay any payTo not listed. */
  allowedRecipients?: string[];
  /** Max DISTINCT recipients funded per process — bounds SOL spent on recipient
   *  ATA rent (USDC caps don't bound SOL). A hostile endpoint cycling fresh payTo
   *  addresses can't drain SOL past this. Default 100; raise for many-seller agents. */
  maxDistinctRecipients?: number;
  /** Optional private RPC URL override */
  rpcUrl?: string;
  /** Path to a durable spend-ledger file. Backs the cumulative cap, the double-pay
   *  guard, and the distinct-recipient cap so they survive a restart. REQUIRED on
   *  mainnet (allowMainnet=true) — without it a restart mid-pending can double-pay. */
  spendLedgerPath?: string;
}
