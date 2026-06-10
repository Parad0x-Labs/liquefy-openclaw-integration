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
}

export interface X402PayConfig {
  /** Hard cap — refuse any challenge above this many USDC. Required safety rail. */
  maxAmountUsdc: number;
  /** Must be true to allow real-money mainnet payments. Default false. */
  allowMainnet: boolean;
  /** Optional private RPC URL override */
  rpcUrl?: string;
}
