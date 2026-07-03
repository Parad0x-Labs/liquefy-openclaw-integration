import type { SolanaNetwork } from "./constants";

/** One acceptable payment method advertised in a 402 response. */
export interface X402PaymentRequirement {
  scheme: "exact";
  network: SolanaNetwork;
  maxAmountRequired: string; // atomic USDC, as string
  resource: string;
  description: string;
  memoPrefix: string;
  payTo: string;
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

/** Full HTTP 402 response body. */
export interface X402Challenge {
  x402Version: number;
  accepts: X402PaymentRequirement[];
  /** Single-use nonce the caller must sign with the payer key (presenter binding). */
  nonce?: string;
}

/** Options for minting a challenge. */
export interface ChallengeOptions {
  /** Price in USDC (e.g. 0.05) */
  priceUsdc: number;
  /** YOUR wallet address — where funds land. Public key only; no custody. */
  recipientAddress: string;
  /** Resource path/id being charged for */
  resource: string;
  description?: string;
  network?: SolanaNetwork;
  /** Optional unique-per-task nonce (binds the receipt hash) */
  nullifierSeed?: string;
  /** Optional platform fee split metadata (informational on the challenge) */
  platformWallet?: string;
  platformFeePct?: number;
  anchorReceipt?: boolean;
  platformId?: string;
  passportId?: string;
}

/** Decoded X-Payment header a caller submits. */
export interface X402PaymentProof {
  signature: string;
  payerAddress: string;
  amount: string; // atomic USDC
  resource: string;
  /** The challenge nonce, echoed back. */
  nonce?: string;
  /** ed25519 signature (base64) by the payer key over the nonce — proves the
   *  presenter controls the paying wallet. */
  payerSig?: string;
  /** A previously-issued capability token, presented to reuse access within its
   *  scope WITHOUT a new payment (still requires presenter-auth). */
  capability?: string;
}

/** Result of verifying an incoming payment. */
export type VerifyResult =
  | {
      valid: true;
      payerAddress: string;
      amountUsdc: number;
      amountAtomic: number;
      receiptHash: string;
      resource: string;
      /** True only if the on-chain tx was confirmed; false = header-only check */
      onChainVerified: boolean;
      signature: string;
      /** Capability token to reuse this access within its scope (no re-payment). */
      capability?: string;
      /** True when this verify was satisfied by reusing a capability (no new payment). */
      reusedCapability?: boolean;
    }
  | { valid: false; error: string };
