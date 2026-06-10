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
    }
  | { valid: false; error: string };
