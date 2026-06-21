/**
 * Non-custodial Solana wallet creation (host-free core).
 *
 * Generates a keypair on the owner's own machine. The SECRET KEY is never
 * returned from the tool (so it never reaches the model context) — the handler
 * writes it to a local file the owner controls and returns only the public key
 * and the path. Pairs with loadKeypair (create here, sign elsewhere).
 */

import { Keypair } from "@solana/web3.js";
import { homedir } from "os";
import { join } from "path";

export interface NewWallet {
  publicKey: string;
  /** 64-byte secret key array — caller writes to disk; NEVER include in a tool result. */
  secretKey: number[];
}

export function generateWallet(): NewWallet {
  const kp = Keypair.generate();
  return { publicKey: kp.publicKey.toBase58(), secretKey: Array.from(kp.secretKey) };
}

/** Public key derived from a stored secret-key array (for verification). */
export function publicKeyOfSecret(secretKey: number[]): string {
  return Keypair.fromSecretKey(Uint8Array.from(secretKey)).publicKey.toBase58();
}

/**
 * Resolve the keypair file path: an explicit path (with ~ expansion) or the
 * default ~/.config/solana/<label>.json. Label is sanitized to a safe basename.
 */
export function resolveWalletPath(opts: { path?: string; label?: string }): string {
  if (opts.path && opts.path.trim()) {
    const p = opts.path.trim();
    return p.startsWith("~") ? join(homedir(), p.slice(1)) : p;
  }
  const label = opts.label && /^[a-z0-9._-]+$/i.test(opts.label) ? opts.label : "web0-agent";
  return join(homedir(), ".config", "solana", `${label}.json`);
}
