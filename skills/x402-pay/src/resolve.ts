/**
 * .null name resolution — turn a `name.null` into its on-chain x402 endpoint.
 *
 * The live mainnet registrar stores each name's payment URL in the NullDomain
 * account, so pay_x402 can accept a name and pay it directly. Resolution is a
 * read on mainnet (where the registrar lives) via the keyless public node; the
 * payment that follows runs on whatever network the 402 challenge names.
 *
 * NullDomain byte layout (registrar state.rs):
 *   disc[1] @0 = 0x4E 'N' · name[64] @1 · owner[32] @65 · arweave_txid[32] @97
 *   x402_endpoint[128] @129 (UTF-8, null-padded; all-zero = not payable)
 *   passport_hash[32] @257 · registered_at[8] @289 · expires_at[8] @297
 *   null_paid[8] @305 · bump[1] @313  → 314-byte base
 *   stealth_meta[64] @314 (v2 only, >=378-byte accounts; all-zero = none)
 * PDA seeds: ["null-domain", sha256(name padded to 64 bytes)].
 */

import { Connection, PublicKey } from "@solana/web3.js";
import { createHash } from "crypto";

/** Live mainnet .null registrar (clean redeploy under multisig). Public program
 *  id; override via opts.registrar. NEVER the seized pre-incident H4wbFJ…. */
export const NULL_REGISTRAR_MAINNET = "NXgQhepFpDCu935H1D4g34g59ZYbo1jR4tBCZWhV8Np";

/** Keyless public-node mainnet RPC for resolution reads (registrar is mainnet). */
export const RESOLVE_RPC_MAINNET = "https://solana-rpc.publicnode.com";

const ND_DISC = 0x4e; // 'N'
const ND_BASE_SIZE = 314;
const OFF_OWNER = 65;
const OFF_ARWEAVE = 97;
const OFF_X402 = 129;
const LEN_X402 = 128;
const OFF_STEALTH = 314;
const LEN_STEALTH = 64;

export interface NullResolution {
  name: string;
  pda: string;
  found: boolean;
  owner?: string;
  /** Resolved x402 endpoint URL, or null if the name has none set. */
  x402Endpoint?: string | null;
  /** ed25519 stealth meta-address (hex), or null if unpublished. */
  stealthMeta?: string | null;
  arweaveTxid?: string | null;
}

/** Strip a ".null" suffix and lowercase. */
export function normalizeNullName(name: string): string {
  const n = name.trim().toLowerCase();
  return n.endsWith(".null") ? n.slice(0, -5) : n;
}

/** True only for an explicit `name.null` (never an http(s) URL). */
export function isNullName(s: string): boolean {
  return s.trim().toLowerCase().endsWith(".null");
}

/** Derive the NullDomain PDA: ["null-domain", sha256(name padded to 64 bytes)]. */
export function deriveNullDomainPda(name: string, registrar = NULL_REGISTRAR_MAINNET): string {
  const label = normalizeNullName(name);
  const padded = Buffer.alloc(64); // zero-filled → null-padded
  Buffer.from(label, "utf8").copy(padded, 0);
  const seed = createHash("sha256").update(padded).digest();
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("null-domain"), seed],
    new PublicKey(registrar),
  );
  return pda.toBase58();
}

/** Read a null-padded UTF-8 field; null if all-zero. */
function readPaddedUtf8(buf: Buffer, off: number, len: number): string | null {
  const slice = buf.subarray(off, off + len);
  if (slice.every((b) => b === 0)) return null;
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? len : end).toString("utf8");
}

/**
 * Parse a raw NullDomain account into a resolution. Pure — no network — so it is
 * unit-testable against a synthetic buffer. Returns found:false for a buffer that
 * isn't a NullDomain (wrong discriminator / too short).
 */
export function parseNullDomain(name: string, pda: string, data: Buffer): NullResolution {
  const res: NullResolution = { name: normalizeNullName(name), pda, found: false };
  if (data.length < ND_BASE_SIZE || data[0] !== ND_DISC) return res;
  res.found = true;
  res.owner = new PublicKey(data.subarray(OFF_OWNER, OFF_OWNER + 32)).toBase58();
  res.x402Endpoint = readPaddedUtf8(data, OFF_X402, LEN_X402);
  const arw = data.subarray(OFF_ARWEAVE, OFF_ARWEAVE + 32);
  res.arweaveTxid = arw.every((b) => b === 0) ? null : Buffer.from(arw).toString("base64url");
  if (data.length >= OFF_STEALTH + LEN_STEALTH) {
    const sm = data.subarray(OFF_STEALTH, OFF_STEALTH + LEN_STEALTH);
    res.stealthMeta = sm.every((b) => b === 0) ? null : Buffer.from(sm).toString("hex");
  } else {
    res.stealthMeta = null;
  }
  return res;
}

/** Resolve a `.null` name on mainnet → owner + x402 endpoint + stealth meta. */
export async function resolveNullName(
  name: string,
  opts?: { rpcUrl?: string; registrar?: string },
): Promise<NullResolution> {
  const registrar = opts?.registrar ?? NULL_REGISTRAR_MAINNET;
  const pda = deriveNullDomainPda(name, registrar);
  try {
    const conn = new Connection(opts?.rpcUrl ?? RESOLVE_RPC_MAINNET, "confirmed");
    const info = await conn.getAccountInfo(new PublicKey(pda));
    if (!info) return { name: normalizeNullName(name), pda, found: false };
    return parseNullDomain(name, pda, Buffer.from(info.data));
  } catch {
    return { name: normalizeNullName(name), pda, found: false };
  }
}
