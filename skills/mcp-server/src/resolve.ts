/**
 * .null name resolution — name → on-chain owner + x402 endpoint + stealth meta.
 *
 * Vendored (no cross-skill import). Reads the live mainnet registrar's NullDomain
 * account. Pure parse is split out so it's unit-testable without a network.
 *
 * NullDomain layout (registrar state.rs): disc[1]@0=0x4E · name[64]@1 ·
 * owner[32]@65 · arweave_txid[32]@97 · x402_endpoint[128]@129 (UTF-8, null-padded,
 * all-zero = not payable) · … · bump@313 (314-byte base) · stealth_meta[64]@314
 * (v2 only). PDA seeds: ["null-domain", sha256(name padded to 64 bytes)].
 */

import { Connection, PublicKey } from "@solana/web3.js";
import { createHash } from "crypto";

/** Live mainnet .null registrar (clean redeploy under multisig). NEVER the
 *  seized pre-incident H4wbFJ…. */
export const NULL_REGISTRAR_MAINNET = "NXgQhepFpDCu935H1D4g34g59ZYbo1jR4tBCZWhV8Np";

/** Keyless public-node mainnet RPC for resolution reads. */
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
  x402_endpoint?: string | null;
  stealth_meta?: string | null;
  arweave_txid?: string | null;
}

export function normalizeNullName(name: string): string {
  const n = name.trim().toLowerCase();
  return n.endsWith(".null") ? n.slice(0, -5) : n;
}

export function deriveNullDomainPda(name: string, registrar = NULL_REGISTRAR_MAINNET): string {
  const label = normalizeNullName(name);
  const padded = Buffer.alloc(64);
  Buffer.from(label, "utf8").copy(padded, 0);
  const seed = createHash("sha256").update(padded).digest();
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("null-domain"), seed],
    new PublicKey(registrar),
  );
  return pda.toBase58();
}

function readPaddedUtf8(buf: Buffer, off: number, len: number): string | null {
  const slice = buf.subarray(off, off + len);
  if (slice.every((b) => b === 0)) return null;
  const end = slice.indexOf(0);
  return slice.subarray(0, end === -1 ? len : end).toString("utf8");
}

/** Parse a raw NullDomain account. Pure — testable on a synthetic buffer. */
export function parseNullDomain(name: string, pda: string, data: Buffer): NullResolution {
  const res: NullResolution = { name: normalizeNullName(name), pda, found: false };
  if (data.length < ND_BASE_SIZE || data[0] !== ND_DISC) return res;
  res.found = true;
  res.owner = new PublicKey(data.subarray(OFF_OWNER, OFF_OWNER + 32)).toBase58();
  res.x402_endpoint = readPaddedUtf8(data, OFF_X402, LEN_X402);
  const arw = data.subarray(OFF_ARWEAVE, OFF_ARWEAVE + 32);
  res.arweave_txid = arw.every((b) => b === 0) ? null : Buffer.from(arw).toString("base64url");
  if (data.length >= OFF_STEALTH + LEN_STEALTH) {
    const sm = data.subarray(OFF_STEALTH, OFF_STEALTH + LEN_STEALTH);
    res.stealth_meta = sm.every((b) => b === 0) ? null : Buffer.from(sm).toString("hex");
  } else {
    res.stealth_meta = null;
  }
  return res;
}

/** Resolve a .null name on mainnet. */
export async function resolveNullName(
  name: string,
  rpcUrl = RESOLVE_RPC_MAINNET,
): Promise<NullResolution> {
  const pda = deriveNullDomainPda(name);
  try {
    const conn = new Connection(rpcUrl, "confirmed");
    const info = await conn.getAccountInfo(new PublicKey(pda));
    if (!info) return { name: normalizeNullName(name), pda, found: false };
    return parseNullDomain(name, pda, Buffer.from(info.data));
  } catch {
    return { name: normalizeNullName(name), pda, found: false };
  }
}
