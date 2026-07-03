/**
 * web0-onboard — seller-side registrar writes (host-free core).
 *
 * Byte-exact instruction encoders for the live mainnet .null registrar
 * (NXgQhepF…), built from its verified ABI:
 *   - REGISTER        0x02  data: name[64] arweave_txid[32] currency[1]
 *   - UPDATE_ENDPOINT 0x06  data: name[64] x402_endpoint[128]
 *   - SET_STEALTH_META 0x0C data: name[64] stealth_meta[64]
 * All names are fixed [u8;64] null-padded; the domain PDA seeds the SHA-256 of
 * that exact 64-byte buffer. Non-custodial: these build UNSIGNED transactions —
 * the owner's wallet signs, this module never holds a key.
 *
 * Self-contained per the modularity contract: addresses are vendored, never the
 * seized pre-incident registrar.
 */

import {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  ComputeBudgetProgram,
} from "@solana/web3.js";
import { createHash } from "crypto";

/** Live mainnet .null registrar (clean redeploy under multisig). */
export const NULL_REGISTRAR_MAINNET = "NXgQhepFpDCu935H1D4g34g59ZYbo1jR4tBCZWhV8Np";
export const RESOLVE_RPC_MAINNET = "https://solana-rpc.publicnode.com";

// Instruction discriminators (registrar instruction.rs).
export const IX_REGISTER = 0x02;
export const IX_UPDATE_ENDPOINT = 0x06;
export const IX_SET_STEALTH_META = 0x0c;
export const CURRENCY_SOL = 1;
export const CURRENCY_NULL = 3;

// PDA seeds.
const DOMAIN_SEED = "null-domain";
const REGISTRY_SEED = "null-registry";
const OWNER_CAP_SEED = "owner-cap";

// RegistryConfig field offsets (state.rs).
const CFG_SOL_FEE = 33; // u64 LE
const CFG_NULL_FEE = 41; // u64 LE
const CFG_TREASURY = 81; // [u8;32]

export const MIN_NAME_LEN = 4;
export const MAX_NAME_LEN = 32;
const NAME_LEN = 64;
const X402_ENDPOINT_LEN = 128;
const STEALTH_META_LEN = 64;

// ── name helpers ──────────────────────────────────────────────────────────────

export function normalizeName(name: string): string {
  const n = name.trim().toLowerCase();
  return n.endsWith(".null") ? n.slice(0, -5) : n;
}

/** Mirror the program's validate_name: a-z / 0-9 / hyphen, 4–32 chars. */
export function validateName(name: string): { ok: boolean; error?: string } {
  const label = normalizeName(name);
  if (label.length < MIN_NAME_LEN || label.length > MAX_NAME_LEN) {
    return { ok: false, error: `name must be ${MIN_NAME_LEN}-${MAX_NAME_LEN} chars (got ${label.length}).` };
  }
  if (!/^[a-z0-9-]+$/.test(label)) {
    return { ok: false, error: "name may contain only lowercase a-z, 0-9, and hyphen." };
  }
  return { ok: true };
}

/** The 64-byte null-padded name buffer the program hashes + stores. */
export function padName64(name: string): Buffer {
  const label = normalizeName(name);
  const buf = Buffer.alloc(NAME_LEN);
  Buffer.from(label, "utf8").copy(buf, 0);
  return buf;
}

// ── PDA derivations ───────────────────────────────────────────────────────────

export function deriveDomainPda(name: string, registrar = NULL_REGISTRAR_MAINNET): PublicKey {
  const seed = createHash("sha256").update(padName64(name)).digest();
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from(DOMAIN_SEED), seed],
    new PublicKey(registrar),
  );
  return pda;
}

export function deriveConfigPda(registrar = NULL_REGISTRAR_MAINNET): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from(REGISTRY_SEED)],
    new PublicKey(registrar),
  );
  return pda;
}

export function deriveOwnerCapPda(owner: string, registrar = NULL_REGISTRAR_MAINNET): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from(OWNER_CAP_SEED), new PublicKey(owner).toBytes()],
    new PublicKey(registrar),
  );
  return pda;
}

export interface RegistryConfig {
  solFeeLamports: bigint;
  nullFeeAmount: bigint;
  treasury: string;
}

/** Parse the on-chain RegistryConfig account (fee + treasury). */
export function parseRegistryConfig(data: Buffer): RegistryConfig {
  return {
    solFeeLamports: data.readBigUInt64LE(CFG_SOL_FEE),
    nullFeeAmount: data.readBigUInt64LE(CFG_NULL_FEE),
    treasury: new PublicKey(data.subarray(CFG_TREASURY, CFG_TREASURY + 32)).toBase58(),
  };
}

// ── instruction encoders (pure, byte-exact) ───────────────────────────────────

/**
 * REGISTER (0x02). Free-pilot path passes no fee account; SOL-fee path passes the
 * treasury wallet (= cfg.treasury) just before the owner-cap. owner_cap is ALWAYS
 * the last account. arweave_txid is left zero (content is set later via 0x03).
 */
export function buildRegisterIx(opts: {
  payer: string;
  name: string;
  treasury?: string; // pass when the SOL fee is > 0
  registrar?: string;
}): TransactionInstruction {
  const registrar = opts.registrar ?? NULL_REGISTRAR_MAINNET;
  const programId = new PublicKey(registrar);
  const payer = new PublicKey(opts.payer);

  const data = Buffer.concat([
    Buffer.from([IX_REGISTER]),
    padName64(opts.name),
    Buffer.alloc(32), // arweave_txid — none at registration
    Buffer.from([CURRENCY_SOL]),
  ]);

  const keys = [
    { pubkey: payer, isSigner: true, isWritable: true },
    { pubkey: deriveDomainPda(opts.name, registrar), isSigner: false, isWritable: true },
    { pubkey: deriveConfigPda(registrar), isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
  if (opts.treasury) {
    keys.push({ pubkey: new PublicKey(opts.treasury), isSigner: false, isWritable: true });
  }
  keys.push({ pubkey: deriveOwnerCapPda(opts.payer, registrar), isSigner: false, isWritable: true });

  return new TransactionInstruction({ programId, keys, data });
}

/** UPDATE_ENDPOINT (0x06) — owner sets the name's x402 endpoint (pay-by-name). */
export function buildUpdateEndpointIx(opts: {
  owner: string;
  name: string;
  endpoint: string;
  registrar?: string;
}): TransactionInstruction {
  if (Buffer.byteLength(opts.endpoint, "utf8") > X402_ENDPOINT_LEN) {
    throw new Error(`x402 endpoint exceeds ${X402_ENDPOINT_LEN} bytes.`);
  }
  const registrar = opts.registrar ?? NULL_REGISTRAR_MAINNET;
  const endpointBuf = Buffer.alloc(X402_ENDPOINT_LEN);
  Buffer.from(opts.endpoint, "utf8").copy(endpointBuf, 0);

  const data = Buffer.concat([Buffer.from([IX_UPDATE_ENDPOINT]), padName64(opts.name), endpointBuf]);
  const keys = [
    { pubkey: new PublicKey(opts.owner), isSigner: true, isWritable: false },
    { pubkey: deriveDomainPda(opts.name, registrar), isSigner: false, isWritable: true },
  ];
  return new TransactionInstruction({ programId: new PublicKey(registrar), keys, data });
}

/** SET_STEALTH_META (0x0C) — owner publishes the recipient-private pay address. */
export function buildSetStealthMetaIx(opts: {
  owner: string;
  name: string;
  stealthMetaHex: string; // 64 bytes = 128 hex chars (spend_pub||view_pub)
  registrar?: string;
}): TransactionInstruction {
  const clean = opts.stealthMetaHex.replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{128}$/.test(clean)) {
    throw new Error("stealth_meta must be 64 bytes (128 hex chars: spend_pub[32]||view_pub[32]).");
  }
  const registrar = opts.registrar ?? NULL_REGISTRAR_MAINNET;
  const metaBuf = Buffer.from(clean, "hex");
  const data = Buffer.concat([Buffer.from([IX_SET_STEALTH_META]), padName64(opts.name), metaBuf]);
  const keys = [
    { pubkey: new PublicKey(opts.owner), isSigner: true, isWritable: true },
    { pubkey: deriveDomainPda(opts.name, registrar), isSigner: false, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];
  return new TransactionInstruction({ programId: new PublicKey(registrar), keys, data });
}

// ── non-custodial tx assembly + broadcast ─────────────────────────────────────

export interface Web0Signer {
  /** base58 public key of the owner wallet */
  publicKey: string;
  /** sign a base64 unsigned tx, return the base64 signed tx */
  signTransaction: (txBase64: string) => Promise<string>;
}

export interface UnsignedTx {
  txBase64: string;
  blockhash: string;
  lastValidBlockHeight: number;
}

/** Assemble an unsigned tx (priority fee + the given ixs) the owner will sign. */
export async function buildUnsignedTx(
  connection: Connection,
  feePayer: string,
  ixs: TransactionInstruction[],
): Promise<UnsignedTx> {
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash("confirmed");
  const tx = new Transaction({ feePayer: new PublicKey(feePayer), blockhash, lastValidBlockHeight });
  tx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 50_000 }), ...ixs);
  const txBase64 = tx
    .serialize({ requireAllSignatures: false, verifySignatures: false })
    .toString("base64");
  return { txBase64, blockhash, lastValidBlockHeight };
}

/** Broadcast an already-signed tx and confirm it within its blockhash window. */
export async function broadcastSigned(
  connection: Connection,
  signedTxBase64: string,
  blockhash: string,
  lastValidBlockHeight: number,
): Promise<string> {
  const raw = Buffer.from(signedTxBase64, "base64");
  const signature = await connection.sendRawTransaction(raw, {
    skipPreflight: false,
    preflightCommitment: "confirmed",
  });
  const conf = await connection.confirmTransaction(
    { signature, blockhash, lastValidBlockHeight },
    "confirmed",
  );
  if (conf.value.err) {
    throw new Error(`transaction failed on-chain: ${JSON.stringify(conf.value.err)}`);
  }
  return signature;
}

// ── tool factory ──────────────────────────────────────────────────────────────

export interface ToolDef {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  handler: (params: Record<string, unknown>) => Promise<unknown>;
}

export interface RegistrarToolsConfig {
  solanaWallet?: string;
  rpcUrl?: string;
  registrar?: string;
}

const EXPLORER = "https://explorer.solana.com/tx/";

/** Read a domain's on-chain owner (offset 65), or null if unregistered. */
async function readDomainOwner(
  connection: Connection,
  name: string,
  registrar: string,
): Promise<{ pda: string; exists: boolean; owner?: string }> {
  const pda = deriveDomainPda(name, registrar);
  const info = await connection.getAccountInfo(pda);
  if (!info || info.data.length < 97) return { pda: pda.toBase58(), exists: false };
  return { pda: pda.toBase58(), exists: true, owner: new PublicKey(info.data.subarray(65, 97)).toBase58() };
}

/**
 * Build the seller-side write tools. Non-custodial: each builds an UNSIGNED tx,
 * the host signer signs it, then it broadcasts. `getSigner` returns the live
 * host signer (or null). Every tool supports `dryRun` to preview without signing.
 */
export function buildRegistrarTools(
  config: RegistrarToolsConfig,
  getSigner: () => Web0Signer | null,
): ToolDef[] {
  const registrar = config.registrar ?? NULL_REGISTRAR_MAINNET;
  const rpcUrl = config.rpcUrl ?? RESOLVE_RPC_MAINNET;
  const conn = () => new Connection(rpcUrl, "confirmed");
  const payerOf = (): string | undefined => getSigner()?.publicKey ?? config.solanaWallet;

  const registerNullName: ToolDef = {
    name: "register_null_name",
    description:
      "Register a .null name on Solana mainnet (the agent's identity + payment handle). " +
      "Non-custodial: builds the transaction; the owner's wallet signs. Costs the on-chain " +
      "registration fee + rent (real SOL). Pass dryRun:true to preview the cost/PDA first.",
    parameters: {
      name: { type: "string", description: "The .null name to register (4-32 chars, a-z/0-9/-)." },
      dryRun: { type: "boolean", description: "Preview the registration (PDA, fee) without signing." },
    },
    async handler(params: Record<string, unknown>) {
      const name = String(params.name ?? "");
      const v = validateName(name);
      if (!v.ok) return { ok: false, error: v.error };
      const dryRun = params.dryRun === true;
      const signer = getSigner();
      const payer = payerOf();
      if (!payer) return { ok: false, error: "Set a signer (setWeb0Signer) or a solanaWallet in config." };
      if (!signer && !dryRun) {
        return { ok: false, error: "No signer configured. Call setWeb0Signer(wallet) to register, or pass dryRun:true to preview." };
      }

      const connection = conn();
      const cfgInfo = await connection.getAccountInfo(deriveConfigPda(registrar));
      if (!cfgInfo) return { ok: false, error: "Registry config not found on-chain." };
      const cfg = parseRegistryConfig(Buffer.from(cfgInfo.data));
      const treasury = cfg.solFeeLamports > 0n ? cfg.treasury : undefined;

      const probe = await readDomainOwner(connection, name, registrar);
      if (probe.exists) {
        return { ok: false, error: `${normalizeName(name)}.null is already registered (owner ${probe.owner}).`, pda: probe.pda };
      }

      const ix = buildRegisterIx({ payer, name, treasury, registrar });
      if (dryRun || !signer) {
        return {
          ok: true,
          dry_run: true,
          would_register: `${normalizeName(name)}.null`,
          pda: probe.pda,
          payer,
          currency: "SOL",
          fee_lamports: Number(cfg.solFeeLamports),
          fee_sol: Number(cfg.solFeeLamports) / 1e9,
          treasury: treasury ?? null,
          note: "Preview only — no transaction sent. Re-run without dryRun (signer set) to register.",
        };
      }

      const unsigned = await buildUnsignedTx(connection, signer.publicKey, [ix]);
      const signed = await signer.signTransaction(unsigned.txBase64);
      const signature = await broadcastSigned(connection, signed, unsigned.blockhash, unsigned.lastValidBlockHeight);
      return { ok: true, name: `${normalizeName(name)}.null`, pda: probe.pda, signature, explorer_url: EXPLORER + signature };
    },
  };

  const setNullEndpoint: ToolDef = {
    name: "set_null_endpoint",
    description:
      "Publish your .null name's x402 endpoint on-chain (UPDATE_ENDPOINT) so buyers can " +
      "pay_x402(\"yourname.null\"). Owner-only, non-custodial; tiny tx fee, no registration fee. " +
      "dryRun:true previews without signing.",
    parameters: {
      name: { type: "string", description: "Your .null name (you must be its owner)." },
      endpoint: { type: "string", description: "The x402 endpoint URL (<=128 bytes), e.g. https://api.you.dev/x402." },
      dryRun: { type: "boolean", description: "Preview without signing." },
    },
    async handler(params: Record<string, unknown>) {
      const name = String(params.name ?? "");
      const endpoint = String(params.endpoint ?? "");
      const v = validateName(name);
      if (!v.ok) return { ok: false, error: v.error };
      if (!/^https?:\/\//.test(endpoint)) return { ok: false, error: "endpoint must be an http(s) URL." };
      if (Buffer.byteLength(endpoint, "utf8") > X402_ENDPOINT_LEN) {
        return { ok: false, error: `endpoint exceeds ${X402_ENDPOINT_LEN} bytes.` };
      }
      const dryRun = params.dryRun === true;
      const signer = getSigner();
      const owner = payerOf();
      if (!owner) return { ok: false, error: "Set a signer (setWeb0Signer) or a solanaWallet in config." };

      const ix = buildUpdateEndpointIx({ owner, name, endpoint, registrar });
      if (dryRun || !signer) {
        return {
          ok: true,
          dry_run: !signer ? false : true,
          would_set_endpoint: endpoint,
          name: `${normalizeName(name)}.null`,
          pda: deriveDomainPda(name, registrar).toBase58(),
          owner,
          note: signer ? "Preview only — re-run without dryRun to publish." : "No signer configured — preview only; call setWeb0Signer to publish.",
        };
      }

      const connection = conn();
      const probe = await readDomainOwner(connection, name, registrar);
      if (!probe.exists) return { ok: false, error: `${normalizeName(name)}.null is not registered yet — register it first.`, pda: probe.pda };
      if (probe.owner !== owner) return { ok: false, error: `You (${owner}) are not the owner of ${normalizeName(name)}.null (owner ${probe.owner}).` };

      const unsigned = await buildUnsignedTx(connection, owner, [ix]);
      const signed = await signer.signTransaction(unsigned.txBase64);
      const signature = await broadcastSigned(connection, signed, unsigned.blockhash, unsigned.lastValidBlockHeight);
      return {
        ok: true,
        name: `${normalizeName(name)}.null`,
        endpoint,
        pda: probe.pda,
        signature,
        explorer_url: EXPLORER + signature,
        note: `Live — buyers can now pay_x402("${normalizeName(name)}.null").`,
      };
    },
  };

  const setNullStealthMeta: ToolDef = {
    name: "set_null_stealth_meta",
    description:
      "Publish your .null name's NullPay stealth meta-address (SET_STEALTH_META) to enable " +
      "recipient-private pay-by-name. Owner-only, non-custodial; small rent top-up on first call. " +
      "dryRun:true previews without signing.",
    parameters: {
      name: { type: "string", description: "Your .null name (you must be its owner)." },
      stealth_meta_hex: { type: "string", description: "64 bytes as 128 hex chars: spend_pub[32]||view_pub[32]." },
      dryRun: { type: "boolean", description: "Preview without signing." },
    },
    async handler(params: Record<string, unknown>) {
      const name = String(params.name ?? "");
      const metaHex = String(params.stealth_meta_hex ?? "");
      const v = validateName(name);
      if (!v.ok) return { ok: false, error: v.error };
      if (!/^(0x)?[0-9a-fA-F]{128}$/.test(metaHex)) {
        return { ok: false, error: "stealth_meta_hex must be 64 bytes (128 hex chars)." };
      }
      const dryRun = params.dryRun === true;
      const signer = getSigner();
      const owner = payerOf();
      if (!owner) return { ok: false, error: "Set a signer (setWeb0Signer) or a solanaWallet in config." };

      const ix = buildSetStealthMetaIx({ owner, name, stealthMetaHex: metaHex, registrar });
      if (dryRun || !signer) {
        return {
          ok: true,
          dry_run: !!signer,
          name: `${normalizeName(name)}.null`,
          pda: deriveDomainPda(name, registrar).toBase58(),
          owner,
          note: signer ? "Preview only — re-run without dryRun to publish." : "No signer configured — preview only.",
        };
      }

      const connection = conn();
      const probe = await readDomainOwner(connection, name, registrar);
      if (!probe.exists) return { ok: false, error: `${normalizeName(name)}.null is not registered yet.`, pda: probe.pda };
      if (probe.owner !== owner) return { ok: false, error: `You (${owner}) are not the owner of ${normalizeName(name)}.null.` };

      const unsigned = await buildUnsignedTx(connection, owner, [ix]);
      const signed = await signer.signTransaction(unsigned.txBase64);
      const signature = await broadcastSigned(connection, signed, unsigned.blockhash, unsigned.lastValidBlockHeight);
      return { ok: true, name: `${normalizeName(name)}.null`, pda: probe.pda, signature, explorer_url: EXPLORER + signature };
    },
  };

  return [registerNullName, setNullEndpoint, setNullStealthMeta];
}
