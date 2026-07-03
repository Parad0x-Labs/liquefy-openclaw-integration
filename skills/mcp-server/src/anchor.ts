/**
 * receipt_anchor instruction encoder (host-free, byte-exact, unit-tested).
 *
 * Built from the verified on-chain ABI of receipt_anchor (6HSRGivd…):
 *   data = [0x01 version][flags][32-byte hash]( [u64 LE bucket_id] )
 *   - 34-byte form: flags=0x00, program derives the bucket from its Clock hour
 *   - 42-byte form: flags=0x01, client pins bucket_id (this is what we use)
 *   keys = [payer(signer,writable), bucket PDA(writable), system_program]
 *   bucket PDA seeds = ["bucket", u64 LE bucket_id], bucket_id = floor(unix/3600)
 *
 * We use the 42-byte pinned-bucket form so the bucket PDA the client derives
 * always matches the one the program writes (the 34-byte form would let the
 * validator's Clock hour drift from the client's near an hour boundary).
 */

import { PublicKey, TransactionInstruction, SystemProgram } from "@solana/web3.js";

export const RECEIPT_ANCHOR_VERSION = 0x01;
export const FLAG_HAS_BUCKET_ID = 0x01;
const BUCKET_SEED_PREFIX = "bucket";
const BUCKET_WINDOW_SECONDS = 3600;

/** The program's hourly bucket id: floor(unix_seconds / 3600); 0 for non-positive. */
export function bucketIdForUnix(unixSeconds: number): bigint {
  return unixSeconds <= 0 ? 0n : BigInt(Math.floor(unixSeconds / BUCKET_WINDOW_SECONDS));
}

function u64le(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b;
}

/** Derive the AnchorBucket PDA for a bucket id: ["bucket", u64 LE bucket_id]. */
export function deriveBucketPda(bucketId: bigint, programId: string): PublicKey {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from(BUCKET_SEED_PREFIX), u64le(bucketId)],
    new PublicKey(programId),
  );
  return pda;
}

/** Build the single-anchor instruction (42-byte pinned-bucket form). */
export function buildAnchorIx(opts: {
  payer: string;
  receiptHashHex: string;
  programId: string;
  bucketId: bigint;
}): TransactionInstruction {
  if (!/^[0-9a-fA-F]{64}$/.test(opts.receiptHashHex)) {
    throw new Error("receipt_hash_hex must be exactly 64 hex characters (32 bytes).");
  }
  const data = Buffer.concat([
    Buffer.from([RECEIPT_ANCHOR_VERSION, FLAG_HAS_BUCKET_ID]),
    Buffer.from(opts.receiptHashHex, "hex"),
    u64le(opts.bucketId),
  ]);
  return new TransactionInstruction({
    programId: new PublicKey(opts.programId),
    keys: [
      { pubkey: new PublicKey(opts.payer), isSigner: true, isWritable: true },
      { pubkey: deriveBucketPda(opts.bucketId, opts.programId), isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}
