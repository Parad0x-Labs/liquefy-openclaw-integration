/**
 * Byte-exact tests for the receipt_anchor encoder (../dist/anchor.js), against
 * the verified on-chain ABI. Hermetic — no network.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { PublicKey, SystemProgram } from "@solana/web3.js";

import {
  buildAnchorIx,
  deriveBucketPda,
  bucketIdForUnix,
  RECEIPT_ANCHOR_VERSION,
  FLAG_HAS_BUCKET_ID,
} from "../dist/anchor.js";

const RECEIPT_ANCHOR = "6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN";
const PAYER = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
const HASH = "a".repeat(64);

test("bucketIdForUnix = floor(unix/3600), 0 for non-positive", () => {
  assert.equal(bucketIdForUnix(3600 * 100), 100n);
  assert.equal(bucketIdForUnix(3600 * 100 + 59 * 60), 100n); // same hour
  assert.equal(bucketIdForUnix(3600 * 101), 101n);
  assert.equal(bucketIdForUnix(0), 0n);
  assert.equal(bucketIdForUnix(-5), 0n);
});

test("deriveBucketPda is deterministic + uses [\"bucket\", u64le(id)]", () => {
  const a = deriveBucketPda(100n, RECEIPT_ANCHOR);
  assert.equal(a.toBase58(), deriveBucketPda(100n, RECEIPT_ANCHOR).toBase58());
  const seed = Buffer.alloc(8);
  seed.writeBigUInt64LE(100n);
  const [exp] = PublicKey.findProgramAddressSync(
    [Buffer.from("bucket"), seed],
    new PublicKey(RECEIPT_ANCHOR),
  );
  assert.equal(a.toBase58(), exp.toBase58());
  assert.notEqual(deriveBucketPda(101n, RECEIPT_ANCHOR).toBase58(), a.toBase58());
});

test("buildAnchorIx: 42-byte v1 pinned-bucket data + 3 accounts in order", () => {
  const ix = buildAnchorIx({ payer: PAYER, receiptHashHex: HASH, programId: RECEIPT_ANCHOR, bucketId: 100n });
  assert.equal(ix.data.length, 42);
  assert.equal(ix.data[0], RECEIPT_ANCHOR_VERSION); // 0x01
  assert.equal(ix.data[1], FLAG_HAS_BUCKET_ID); // 0x01
  assert.equal(ix.data.subarray(2, 34).toString("hex"), HASH);
  assert.equal(ix.data.readBigUInt64LE(34), 100n);
  assert.equal(ix.programId.toBase58(), RECEIPT_ANCHOR);

  const k = ix.keys;
  assert.equal(k.length, 3);
  assert.ok(k[0].isSigner && k[0].isWritable); // payer
  assert.equal(k[0].pubkey.toBase58(), PAYER);
  assert.ok(!k[1].isSigner && k[1].isWritable); // bucket PDA
  assert.equal(k[1].pubkey.toBase58(), deriveBucketPda(100n, RECEIPT_ANCHOR).toBase58());
  assert.ok(!k[2].isSigner && !k[2].isWritable); // system program
  assert.equal(k[2].pubkey.toBase58(), SystemProgram.programId.toBase58());
});

test("buildAnchorIx rejects a malformed hash", () => {
  assert.throws(
    () => buildAnchorIx({ payer: PAYER, receiptHashHex: "abcd", programId: RECEIPT_ANCHOR, bucketId: 1n }),
    /64 hex/,
  );
});
