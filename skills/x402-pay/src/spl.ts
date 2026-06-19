/**
 * Minimal, vendored SPL Token instruction builders.
 *
 * The skill needs exactly three helpers from the SPL Token program: derive an
 * associated token account address, create one idempotently, and build a checked
 * transfer. Pulling the full @solana/spl-token package for these dragged in
 * @solana/buffer-layout-utils -> bigint-buffer@1.1.5 — an UNMAINTAINED native
 * addon with an install script and an unpatched buffer-overflow advisory
 * (GHSA-3gc7-fjrx-p6mg), running build-time code on the host that holds the
 * signer. There is no fixed bigint-buffer release to pin to.
 *
 * Vendoring these tiny, frozen instruction layouts (verified byte-for-byte
 * identical to @solana/spl-token in the wire tests) removes that dependency
 * entirely: the package's only runtime dep is @solana/web3.js (+ bs58, pure JS,
 * already in its tree). The instruction encodings below match the on-chain SPL
 * Token and Associated Token programs, which have been stable for years.
 */

import { PublicKey, SystemProgram, TransactionInstruction } from "@solana/web3.js";

/** SPL Token program (classic; USDC is a classic-Token mint). */
export const TOKEN_PROGRAM_ID = new PublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA");
/** Associated Token Account program. */
export const ASSOCIATED_TOKEN_PROGRAM_ID = new PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/**
 * Derive the associated token account address for (mint, owner). Mirrors
 * @solana/spl-token's getAssociatedTokenAddressSync with allowOwnerOffCurve:
 * the ATA is a PDA of [owner, TOKEN_PROGRAM, mint] under the ATA program, so an
 * off-curve owner (a PDA / Squads-multisig recipient) is derivable too.
 */
export function getAssociatedTokenAddressSync(mint: PublicKey, owner: PublicKey): PublicKey {
  const [address] = PublicKey.findProgramAddressSync(
    [owner.toBuffer(), TOKEN_PROGRAM_ID.toBuffer(), mint.toBuffer()],
    ASSOCIATED_TOKEN_PROGRAM_ID,
  );
  return address;
}

/**
 * Build a CreateIdempotent instruction for the ATA. Idempotent variant
 * (discriminator byte 1) is a no-op if the account already exists, so paying a
 * fresh recipient never fails and re-paying never errors on an existing ATA.
 * Account order matches @solana/spl-token exactly.
 */
export function createAssociatedTokenAccountIdempotentInstruction(
  payer: PublicKey,
  associatedToken: PublicKey,
  owner: PublicKey,
  mint: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: associatedToken, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    programId: ASSOCIATED_TOKEN_PROGRAM_ID,
    data: Buffer.from([1]), // 1 = CreateIdempotent
  });
}

/**
 * Build a TransferChecked instruction (SPL Token instruction 12). Layout:
 * [u8 instruction=12][u64 amount LE][u8 decimals]. "Checked" forces the program
 * to verify the mint + decimals, so a wrong-mint/wrong-decimals transfer fails
 * on-chain rather than moving funds. Account order matches @solana/spl-token.
 */
export function createTransferCheckedInstruction(
  source: PublicKey,
  mint: PublicKey,
  destination: PublicKey,
  owner: PublicKey,
  amount: bigint,
  decimals: number,
): TransactionInstruction {
  const data = Buffer.alloc(10);
  data.writeUInt8(12, 0); // TransferChecked
  data.writeBigUInt64LE(amount, 1);
  data.writeUInt8(decimals, 9);
  return new TransactionInstruction({
    keys: [
      { pubkey: source, isSigner: false, isWritable: true },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: destination, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: true, isWritable: false },
    ],
    programId: TOKEN_PROGRAM_ID,
    data,
  });
}
