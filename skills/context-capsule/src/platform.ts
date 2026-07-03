/**
 * Platform crypto/compression primitives for the context-capsule core.
 *
 * This is the DEFAULT (Node) implementation — `node:crypto` + `node:zlib`, the
 * exact behavior the published OpenClaw plugin has always had (zero runtime
 * deps). The compression core imports these names instead of the Node builtins
 * directly so the SAME source can run in a browser: a browser build aliases this
 * module to `platform.browser.ts` (pure-JS @noble/hashes + pako). The two
 * backends agree on everything that matters — see test/platform-parity.test.mjs:
 *   • SHA-256 is byte-identical, so a capsule's merkleRoot, capsuleId, and the
 *     injected memory the model sees are byte-identical across backends.
 *   • deflate is interoperable/round-trip-identical (each inflates the other's
 *     output to the exact original); compressed BYTES may differ on highly
 *     repetitive input — which never affects integrity, since the merkle root is
 *     built over sha256 leaves, not the compressed blob.
 * No source line of compression.ts cares which backend is active.
 */
import { createHash } from "node:crypto";
import { deflateSync } from "node:zlib";

/** SHA-256 of a UTF-8 string (or raw bytes) -> 32 bytes. */
export function sha256Bytes(data: string | Uint8Array): Uint8Array {
  const buf = typeof data === "string" ? Buffer.from(data, "utf8") : Buffer.from(data);
  return new Uint8Array(createHash("sha256").update(buf).digest());
}

/** SHA-256 of a UTF-8 string -> lowercase hex. */
export function sha256Hex(data: string): string {
  return createHash("sha256").update(Buffer.from(data, "utf8")).digest("hex");
}

/** SHA-256 of (a ‖ b) raw bytes — the merkle internal-node hash. */
export function sha256Concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(Buffer.from(a)).update(Buffer.from(b)).digest());
}

/** Deflate (zlib, level 9) a UTF-8 string -> base64 + raw byte length. */
export function deflate(text: string): { base64: string; bytes: number } {
  const out = deflateSync(Buffer.from(text, "utf8"), { level: 9 });
  return { base64: out.toString("base64"), bytes: out.length };
}

export function utf8ByteLength(text: string): number {
  return Buffer.byteLength(text, "utf8");
}

export function zeroBytes(n: number): Uint8Array {
  return new Uint8Array(n);
}

export function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
