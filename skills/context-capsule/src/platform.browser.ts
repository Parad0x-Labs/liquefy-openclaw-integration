/**
 * Browser implementation of the platform primitives — pure JS, no Node builtins,
 * no secure-context requirement (runs on file://, http-localhost, in Web Workers).
 *
 *   SHA-256  -> @noble/hashes (sync, pure-JS) — byte-identical to node:crypto
 *   deflate  -> pako level 9 (zlib port)       — interoperable with node:zlib
 *
 * Parity with the Node backend is enforced by test/platform-parity.test.mjs: a
 * capsule built in a browser tab has the SAME merkleRoot, capsuleId, and injected
 * memory as one built in Node (the SHA-256 path is byte-identical). The stored
 * audit blob (compressedBase64) is round-trip-identical — pako and node:zlib each
 * inflate the other's output to the exact original — though the compressed bytes
 * can differ on highly repetitive input; that never affects integrity, since the
 * merkle root is built over sha256 leaves, not the blob. Lets NULLA's redaction +
 * compression run IN-TAB before any history leaves the device (the privacy front
 * door).
 */
import { sha256 } from "@noble/hashes/sha2.js";
import pako from "pako";

const enc = new TextEncoder();

export function sha256Bytes(data: string | Uint8Array): Uint8Array {
  return sha256(typeof data === "string" ? enc.encode(data) : data);
}

export function sha256Hex(data: string): string {
  return bytesToHex(sha256(enc.encode(data)));
}

export function sha256Concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const cat = new Uint8Array(a.length + b.length);
  cat.set(a, 0);
  cat.set(b, a.length);
  return sha256(cat);
}

export function deflate(text: string): { base64: string; bytes: number } {
  const out = pako.deflate(enc.encode(text), { level: 9 });
  return { base64: bytesToBase64(out), bytes: out.length };
}

export function utf8ByteLength(text: string): number {
  return enc.encode(text).length;
}

export function zeroBytes(n: number): Uint8Array {
  return new Uint8Array(n);
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

function bytesToBase64(bytes: Uint8Array): string {
  // chunked to avoid call-stack limits on large blobs; btoa is a browser global
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  // eslint-disable-next-line no-undef
  return btoa(binary);
}
