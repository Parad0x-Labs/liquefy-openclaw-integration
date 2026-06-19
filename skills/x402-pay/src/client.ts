/**
 * x402 client flow: fetch a resource, and if it answers HTTP 402, pay for it
 * with the owner's signer and retry — enforcing the spend cap and the explicit
 * mainnet opt-in BEFORE any transaction is built.
 */

import { Connection } from "@solana/web3.js";
import {
  DEFAULT_RPC,
  USDC_MINT,
  PRESENTER_AUTH_DOMAIN,
  atomicToUsdc,
  type SolanaNetwork,
} from "./constants";
import { payWithSigner } from "./signer";
import { SpendLedger } from "./ledger";
import type {
  X402Challenge,
  X402PayConfig,
  X402PayResult,
  X402PaymentRequirement,
  X402Signer,
} from "./types";

/**
 * Spend-safety state — cumulative cap, the cross-call double-pay guard (pending
 * payments), and the distinct-recipient cap. Backed by a durable file when
 * config.spendLedgerPath is set (REQUIRED on mainnet) so it survives restarts;
 * otherwise in-memory (devnet/testing). Lazily created from the first config.
 */
let ledger: SpendLedger | null = null;
function getLedger(config: X402PayConfig): SpendLedger {
  if (!ledger) ledger = new SpendLedger(config.spendLedgerPath);
  return ledger;
}

/** Capability tokens held from prior payments, keyed by payer|host|resource, so the
 *  same resource can be reused within its scope without paying again. In-memory:
 *  losing one on restart costs at most a re-pay, never a double-pay. */
interface CachedCapability {
  token: string;
  exp: number;
}
const capabilityStore = new Map<string, CachedCapability>();
// Key by payer + ORIGIN HOST + resource so a capability paid at one seller can
// never be presented to a different origin that happens to use the same resource path.
const capKey = (payer: string, host: string, resource: string): string => `${payer}|${host}|${resource}`;
const capExp = (token: string): number => {
  const n = Number(token.split(".")[0]);
  return Number.isFinite(n) ? n : 0;
};

const MAX_CHALLENGE_BYTES = 65_536;
const MAX_RESOURCE_BYTES = 16 * 1024 * 1024;

/** Read a response body, aborting past maxBytes. Bounds the ACTUAL bytes streamed,
 *  not the server-advertised Content-Length (which a malicious server can omit or
 *  send chunked) — so an untrusted endpoint can't OOM the wallet-bearing process. */
async function readCappedText(res: Response, maxBytes: number): Promise<string> {
  const body = res.body;
  if (!body) return await res.text();
  const reader = body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.length;
        if (total > maxBytes) {
          await reader.cancel().catch(() => {});
          throw new Error(`x402: response body exceeds ${maxBytes} bytes`);
        }
        chunks.push(Buffer.from(value));
      }
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks).toString("utf8");
}

/** Reject a fetch target that is not http(s) or points at the cloud-metadata
 *  service — the highest-value SSRF abuse of a wallet-bearing process by a
 *  prompt-injected agent. (Recipient/amount/caps are decoupled from the URL, so
 *  fund safety does not depend on this; it bounds the request surface.) */
function assertSafeUrl(raw: string): void {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("x402: invalid URL");
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") {
    throw new Error(`x402: refusing non-http(s) URL scheme "${u.protocol}"`);
  }
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "169.254.169.254" || host === "fd00:ec2::254" || host === "0.0.0.0") {
    throw new Error(`x402: refusing cloud-metadata / unspecified host "${host}"`);
  }
}

/** Parse + minimally validate a 402 response body into a challenge. */
export function parseChallenge(body: string): X402Challenge {
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new Error("x402: 402 response body is not valid JSON");
  }
  const c = parsed as X402Challenge;
  if (!c || !Array.isArray(c.accepts) || c.accepts.length === 0) {
    throw new Error("x402: 402 response has no `accepts` payment options");
  }
  return c;
}

/**
 * Choose a requirement we are allowed and able to pay. Throws (refuses to pay)
 * if every option is over the cap or requires un-opted-in mainnet.
 */
export function selectRequirement(
  challenge: X402Challenge,
  config: X402PayConfig,
): X402PaymentRequirement {
  // The cap must be a finite positive number — a NaN/Infinity/0/negative cap is a
  // refuse-all (an explicit 0 means "pay nothing"), never a silent open spend.
  if (!Number.isFinite(config.maxAmountUsdc) || config.maxAmountUsdc <= 0) {
    throw new Error("x402: maxAmountUsdc is not a positive number — refusing to pay (set a positive per-payment cap)");
  }
  const reasons: string[] = [];
  let best: X402PaymentRequirement | null = null;
  let bestAtomic = 0n;

  for (const req of challenge.accepts) {
    if (req.scheme !== "exact") {
      reasons.push(`unsupported scheme "${req.scheme}"`);
      continue;
    }
    if (req.network !== "solana-mainnet" && req.network !== "solana-devnet") {
      reasons.push(`unknown network "${req.network}"`);
      continue;
    }
    if (req.network === "solana-mainnet" && !config.allowMainnet) {
      reasons.push("mainnet payment requires allowMainnet=true (real-money opt-in)");
      continue;
    }
    // The cap is USDC-denominated (6 decimals). Refuse any other mint, or a
    // malicious challenge could name a more-valuable 6-decimal token and slip
    // a large transfer under the cap.
    if (!req.asset || req.asset !== USDC_MINT[req.network]) {
      reasons.push(`refusing non-USDC asset ${req.asset}`);
      continue;
    }
    if (!req.payTo) {
      reasons.push("requirement missing payTo");
      continue;
    }
    if (config.allowedRecipients && config.allowedRecipients.length > 0 && !config.allowedRecipients.includes(req.payTo)) {
      reasons.push(`recipient ${req.payTo} not in allowedRecipients`);
      continue;
    }
    if (!/^[0-9]+$/.test(req.maxAmountRequired) || BigInt(req.maxAmountRequired) <= 0n) {
      reasons.push(`invalid amount "${req.maxAmountRequired}" (must be a positive integer of atomic units)`);
      continue;
    }
    const usdc = atomicToUsdc(Number(req.maxAmountRequired));
    if (usdc > config.maxAmountUsdc) {
      reasons.push(`${usdc} USDC exceeds maxAmountUsdc cap of ${config.maxAmountUsdc}`);
      continue;
    }
    // Among acceptable options pick the CHEAPEST, so a greedy/hostile gate can't
    // force overpayment by listing an expensive in-cap option first.
    const atomic = BigInt(req.maxAmountRequired);
    if (best === null || atomic < bestAtomic) {
      best = req;
      bestAtomic = atomic;
    }
  }

  if (best) return best;
  throw new Error(`x402: refusing to pay — ${reasons.join("; ")}`);
}

/** Build the X-Payment header value (base64 JSON proof). Field names MUST match
 *  the gate's X402PaymentProof exactly: { signature, payerAddress, amount, resource }. */
export function buildPaymentHeader(opts: {
  signature: string;
  payerAddress: string;
  amount: string;
  resource: string;
  nonce?: string;
  payerSig?: string;
  capability?: string;
}): string {
  return Buffer.from(JSON.stringify(opts), "utf8").toString("base64");
}

/** Shape of a gate-issued nonce: `<exp>.<rand-hex>.<sha256-hex>`. */
const NONCE_RE = /^\d+\.[0-9a-f]+\.[0-9a-f]{64}$/;

/** The exact message the payer key signs for presenter-auth: a domain-tagged,
 *  shape-validated nonce — never raw attacker-chosen bytes (anti signing-oracle). */
function authMessage(nonce: string): string {
  if (!NONCE_RE.test(nonce)) {
    throw new Error("x402: gate nonce is not a well-formed token — refusing to sign (possible signing oracle)");
  }
  return PRESENTER_AUTH_DOMAIN + nonce;
}

export interface FetchWithX402Options {
  signer: X402Signer;
  config: X402PayConfig;
  /** Passed through to fetch() for the initial + retried request */
  init?: RequestInit;
}

/**
 * Fetch `url`; if it returns 402, pay and retry once with the X-Payment header.
 * Returns the resource body plus payment metadata. Never pays more than the cap,
 * never touches mainnet unless explicitly opted in, never holds a key.
 */
export async function fetchWithX402(
  url: string,
  opts: FetchWithX402Options,
): Promise<X402PayResult> {
  const { signer, config, init } = opts;
  const led = getLedger(config);
  assertSafeUrl(url);

  const first = await fetch(url, init);
  if (first.status !== 402) {
    return { ok: first.ok, status: first.status, body: await readCappedText(first, MAX_RESOURCE_BYTES) };
  }

  // Decide what (if anything) we will pay — enforced before building any tx. Read
  // the challenge with a hard byte cap (not the server's Content-Length, which it
  // can omit or chunk to slip an unbounded body past the guard).
  const challenge = parseChallenge(await readCappedText(first, MAX_CHALLENGE_BYTES));
  const req = selectRequirement(challenge, config);
  const network: SolanaNetwork = req.network;
  const nowSec = Math.floor(Date.now() / 1000);

  // Presenter auth needs message signing — confirm we can BEFORE spending anything.
  if (challenge.nonce && !signer.signMessage) {
    throw new Error("x402: gate requires presenter auth (a signed nonce) but the signer has no signMessage");
  }

  // Mainnet fail-closed, BEFORE any RPC connection or capability/pending probe:
  // (a) an explicit private rpcUrl is required (the public RPC is a third-party
  // observer and unreliable for money — and we must never silently fall back to it
  // on mainnet, including on the pending re-check below), and (b) the spend rails
  // must be durable (a restart must not re-arm the caps or lose a pending signature).
  if (network === "solana-mainnet") {
    if (!config.rpcUrl) {
      throw new Error(
        "x402: mainnet requires an explicit rpcUrl in config — the public RPC is a third-party observer and unreliable for real payments.",
      );
    }
    if (!led.durable) {
      throw new Error(
        "x402: mainnet requires a durable spend ledger — set spendLedgerPath so the spend cap and double-pay guard survive a restart.",
      );
    }
  }
  // Single resolved RPC for every on-chain call below. DEFAULT_RPC has no mainnet
  // entry, so mainnet uses the (guaranteed) config.rpcUrl; devnet may use the default.
  const rpcUrl = config.rpcUrl ?? DEFAULT_RPC[network];
  if (!rpcUrl) {
    throw new Error(`x402: no RPC URL configured for ${network} — set an rpcUrl in config.`);
  }

  // Capability reuse: if we hold a live capability for this resource, present it
  // (signing the fresh nonce to prove the key) and skip payment entirely.
  let host = "";
  try {
    host = new URL(url).host;
  } catch {
    /* leave host empty if url has no parseable host */
  }
  const ckey = capKey(signer.publicKey, host, req.resource);
  const cached = capabilityStore.get(ckey);
  if (cached && cached.exp > nowSec + 5 && challenge.nonce && signer.signMessage) {
    const reuseSig = await signer.signMessage(authMessage(challenge.nonce));
    const reuseHeader = buildPaymentHeader({
      signature: "",
      payerAddress: signer.publicKey,
      amount: "0",
      resource: req.resource,
      nonce: challenge.nonce,
      payerSig: reuseSig,
      capability: cached.token,
    });
    const reuse = await fetch(url, { ...init, headers: { ...(init?.headers ?? {}), "X-Payment": reuseHeader } });
    if (reuse.ok) {
      return { ok: true, status: reuse.status, body: await readCappedText(reuse, MAX_RESOURCE_BYTES), payTo: req.payTo, network, reusedCapability: true };
    }
    capabilityStore.delete(ckey); // rejected / expired — fall through to a fresh payment
  }

  // Cross-call double-pay guard: if a prior payment for this (wallet,host,resource)
  // is still unredeemed, re-check it on-chain before building another transfer.
  const pending = led.getPending(ckey);
  if (pending) {
    const probe = new Connection(rpcUrl, "confirmed");
    const st = (await probe.getSignatureStatus(pending.signature, { searchTransactionHistory: true })).value;
    if (st && !st.err && st.confirmationStatus === "finalized") {
      return {
        ok: false,
        status: 0,
        paymentSignature: pending.signature,
        network,
        error: `x402: a prior payment for this resource has finalized (signature ${pending.signature}) — redeem it; not paying again`,
      };
    }
    if (st?.err) {
      led.clearPending(ckey); // landed + failed → no funds moved → safe to pay again
    } else if (!st) {
      // Not seen on-chain. Only safe to clear + re-pay once the blockhash window has
      // passed (past lastValidBlockHeight the tx can NEVER land); until then a "null"
      // status may just be RPC lag on a tx that DID land — treat as pending, never re-pay.
      const height = await probe.getBlockHeight("confirmed");
      if (height > pending.lastValidBlockHeight) {
        led.clearPending(ckey); // window expired → tx is dead → safe to pay again
      } else {
        return {
          ok: false,
          status: 0,
          paymentSignature: pending.signature,
          network,
          pending: true,
          error: `x402: a prior payment for this resource is not yet final and its blockhash window is still open (signature ${pending.signature}) — verify before retrying`,
        };
      }
    } else {
      return {
        ok: false,
        status: 0,
        paymentSignature: pending.signature,
        network,
        pending: true,
        error: `x402: a prior payment for this resource is still pending (signature ${pending.signature}) — verify before retrying`,
      };
    }
  }

  // Cumulative spend rail — bound total spend across this process / ledger.
  const reqUsdc = atomicToUsdc(Number(req.maxAmountRequired));
  if (config.maxTotalUsdc !== undefined && led.totalSpent() + reqUsdc > config.maxTotalUsdc) {
    throw new Error(
      `x402: refusing to pay — cumulative cap reached (${led.totalSpent()} + ${reqUsdc} > ${config.maxTotalUsdc} USDC)`,
    );
  }
  // SOL-drain rail: paying a brand-new recipient funds ~0.002 SOL of ATA rent, which
  // the USDC caps don't bound. Cap distinct recipients.
  if (
    config.maxDistinctRecipients !== undefined &&
    !led.hasRecipient(req.payTo) &&
    led.recipientCount() >= config.maxDistinctRecipients
  ) {
    throw new Error(
      `x402: refusing to pay — distinct-recipient cap reached (${config.maxDistinctRecipients}); ` +
        `a hostile endpoint cycling fresh recipients can't drain SOL on ATA rent past this`,
    );
  }
  const connection = new Connection(rpcUrl, "confirmed");

  // WRITE-AHEAD: the moment the signed tx is known (before it touches the network),
  // persist the recheck marker + count the spend + record the recipient in ONE
  // durable write. So a throw or crash during broadcast can never lose the signature
  // (a retry would re-check it, not re-pay) and can never re-arm the caps.
  let signature: string, receiptHash: string, amountUsdc: number, status: "confirmed" | "pending";
  try {
    ({ signature, receiptHash, amountUsdc, status } = await payWithSigner(
      connection,
      signer,
      req,
      (sig, lvbh) => led.recordBroadcast(ckey, sig, lvbh, reqUsdc, req.payTo),
    ));
  } catch (e) {
    // Reached only on a DEFINITIVE on-chain execution error (the tx landed and
    // failed → atomic → no USDC moved) or a pre-broadcast error (build/sign failed →
    // nothing sent). Either way no funds moved: clear the recheck marker so a retry
    // may safely re-pay, and surface a clean failure.
    led.clearPending(ckey);
    throw e;
  }

  // Ambiguous confirmation — the tx MAY have landed. The marker is already persisted
  // (write-ahead); surface the signature and do NOT report a clean retryable failure.
  if (status !== "confirmed") {
    return {
      ok: false,
      status: 0,
      error: `x402: payment pending on-chain confirmation — verify signature ${signature} before any retry (do not re-pay)`,
      paymentSignature: signature,
      network,
      pending: true,
    };
  }
  // Confirmed on-chain. The recheck marker stays set (from the write-ahead record)
  // until we've SUCCESSFULLY redeemed — so if the redeem leg fails, a retry re-checks
  // the signature on-chain (and does not pay again) rather than broadcasting again.

  // Presenter binding: sign the gate-issued nonce with the payer key so an
  // observer of the on-chain payment can't replay this proof for free access.
  let nonce: string | undefined;
  let payerSig: string | undefined;
  if (challenge.nonce) {
    nonce = challenge.nonce;
    payerSig = await signer.signMessage!(authMessage(challenge.nonce));
  }

  const header = buildPaymentHeader({
    signature,
    payerAddress: signer.publicKey,
    amount: req.maxAmountRequired,
    resource: req.resource,
    nonce,
    payerSig,
  });

  let retried: Response;
  try {
    retried = await fetch(url, {
      ...init,
      headers: { ...(init?.headers ?? {}), "X-Payment": header },
    });
  } catch (e) {
    // Redeem leg failed AFTER a confirmed payment. Keep the marker so a retry hits
    // the on-chain re-check (never re-pays); surface the paid signature.
    return {
      ok: false,
      status: 0,
      error: `x402: payment confirmed (signature ${signature}) but the redeem request failed (${e instanceof Error ? e.message : String(e)}) — retry to redeem; do NOT re-pay`,
      paymentSignature: signature,
      network,
      pending: true,
    };
  }

  // Cache any capability the gate issued (the seller echoes x402_verify's
  // `capability` in the X-Payment-Capability response header) for later reuse.
  const capToken = retried.headers.get("X-Payment-Capability");
  if (capToken) capabilityStore.set(ckey, { token: capToken, exp: capExp(capToken) });
  const body = await readCappedText(retried, MAX_RESOURCE_BYTES);
  // Redeemed only once the gate accepted the proof. If it rejected (non-ok), keep
  // the marker so a retry re-checks the confirmed signature instead of re-paying.
  if (retried.ok) led.clearPending(ckey);

  return {
    ok: retried.ok,
    status: retried.status,
    body,
    paymentSignature: signature,
    receiptHash,
    amountUsdc,
    payTo: req.payTo,
    network,
    capability: capToken ?? undefined,
  };
}
