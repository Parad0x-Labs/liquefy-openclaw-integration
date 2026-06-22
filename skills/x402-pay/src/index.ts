/**
 * openclaw-x402-pay — self-custody x402 payments for OpenClaw agents.
 *
 * Tools:
 *   - `pay_x402`        fetch an x402-gated URL (or .null name) and pay on Solana if 402.
 *   - `rep_identity`    return the agent's public reputation commitment (for gate binding).
 *   - `prove_reputation` generate a PRIVATE proof of track record (>= minCount receipts
 *                       totalling >= minVolume in-window) for an x402 gate's x402_rep_verify,
 *                       revealing no amount, counterparty, or wallet. See ./prover.ts.
 *
 * Trust model (v1.1.0):
 *   - BRING YOUR OWN SIGNER. The host supplies an X402Signer (wallet adapter,
 *     hardware signer, KMS). This plugin builds an UNSIGNED transaction, hands
 *     it to that signer, then broadcasts the signed bytes. It never holds,
 *     requests, or reads a private key.
 *   - REAL-MONEY IS OPT-IN. Set config.allowMainnet=true to enable mainnet (also needs rpcUrl).
 *   - HARD SPEND CAP. config.maxAmountUsdc is enforced before any tx is built;
 *     a 402 demanding more is refused.
 *   - NETWORK: talks only to the configured Solana RPC and the target URL.
 *     No telemetry, no third-party endpoints.
 *
 * Non-custodial and spend-capped: the agent signs with its own wallet, and no
 * single payment can exceed the configured USDC cap.
 *
 * Plugin contract: defined with `defineToolPlugin` against the real OpenClaw SDK
 * (TypeBox `parameters` + `execute(params, config, context)`); registration is
 * handled by the SDK at plugin startup.
 */

import { Type } from "typebox";
import { defineToolPlugin } from "openclaw/plugin-sdk/tool-plugin";

import { fetchWithX402, quoteX402, needsApproval } from "./client";
import { resolveNullName, isNullName } from "./resolve";
import {
  proveReputation,
  agentCommitment as computeAgentCommitment,
  getReputationKey,
  type WitnessReceipt,
} from "./prover";
import type { X402PayConfig, X402Signer } from "./types";

export * from "./constants";
export * from "./types";
export * from "./signer";
export * from "./client";
export * from "./resolve";
export * from "./prover";

const DEFAULT_MAX_USDC = 1.0;

/**
 * The host registers the owner's wallet here at startup. Kept out of JSON config
 * on purpose — a signer is a live capability, never a serialized secret.
 */
let activeSigner: X402Signer | null = null;
export function setX402Signer(signer: X402Signer): void {
  activeSigner = signer;
}

// The agent's PRIVATE reputation key is registered via setReputationKey (re-exported from
// ./prover). Same rule as the signer: a secret is a live capability, never serialized JSON
// config. The secret stays inside ./prover; only the public agent_commitment + proofs leave.

/** Parse a config boolean robustly — a real boolean or common true/false strings
 *  (case-insensitive). Unrecognized junk falls back to the default, but explicit
 *  disable words ("false"/"no"/"off"/"0") are always honored so an operator who
 *  meant to turn a safety flag OFF never silently keeps it on. */
function readBool(v: unknown, dflt: boolean): boolean {
  if (typeof v === "boolean") return v;
  if (typeof v === "string") {
    const s = v.trim().toLowerCase();
    if (s === "true" || s === "yes" || s === "on" || s === "1") return true;
    if (s === "false" || s === "no" || s === "off" || s === "0") return false;
  }
  return dflt;
}

/** A finite, positive number or undefined — NaN/Infinity/±junk never pass, so a
 *  malformed value can't silently disable a spend cap on a real-money wallet. */
function finitePositive(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) && v > 0 ? v : undefined;
}

function readConfig(raw: Record<string, unknown> | undefined): X402PayConfig {
  const cfg = raw ?? {};
  // An EXPLICIT cap is honored as-is — a 0 or negative value means "pay nothing"
  // (refuse-all), and a non-finite value (NaN/Infinity/junk numeric string) is also
  // refused downstream by selectRequirement. The 1.0 default applies ONLY when the
  // operator left maxAmountUsdc unset, so an intended "0" is never silently raised.
  const rawMax = cfg.maxAmountUsdc;
  const maxAmountUsdc =
    typeof rawMax === "number"
      ? rawMax
      : typeof rawMax === "string" && rawMax.trim() !== ""
        ? Number(rawMax)
        : DEFAULT_MAX_USDC;
  return {
    maxAmountUsdc,
    // Real-money spending is OPT-IN: must be explicitly enabled. Mainnet also
    // requires an explicit rpcUrl, so enabling mainnet is already a conscious step.
    allowMainnet: readBool(cfg.allowMainnet, false),
    // Generous-but-FINITE default so a runaway or malicious endpoint can't drain
    // the wallet one capped payment at a time. Not off by default; raise via config.
    maxTotalUsdc: finitePositive(cfg.maxTotalUsdc) ?? maxAmountUsdc * 100,
    allowedRecipients: Array.isArray(cfg.allowedRecipients)
      ? cfg.allowedRecipients.filter((x): x is string => typeof x === "string")
      : undefined,
    // Finite default so a hostile endpoint cycling fresh recipients can't drain SOL
    // on ATA rent (USDC caps don't bound SOL). Raise for legitimately many-seller agents.
    maxDistinctRecipients: finitePositive(cfg.maxDistinctRecipients) ?? 100,
    rpcUrl: typeof cfg.rpcUrl === "string" ? cfg.rpcUrl : undefined,
    spendLedgerPath:
      typeof cfg.spendLedgerPath === "string" && cfg.spendLedgerPath.trim() !== ""
        ? cfg.spendLedgerPath
        : undefined,
    allowInternalHosts: readBool(cfg.allowInternalHosts, false),
    requireApproval: readBool(cfg.requireApproval, false),
  };
}

/** Plugin config schema. Lenient by design — host configs commonly arrive as
 *  strings (env/JSON), and readConfig() does the robust coercion + safe defaults
 *  above. additionalProperties stays open so an unknown host key is never rejected. */
const ConfigSchema = Type.Object(
  {
    maxAmountUsdc: Type.Optional(Type.Union([Type.Number(), Type.String()])),
    allowMainnet: Type.Optional(Type.Union([Type.Boolean(), Type.String()])),
    maxTotalUsdc: Type.Optional(Type.Union([Type.Number(), Type.String()])),
    allowedRecipients: Type.Optional(Type.Array(Type.String())),
    maxDistinctRecipients: Type.Optional(Type.Union([Type.Number(), Type.String()])),
    rpcUrl: Type.Optional(Type.String()),
    spendLedgerPath: Type.Optional(Type.String()),
    allowInternalHosts: Type.Optional(Type.Union([Type.Boolean(), Type.String()])),
    requireApproval: Type.Optional(Type.Union([Type.Boolean(), Type.String()])),
    // zk-rep prover artifacts (track_record.circom). Not bundled — host them (e.g. on
    // Arweave via web0) and point here, or pass per-call in prove_reputation.
    repWasmPath: Type.Optional(Type.String()),
    repZkeyPath: Type.Optional(Type.String()),
  },
  { additionalProperties: true },
);

const PayParams = Type.Object({
  url: Type.String({
    description: 'The x402-gated resource URL, OR a .null name (e.g. "myagent.null") to pay by name.',
  }),
  method: Type.Optional(Type.String({ description: "HTTP method (default GET)" })),
  approved: Type.Optional(
    Type.Boolean({
      description:
        "Host-set only. When requireApproval is enabled, the host sets this true after the " +
        "owner confirms the payment; the model should not set it.",
    }),
  ),
});

const FieldStrOrNum = Type.Union([Type.String(), Type.Number()]);

/** One settled receipt with its inclusion proof against the anchored tree root. The host
 *  fills this from the receipt-dag / anchored-tree indexer — not the model freehand. */
const RepReceiptSchema = Type.Object({
  amount: FieldStrOrNum,
  timestamp: FieldStrOrNum,
  counterparty: FieldStrOrNum,
  nonce: FieldStrOrNum,
  leafIndex: FieldStrOrNum,
  pathElements: Type.Array(Type.String()),
  pathIndex: Type.Array(Type.Number()),
});

const ProveRepParams = Type.Object({
  epoch: Type.Union([Type.String(), Type.Number()], {
    description: "Reputation epoch — rotates the single-use nullifier (e.g. a day or week index).",
  }),
  root: Type.String({ description: "Anchored receipt-tree root the gate trusts (decimal field element)." }),
  minCount: Type.Number({ description: "Receipt-count bar to advertise (0..4 in v1)." }),
  minVolume: Type.Union([Type.String(), Type.Number()], {
    description: "Total-volume bar to advertise (atomic units). The proof shows the real total >= this.",
  }),
  windowStart: Type.Number({ description: "Earliest receipt timestamp to prove (unix seconds)." }),
  receipts: Type.Array(RepReceiptSchema, {
    description: "Exactly 4 receipts with inclusion paths, ordered by strictly increasing leafIndex (v1).",
  }),
  wasmPath: Type.Optional(Type.String({ description: "Path/URL to track_record.wasm (else config.repWasmPath)." })),
  zkeyPath: Type.Optional(Type.String({ description: "Path/URL to track_record_final.zkey (else config.repZkeyPath)." })),
});

export default defineToolPlugin({
  id: "x402-pay",
  name: "x402 Pay",
  description:
    "Let your agent pay for x402-gated APIs, data, and other agents on Solana " +
    "mainnet. Bring your own signer — the skill never holds a private key — with " +
    "a hard USDC spend cap. Set allowMainnet=true to enable real-money mainnet payments. " +
    "Also proves PRIVATE reputation (prove_reputation): show you hold enough settled " +
    "receipts to clear a gate without revealing any amount, counterparty, or wallet.",
  configSchema: ConfigSchema,
  tools: (tool) => [
    tool({
      name: "pay_x402",
      label: "Pay x402",
      description:
        "Fetch a URL or a .null name; if it returns HTTP 402, pay the demanded USDC " +
        "on Solana (within the configured cap and network) and return the resource. " +
        "A name.null resolves on mainnet to its published x402 endpoint (pay-by-name). " +
        "Refuses any payment over the configured USDC cap.",
      parameters: PayParams,
      async execute(params, rawConfig) {
        const config = readConfig(rawConfig as Record<string, unknown>);

        if (!activeSigner) {
          return {
            ok: false,
            error:
              "No signer configured. The host must call setX402Signer(wallet) " +
              "before pay_x402 can authorize a payment.",
          };
        }
        const url = String(params.url ?? "");
        if (!url) return { ok: false, error: "url is required" };

        // Pay-by-name: a `name.null` resolves on mainnet to its published x402
        // endpoint, which is what we then pay. A plain URL is used as-is.
        let targetUrl = url;
        let resolvedName: { name: string; pda: string; owner?: string } | undefined;
        if (isNullName(url)) {
          let r;
          try {
            r = await resolveNullName(url);
          } catch (err) {
            return {
              ok: false,
              error: `x402: failed to resolve ${url}: ${err instanceof Error ? err.message : String(err)}`,
            };
          }
          if (!r.found) {
            return { ok: false, error: `x402: .null name "${url}" is not registered on mainnet (pda ${r.pda}).` };
          }
          if (!r.x402Endpoint) {
            return {
              ok: false,
              error: `x402: ${url} resolves (owner ${r.owner}) but has no x402 endpoint published yet — the owner must set one before it can be paid by name.`,
              resolved: { name: r.name, pda: r.pda, owner: r.owner },
            };
          }
          targetUrl = r.x402Endpoint;
          resolvedName = { name: r.name, pda: r.pda, owner: r.owner };
        }

        const init = params.method ? { method: String(params.method) } : undefined;

        // Approval handoff (opt-in): when requireApproval is set, do NOT pay on the
        // first call — return a structured quote the host gates through its own
        // confirmation (e.g. OpenClaw exec_approval). The host re-invokes with
        // approved:true once the owner consents. See APPROVAL_INTEGRATION.md.
        const approved = params.approved === true;
        if (needsApproval(config, approved)) {
          try {
            const quote = await quoteX402(targetUrl, { config, init });
            if (!quote.paymentRequired) {
              // Free resource — nothing to approve; return it.
              return {
                ok: true,
                status: quote.status,
                body: quote.body,
                ...(resolvedName ? { resolved_name: resolvedName } : {}),
              };
            }
            return {
              ok: false,
              approval_required: true,
              quote: {
                url: targetUrl,
                name: resolvedName?.name ?? null,
                amount_usdc: quote.amountUsdc,
                pay_to: quote.requirement?.payTo,
                network: quote.network,
                resource: quote.requirement?.resource,
                description: quote.requirement?.description,
              },
              contract:
                "Re-invoke pay_x402 with approved:true once the owner confirms this payment. " +
                "The host MUST gate this approval (e.g. via OpenClaw exec_approval) — the approved " +
                "flag is set by the host after user consent, not by the model.",
            };
          } catch (err) {
            return { ok: false, error: err instanceof Error ? err.message : String(err) };
          }
        }

        try {
          const result = await fetchWithX402(targetUrl, { signer: activeSigner, config, init });
          return resolvedName ? { ...result, resolved_name: resolvedName } : result;
        } catch (err) {
          return { ok: false, error: err instanceof Error ? err.message : String(err) };
        }
      },
    }),

    // ── zk-rep (private reputation) ────────────────────────────────────────────────
    tool({
      name: "rep_identity",
      label: "Reputation identity",
      description:
        "Return this agent's PUBLIC reputation commitment (agent_commitment = " +
        "Poseidon(secret, agent_id)). Hand it to an x402 gate as expectedAgentCommitment so " +
        "a reputation proof is bound to this agent and cannot be transplanted by another. " +
        "Reveals nothing secret. Requires the host to have called setReputationKey first.",
      parameters: Type.Object({}),
      async execute() {
        const key = getReputationKey();
        if (!key) {
          return {
            ok: false,
            error: "No reputation key. The host must call setReputationKey({secret, agentId}) first.",
          };
        }
        try {
          return { ok: true, agent_commitment: computeAgentCommitment(key.secret, key.agentId) };
        } catch (err) {
          return { ok: false, error: err instanceof Error ? err.message : String(err) };
        }
      },
    }),

    tool({
      name: "prove_reputation",
      label: "Prove reputation (zk)",
      description:
        "Generate a PRIVATE reputation proof: prove this agent holds >= minCount settled " +
        "receipts totalling >= minVolume since windowStart, in an anchored receipt tree — " +
        "revealing NO individual amount, counterparty, or wallet. Returns a Groth16 proof + " +
        "public signals to send to a gate's x402_rep_verify. The host supplies the receipts " +
        "with inclusion paths (from the receipt-dag indexer) and the proving artifacts. " +
        "Requires setReputationKey first; the secret never leaves the skill.",
      parameters: ProveRepParams,
      async execute(params, rawConfig) {
        const key = getReputationKey();
        if (!key) {
          return {
            ok: false,
            error: "No reputation key. The host must call setReputationKey({secret, agentId}) first.",
          };
        }
        const cfg = (rawConfig ?? {}) as Record<string, unknown>;
        const wasmPath =
          (typeof params.wasmPath === "string" && params.wasmPath) ||
          (typeof cfg.repWasmPath === "string" ? cfg.repWasmPath : "");
        const zkeyPath =
          (typeof params.zkeyPath === "string" && params.zkeyPath) ||
          (typeof cfg.repZkeyPath === "string" ? cfg.repZkeyPath : "");
        if (!wasmPath || !zkeyPath) {
          return {
            ok: false,
            error:
              "prove_reputation needs the proving artifacts: set params.wasmPath/zkeyPath or " +
              "config.repWasmPath/repZkeyPath. Host them (e.g. on Arweave via web0) — they are not bundled.",
          };
        }
        try {
          const res = await proveReputation(
            {
              epoch: params.epoch,
              root: String(params.root),
              minCount: Number(params.minCount),
              minVolume: params.minVolume,
              windowStart: Number(params.windowStart),
              receipts: params.receipts as unknown as WitnessReceipt[],
              wasmPath,
              zkeyPath,
            },
            key,
          );
          return {
            ok: true,
            proof: res.proof,
            public_signals: res.publicSignals,
            agent_commitment: res.agentCommitment,
            reputation_nullifier: res.reputationNullifier,
            root: res.root,
            proving_ms: res.provingMs,
            note:
              "Send proof + public_signals to the gate's x402_rep_verify. Bind with " +
              "expectedAgentCommitment = agent_commitment so the proof is non-transferable.",
          };
        } catch (err) {
          // proveReputation never echoes secret/amount values; pass its label-only message through.
          return { ok: false, error: err instanceof Error ? err.message : String(err) };
        }
      },
    }),
  ],
});
