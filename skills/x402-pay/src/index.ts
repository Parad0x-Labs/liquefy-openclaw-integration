/**
 * openclaw-x402-pay — self-custody x402 payments for OpenClaw agents.
 *
 * Gives an agent one tool, `pay_x402`, that fetches an x402-gated URL and, if it
 * answers HTTP 402, pays for it on Solana and returns the resource.
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
 */

// Provided by the host OpenClaw runtime at load time (declared as a peer
// dependency), same pattern as @parad0x_labs/openclaw-context-capsule.
// definePluginEntry is a runtime value, not a type-only import.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { fetchWithX402, quoteX402, needsApproval } from "./client";
import type { X402PayConfig, X402Signer } from "./types";

export * from "./constants";
export * from "./types";
export * from "./signer";
export * from "./client";

const DEFAULT_MAX_USDC = 1.0;

/**
 * The host registers the owner's wallet here at startup. Kept out of JSON config
 * on purpose — a signer is a live capability, never a serialized secret.
 */
let activeSigner: X402Signer | null = null;
export function setX402Signer(signer: X402Signer): void {
  activeSigner = signer;
}

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

export default definePluginEntry({
  id: "x402-pay",
  name: "x402 Pay",
  description:
    "Let your agent pay for x402-gated APIs, data, and other agents on Solana " +
    "mainnet. Bring your own signer — the skill never holds a private key — with " +
    "a hard USDC spend cap. Set allowMainnet=true to enable real-money mainnet payments.",
  register(api: {
    registerTool: (tool: {
      name: string;
      description: string;
      parameters: Record<string, unknown>;
      handler: (params: Record<string, unknown>) => Promise<unknown>;
    }) => void;
    config?: Record<string, unknown>;
  }) {
    const config = readConfig(api.config);

    api.registerTool({
      name: "pay_x402",
      description:
        "Fetch a URL; if it returns HTTP 402, pay the demanded USDC on Solana " +
        "(within the configured cap and network) and return the resource. " +
        "Refuses any payment over the configured USDC cap.",
      parameters: {
        url: { type: "string", description: "The x402-gated resource URL to fetch" },
        method: { type: "string", description: "HTTP method (default GET)" },
        approved: {
          type: "boolean",
          description:
            "Host-set only. When requireApproval is enabled, the host sets this true " +
            "after the owner confirms the payment; the model should not set it.",
        },
      },
      async handler(params: Record<string, unknown>) {
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

        const init = params.method ? { method: String(params.method) } : undefined;

        // Approval handoff (opt-in): when requireApproval is set, do NOT pay on the
        // first call — return a structured quote the host gates through its own
        // confirmation (e.g. OpenClaw exec_approval). The host re-invokes with
        // approved:true once the owner consents. See APPROVAL_INTEGRATION.md.
        const approved = params.approved === true;
        if (needsApproval(config, approved)) {
          try {
            const quote = await quoteX402(url, { config, init });
            if (!quote.paymentRequired) {
              // Free resource — nothing to approve; return it.
              return { ok: true, status: quote.status, body: quote.body };
            }
            return {
              ok: false,
              approval_required: true,
              quote: {
                url,
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
          return await fetchWithX402(url, { signer: activeSigner, config, init });
        } catch (err) {
          return { ok: false, error: err instanceof Error ? err.message : String(err) };
        }
      },
    });
  },
});
