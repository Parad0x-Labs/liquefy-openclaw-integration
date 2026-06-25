/**
 * web0-onboard — host-free core.
 *
 * One call assembles a complete, validated web0 setup for an OpenClaw agent:
 * on-chain identity, a paid x402 storefront, receipt anchoring, and a .null
 * name-binding plan. All logic lives here with NO `openclaw/*` host import, so
 * it loads and unit-tests standalone. index.ts is the thin plugin wrapper.
 *
 * Trust model: READ-ONLY. Derives/queries on-chain state and emits config — it
 * never signs, never holds a key, never moves funds. The agent's own signer
 * runs the x402-gate and (when the naming layer is live) the registration tx.
 *
 * Self-contained per the openclaw-skills modularity contract: constants are
 * vendored, never imported from sibling skills. No seized pre-incident IDs.
 */

import { Connection, PublicKey } from "@solana/web3.js";

export type SolanaNetwork = "solana-mainnet" | "solana-devnet";

// ── Live program IDs (vendored) ──────────────────────────────────────────────
// Never add dark_x402_access_gate / dark_nullifier_record — seized pre-incident
// IDs awaiting clean redeploy under Squads multisig.
export const DARK_SECP256K1_AUTH = "AqwBbV13AoczhoELwP8oxT3nDqB6MsLWXauNzHkssZ9B";
export const RECEIPT_ANCHOR = "6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN";

/** USDC SPL mint per network. */
export const USDC_MINT: Record<SolanaNetwork, string> = {
  "solana-mainnet": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  "solana-devnet": "Gh9ZwEmdLJ8DscKNTkTqPbNwLNNBjuSzaG9Vp2KGtKJr",
};

// Public RPC — never api.mainnet-beta.solana.com (403s with an Origin header).
export const DEFAULT_RPC = "https://solana-rpc.publicnode.com";

/** Sanity ceiling on a single service price (USDC) — guards a fat-finger. */
export const MAX_SERVICE_PRICE_USDC = 10_000;

// ── Config + inputs ──────────────────────────────────────────────────────────

export interface Web0OnboardConfig {
  /** Default Solana wallet (base58) used when a call omits it. */
  solanaWallet?: string;
  /** Default .null name (without or with the .null suffix). */
  name?: string;
  /** Settlement network. Default solana-mainnet. */
  network?: SolanaNetwork;
  /** RPC override; defaults to publicnode. */
  rpcUrl?: string;
}

export interface ServiceInput {
  name: string;
  priceUsdc: number;
  description?: string;
}

export interface OnboardParams {
  name?: string;
  solanaWallet?: string;
  ethAddress?: string;
  services?: ServiceInput[];
  network?: SolanaNetwork;
  rpcUrl?: string;
}

export function readConfig(raw: Record<string, unknown> | undefined): Web0OnboardConfig {
  const cfg = raw ?? {};
  const net = cfg.network === "solana-devnet" ? "solana-devnet" : undefined;
  return {
    solanaWallet: typeof cfg.solanaWallet === "string" ? cfg.solanaWallet : undefined,
    name: typeof cfg.name === "string" ? cfg.name : undefined,
    network: net,
    rpcUrl: typeof cfg.rpcUrl === "string" ? cfg.rpcUrl : undefined,
  };
}

// ── Validators (pure) ─────────────────────────────────────────────────────────

/** Strip an optional ".null" suffix and lowercase. */
export function normalizeName(name: string): string {
  const n = name.trim().toLowerCase();
  return n.endsWith(".null") ? n.slice(0, -5) : n;
}

/**
 * A valid .null label: lowercase letters/digits/hyphens, 3–63 chars, no leading
 * or trailing hyphen, no consecutive hyphens. (Suffix is stripped first.)
 */
export function isValidNullLabel(name: string): boolean {
  const label = normalizeName(name);
  if (label.length < 3 || label.length > 63) return false;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) return false;
  if (label.includes("--")) return false;
  return true;
}

/**
 * Suggest a registerable .null label from the agent's setup when the caller
 * didn't pick one — prefer a slug of the first service, else a wallet-derived
 * handle. 4+ chars only (1–3 char names are premium / auction-only, not directly
 * registerable). Returns null if nothing valid can be formed.
 */
export function suggestNullLabel(services: ServiceInput[], wallet?: string): string | null {
  for (const s of services) {
    if (s && typeof s.name === "string") {
      const slug = normalizeName(s.name)
        .replace(/[^a-z0-9-]+/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-|-$/g, "");
      if (slug.length >= 4 && isValidNullLabel(slug)) return slug;
    }
  }
  if (wallet) {
    const tail = wallet.toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 6);
    const cand = `agent-${tail}`;
    if (isValidNullLabel(cand)) return cand;
  }
  return null;
}

export function isValidWallet(wallet: string): boolean {
  try {
    // eslint-disable-next-line no-new
    new PublicKey(wallet);
    return true;
  } catch {
    return false;
  }
}

export function isValidPrice(n: unknown): n is number {
  return typeof n === "number" && Number.isFinite(n) && n > 0 && n <= MAX_SERVICE_PRICE_USDC;
}

export interface ValidationResult {
  ok: boolean;
  errors: string[];
  wallet?: string;
  network: SolanaNetwork;
  services: ServiceInput[];
  name?: string;
}

/** Validate + normalize onboard inputs. Pure — no network. */
export function validateOnboardInput(
  config: Web0OnboardConfig,
  params: OnboardParams,
): ValidationResult {
  const errors: string[] = [];
  const network: SolanaNetwork =
    params.network ?? config.network ?? "solana-mainnet";

  const wallet = params.solanaWallet ?? config.solanaWallet;
  if (!wallet) {
    errors.push("solanaWallet is required (your agent's payout wallet, base58).");
  } else if (!isValidWallet(wallet)) {
    errors.push(`solanaWallet "${wallet}" is not a valid base58 Solana address.`);
  }

  const rawName = params.name ?? config.name;
  let name: string | undefined;
  if (rawName) {
    if (isValidNullLabel(rawName)) {
      name = normalizeName(rawName);
    } else {
      errors.push(
        `name "${rawName}" is not a valid .null label (3–63 chars, lowercase a–z/0–9/-, no leading/trailing or double hyphen).`,
      );
    }
  }

  const services = Array.isArray(params.services) ? params.services : [];
  if (services.length === 0) {
    errors.push("services must list at least one service to sell ({ name, priceUsdc }).");
  }
  services.forEach((s, i) => {
    if (!s || typeof s.name !== "string" || s.name.trim() === "") {
      errors.push(`services[${i}] needs a non-empty name.`);
    }
    if (!isValidPrice(s?.priceUsdc)) {
      errors.push(
        `services[${i}] (${s?.name ?? "?"}) needs a priceUsdc > 0 and <= ${MAX_SERVICE_PRICE_USDC}.`,
      );
    }
  });

  return { ok: errors.length === 0, errors, wallet, network, services, name };
}

// ── PDA derivation (vendored, pure) ──────────────────────────────────────────

/** Derive the agent's identity PDA on dark_secp256k1_auth (seed ["sol_agent", wallet]). */
export function derivePassportPda(wallet: string): string | null {
  try {
    const walletKey = new PublicKey(wallet);
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("sol_agent"), walletKey.toBytes()],
      new PublicKey(DARK_SECP256K1_AUTH),
    );
    return pda.toBase58();
  } catch {
    return null;
  }
}

/** True if a PDA account exists on-chain. */
export async function accountExists(connection: Connection, pda: string): Promise<boolean> {
  try {
    const info = await connection.getAccountInfo(new PublicKey(pda));
    return info !== null;
  } catch {
    return false;
  }
}

// ── Plan assembly (pure) ──────────────────────────────────────────────────────

/**
 * Assemble the consolidated onboard plan. Pure — `identityRegistered` is passed
 * in so the assembly is testable without a network call. The tool handler does
 * the on-chain check and feeds the result here.
 */
export function buildOnboardPlan(opts: {
  validation: ValidationResult;
  identityRegistered: boolean;
}): Record<string, unknown> {
  const { validation: v, identityRegistered } = opts;
  const wallet = v.wallet!;
  const passportPda = derivePassportPda(wallet);
  const fullName = v.name ? `${v.name}.null` : null;
  const suggested = fullName ? null : suggestNullLabel(v.services, wallet);

  // Recommend a gate config keyed off the first/cheapest service price.
  const defaultPrice = v.services.reduce(
    (min, s) => (s.priceUsdc < min ? s.priceUsdc : min),
    v.services[0]?.priceUsdc ?? 0,
  );

  return {
    ok: true,
    network: v.network,
    identity: {
      solana_wallet: wallet,
      passport_pda: passportPda,
      registered: identityRegistered,
      program: DARK_SECP256K1_AUTH,
      note: identityRegistered
        ? "Identity already bound on-chain."
        : "No binding yet — register via the agent-passport flow to make the identity verifiable.",
    },
    storefront: {
      recipient: wallet,
      network: v.network,
      usdc_mint: USDC_MINT[v.network],
      services: v.services.map((s) => ({
        name: s.name,
        priceUsdc: s.priceUsdc,
        description: s.description ?? null,
      })),
      // Drop-in config for the x402-gate plugin (charges per request to your wallet).
      x402_gate_config: {
        recipientAddress: wallet,
        priceUsdc: defaultPrice,
        network: v.network,
        requireOnChain: true,
      },
      note:
        "Configure the x402-gate plugin with x402_gate_config to start charging. " +
        "For multiple price points, run one gate per price (or per route).",
    },
    receipts: {
      program: RECEIPT_ANCHOR,
      note:
        "x402-gate and x402-pay derive matching receipt hashes; anchor each sale " +
        "via receipt_anchor for a permanent, verifiable trail.",
    },
    name: fullName
      ? {
          requested: fullName,
          valid: true,
          binding: {
            target_x402_endpoint: "<your x402-gate URL>",
            owner: wallet,
          },
          status:
            `the .null naming layer is LIVE on mainnet (registrar NXgQhepF…). Claim ${fullName} now: ` +
            `call register_null_name({ name: "${v.name}", dryRun: true }) to preview the PDA + fee, then run ` +
            `it again to sign. Follow with set_null_endpoint to publish your x402 URL — pay-by-name is live the moment you do.`,
          claim_preview: `register_null_name({ name: "${v.name}", dryRun: true })`,
          pay_by_name_preview: `pay_x402("${fullName}")  // live once you register + publish your endpoint`,
        }
      : null,
    name_suggestion: suggested
      ? {
          suggested: `${suggested}.null`,
          claim_preview: `register_null_name({ name: "${suggested}", dryRun: true })`,
          note:
            `no name set — "${suggested}.null" is derived from your setup. Claim it (or pass your own) ` +
            `to give this agent a pay-by-name identity. The naming layer is LIVE on mainnet.`,
        }
      : null,
    // claim first: the name is the agent's identity + pay-by-name address, so it
    // leads the checklist (not an afterthought). register/endpoint are live tools.
    next_steps: [
      fullName
        ? `Claim ${fullName} now — register_null_name({ name: "${v.name}", dryRun: true }) to preview, then run it again to sign. This is your agent's identity + pay-by-name address.`
        : suggested
          ? `Claim your .null name now — register_null_name({ name: "${suggested}", dryRun: true }) previews "${suggested}.null" (or pass your own). It's your agent's identity + pay-by-name address.`
          : `Pick a .null name and claim it — register_null_name({ name: "<yourname>", dryRun: true }) previews it. It's your agent's identity + pay-by-name address.`,
      `Publish your x402 endpoint on the name — set_null_endpoint({ name: "${v.name ?? suggested ?? "<yourname>"}", endpoint: "<your x402-gate URL>" }) — now buyers pay_x402("${fullName ?? (suggested ? `${suggested}.null` : "<yourname>.null")}").`,
      "Enable the x402-gate plugin with the storefront.x402_gate_config block — you're selling for USDC, funds to your own wallet.",
      identityRegistered
        ? "Identity is on-chain — nothing to do."
        : "Optionally bind your identity with the agent-passport plugin (recommended for verifiable counterparties).",
      "Point buyers at your x402 endpoint; their agents pay with x402-pay and receipts anchor automatically.",
    ],
    summary:
      `web0 setup assembled for ${wallet} on ${v.network}: ` +
      `${v.services.length} service(s), payout to your wallet, receipts anchored` +
      (fullName
        ? `, claim ${fullName} now (register_null_name) to turn on pay-by-name.`
        : suggested
          ? `, claim "${suggested}.null" (register_null_name) to turn on pay-by-name.`
          : "."),
  };
}

// ── Tool factory ──────────────────────────────────────────────────────────────

export interface ToolDef {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  handler: (params: Record<string, unknown>) => Promise<unknown>;
}

export function buildOnboardTools(config: Web0OnboardConfig): ToolDef[] {
  const rpcUrl = config.rpcUrl ?? DEFAULT_RPC;

  const web0Onboard: ToolDef = {
    name: "web0_onboard",
    description:
      "Set up an agent on web0 in one call: validate inputs, check on-chain identity, " +
      "and return a complete setup — a paid x402 storefront config (funds to your wallet), " +
      "receipt anchoring, and a .null name-binding plan. Read-only: emits config and checks " +
      "state; never signs or moves funds.",
    parameters: {
      name: {
        type: "string",
        description: "Desired .null name (e.g. \"myagent\" or \"myagent.null\"). Optional.",
      },
      solanaWallet: {
        type: "string",
        description: "Your agent's payout Solana wallet (base58). Required if not set in config.",
      },
      ethAddress: {
        type: "string",
        description: "Optional ETH address to note for identity binding.",
      },
      services: {
        type: "array",
        description: "Services to sell, each { name, priceUsdc, description? }.",
        items: {
          type: "object",
          properties: {
            name: { type: "string" },
            priceUsdc: { type: "number" },
            description: { type: "string" },
          },
          required: ["name", "priceUsdc"],
        },
      },
      network: {
        type: "string",
        enum: ["solana-mainnet", "solana-devnet"],
        description: "Settlement network (default solana-mainnet).",
      },
    },
    async handler(params: Record<string, unknown>) {
      const validation = validateOnboardInput(config, params as OnboardParams);
      if (!validation.ok) {
        return { ok: false, errors: validation.errors };
      }

      let identityRegistered = false;
      const pda = derivePassportPda(validation.wallet!);
      if (pda) {
        const connection = new Connection(params.rpcUrl ? String(params.rpcUrl) : rpcUrl, "confirmed");
        identityRegistered = await accountExists(connection, pda);
      }

      return buildOnboardPlan({ validation, identityRegistered });
    },
  };

  return [web0Onboard];
}
