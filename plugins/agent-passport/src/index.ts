/**
 * openclaw-agent-passport — on-chain identity for OpenClaw agents.
 *
 * Gives an agent two tools:
 *   - `get_agent_passport`: returns this agent's on-chain identity record
 *     (null name, Solana wallet, ETH address, PDA existence checks).
 *   - `verify_agent_identity`: verifies a DIFFERENT agent's identity by their
 *     Solana wallet or ETH address.
 *
 * Trust model:
 *   - READ-ONLY. No transactions, no signing, no private key access.
 *   - PUBLIC RPC ONLY. Uses solana-rpc.publicnode.com by default.
 *     Never api.mainnet-beta.solana.com (returns 403 with Origin header).
 *   - PDA derivation uses the on-chain seed patterns from dark_secp256k1_auth
 *     and dark_secp256r1_vault. No hardcoded seized or pre-incident program IDs.
 *
 * Status: ETH binding + WebAuthn vault live on mainnet.
 * .null name resolution wiring coming with null-resolver deployment.
 */

// Type-only import: resolved from the host OpenClaw runtime at load time, same
// pattern as openclaw-x402-pay. No build-time dependency.
import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";

import { Connection, PublicKey } from "@solana/web3.js";

// ── Program IDs — derived here, never hardcoded as PDAs ─────────────────────
// Do NOT add dark_x402_access_gate or dark_nullifier_record here — those are
// seized pre-incident IDs awaiting clean redeploy under Squads multisig.

const DARK_SECP256K1_AUTH = "AqwBbV13AoczhoELwP8oxT3nDqB6MsLWXauNzHkssZ9B";
const DARK_SECP256R1_VAULT = "3hbbtjeSrTVYXq6eRwjeofDe2DCPh3n8cfN6kZcQfewi";
const RECEIPT_ANCHOR = "6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN";

// Public RPC — never api.mainnet-beta.solana.com (403s with Origin header)
const DEFAULT_RPC = "https://solana-rpc.publicnode.com";

// ── Config ──────────────────────────────────────────────────────────────────

interface AgentPassportConfig {
  solanaWallet?: string;
  ethAddress?: string;
  nullName?: string;
  rpcUrl?: string;
}

function readConfig(raw: Record<string, unknown> | undefined): AgentPassportConfig {
  const cfg = raw ?? {};
  return {
    solanaWallet: typeof cfg.solanaWallet === "string" ? cfg.solanaWallet : undefined,
    ethAddress: typeof cfg.ethAddress === "string" ? cfg.ethAddress : undefined,
    nullName: typeof cfg.nullName === "string" ? cfg.nullName : undefined,
    rpcUrl: typeof cfg.rpcUrl === "string" ? cfg.rpcUrl : undefined,
  };
}

// ── PDA derivation ───────────────────────────────────────────────────────────

/**
 * Derive the ETH-binding PDA for a hex ETH address on dark_secp256k1_auth.
 * Seeds: ["eth_agent", <20-byte eth address>]
 *
 * ETH address may be "0x"-prefixed or bare hex; we normalise to 20 raw bytes.
 * Returns null if the address is malformed.
 */
function deriveEthBindingPda(ethAddress: string): string | null {
  try {
    const hex = ethAddress.startsWith("0x") ? ethAddress.slice(2) : ethAddress;
    if (hex.length !== 40) return null;
    const addrBytes = Buffer.from(hex, "hex");
    if (addrBytes.length !== 20) return null;

    const programId = new PublicKey(DARK_SECP256K1_AUTH);
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("eth_agent"), addrBytes],
      programId,
    );
    return pda.toBase58();
  } catch {
    return null;
  }
}

/**
 * Derive the Solana-wallet PDA on dark_secp256k1_auth.
 * Seeds: ["sol_agent", <wallet pubkey bytes>]
 *
 * Returns null if the wallet address is malformed.
 */
function deriveSolAgentPda(solanaWallet: string): string | null {
  try {
    const walletKey = new PublicKey(solanaWallet);
    const programId = new PublicKey(DARK_SECP256K1_AUTH);
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("sol_agent"), walletKey.toBytes()],
      programId,
    );
    return pda.toBase58();
  } catch {
    return null;
  }
}

/**
 * Derive the WebAuthn vault PDA on dark_secp256r1_vault for a Solana wallet.
 * Seeds: ["webauthn_vault", <wallet pubkey bytes>]
 */
function deriveWebAuthnVaultPda(solanaWallet: string): string | null {
  try {
    const walletKey = new PublicKey(solanaWallet);
    const programId = new PublicKey(DARK_SECP256R1_VAULT);
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from("webauthn_vault"), walletKey.toBytes()],
      programId,
    );
    return pda.toBase58();
  } catch {
    return null;
  }
}

/**
 * Check whether a PDA account exists on-chain (any non-null, non-zero lamport
 * account counts as registered).
 */
async function accountExists(connection: Connection, pda: string): Promise<boolean> {
  try {
    const info = await connection.getAccountInfo(new PublicKey(pda));
    return info !== null;
  } catch {
    return false;
  }
}

// ── Plugin entry ─────────────────────────────────────────────────────────────

export default definePluginEntry({
  id: "agent-passport",
  name: "Agent Passport",
  description:
    "On-chain identity for OpenClaw agents — .null name, ETH↔Solana binding, " +
    "verifiable agent identity without touching private keys.",

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
    const rpcUrl = config.rpcUrl ?? DEFAULT_RPC;

    // ── Tool 1: get_agent_passport ──────────────────────────────────────────

    api.registerTool({
      name: "get_agent_passport",
      description:
        "Return this agent's on-chain identity record: .null name, Solana wallet, " +
        "ETH address, derived PDAs, and whether the binding accounts exist on-chain. " +
        "Read-only — no signing or transactions.",
      parameters: {},
      async handler(_params: Record<string, unknown>) {
        const connection = new Connection(rpcUrl, "confirmed");

        const programs = {
          dark_secp256k1_auth: DARK_SECP256K1_AUTH,
          dark_secp256r1_vault: DARK_SECP256R1_VAULT,
          receipt_anchor: RECEIPT_ANCHOR,
        };

        // Derive ETH binding PDA if ethAddress is configured
        const ethBindingPda = config.ethAddress
          ? deriveEthBindingPda(config.ethAddress)
          : null;

        // Check account existence in parallel where PDAs are available
        const [ethBindingRegistered, webauthnVaultRegistered] = await Promise.all([
          ethBindingPda ? accountExists(connection, ethBindingPda) : Promise.resolve(false),
          config.solanaWallet
            ? (async () => {
                const vaultPda = deriveWebAuthnVaultPda(config.solanaWallet!);
                return vaultPda ? accountExists(connection, vaultPda) : false;
              })()
            : Promise.resolve(false),
        ]);

        return {
          null_name: config.nullName ?? null,
          solana_wallet: config.solanaWallet ?? null,
          eth_address: config.ethAddress ?? null,
          eth_binding_pda: ethBindingPda,
          eth_binding_registered: ethBindingRegistered,
          webauthn_vault_registered: webauthnVaultRegistered,
          network: "solana-mainnet" as const,
          programs,
        };
      },
    });

    // ── Tool 2: verify_agent_identity ───────────────────────────────────────

    api.registerTool({
      name: "verify_agent_identity",
      description:
        "Verify a DIFFERENT agent's on-chain identity. Supply at least one of " +
        "`target_solana_wallet`, `target_eth_address`, or `target_null_name`. " +
        "Returns whether the corresponding PDAs are registered on-chain. " +
        "Read-only — no signing or transactions.",
      parameters: {
        target_solana_wallet: {
          type: "string",
          description: "Target agent's Solana wallet address (base58 public key).",
        },
        target_eth_address: {
          type: "string",
          description: "Target agent's ETH address (hex, with or without 0x prefix).",
        },
        target_null_name: {
          type: "string",
          description:
            "Target agent's .null name (e.g. otheragent.null). " +
            "Informational — not resolved on-chain until null-resolver deployment.",
        },
      },
      async handler(params: Record<string, unknown>) {
        const targetWallet =
          typeof params.target_solana_wallet === "string"
            ? params.target_solana_wallet
            : undefined;
        const targetEth =
          typeof params.target_eth_address === "string"
            ? params.target_eth_address
            : undefined;
        const targetNull =
          typeof params.target_null_name === "string"
            ? params.target_null_name
            : undefined;

        if (!targetWallet && !targetEth && !targetNull) {
          return {
            ok: false,
            error:
              "Provide at least one of: target_solana_wallet, target_eth_address, target_null_name.",
          };
        }

        const connection = new Connection(rpcUrl, "confirmed");

        // Derive PDAs for the target
        const ethBindingPda = targetEth ? deriveEthBindingPda(targetEth) : null;
        const solAgentPda = targetWallet ? deriveSolAgentPda(targetWallet) : null;
        const webAuthnVaultPda = targetWallet ? deriveWebAuthnVaultPda(targetWallet) : null;

        // Check account existence in parallel
        const [ethBindingRegistered, solAgentRegistered, webauthnVaultRegistered] =
          await Promise.all([
            ethBindingPda ? accountExists(connection, ethBindingPda) : Promise.resolve(false),
            solAgentPda ? accountExists(connection, solAgentPda) : Promise.resolve(false),
            webAuthnVaultPda
              ? accountExists(connection, webAuthnVaultPda)
              : Promise.resolve(false),
          ]);

        return {
          ok: true,
          target: {
            null_name: targetNull ?? null,
            solana_wallet: targetWallet ?? null,
            eth_address: targetEth ?? null,
          },
          pdas: {
            eth_binding_pda: ethBindingPda,
            sol_agent_pda: solAgentPda,
            webauthn_vault_pda: webAuthnVaultPda,
          },
          registered: {
            eth_binding: ethBindingRegistered,
            sol_agent: solAgentRegistered,
            webauthn_vault: webauthnVaultRegistered,
          },
          network: "solana-mainnet" as const,
          programs: {
            dark_secp256k1_auth: DARK_SECP256K1_AUTH,
            dark_secp256r1_vault: DARK_SECP256R1_VAULT,
            receipt_anchor: RECEIPT_ANCHOR,
          },
        };
      },
    });
  },
});
