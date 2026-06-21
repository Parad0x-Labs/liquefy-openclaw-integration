/**
 * Pure, host-free permission logic for the Parad0x MCP server.
 *
 * Extracted from index.ts so the security-critical decisions — what may write,
 * which programs are seized, and when a write is allowed — can be unit-tested
 * without spawning the stdio server or touching Solana.
 */

/** Tools that submit an on-chain transaction (cost money / mutate state). */
export const WRITE_TOOLS = new Set<string>(["anchor_receipt", "private_compute"]);

/** Read-only tools — always callable, never gated. */
export const READ_TOOLS = new Set<string>([
  "x402_get_quote",
  "get_stack_status",
  "lookup_passport",
  "check_nullifier",
  "compress_receipts",
  "build_outcome_receipt",
  "get_scope_status",
  "grant_write_consent",
  "revoke_write_consent",
]);

/**
 * Pre-incident program IDs whose upgrade authority is under hostile control
 * (deployer key stolen 2026-06-14). NEVER call these — they await a clean
 * redeploy under Squads multisig after the trusted-setup ceremony.
 */
export const SEIZED_PROGRAMS = new Set<string>([
  "EepqzVBNuzCgD6XGiB19pDDhzFG3gUL4z1nabBYxpfjS",
  "24tmjEd1DhPW2QuPV6BzkFFHrq2PtELoLqv5cuv2Xu65",
]);

/** Throw if a program ID is one of the seized pre-incident deployments. */
export function assertNotSeized(programId: string, name: string): void {
  if (SEIZED_PROGRAMS.has(programId)) {
    throw new Error(
      `${name} (${programId}) is a SEIZED pre-incident program — upgrade authority is under hostile control. ` +
        `Do not call this program. Post-redeploy IDs will be updated here after the trusted-setup ceremony.`
    );
  }
}

export interface WriteDecision {
  allowed: boolean;
  blockedReason?: string;
}

/**
 * Decide whether an on-chain write may proceed. Grant-OR-confirm model:
 *   - `allowWrite` (operator set PARAD0X_MCP_ALLOW_WRITE=1 on this machine) is a
 *     hard prerequisite — without it, nothing writes.
 *   - then EITHER a per-call `confirm:true` OR a prior session consent
 *     (grant_write_consent) authorizes the submission.
 *
 * Pure function: all inputs are explicit so the truth table is unit-testable.
 */
export function canSubmitWrite(opts: {
  allowWrite: boolean;
  confirm: boolean;
  consented: boolean;
}): WriteDecision {
  if (!opts.allowWrite) {
    return {
      allowed: false,
      blockedReason:
        "writes disabled — operator must set PARAD0X_MCP_ALLOW_WRITE=1 on this machine",
    };
  }
  if (opts.confirm || opts.consented) {
    return { allowed: true };
  }
  return {
    allowed: false,
    blockedReason:
      "confirm:true required to submit a real transaction (or call grant_write_consent first to authorize this tool for the session)",
  };
}
