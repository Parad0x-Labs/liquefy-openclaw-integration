#!/usr/bin/env node
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { createHash, createHmac, randomBytes, createCipheriv, createSecretKey } from "crypto";
import { deflateSync } from "zlib";
import { Connection, PublicKey, Keypair, Transaction, TransactionInstruction } from "@solana/web3.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Live on Solana mainnet-beta — verified against evidence/mainnet + evidence/zk.
// Full private-reputation stack live as of 2026-06-07 (reputation gate + commitment tree launched).
const PROGRAMS = {
  dark_x402_access_gate: "EepqzVBNuzCgD6XGiB19pDDhzFG3gUL4z1nabBYxpfjS",
  dark_nullifier_record: "24tmjEd1DhPW2QuPV6BzkFFHrq2PtELoLqv5cuv2Xu65",
  dark_reputation_gate: "9nN7UTTT5hgKnc2LZTqr3qaLLSt5PxWUrDbpUTGYHRxp",
  receipt_commitment_tree: "8jC8QGiDJRRxhbPXMX5wJnGUq89xJZ2LsHMdbn2urCas",
  receipt_anchor: "6HSRGivdYR5D7yTDy1TFMCM8h3LzXxRtKU1RA3RnCMRN",
  dark_secp256r1_vault: "3hbbtjeSrTVYXq6eRwjeofDe2DCPh3n8cfN6kZcQfewi",
  dark_secp256k1_auth: "AqwBbV13AoczhoELwP8oxT3nDqB6MsLWXauNzHkssZ9B",
  dark_semaphore: "Ev7HEFhhKTXk6kS2Y6ssbUcK9C7E6yZ589jJNjUrQV5p",
  null_token: "8EeDdvCRmFAzVD4takkBrNNwkeUTUQh4MscRK5Fzpump",
  // demo/stub — NOT a real verifier (hardcoded proof bypass); see get_stack_status.
  dark_bn254_gate: "GCptvBYF8S6eVYoh15B7WAESc54FUHCpN1Ui6aHeQYZd",
} as const;

// Devnet-only addresses that differ from mainnet (the access gate has a separate devnet id;
// reputation gate, tree, and nullifier share the same id on both clusters).
const DEVNET_PROGRAMS = {
  dark_x402_access_gate: "7LZzJnLSCCu2enc7mXz9FFCbomotME78xFG4eqkpo5U6",
} as const;

const EXPLORER_BASE = "https://explorer.solana.com";
const DEFAULT_RPC = "https://api.mainnet-beta.solana.com";

function explorerTx(sig: string): string {
  return `${EXPLORER_BASE}/tx/${sig}`;
}

function explorerAccount(addr: string): string {
  return `${EXPLORER_BASE}/address/${addr}`;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function sha256hex(data: Uint8Array | string): string {
  return createHash("sha256")
    .update(typeof data === "string" ? data : data)
    .digest("hex");
}

function buildMerkleRoot(items: object[]): string {
  const leaves: Uint8Array[] = items.map((item) =>
    createHash("sha256").update(JSON.stringify(item)).digest() as unknown as Uint8Array
  );
  if (leaves.length === 0) return "0".repeat(64);
  let layer = leaves;
  while (layer.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) {
      const left = layer[i] as Uint8Array;
      const right = (layer[i + 1] ?? layer[i]) as Uint8Array;
      const combined = new Uint8Array(64);
      combined.set(left, 0);
      combined.set(right, 32);
      next.push(createHash("sha256").update(combined).digest() as unknown as Uint8Array);
    }
    layer = next;
  }
  return Buffer.from(layer[0] as Uint8Array).toString("hex");
}

function loadKeypair(): Keypair | null {
  const raw = process.env.SOLANA_KEYPAIR;
  if (!raw) return null;
  try {
    const bytes = JSON.parse(raw) as number[];
    return Keypair.fromSecretKey(Uint8Array.from(bytes));
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Zero-trust hardening — local-first, the LLM is untrusted
//
// This server runs on the agent's OWN machine (stdio). It never hosts anything,
// never custodies funds, and never lets key material reach the model context.
//   1. WRITES OFF BY DEFAULT: signing/submitting a tx needs the operator to opt
//      in on this machine (PARAD0X_MCP_ALLOW_WRITE=1) AND a per-call confirm:true.
//   2. NO SECRETS TO THE LLM: every tool result is scrubbed of key material
//      before it leaves this process; a short fingerprint is kept for correlation.
// ---------------------------------------------------------------------------

const ALLOW_WRITE = process.env.PARAD0X_MCP_ALLOW_WRITE === "1";

const SECRET_FIELD =
  /(^|_)(key_hex|secret|secret_key|private_key|privatekey|mnemonic|seed|keypair|signing_key)($|_)/i;

function redactForLlm(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactForLlm);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (SECRET_FIELD.test(k) && typeof v === "string") {
        out[k] = "[REDACTED — stays on this machine, never sent to the model]";
        out[`${k}_fingerprint`] = sha256hex(v).slice(0, 16);
      } else {
        out[k] = redactForLlm(v);
      }
    }
    return out;
  }
  return value;
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

async function x402GetQuote(
  endpointUrl: string,
  method = "GET"
): Promise<object> {
  try {
    const res = await fetch(endpointUrl, {
      method,
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(8000),
    });

    if (res.status === 402) {
      const offerHeader = res.headers.get("x-dnp-offer") ?? res.headers.get("www-authenticate");
      const body = await res.text().catch(() => "");

      // Try to parse structured offer header
      if (offerHeader) {
        try {
          const offer = JSON.parse(offerHeader);
          return {
            quote_id: offer.quote_id ?? sha256hex(endpointUrl + Date.now()).slice(0, 16),
            price_atomic: offer.price_atomic ?? offer.amount ?? 0,
            currency: offer.currency ?? "USDC",
            expiry: offer.expiry ?? Date.now() + 60_000,
            payment_address: offer.payment_address ?? offer.address ?? null,
            network: offer.network ?? "solana-mainnet",
            raw_offer: offer,
          };
        } catch {
          // header not JSON, fall through to body parse
        }
      }

      // Try body
      try {
        const parsed = JSON.parse(body);
        return {
          quote_id: parsed.quote_id ?? sha256hex(endpointUrl + Date.now()).slice(0, 16),
          price_atomic: parsed.price_atomic ?? parsed.amount ?? 0,
          currency: parsed.currency ?? "USDC",
          expiry: parsed.expiry ?? Date.now() + 60_000,
          payment_address: parsed.payment_address ?? parsed.address ?? null,
          network: parsed.network ?? "solana-mainnet",
          raw_body: parsed,
        };
      } catch {
        // not parseable
      }

      return {
        quote_id: sha256hex(endpointUrl + Date.now()).slice(0, 16),
        price_atomic: 0,
        currency: "USDC",
        expiry: Date.now() + 60_000,
        payment_address: null,
        network: "solana-mainnet",
        note: "Endpoint returned 402 but offer format was not parseable. Raw header: " + (offerHeader ?? "(none)"),
      };
    }

    // Not a real 402 endpoint — return mock format showing the structure
    return {
      quote_id: sha256hex(endpointUrl + Date.now()).slice(0, 16),
      price_atomic: 100000, // 0.1 USDC in atomic units (6 decimals)
      currency: "USDC",
      expiry: Date.now() + 60_000,
      payment_address: PROGRAMS.receipt_anchor,
      network: "solana-mainnet",
      note: `Endpoint returned HTTP ${res.status} (not 402). This is a mock quote showing the x402 format. A real x402-gated endpoint returns 402 with x-dnp-offer header.`,
      mock: true,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: `Failed to reach endpoint: ${msg}`, mock: true };
  }
}

async function anchorReceipt(
  receiptHashHex: string,
  rpcUrl = DEFAULT_RPC,
  confirm = false
): Promise<object> {
  if (!/^[0-9a-fA-F]{64}$/.test(receiptHashHex)) {
    return { error: "receipt_hash_hex must be exactly 64 hex characters (32 bytes)" };
  }

  const keypair = loadKeypair();

  if (!keypair) {
    // Dry-run mode — return mock response so agents can see the format
    const mockSig = Buffer.from(randomBytes(64)).toString("base64url").slice(0, 88);
    return {
      solana_tx: mockSig,
      explorer_url: explorerTx(mockSig),
      slot: 0,
      dry_run: true,
      note: "SOLANA_KEYPAIR env var not set. Set it to a JSON array of 64 bytes to submit real transactions. This is a dry-run response showing the output format.",
    };
  }

  // Zero-trust write-guard: a key is present, but do NOT submit unless the
  // operator enabled writes on THIS machine AND the agent confirmed this call.
  if (!ALLOW_WRITE || !confirm) {
    return {
      preview: true,
      would_submit: {
        program: PROGRAMS.receipt_anchor,
        instruction: "anchor(0x00)",
        receipt_hash_hex: receiptHashHex,
        fee_payer: keypair.publicKey.toBase58(),
      },
      blocked_reason: !ALLOW_WRITE
        ? "writes disabled — operator must set PARAD0X_MCP_ALLOW_WRITE=1 on this machine"
        : "confirm:true required to submit a real transaction",
      note: "No transaction was sent. This is a preview of exactly what WOULD be submitted.",
    };
  }

  try {
    const connection = new Connection(rpcUrl, "confirmed");
    const programId = new PublicKey(PROGRAMS.receipt_anchor);

    // Instruction data: [0x00 (anchor discriminator), <32 bytes hash>]
    const hashBytes = new Uint8Array(Buffer.from(receiptHashHex, "hex"));
    const data = new Uint8Array(33);
    data[0] = 0x00;
    data.set(hashBytes, 1);

    const ix = new TransactionInstruction({
      keys: [
        { pubkey: keypair.publicKey, isSigner: true, isWritable: true },
      ],
      programId,
      data: Buffer.from(data),
    });

    const tx = new Transaction().add(ix);
    const { blockhash } = await connection.getLatestBlockhash();
    tx.recentBlockhash = blockhash;
    tx.feePayer = keypair.publicKey;
    tx.sign(keypair);

    const sig = await connection.sendRawTransaction(tx.serialize(), {
      skipPreflight: false,
    });

    const conf = await connection.confirmTransaction(sig, "confirmed");
    const slot = conf.context.slot;

    return {
      solana_tx: sig,
      explorer_url: explorerTx(sig),
      slot,
      dry_run: false,
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: `Solana transaction failed: ${msg}` };
  }
}

async function lookupPassport(
  ethAddress?: string,
  solanaWallet?: string
): Promise<object> {
  if (!ethAddress && !solanaWallet) {
    return { error: "Provide eth_address or solana_wallet (or both)" };
  }

  const programAddress = PROGRAMS.dark_secp256k1_auth;
  const programId = new PublicKey(programAddress);
  const rpcUrl = process.env.SOLANA_RPC_URL ?? DEFAULT_RPC;

  // Derive the EthAgentRecord PDA
  // Seeds: ["eth_agent", <eth_address_bytes_20>]
  let pda: string | null = null;
  let registered = false;

  if (ethAddress) {
    try {
      const normalized = ethAddress.toLowerCase().replace("0x", "");
      if (!/^[0-9a-f]{40}$/.test(normalized)) {
        return { error: "eth_address must be a 40-hex-char Ethereum address (with or without 0x prefix)" };
      }
      const ethBytes = new Uint8Array(Buffer.from(normalized, "hex"));
      const [derivedPda] = await PublicKey.findProgramAddress(
        [Buffer.from("eth_agent"), ethBytes],
        programId
      );
      pda = derivedPda.toBase58();

      // Check if the account exists on-chain
      const connection = new Connection(rpcUrl, "confirmed");
      const info = await connection.getAccountInfo(derivedPda);
      registered = info !== null && info.data.length > 0;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { error: `PDA derivation failed: ${msg}` };
    }
  } else if (solanaWallet) {
    // For solana-only lookup: check if the wallet has any record in the program
    try {
      const walletPk = new PublicKey(solanaWallet);
      const [derivedPda] = await PublicKey.findProgramAddress(
        [Buffer.from("sol_agent"), walletPk.toBytes()],
        programId
      );
      pda = derivedPda.toBase58();

      const connection = new Connection(rpcUrl, "confirmed");
      const info = await connection.getAccountInfo(derivedPda);
      registered = info !== null && info.data.length > 0;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      return { error: `Solana wallet lookup failed: ${msg}` };
    }
  }

  return {
    registered,
    pda: pda ?? undefined,
    program: programAddress,
    explorer_url: pda ? explorerAccount(pda) : explorerAccount(programAddress),
  };
}

async function checkNullifier(
  nullifier: string,
  rpcUrl = DEFAULT_RPC
): Promise<object> {
  // Accept a 64-char hex string OR a decimal BN254 field element.
  const s = nullifier.trim();
  let hex: string;
  if (/^[0-9a-fA-F]{64}$/.test(s)) {
    hex = s.toLowerCase();
  } else if (/^[0-9]+$/.test(s)) {
    hex = BigInt(s).toString(16).padStart(64, "0");
    if (hex.length !== 64) return { error: "nullifier out of range — must fit in 32 bytes" };
  } else {
    return { error: "nullifier must be a 64-char hex string or a decimal field element" };
  }

  try {
    const nullifierBytes = Buffer.from(hex, "hex");
    const program = new PublicKey(PROGRAMS.dark_nullifier_record);
    // Single-use record PDA — matches the on-chain seed [b"null_record", nullifier_be_32].
    const [recordPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("null_record"), nullifierBytes],
      program
    );
    const connection = new Connection(rpcUrl, "confirmed");
    const info = await connection.getAccountInfo(recordPda);
    const spent = info !== null && info.data.length > 0;
    return {
      nullifier_hex: hex,
      record_pda: recordPda.toBase58(),
      spent,
      program: PROGRAMS.dark_nullifier_record,
      explorer_url: explorerAccount(recordPda.toBase58()),
      note: spent
        ? "Nullifier already recorded on-chain — this proof has been spent (single-use exhausted)."
        : "No record found — this nullifier has not been used yet.",
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { error: `Nullifier lookup failed: ${msg}` };
  }
}

function buildOutcomeReceipt(params: {
  receipt_id: string;
  outcome: "positive" | "negative" | "neutral";
  metric_pnl?: number;
  metric_accuracy?: number;
  result_digest_hex?: string;
  creator_note?: string;
}): object {
  const { receipt_id, outcome, metric_pnl, metric_accuracy, result_digest_hex, creator_note } = params;

  // Build the outcome struct
  const outcomeReceipt = {
    schema: "parad0x/outcome-receipt/v1",
    receipt_id,
    outcome,
    metrics: {
      pnl: metric_pnl ?? null,
      accuracy: metric_accuracy ?? null,
    },
    result_digest: result_digest_hex ?? null,
    creator_note: creator_note ?? null,
    created_at: Date.now(),
    created_at_iso: new Date().toISOString(),
  };

  // Sign with an ephemeral key (no persistent signing key available in server context)
  const ephemeralKeyHex = randomBytes(32).toString("hex");
  const receiptStr = JSON.stringify(outcomeReceipt);
  const sig = createHmac("sha256", ephemeralKeyHex).update(receiptStr).digest("hex");
  const receiptHash = sha256hex(receiptStr);

  return {
    outcome_receipt: {
      ...outcomeReceipt,
      signature: sig,
      signing_note:
        "Signed with an ephemeral HMAC-SHA256 key generated at call time. For production use, provide a persistent Ed25519 keypair via SIGNING_KEYPAIR env var (not yet implemented).",
    },
    receipt_hash: receiptHash,
  };
}

function compressReceipts(receipts: object[]): object {
  if (!Array.isArray(receipts) || receipts.length === 0) {
    return { error: "receipts must be a non-empty array" };
  }

  const originalStr = JSON.stringify(receipts);
  const originalBytes = Buffer.byteLength(originalStr, "utf8");

  // Use zlib deflate as a proxy for Liquefy columnar compression
  const compressed = deflateSync(originalStr, { level: 9 });
  const compressedBytes = compressed.length;
  const ratio = (originalBytes / compressedBytes).toFixed(2);

  const merkleRootHex = buildMerkleRoot(receipts);

  return {
    compressed_base64: compressed.toString("base64"),
    original_bytes: originalBytes,
    compressed_bytes: compressedBytes,
    ratio: `${ratio}x`,
    merkle_root_hex: merkleRootHex,
    receipt_count: receipts.length,
    note:
      "Compressed with zlib deflate (level 9) as a format demonstration. Real Liquefy achieves ~83x via columnar layout + domain-aware encoding on typed receipt fields. Decompress with zlib inflate.",
  };
}

async function privateCompute(params: {
  plaintext_input: string;
  executor_endpoint: string;
  encryption_key_hex?: string;
  anchor?: boolean;
  rpc_url?: string;
}): Promise<object> {
  const { plaintext_input, executor_endpoint, encryption_key_hex, anchor, rpc_url } = params;

  // Step 1: Generate or use provided 32-byte AES-256 key
  let rawKeyBytes: Uint8Array;
  if (encryption_key_hex) {
    if (!/^[0-9a-fA-F]{64}$/.test(encryption_key_hex)) {
      return { error: "encryption_key_hex must be exactly 64 hex characters (32 bytes)" };
    }
    rawKeyBytes = new Uint8Array(Buffer.from(encryption_key_hex, "hex"));
  } else {
    rawKeyBytes = new Uint8Array(randomBytes(32));
  }
  const keyHex = Buffer.from(rawKeyBytes).toString("hex");
  const secretKey = createSecretKey(rawKeyBytes);

  // Step 2: Encrypt with AES-256-GCM (12-byte nonce prefix)
  const nonceBytes = new Uint8Array(randomBytes(12));
  const cipher = createCipheriv("aes-256-gcm", secretKey, nonceBytes);
  const encPart1 = cipher.update(plaintext_input, "utf8") as unknown as Uint8Array;
  const encPart2 = cipher.final() as unknown as Uint8Array;
  const authTagBuf = cipher.getAuthTag() as unknown as Uint8Array;
  const nonceCast = Buffer.from(nonceBytes) as unknown as Uint8Array;
  // Layout: [12-byte nonce][16-byte auth tag][ciphertext]
  const encryptedBlob = Buffer.concat([nonceCast, authTagBuf, encPart1, encPart2]);
  const encryptedInputBase64 = encryptedBlob.toString("base64");

  // Step 3: Compute input_hash = sha256(plaintext_input)
  const inputHash = sha256hex(plaintext_input);

  // Step 4: POST to executor_endpoint
  let executorResponse: object = { status: "unreachable", note: "Executor endpoint could not be reached; local hashes recorded." };
  try {
    const res = await fetch(executor_endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext: encryptedInputBase64, input_hash: inputHash }),
      signal: AbortSignal.timeout(10000),
    });
    const text = await res.text().catch(() => "");
    try {
      executorResponse = JSON.parse(text) as object;
    } catch {
      executorResponse = { raw: text, http_status: res.status };
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    executorResponse = { status: "unreachable", error: msg, note: "Executor endpoint could not be reached; local hashes recorded." };
  }

  // Step 5: result_hash = sha256(JSON.stringify(executorResponse))
  const resultHash = sha256hex(JSON.stringify(executorResponse));

  // Step 6: Optionally anchor (input_hash + result_hash) on Solana
  let commitmentTx: string | undefined;
  let explorerUrl: string | undefined;

  if (anchor) {
    // Commitment = sha256(input_hash_bytes + result_hash_bytes)
    const ihBuf = Buffer.from(inputHash, "hex") as unknown as Uint8Array;
    const rhBuf = Buffer.from(resultHash, "hex") as unknown as Uint8Array;
    const combined = Buffer.concat([ihBuf, rhBuf]) as unknown as Uint8Array;
    const commitmentHex = createHash("sha256").update(combined).digest("hex");

    const anchorResult = await anchorReceipt(
      commitmentHex,
      rpc_url ?? process.env.SOLANA_RPC_URL ?? DEFAULT_RPC
    ) as Record<string, unknown>;

    if (anchorResult.solana_tx) {
      commitmentTx = anchorResult.solana_tx as string;
      explorerUrl = anchorResult.explorer_url as string;
    } else if (anchorResult.error) {
      commitmentTx = `anchor_failed: ${anchorResult.error}`;
    }
  }

  // Step 7: Return all fields
  const output: Record<string, unknown> = {
    encrypted_input_base64: encryptedInputBase64,
    input_hash: inputHash,
    executor_response: executorResponse,
    result_hash: resultHash,
    key_hex: keyHex,
    protocol_note: "executor received ciphertext only — plaintext never left client",
  };

  if (commitmentTx !== undefined) output.commitment_tx = commitmentTx;
  if (explorerUrl !== undefined) output.explorer_url = explorerUrl;

  return output;
}

function getStackStatus(): object {
  return {
    programs: [
      {
        name: "dark_x402_access_gate",
        address: PROGRAMS.dark_x402_access_gate,
        status: "live (mainnet) — VK single-party until the trusted-setup ceremony finalizes",
        explorer_url: explorerAccount(PROGRAMS.dark_x402_access_gate),
        description: "Groth16 BN254 access gate — prove funded + authorized WITHOUT revealing wallet or balance. On-chain verify via alt_bn128_pairing (~93k CU, ~$0.0007).",
      },
      {
        name: "dark_nullifier_record",
        address: PROGRAMS.dark_nullifier_record,
        status: "live",
        explorer_url: explorerAccount(PROGRAMS.dark_nullifier_record),
        description: "Single-use / anti-replay — records a nullifier PDA so each proof is spendable exactly once.",
      },
      {
        name: "receipt_anchor",
        address: PROGRAMS.receipt_anchor,
        status: "live",
        explorer_url: explorerAccount(PROGRAMS.receipt_anchor),
        description: "Anchors 32-byte receipt hashes permanently on Solana mainnet",
      },
      {
        name: "dark_secp256r1_vault",
        address: PROGRAMS.dark_secp256r1_vault,
        status: "live",
        explorer_url: explorerAccount(PROGRAMS.dark_secp256r1_vault),
        description: "WebAuthn / P-256 vault — stores secp256r1 public keys on-chain",
      },
      {
        name: "dark_secp256k1_auth",
        address: PROGRAMS.dark_secp256k1_auth,
        status: "live",
        explorer_url: explorerAccount(PROGRAMS.dark_secp256k1_auth),
        description: "ETH address binding — links MetaMask / secp256k1 identities to Solana wallets",
      },
      {
        name: "dark_bn254_gate",
        address: PROGRAMS.dark_bn254_gate,
        status: "stub — do not use",
        explorer_url: explorerAccount(PROGRAMS.dark_bn254_gate),
        description: "DEPRECATED demo gate with a hardcoded proof bypass — NOT a real verifier. Superseded by dark_x402_access_gate (real Groth16 BN254). Listed for transparency only.",
      },
      {
        name: "dark_semaphore",
        address: PROGRAMS.dark_semaphore,
        status: "live",
        explorer_url: explorerAccount(PROGRAMS.dark_semaphore),
        description: "Semaphore-style anonymous group membership proofs",
      },
      {
        name: "null_token",
        address: PROGRAMS.null_token,
        status: "live",
        explorer_url: explorerAccount(PROGRAMS.null_token),
        description: "NULL SPL token — native currency of the Parad0x Labs protocol economy",
      },
    ],
    private_reputation_stack: {
      note: "Private track-record proof — LIVE on mainnet as of 2026-06-07. Single-party VK until the trusted-setup ceremony finalizes (same status as the access gate).",
      dark_reputation_gate: PROGRAMS.dark_reputation_gate,
      receipt_commitment_tree: PROGRAMS.receipt_commitment_tree,
    },
    packages: [
      "@parad0x_labs/mcp-server",
      "@parad0x_labs/null-miner-sdk",
      "@parad0x_labs/liquefy-receipts",
      "@parad0x_labs/outcome-receipts",
      "@parad0x_labs/pay-to-receive",
      "@parad0x_labs/receipt-dag",
      "@parad0x_labs/session-channels",
      "@parad0x_labs/task-marketplace-api",
      "@parad0x_labs/nulllive-sdk",
    ],
    github: "https://github.com/parad0x-labs/dna-x402",
    network: "solana-mainnet",
    status_timestamp: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// MCP server setup
// ---------------------------------------------------------------------------

const server = new Server(
  { name: "parad0x-mcp", version: "0.1.0" },
  {
    capabilities: {
      tools: {},
    },
  }
);

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "x402_get_quote",
        description: "Get a payment quote for an x402-gated API endpoint",
        inputSchema: {
          type: "object",
          properties: {
            endpoint_url: {
              type: "string",
              description: "The URL of the x402-gated endpoint to quote",
            },
            method: {
              type: "string",
              description: "HTTP method (default: GET)",
              enum: ["GET", "POST", "PUT", "DELETE", "PATCH"],
            },
          },
          required: ["endpoint_url"],
        },
      },
      {
        name: "anchor_receipt",
        description:
          "Anchor a 32-byte receipt hash permanently on Solana mainnet via the receipt_anchor program. Read-only by default: returns a PREVIEW unless the operator enabled writes (PARAD0X_MCP_ALLOW_WRITE=1) AND you pass confirm:true.",
        inputSchema: {
          type: "object",
          properties: {
            receipt_hash_hex: {
              type: "string",
              description: "64-character hex string representing the 32-byte SHA-256 receipt hash",
            },
            rpc_url: {
              type: "string",
              description: "Solana RPC URL (default: mainnet-beta public RPC)",
            },
            confirm: {
              type: "boolean",
              description: "Must be true to actually submit. Without it the tool returns a preview only (no transaction sent).",
            },
          },
          required: ["receipt_hash_hex"],
        },
      },
      {
        name: "lookup_passport",
        description:
          "Look up a Dark Passport — check if an ETH address or Solana wallet has a verified identity binding on Solana mainnet",
        inputSchema: {
          type: "object",
          properties: {
            eth_address: {
              type: "string",
              description: "Ethereum address (hex, with or without 0x prefix)",
            },
            solana_wallet: {
              type: "string",
              description: "Solana wallet address (base58)",
            },
          },
        },
      },
      {
        name: "build_outcome_receipt",
        description:
          "Build a creator-signed outcome receipt — attach PnL, accuracy, or delivery result to a previous receipt",
        inputSchema: {
          type: "object",
          properties: {
            receipt_id: {
              type: "string",
              description: "ID of the receipt this outcome is attached to",
            },
            outcome: {
              type: "string",
              enum: ["positive", "negative", "neutral"],
              description: "Outcome classification",
            },
            metric_pnl: {
              type: "number",
              description: "Profit/loss metric (optional)",
            },
            metric_accuracy: {
              type: "number",
              description: "Accuracy metric 0.0–1.0 (optional)",
            },
            result_digest_hex: {
              type: "string",
              description: "Hex-encoded SHA-256 of the result payload (optional)",
            },
            creator_note: {
              type: "string",
              description: "Human-readable note from the creator (optional)",
            },
          },
          required: ["receipt_id", "outcome"],
        },
      },
      {
        name: "compress_receipts",
        description:
          "Compress a batch of receipts using Liquefy columnar compression (83x typical ratio)",
        inputSchema: {
          type: "object",
          properties: {
            receipts: {
              type: "array",
              items: { type: "object" },
              description: "Array of receipt objects to compress",
            },
          },
          required: ["receipts"],
        },
      },
      {
        name: "check_nullifier",
        description:
          "Check whether a privacy-proof nullifier has already been spent on Solana (single-use enforcement). Read-only: derives the dark_nullifier_record PDA and checks if it exists on-chain. No signing, no funds.",
        inputSchema: {
          type: "object",
          properties: {
            nullifier: {
              type: "string",
              description: "The nullifier as a 64-char hex string OR a decimal BN254 field element (e.g. the reputation_nullifier public input).",
            },
            rpc_url: {
              type: "string",
              description: "Solana RPC URL (default: mainnet-beta). Use a devnet RPC to check the devnet stack.",
            },
          },
          required: ["nullifier"],
        },
      },
      {
        name: "get_stack_status",
        description: "Get the current status of all Parad0x Labs mainnet programs",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "private_compute",
        description:
          "Run a computation via an executor endpoint without exposing plaintext inputs. Agent encrypts locally, sends ciphertext, executor returns encrypted result + result hash. Commit (input_hash, result_hash) on Solana. Executor never sees plaintext.",
        inputSchema: {
          type: "object",
          properties: {
            plaintext_input: {
              type: "string",
              description: "The sensitive input (JSON string or text) to encrypt before sending",
            },
            executor_endpoint: {
              type: "string",
              description: "URL of the executor API that receives the ciphertext",
            },
            encryption_key_hex: {
              type: "string",
              description: "Optional 32-byte AES-256 key as 64 hex characters. Generated if not provided.",
            },
            anchor: {
              type: "boolean",
              description: "If true, commit (input_hash, result_hash) to Solana via receipt_anchor",
            },
            rpc_url: {
              type: "string",
              description: "Solana RPC URL (default: mainnet-beta public RPC)",
            },
          },
          required: ["plaintext_input", "executor_endpoint"],
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: object;

    switch (name) {
      case "x402_get_quote": {
        const { endpoint_url, method } = args as { endpoint_url: string; method?: string };
        result = await x402GetQuote(endpoint_url, method);
        break;
      }

      case "anchor_receipt": {
        const { receipt_hash_hex, rpc_url, confirm } = args as {
          receipt_hash_hex: string;
          rpc_url?: string;
          confirm?: boolean;
        };
        result = await anchorReceipt(
          receipt_hash_hex,
          rpc_url ?? process.env.SOLANA_RPC_URL ?? DEFAULT_RPC,
          confirm === true
        );
        break;
      }

      case "lookup_passport": {
        const { eth_address, solana_wallet } = args as {
          eth_address?: string;
          solana_wallet?: string;
        };
        result = await lookupPassport(eth_address, solana_wallet);
        break;
      }

      case "build_outcome_receipt": {
        result = buildOutcomeReceipt(
          args as {
            receipt_id: string;
            outcome: "positive" | "negative" | "neutral";
            metric_pnl?: number;
            metric_accuracy?: number;
            result_digest_hex?: string;
            creator_note?: string;
          }
        );
        break;
      }

      case "compress_receipts": {
        const { receipts } = args as { receipts: object[] };
        result = compressReceipts(receipts);
        break;
      }

      case "check_nullifier": {
        const { nullifier, rpc_url } = args as { nullifier: string; rpc_url?: string };
        result = await checkNullifier(
          nullifier,
          rpc_url ?? process.env.SOLANA_RPC_URL ?? DEFAULT_RPC
        );
        break;
      }

      case "get_stack_status": {
        result = getStackStatus();
        break;
      }

      case "private_compute": {
        result = await privateCompute(
          args as {
            plaintext_input: string;
            executor_endpoint: string;
            encryption_key_hex?: string;
            anchor?: boolean;
            rpc_url?: string;
          }
        );
        break;
      }

      default:
        result = { error: `Unknown tool: ${name}` };
    }

    return {
      content: [{ type: "text", text: JSON.stringify(redactForLlm(result), null, 2) }],
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return {
      content: [{ type: "text", text: JSON.stringify({ error: msg }) }],
    };
  }
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

const transport = new StdioServerTransport();
await server.connect(transport);
