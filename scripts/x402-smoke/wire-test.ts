/**
 * Wire-contract test: the buyer's payment header (x402-pay) must be accepted by
 * the seller's structural verifier (x402-gate). This catches field-name drift
 * between the two skills — the class of bug (amountAtomic vs amount) that makes
 * every real payment fail AFTER the buyer's funds have settled.
 *
 * No network. Run: cd scripts/x402-smoke && npx tsx wire-test.ts
 */

import { buildPaymentHeader } from "../../skills/x402-pay/src/client";
import { makeRequirement, verifyPaymentStructure } from "../../skills/x402-gate/src/gate";

let fail = 0;
const assert = (name: string, ok: boolean, extra?: string) => {
  if (!ok) fail++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${extra ? " — " + extra : ""}`);
};

const requirement = makeRequirement({
  priceUsdc: 0.05,
  recipientAddress: "9vDnXsPonRJa7yAmvwRGMAdxt8W13Qbm7HZuvauM3Ya3",
  resource: "/premium",
  network: "solana-devnet",
});

// The buyer pays exactly what was asked and presents the proof.
const header = buildPaymentHeader({
  signature: "wireTestSignaturePlaceholder000000000000000000000000000000000000",
  payerAddress: "FZAG4bTAmMTkb9hwmq5eFRn82k2UjDcGWCNHoERjpxi1",
  amount: requirement.maxAmountRequired,
  resource: requirement.resource,
});

const res = verifyPaymentStructure(header, requirement);
assert("buyer proof passes gate structural verify (wire fields agree)", res.valid === true, res.valid ? "" : (res as { error: string }).error);
if (res.valid) {
  assert("amount round-trips", res.amountAtomic === Number(requirement.maxAmountRequired), `${res.amountAtomic} vs ${requirement.maxAmountRequired}`);
  assert("resource matches", res.resource === requirement.resource);
}

// An underpaid proof must be rejected structurally.
const cheap = buildPaymentHeader({ signature: "s", payerAddress: "p", amount: "1", resource: requirement.resource });
const r2 = verifyPaymentStructure(cheap, requirement);
assert("underpaid proof rejected", r2.valid === false);

console.log(`\n${fail === 0 ? "WIRE OK" : "WIRE FAILED"} — ${fail} failure(s)`);
process.exit(fail === 0 ? 0 : 1);
