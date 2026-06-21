/**
 * Tests for the streaming/recurring billing engine (../dist/session.js) and the
 * stateful tools (../dist/tools.js, driven by a fake clock). Hermetic.
 */
import test from "node:test";
import assert from "node:assert/strict";

import {
  openSession,
  meter,
  settlementDue,
  recordSettled,
  closeSession,
  remainingBudget,
} from "../dist/session.js";
import { buildSessionTools } from "../dist/tools.js";

const meteredOpts = (over = {}) => ({
  id: "s1",
  payee: "seller.null",
  policy: { kind: "metered", settleAtUsdc: 1 },
  maxTotalUsdc: 10,
  nowUnix: 1000,
  ...over,
});

// ── validation ────────────────────────────────────────────────────────────────

test("openSession validates inputs", () => {
  assert.throws(() => openSession(meteredOpts({ payee: "" })), /id and a payee/);
  assert.throws(() => openSession(meteredOpts({ maxTotalUsdc: 0 })), /positive cap/);
  assert.throws(() => openSession(meteredOpts({ policy: { kind: "metered", settleAtUsdc: 0 } })), /settleAtUsdc/);
  assert.throws(
    () => openSession(meteredOpts({ policy: { kind: "subscription", periodSeconds: 0, periodUsdc: 1 } })),
    /periodSeconds/,
  );
});

// ── metered (pay-as-you-go) ─────────────────────────────────────────────────────

test("metered: accrue, settle at threshold, reduce accrual", () => {
  const s = openSession(meteredOpts());
  meter(s, 0.4);
  assert.equal(settlementDue(s, 1000).due, false); // 0.4 < 1
  meter(s, 0.7); // accrued 1.1 ≥ 1
  const d = settlementDue(s, 1000);
  assert.equal(d.due, true);
  assert.equal(d.amountUsdc, 1.1);
  recordSettled(s, 1.1, 1000);
  assert.equal(s.accruedUsdc, 0);
  assert.equal(s.totalSettledUsdc, 1.1);
  assert.equal(s.settlements, 1);
});

test("metered: meter() rejected on a subscription session", () => {
  const s = openSession(meteredOpts({ policy: { kind: "subscription", periodSeconds: 60, periodUsdc: 1 } }));
  assert.throws(() => meter(s, 1), /only to a metered/);
});

// ── subscription (streaming) ────────────────────────────────────────────────────

test("subscription: due after a full period, amount = periods × periodUsdc", () => {
  const s = openSession(meteredOpts({ policy: { kind: "subscription", periodSeconds: 100, periodUsdc: 2 }, maxTotalUsdc: 100 }));
  assert.equal(settlementDue(s, 1050).due, false); // 50s < 100s
  const d = settlementDue(s, 1250); // 250s elapsed → 2 periods
  assert.equal(d.due, true);
  assert.equal(d.amountUsdc, 4); // 2 periods × 2 USDC
  recordSettled(s, 4, 1250);
  assert.equal(s.totalSettledUsdc, 4);
  assert.equal(s.lastSettleUnix, 1200); // advanced by 2 × 100
  assert.equal(settlementDue(s, 1250).due, false); // caught up
});

// ── lifetime cap ────────────────────────────────────────────────────────────────

test("maxTotalUsdc caps the settlement amount and rejects over-budget settle", () => {
  const s = openSession(meteredOpts({ maxTotalUsdc: 1.5 }));
  meter(s, 5); // accrued 5, but budget only 1.5
  const d = settlementDue(s, 1000);
  assert.equal(d.amountUsdc, 1.5); // capped at remaining budget
  recordSettled(s, 1.5, 1000);
  assert.equal(remainingBudget(s), 0);
  assert.equal(settlementDue(s, 1000).due, false); // cap reached
  assert.throws(() => recordSettled(s, 0.1, 1000), /exceeds remaining budget/);
});

// ── close ────────────────────────────────────────────────────────────────────────

test("closeSession returns the final metered remainder + locks the session", () => {
  const s = openSession(meteredOpts());
  meter(s, 0.5); // below threshold, but owed on close
  const fin = closeSession(s, 1000);
  assert.equal(fin.due, true);
  assert.equal(fin.amountUsdc, 0.5);
  assert.equal(s.closed, true);
  assert.throws(() => meter(s, 1), /closed/);
});

// ── tools, with a fake clock ──────────────────────────────────────────────────────

test("tools: open → meter → check_due → record_settled end to end", async () => {
  let now = 1000;
  const [open, meterUsage, checkDue, recordSettledTool] = buildSessionTools(() => now);

  const opened = await open.handler({ payee: "seller.null", mode: "metered", settleAtUsdc: 1, maxTotalUsdc: 5 });
  assert.equal(opened.ok, true);
  const id = opened.session_id;

  await meterUsage.handler({ session_id: id, usdc: 0.6 });
  let due = await checkDue.handler({ session_id: id });
  assert.equal(due.due, false);

  await meterUsage.handler({ session_id: id, usdc: 0.6 }); // 1.2 ≥ 1
  due = await checkDue.handler({ session_id: id });
  assert.equal(due.due, true);
  assert.equal(due.amount_usdc, 1.2);
  assert.equal(due.payee, "seller.null");
  assert.match(due.next, /pay_x402/);

  const rec = await recordSettledTool.handler({ session_id: id, amount_usdc: 1.2, signature: "sig123" });
  assert.equal(rec.ok, true);
  assert.equal(rec.total_settled_usdc, 1.2);
  assert.equal(rec.signature, "sig123");
});

test("tools: subscription becomes due as the clock advances", async () => {
  let now = 1000;
  const [open, , checkDue] = buildSessionTools(() => now);
  const opened = await open.handler({ payee: "api.null", mode: "subscription", periodSeconds: 100, periodUsdc: 3, maxTotalUsdc: 30 });
  const id = opened.session_id;
  assert.equal((await checkDue.handler({ session_id: id })).due, false);
  now = 1100; // one period later
  const due = await checkDue.handler({ session_id: id });
  assert.equal(due.due, true);
  assert.equal(due.amount_usdc, 3);
});

test("tools: unknown session id errors cleanly", async () => {
  const [, , checkDue] = buildSessionTools(() => 1000);
  const r = await checkDue.handler({ session_id: "nope" });
  assert.equal(r.ok, false);
  assert.match(r.error, /unknown session_id/);
});

test("buildSessionTools registers the five session tools", () => {
  const names = buildSessionTools(() => 0).map((t) => t.name).sort();
  assert.deepEqual(names, [
    "check_settlement_due",
    "close_payment_session",
    "meter_usage",
    "open_payment_session",
    "record_settled",
  ]);
});
