/**
 * payment-session tools — stateful session registry over the pure engine.
 *
 * The agent loop: open_payment_session → meter_usage (metered) or just wait
 * (subscription) → check_settlement_due → if due, pay the payee via x402-pay's
 * pay_x402 → record_settled. close_payment_session settles any remainder.
 *
 * `nowFn` is injectable so the scheduling is unit-testable with a fake clock.
 */

import {
  openSession,
  meter,
  settlementDue,
  recordSettled,
  closeSession,
  remainingBudget,
} from "./session.js";
import type { PaymentSession, SettlePolicy } from "./session.js";

export interface ToolDef {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  handler: (params: Record<string, unknown>) => Promise<unknown>;
}

function snapshot(s: PaymentSession) {
  return {
    session_id: s.id,
    payee: s.payee,
    mode: s.policy.kind,
    accrued_usdc: s.accruedUsdc,
    total_settled_usdc: s.totalSettledUsdc,
    settlements: s.settlements,
    remaining_budget_usdc: remainingBudget(s),
    closed: s.closed,
  };
}

export function buildSessionTools(nowFn: () => number = () => Math.floor(Date.now() / 1000)): ToolDef[] {
  const sessions = new Map<string, PaymentSession>();
  let counter = 0;
  const get = (id: string): PaymentSession | undefined => sessions.get(id);

  const open: ToolDef = {
    name: "open_payment_session",
    description:
      "Open a streaming/recurring billing session. mode=metered (pay-as-you-go: accrue usage, settle at a threshold) " +
      "or mode=subscription (charge periodUsdc every periodSeconds). A hard maxTotalUsdc lifetime cap bounds it. " +
      "Settlement rides x402: when due, pay the payee with pay_x402, then call record_settled.",
    parameters: {
      payee: { type: "string", description: "Who gets paid — a .null name or an x402 endpoint URL." },
      mode: { type: "string", enum: ["metered", "subscription"], description: "Billing shape." },
      maxTotalUsdc: { type: "number", description: "Hard lifetime cap (USDC) for this session." },
      settleAtUsdc: { type: "number", description: "metered: settle once accrued usage reaches this many USDC." },
      periodSeconds: { type: "number", description: "subscription: seconds per billing period." },
      periodUsdc: { type: "number", description: "subscription: USDC charged each period." },
    },
    async handler(p: Record<string, unknown>) {
      try {
        const payee = String(p.payee ?? "");
        const mode = String(p.mode ?? "");
        const maxTotalUsdc = Number(p.maxTotalUsdc);
        let policy: SettlePolicy;
        if (mode === "metered") {
          policy = { kind: "metered", settleAtUsdc: Number(p.settleAtUsdc) };
        } else if (mode === "subscription") {
          policy = { kind: "subscription", periodSeconds: Number(p.periodSeconds), periodUsdc: Number(p.periodUsdc) };
        } else {
          return { ok: false, error: "mode must be 'metered' or 'subscription'." };
        }
        const id = `sess_${++counter}`;
        const s = openSession({ id, payee, policy, maxTotalUsdc, nowUnix: nowFn() });
        sessions.set(id, s);
        return { ok: true, ...snapshot(s) };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    },
  };

  const meterUsage: ToolDef = {
    name: "meter_usage",
    description: "Record metered (pay-as-you-go) usage in USDC against a session. Metered sessions only.",
    parameters: {
      session_id: { type: "string" },
      usdc: { type: "number", description: "USDC value of the usage to accrue." },
    },
    async handler(p: Record<string, unknown>) {
      const s = get(String(p.session_id ?? ""));
      if (!s) return { ok: false, error: "unknown session_id." };
      try {
        meter(s, Number(p.usdc));
        return { ok: true, ...snapshot(s) };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    },
  };

  const checkDue: ToolDef = {
    name: "check_settlement_due",
    description:
      "Check whether a payment is due now and for how much. If due, pay the payee with pay_x402(payee, amount_usdc), " +
      "then call record_settled with the same amount.",
    parameters: { session_id: { type: "string" } },
    async handler(p: Record<string, unknown>) {
      const s = get(String(p.session_id ?? ""));
      if (!s) return { ok: false, error: "unknown session_id." };
      const d = settlementDue(s, nowFn());
      return {
        ok: true,
        session_id: s.id,
        payee: s.payee,
        due: d.due,
        amount_usdc: d.amountUsdc,
        reason: d.reason,
        next: d.due
          ? `Pay it: pay_x402("${s.payee}") for ${d.amountUsdc} USDC, then record_settled({ session_id, amount_usdc: ${d.amountUsdc} }).`
          : "Nothing due yet.",
      };
    },
  };

  const recordSettledTool: ToolDef = {
    name: "record_settled",
    description: "Record that a settlement was paid (after pay_x402 succeeded). Advances the session and enforces the cap.",
    parameters: {
      session_id: { type: "string" },
      amount_usdc: { type: "number" },
      signature: { type: "string", description: "Optional Solana tx signature of the settlement payment." },
    },
    async handler(p: Record<string, unknown>) {
      const s = get(String(p.session_id ?? ""));
      if (!s) return { ok: false, error: "unknown session_id." };
      try {
        recordSettled(s, Number(p.amount_usdc), nowFn());
        return { ok: true, signature: typeof p.signature === "string" ? p.signature : null, ...snapshot(s) };
      } catch (err) {
        return { ok: false, error: err instanceof Error ? err.message : String(err) };
      }
    },
  };

  const close: ToolDef = {
    name: "close_payment_session",
    description: "Close a session. Returns any final metered remainder due (pay it + record_settled, then it's done).",
    parameters: { session_id: { type: "string" } },
    async handler(p: Record<string, unknown>) {
      const s = get(String(p.session_id ?? ""));
      if (!s) return { ok: false, error: "unknown session_id." };
      const d = closeSession(s, nowFn());
      return { ok: true, final_due: d.due, final_amount_usdc: d.amountUsdc, reason: d.reason, ...snapshot(s) };
    },
  };

  return [open, meterUsage, checkDue, recordSettledTool, close];
}
