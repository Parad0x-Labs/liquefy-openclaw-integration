/**
 * payment-session — streaming / recurring billing engine (host-free core).
 *
 * The x402 rail is discrete per-call. This adds the two billing shapes it lacks,
 * settled THROUGH x402 in batches (so you pay one tx per settlement, not per
 * tick — the only economical way to do micropayments given fees + ATA rent):
 *
 *   - metered (pay-as-you-go): accrue per-use charges, settle when the accrued
 *     amount crosses a threshold (or on close).
 *   - subscription (streaming): charge a fixed amount every period; settlement
 *     falls due once a full period has elapsed.
 *
 * Pure accounting — it never moves money. It tells the agent WHEN and HOW MUCH
 * to settle; the agent pays the payee via x402-pay and calls recordSettled. A
 * hard maxTotalUsdc lifetime cap bounds every session (a runaway stream can't
 * drain past it).
 */

export type SettlePolicy =
  | { kind: "metered"; settleAtUsdc: number }
  | { kind: "subscription"; periodSeconds: number; periodUsdc: number };

export interface PaymentSession {
  id: string;
  payee: string; // .null name or x402 endpoint
  policy: SettlePolicy;
  accruedUsdc: number; // metered: usage recorded but not yet settled
  totalSettledUsdc: number;
  settlements: number;
  openedAtUnix: number;
  lastSettleUnix: number; // subscription: the last period boundary settled
  maxTotalUsdc: number; // hard lifetime cap
  closed: boolean;
}

export interface SettlementDue {
  due: boolean;
  amountUsdc: number;
  reason: string;
}

function round6(n: number): number {
  return Math.round(n * 1e6) / 1e6; // USDC precision
}

export function remainingBudget(s: PaymentSession): number {
  return round6(Math.max(0, s.maxTotalUsdc - s.totalSettledUsdc));
}

export function openSession(opts: {
  id: string;
  payee: string;
  policy: SettlePolicy;
  maxTotalUsdc: number;
  nowUnix: number;
}): PaymentSession {
  if (!opts.id || !opts.payee) throw new Error("session needs an id and a payee.");
  if (!(opts.maxTotalUsdc > 0)) throw new Error("maxTotalUsdc must be a positive cap.");
  if (opts.policy.kind === "metered" && !(opts.policy.settleAtUsdc > 0)) {
    throw new Error("metered policy needs settleAtUsdc > 0.");
  }
  if (opts.policy.kind === "subscription") {
    if (!(opts.policy.periodSeconds > 0)) throw new Error("subscription needs periodSeconds > 0.");
    if (!(opts.policy.periodUsdc > 0)) throw new Error("subscription needs periodUsdc > 0.");
  }
  return {
    id: opts.id,
    payee: opts.payee,
    policy: opts.policy,
    accruedUsdc: 0,
    totalSettledUsdc: 0,
    settlements: 0,
    openedAtUnix: opts.nowUnix,
    lastSettleUnix: opts.nowUnix,
    maxTotalUsdc: opts.maxTotalUsdc,
    closed: false,
  };
}

/** Record metered usage (pay-as-you-go). No-op shape for subscription sessions. */
export function meter(s: PaymentSession, usdc: number): PaymentSession {
  if (s.closed) throw new Error("session is closed.");
  if (s.policy.kind !== "metered") throw new Error("meter() applies only to a metered session.");
  if (!(usdc > 0)) throw new Error("metered usage must be > 0.");
  s.accruedUsdc = round6(s.accruedUsdc + usdc);
  return s;
}

/** Whether a settlement is due now, and for how much (capped at remaining budget). */
export function settlementDue(s: PaymentSession, nowUnix: number): SettlementDue {
  const budget = remainingBudget(s);
  if (s.closed) return { due: false, amountUsdc: 0, reason: "session closed." };
  if (budget <= 0) return { due: false, amountUsdc: 0, reason: "lifetime cap reached." };

  if (s.policy.kind === "metered") {
    if (s.accruedUsdc >= s.policy.settleAtUsdc) {
      const amount = round6(Math.min(s.accruedUsdc, budget));
      return { due: true, amountUsdc: amount, reason: `accrued ${s.accruedUsdc} ≥ threshold ${s.policy.settleAtUsdc} USDC.` };
    }
    return { due: false, amountUsdc: 0, reason: `accrued ${s.accruedUsdc} < threshold ${s.policy.settleAtUsdc} USDC.` };
  }

  // subscription
  const elapsed = nowUnix - s.lastSettleUnix;
  const periods = Math.floor(elapsed / s.policy.periodSeconds);
  if (periods >= 1) {
    const amount = round6(Math.min(periods * s.policy.periodUsdc, budget));
    return { due: true, amountUsdc: amount, reason: `${periods} period(s) elapsed × ${s.policy.periodUsdc} USDC.` };
  }
  return { due: false, amountUsdc: 0, reason: `current period not yet elapsed (${elapsed}s / ${s.policy.periodSeconds}s).` };
}

/**
 * Record that `amountUsdc` was settled (after the agent paid via x402). Reduces
 * metered accrual / advances the subscription boundary, bumps totals, and
 * enforces the lifetime cap (throws if the amount would exceed remaining budget).
 */
export function recordSettled(s: PaymentSession, amountUsdc: number, nowUnix: number): PaymentSession {
  if (s.closed) throw new Error("session is closed.");
  if (!(amountUsdc > 0)) throw new Error("settled amount must be > 0.");
  if (round6(amountUsdc) > remainingBudget(s) + 1e-9) {
    throw new Error(`settled ${amountUsdc} exceeds remaining budget ${remainingBudget(s)} USDC.`);
  }
  s.totalSettledUsdc = round6(s.totalSettledUsdc + amountUsdc);
  s.settlements += 1;

  if (s.policy.kind === "metered") {
    s.accruedUsdc = round6(Math.max(0, s.accruedUsdc - amountUsdc));
  } else {
    const periods = Math.max(1, Math.floor(amountUsdc / s.policy.periodUsdc));
    s.lastSettleUnix += periods * s.policy.periodSeconds;
    if (s.lastSettleUnix > nowUnix) s.lastSettleUnix = nowUnix;
  }
  return s;
}

/** Close the session; returns any final metered remainder due (capped at budget). */
export function closeSession(s: PaymentSession, nowUnix: number): SettlementDue {
  if (s.closed) return { due: false, amountUsdc: 0, reason: "already closed." };
  let final: SettlementDue = { due: false, amountUsdc: 0, reason: "nothing outstanding." };
  if (s.policy.kind === "metered" && s.accruedUsdc > 0) {
    const amount = round6(Math.min(s.accruedUsdc, remainingBudget(s)));
    if (amount > 0) final = { due: true, amountUsdc: amount, reason: `final metered remainder ${s.accruedUsdc} USDC.` };
  }
  s.closed = true;
  return final;
}
