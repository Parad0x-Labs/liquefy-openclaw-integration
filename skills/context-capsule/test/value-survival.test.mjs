/**
 * Value-survival regression: a lone distinctive value stated ONCE early and buried under
 * filler must survive compression at a tight budget, because it is emitted as its own dense
 * atom (ATOM_VALUE_RE) rather than surviving only when its whole line happens to be selected.
 *
 * Guards the value-atom pass added in v1.7.0. Without it, a bare port / issue-ref / version /
 * ISO-date / hyphenated code is dropped once its surrounding sentence loses the budget race.
 */
import assert from 'node:assert/strict';
import { compressContext, injectCapsule } from '../dist/compression.js';

// Each distinctive value is stated once, early, in an otherwise ordinary sentence.
const seeded = [
  { role: 'user', content: 'The staging database listens on port 5433 for the analytics service.' },
  { role: 'assistant', content: 'Noted. The tracking issue for that work is #4821 on the board.' },
  { role: 'user', content: 'We pinned the runtime to version v2.13.0 last week for stability.' },
  { role: 'assistant', content: 'Understood. The launch deadline on the calendar is 2026-07-15.' },
  { role: 'user', content: 'The provisioning code for that node is NEEDLE-ZX-7742, keep it around.' },
];

// A wall of low-value chatter so a tight budget must drop most prose lines.
const filler = Array.from({ length: 24 }, (_v, i) => ([
  { role: 'user', content: `Can you explain best practices for topic number ${i} in general terms?` },
  { role: 'assistant', content: 'Sure — here is a broad, generic overview with the usual trade-offs and considerations.' },
])).flat();

const messages = [...seeded, ...filler];

const capsule = compressContext(messages, { sessionId: 'value-survival', maxOutputTokens: 200 });
const injected = injectCapsule(capsule, { maxOutputTokens: 200 });

for (const value of ['5433', '#4821', 'v2.13.0', '2026-07-15', 'NEEDLE-ZX-7742']) {
  assert.ok(
    injected.includes(value),
    `distinctive value "${value}" was lost in compression (injected capsule: ${injected})`,
  );
}

// Still bounded by the budget — the guarantee is value-survival, not keeping everything.
assert.ok(injected.length <= 200 * 4, `capsule exceeded budget: ${injected.length}`);

console.log('value-survival.test.mjs: all distinctive values survived compression');
