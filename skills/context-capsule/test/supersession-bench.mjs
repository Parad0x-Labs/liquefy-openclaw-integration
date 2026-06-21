/**
 * Lane-change / supersession DEV benchmark (non-leaking).
 *
 * When a session pivots ("forget X, use Y instead"), the capsule must keep the
 * LIVE direction and either OMIT the abandoned one or mark it with a
 * capsule-added supersession marker. Echoing the user's natural pivot words does
 * NOT count as marking — only the markers the CAPSULE adds count.
 *
 * Marker convention the capsule must use: wrap an abandoned subject in
 * ~~strikethrough~~ and/or put it on a line containing the word "superseded".
 * The metric recognizes only those (see MARK) — never natural words like
 * "forget"/"instead"/"replace", so a capsule cannot pass by parroting the input.
 *
 * Metrics per case:
 *   liveKept            live subjects present on an UNMARKED line
 *   abClean             abandoned subjects ABSENT or only on MARKED lines
 *   liveWronglyFlagged  live subjects appearing on a MARKED line  ← PRECISION; MUST be 0
 *   mangled             emitted bullets gutted by over-aggressive scrubbing
 *
 * HARD GATES for a usable detector: liveWronglyFlagged === 0 (never strike a
 * live choice) AND mangled === 0. Then maximize abClean while liveKept stays high.
 * Source text below contains ONLY natural pivots — NO marker words — so the
 * detector must do real work, and the numbers reflect generalization, not leakage.
 */
import { compressContext, injectCapsule } from '../dist/compression.js';

const MARK = /~~|\bsuperseded\b/i; // capsule-ADDED markers only

const CORPUS = [
  {
    id: 'provider-switch',
    live: ['Ollama', 'qwen2.5'],
    abandoned: ['Gemini'],
    messages: [
      { role: 'user', content: 'I want a local helper agent. Use Gemini as the model for everything.' },
      { role: 'assistant', content: 'Wiring Gemini as the provider for the helper agent.' },
      { role: 'user', content: 'It should summarize my notes and answer questions about them.' },
      { role: 'assistant', content: 'Summarization plus Q&A over your notes.' },
      { role: 'user', content: 'Actually, forget Gemini. Use Ollama with qwen2.5 for everything.' },
      { role: 'assistant', content: 'Now using Ollama with qwen2.5 for all inference.' },
      { role: 'user', content: 'Keep all inference local, nothing leaves the box.' },
      { role: 'assistant', content: 'Confirmed: Ollama qwen2.5, fully local.' },
      { role: 'user', content: 'Add a daily digest at 9am.' },
      { role: 'assistant', content: 'Daily digest scheduled for 9am.' },
    ],
  },
  {
    id: 'theme-pivot',
    live: ['token-launch landing page', 'Privacy is the default'],
    abandoned: ['SaaS dashboard', 'billing page'],
    messages: [
      { role: 'user', content: 'Build me a SaaS dashboard with charts, a sidebar, and a billing page.' },
      { role: 'assistant', content: 'Starting a SaaS dashboard: sidebar nav, charts, billing page.' },
      { role: 'user', content: 'Use a blue corporate palette.' },
      { role: 'assistant', content: 'Blue corporate palette applied.' },
      { role: 'user', content: 'Scratch that. Instead make a minimal token-launch landing page, one scroll.' },
      { role: 'assistant', content: 'Switching to a minimal one-scroll token-launch landing page.' },
      { role: 'user', content: 'Headline: "Privacy is the default".' },
      { role: 'assistant', content: 'Headline set to "Privacy is the default".' },
      { role: 'user', content: 'Add a roadmap section at the bottom.' },
      { role: 'assistant', content: 'Roadmap section added.' },
    ],
  },
  {
    id: 'port-change',
    live: ['8096'],
    abandoned: ['3000'],
    messages: [
      { role: 'user', content: 'Run the dev server on port 3000.' },
      { role: 'assistant', content: 'Dev server will listen on port 3000.' },
      { role: 'user', content: 'Wire the health check to /healthz.' },
      { role: 'assistant', content: 'Health check at /healthz.' },
      { role: 'user', content: 'Port 3000 conflicts with something. Switch to port 8096 everywhere now.' },
      { role: 'assistant', content: 'The server now uses port 8096.' },
      { role: 'user', content: 'Restart and confirm.' },
      { role: 'assistant', content: 'Restarted on port 8096, health check green.' },
      { role: 'user', content: 'Add a readiness probe too.' },
      { role: 'assistant', content: 'Readiness probe added.' },
    ],
  },
  {
    id: 'arch-pivot',
    live: ['WebSockets', 'NDJSON'],
    abandoned: ['REST'],
    messages: [
      { role: 'user', content: 'Expose the API over REST with JSON endpoints under /api/v1.' },
      { role: 'assistant', content: 'A REST API under /api/v1 with JSON.' },
      { role: 'user', content: 'Each task needs create, get, list, delete.' },
      { role: 'assistant', content: 'CRUD endpoints planned.' },
      { role: 'user', content: 'On second thought, forget REST. Go full WebSockets with one duplex channel.' },
      { role: 'assistant', content: 'Moving to a single WebSockets duplex channel.' },
      { role: 'user', content: 'Messages are newline-delimited JSON frames.' },
      { role: 'assistant', content: 'NDJSON frames over the channel.' },
      { role: 'user', content: 'Add a heartbeat every 20s.' },
      { role: 'assistant', content: 'Heartbeat every 20s.' },
    ],
  },
  {
    id: 'lib-swap',
    live: ['date-fns'],
    abandoned: ['moment'],
    messages: [
      { role: 'user', content: 'Use moment for all date formatting.' },
      { role: 'assistant', content: 'moment will handle date formatting.' },
      { role: 'user', content: 'Format timestamps as relative time.' },
      { role: 'assistant', content: 'Relative-time formatting planned.' },
      { role: 'user', content: 'Replace moment with date-fns, it is lighter.' },
      { role: 'assistant', content: 'Now using date-fns for formatting.' },
      { role: 'user', content: 'Tree-shake unused locales.' },
      { role: 'assistant', content: 'Locale tree-shaking enabled.' },
      { role: 'user', content: 'Add a unit test for the formatter.' },
      { role: 'assistant', content: 'Formatter unit test added.' },
    ],
  },
  {
    id: 'no-pivot-control',
    live: ['Postgres', 'users, sessions, events'],
    abandoned: [],
    messages: [
      { role: 'user', content: 'Use Postgres for storage.' },
      { role: 'assistant', content: 'Postgres selected for storage.' },
      { role: 'user', content: 'Tables: users, sessions, events.' },
      { role: 'assistant', content: 'Schema: users, sessions, events.' },
      { role: 'user', content: 'Index events by timestamp.' },
      { role: 'assistant', content: 'Timestamp index on events.' },
      { role: 'user', content: 'Add a migration tool.' },
      { role: 'assistant', content: 'Migration tooling added.' },
      { role: 'user', content: 'Back up nightly.' },
      { role: 'assistant', content: 'Nightly backups scheduled.' },
    ],
  },
];

const lines = (t) => t.split(/\n+/).filter((l) => !l.startsWith('[CONTEXT CAPSULE'));
const has = (t, n) => t.toLowerCase().includes(n.toLowerCase());
const presentLive = (t, n) => {
  const ls = lines(t).filter((l) => has(l, n));
  return ls.length > 0 && ls.some((l) => !MARK.test(l));
};
const inMarked = (t, n) => lines(t).some((l) => has(l, n) && MARK.test(l));
const abClean = (t, n) => {
  if (!has(t, n)) return true;
  return lines(t).filter((l) => has(l, n)).every((l) => MARK.test(l));
};
// crude mangling probe: a bullet gutted by scrubbing (dangling connector before
// punctuation, double-punct, or leading punctuation).
const MANGLE_RE = /\b(?:and|with|or|to|for|of|the|a|an|using|use|by|in|on)\s*[.,;]|[.,;]\s*[.,;]|^\s*[-]?\s*[.,;]|\s[.,;]\s[a-z]*\s*[.,;]/i;
function mangledBullets(t) {
  return lines(t).filter((l) => l.trim().startsWith('-') && MANGLE_RE.test(l.replace(/^[-\s]+/, ''))).length;
}

function runBudget(budget) {
  let lk = 0, ld = 0, ac = 0, ad = 0, fa = 0, mang = 0;
  const rows = [];
  for (const tc of CORPUS) {
    const cap = compressContext(tc.messages, { sessionId: tc.id, maxOutputTokens: budget });
    const t = injectCapsule(cap, { maxOutputTokens: budget });
    const l = tc.live.filter((x) => presentLive(t, x)).length;
    const a = tc.abandoned.filter((x) => abClean(t, x)).length;
    const wf = tc.live.filter((x) => inMarked(t, x)).length;
    const mg = mangledBullets(t);
    lk += l; ld += tc.live.length; ac += a; ad += tc.abandoned.length; fa += wf; mang += mg;
    rows.push({ id: tc.id, live: `${l}/${tc.live.length}`, ab: `${a}/${tc.abandoned.length}`, wronglyFlagged: wf, mangled: mg });
  }
  return {
    budget,
    liveKeptPct: ld ? Math.round((100 * lk) / ld) : 100,
    abCleanPct: ad ? Math.round((100 * ac) / ad) : 100,
    liveWronglyFlagged: fa,
    mangled: mang,
    rows,
  };
}

const JSON_OUT = process.argv.includes('--json');
const results = [700, 1400].map(runBudget);

// CI gate: the safety-critical invariant is that a LIVE choice is never struck
// and no fact is mangled (precision), at every budget. We also guard the verified
// recall floor (>=83% abandoned-clean at budget 1400) so a quiet regression fails CI.
const precisionFail = results.some((r) => r.liveWronglyFlagged > 0 || r.mangled > 0);
const recallFail = (results.find((r) => r.budget === 1400)?.abCleanPct ?? 0) < 83;
const exitCode = precisionFail || recallFail ? 1 : 0;

if (JSON_OUT) {
  console.log(JSON.stringify({ supersession: results.map((r) => ({ budget: r.budget, liveKeptPct: r.liveKeptPct, abCleanPct: r.abCleanPct, liveWronglyFlagged: r.liveWronglyFlagged, mangled: r.mangled })) }));
  process.exit(exitCode);
}

console.log('Lane-change / supersession DEV benchmark (non-leaking; ~~ or "superseded" = marked)');
for (const r of results) {
  console.log(`\n=== budget ${r.budget} ===`);
  console.log('case                |  live | ab-clean | liveWronglyFlagged | mangled');
  console.log('--------------------|-------|----------|--------------------|--------');
  for (const row of r.rows) {
    console.log(`${row.id.padEnd(20)}| ${row.live.padStart(5)} | ${row.ab.padStart(8)} | ${String(row.wronglyFlagged).padStart(18)} | ${String(row.mangled).padStart(7)}`);
  }
  const gate = r.liveWronglyFlagged === 0 && r.mangled === 0 ? 'PASS' : 'FAIL';
  console.log(`OVERALL liveKept=${r.liveKeptPct}% abClean=${r.abCleanPct}% wronglyFlagged=${r.liveWronglyFlagged} mangled=${r.mangled}  precision-gate=${gate}`);
}
process.exit(exitCode);
