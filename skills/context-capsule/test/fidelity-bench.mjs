/**
 * Fidelity-vs-compression benchmark on REAL OpenClaw session transcripts.
 *
 * Answers the only question that matters for a context engine: at a given
 * compression ratio, how much of what mattered survives?
 *
 *   reduction = tokens(older history) / tokens(injected capsule)
 *   recall    = key items still present in the capsule / key items in older history
 *
 * "Key items" = the distinctive, must-not-lose signals: file paths, URLs,
 * shell commands, error phrases, numbers/IDs, and decision/constraint lines.
 *
 * Usage: node test/fidelity-bench.mjs [sessionDir] [keepRecent]
 * Default sessionDir: ~/.openclaw/agents/nulla/sessions
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { compressContext, injectCapsule } from '../dist/compression.js';

const positional = process.argv.slice(2).filter((a) => !a.startsWith('--'));
const sessionDir = positional[0] || join(homedir(), '.openclaw/agents/nulla/sessions');
const keepRecent = Number(positional[1] || 10);

function loadSession(file) {
  const rows = readFileSync(file, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
  const msgs = [];
  for (const r of rows) {
    if (r.type !== 'message' || !r.message) continue;
    const m = r.message;
    const c = m.content;
    const text = typeof c === 'string'
      ? c
      : Array.isArray(c)
        ? c.map((b) => (b && typeof b === 'object' ? (b.text ?? (typeof b.content === 'string' ? b.content : '')) : '')).filter(Boolean).join('\n')
        : '';
    if (text.trim()) msgs.push({ role: m.role || 'unknown', content: text });
  }
  return msgs;
}

const estTokens = (s) => Math.ceil(s.length / 4);
const tokensOf = (msgs) => msgs.reduce((n, m) => n + estTokens(m.content), 0);

/**
 * Strip noise that should NOT count as must-keep signal: base64/data/payload
 * blobs (a single encoded asset fragments into dozens of bogus "hashes") and
 * encoded query payloads. Counting these would reward preserving garbage.
 */
function denoise(text) {
  return text
    .replace(/https?:\/\/[^\s)\]}>"']*payload=[^\s)\]}>"']+/gi, ' ') // payload= data URLs
    .replace(/data:[^\s)\]}>"']+/gi, ' ')                            // data: URIs
    .replace(/[A-Za-z0-9+/]{40,}={0,2}/g, ' ');                       // long base64 runs
}

/** Distinctive, must-not-lose signals extracted from a block of text. */
function keyItems(raw) {
  const text = denoise(raw);
  const items = new Set();
  for (const m of text.match(/https?:\/\/[^\s)\]}>"']+/g) ?? []) items.add('url:' + m.slice(0, 60));
  for (const m of text.match(/(?:[.~]?\/)?[\w.-]+\/[\w./@+-]*\.[A-Za-z0-9]{1,8}/g) ?? []) items.add('path:' + m.slice(0, 60));
  for (const m of text.match(/\b(?:pnpm|npm|bun|node|git|gh|openclaw|launchctl|lsof|curl|docker|kubectl)\s+(?:-{1,2}[\w-]+|[\w./@-]*[/.:][\w./@:-]*|run|start|build|install|test|dev|add|remove|rm|status|deploy|clone|commit|push|pull|logs?|exec|restart)\b/gi) ?? []) items.add('cmd:' + m.slice(0, 50));
  for (const m of text.match(/\b\d[\d,._:-]{3,}\b/g) ?? []) items.add('num:' + m);            // ports, ids, amounts, dates
  for (const m of text.match(/\b[A-Za-z0-9]{20,}\b/g) ?? []) items.add('hash:' + m.slice(0, 24)); // addresses/hashes
  for (const line of text.split(/\n+/)) {
    if (/\b(error|failed|failure|exception|denied|unsupported|refused|timeout)\b/i.test(line)) {
      items.add('err:' + line.trim().slice(0, 50).toLowerCase());
    }
    if (/\b(always|never|must|do not|don't|decided|decision)\b/i.test(line)) {
      items.add('dec:' + line.trim().slice(0, 50).toLowerCase());
    }
  }
  return items;
}

function recall(olderText, capsule) {
  const want = keyItems(olderText);
  if (want.size === 0) return { recall: 1, found: 0, total: 0 };
  const hay = capsule.toLowerCase();
  let found = 0;
  for (const item of want) {
    const needle = item.slice(item.indexOf(':') + 1).toLowerCase().trim();
    if (needle.length >= 4 && hay.includes(needle)) found += 1;
  }
  return { recall: found / want.size, found, total: want.size };
}

const JSON_OUT = process.argv.includes('--json');

function benchOne(file, msgs) {
  if (msgs.length <= keepRecent + 2) return null;
  const older = msgs.slice(0, -keepRecent);
  const olderText = older.map((m) => m.content).join('\n');
  const olderTok = tokensOf(older);
  const full = tokensOf(msgs);
  const rows = [];
  for (const budget of [300, 500, 700, 1200, 2000]) {
    const cap = compressContext(older, { sessionId: 'bench', maxOutputTokens: budget });
    const injected = injectCapsule(cap, { maxOutputTokens: budget });
    const capTok = estTokens(injected);
    const tail = tokensOf(msgs.slice(-keepRecent));
    const r = recall(olderText, injected);
    rows.push({
      budget,
      capTok,
      olderRed: Number((olderTok / Math.max(1, capTok)).toFixed(1)),
      overallRed: Number((full / Math.max(1, capTok + tail)).toFixed(1)),
      recallPct: Math.round(100 * r.recall),
      found: r.found,
      total: r.total,
    });
  }
  const out = { file, messages: msgs.length, full, older: olderTok, rows };
  if (JSON_OUT) return out;
  console.log(`\n### ${file}`);
  console.log(`messages=${msgs.length}  full≈${full} tok  older≈${olderTok} tok (${older.length} msgs)  tail=${keepRecent} verbatim`);
  console.log('budget |  capsule tok | older-reduction | overall-reduction | key-recall (found/total)');
  console.log('-------|--------------|-----------------|-------------------|--------------------------');
  for (const x of rows) {
    console.log(
      `${String(x.budget).padStart(6)} | ${String(x.capTok).padStart(12)} | ${(x.olderRed + 'x').padStart(15)} | ${(x.overallRed + 'x').padStart(17)} | ${String(x.recallPct).padStart(3)}%  (${x.found}/${x.total})`,
    );
  }
  return out;
}

let files;
try {
  files = readdirSync(sessionDir).filter((f) => f.endsWith('.jsonl') && !f.includes('trajectory'));
} catch (e) {
  console.error(`No session dir at ${sessionDir} — pass a path as arg 1.`);
  process.exit(0);
}

const loaded = files
  .map((f) => ({ f, msgs: loadSession(join(sessionDir, f)) }))
  .filter((x) => x.msgs.length > keepRecent + 2)
  .sort((a, b) => b.msgs.length - a.msgs.length);

if (loaded.length === 0) {
  console.log(`No sessions in ${sessionDir} long enough to compress (need > ${keepRecent + 2} messages).`);
  process.exit(0);
}

if (!JSON_OUT) console.log(`Fidelity-vs-compression on REAL sessions in ${sessionDir}`);
const benched = loaded.slice(0, 3).map(({ f, msgs }) => benchOne(f, msgs)).filter(Boolean);
if (JSON_OUT) console.log(JSON.stringify({ sessions: benched }));
