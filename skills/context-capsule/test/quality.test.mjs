/**
 * Extraction-quality regression test over a realistic long agent session.
 *
 * Guards the fixes that turn the capsule from noisy to useful:
 *   1. Topics carry domain nouns, not capitalized sentence-openers/filler.
 *   2. Raw JSON tool-result blobs are dropped; only a clean error line survives.
 *   3. Lines that announce themselves ("Decision:", "TODO:") are classified as such.
 */
import assert from 'node:assert/strict';
import { compressContext, injectCapsule } from '../dist/compression.js';

const messages = [
  { role: 'user', content: 'Hey, I want to build a token launch page on web0 for my project called DarkNull. Can you help?' },
  { role: 'assistant', content: 'Absolutely. Let me start by understanding the requirements. What chain is the token on, and do you have a contract address?' },
  { role: 'user', content: 'It is on Solana. Mint address is 9stSimAbCdEfGh1234567890XyZ. Decimals 9, supply 1 billion.' },
  { role: 'assistant', content: 'Got it. I will use the token_launch template. First I need to scaffold the project.' },
  { role: 'tool', content: '{"tool":"web0_create_project","result":{"project_id":"proj_8841","template":"token_launch"}}' },
  { role: 'user', content: 'Make the hero headline say "DarkNull — Privacy is the default" and use a black/purple theme.' },
  { role: 'assistant', content: 'Decision recorded: headline = "DarkNull — Privacy is the default", theme = black/purple.' },
  { role: 'tool', content: '{"tool":"web0_fill_slots","result":{"ok":true,"slots_filled":6}}' },
  { role: 'user', content: 'Also add a roadmap section and a link to our docs at https://docs.darknull.xyz/intro' },
  { role: 'user', content: 'Run the preview build so I can see it.' },
  { role: 'tool', content: '{"tool":"web0_compile_preview","result":{"error":"PortalUnavailable: connection refused at http://localhost:3000"}}' },
  { role: 'assistant', content: 'Error seen: the local Web0 portal is not running. Start the null-portal dev server first.' },
  { role: 'user', content: 'Decision: switch hero headline font to monospace. I will update the theme tokens.' },
  { role: 'user', content: 'TODO: change the headline font to a monospace, it looks too generic right now.' },
  { role: 'user', content: 'Also we must never expose the mint authority key in the page source.' },
];

const capsule = compressContext(messages, { sessionId: 'quality', maxOutputTokens: 700 });
const injected = injectCapsule(capsule, { maxOutputTokens: 700 });

// 1. Topics carry real nouns and none of the known filler/openers.
const topicSet = new Set(capsule.topics.map((t) => t.toLowerCase()));
for (const filler of ['absolutely', 'what', 'first', 'got', 'run', 'make', 'also', 'good']) {
  assert.ok(!topicSet.has(filler), `topic filler leaked: ${filler} (topics: ${capsule.topics.join(', ')})`);
}
assert.ok(topicSet.has('darknull'), 'expected DarkNull in topics');
assert.ok(topicSet.has('solana'), 'expected Solana in topics');

// 2. Raw JSON plumbing never appears verbatim; the error is surfaced cleanly.
assert.ok(!/"tool"\s*:/.test(injected), 'raw JSON tool blob leaked into capsule');
assert.ok(!injected.includes('web0_create_project'), 'success tool blob should be dropped');
assert.match(injected, /Tool error: PortalUnavailable/, 'extracted tool error missing');

// 3. Self-announcing lines are classified by what they say.
const decisionFact = capsule.facts.find((f) => f.text.includes('switch hero headline font'));
assert.ok(decisionFact, 'expected the "Decision:" line to be extracted');
assert.equal(decisionFact.kind, 'decision', `"Decision:" line misclassified as ${decisionFact?.kind}`);
const todoFact = capsule.facts.find((f) => f.text.startsWith('TODO: change the headline'));
assert.ok(todoFact, 'expected the "TODO:" line to be extracted');
assert.equal(todoFact.kind, 'task', `"TODO:" line misclassified as ${todoFact?.kind}`);

// 4. Still bounded by the token budget.
assert.ok(injected.length <= 700 * 4, `capsule exceeded budget: ${injected.length}`);

console.log('quality.test.mjs: all assertions passed');
