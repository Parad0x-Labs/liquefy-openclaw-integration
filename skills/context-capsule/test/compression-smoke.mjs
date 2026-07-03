import assert from 'node:assert/strict';
import { compressContext, injectCapsule } from '../dist/compression.js';

const messages = [
  { role: 'user', content: 'Always use Gemini for NULLA, never OpenAI for this local helper.' },
  { role: 'assistant', content: 'Decision recorded: provider must stay nulla/nulla through Ollama.' },
  { role: 'user', content: 'TODO: fix ui/src/ui/chat/session-controls.ts so the selector does not say nulla off.' },
  { role: 'assistant', content: 'Error seen: thinkingLevel high is unsupported for nulla/nulla; use off.' },
  { role: 'user', content: 'Run pnpm build and verify http://127.0.0.1:18789 after restart.' },
];

const capsule = compressContext(messages, { sessionId: 'smoke', maxOutputTokens: 180 });
const injected = injectCapsule(capsule, { maxOutputTokens: 180 });

assert.equal(capsule.sessionId, 'smoke');
assert.ok(capsule.compressedBase64.length > 0);
assert.ok(capsule.facts.length >= 3, 'expected extracted facts');
assert.match(injected, /CONTEXT CAPSULE/);
assert.match(injected, /Gemini|NULLA|nulla\/nulla/i);
assert.match(injected, /session-controls\.ts|pnpm build|thinkingLevel/i);
assert.ok(injected.length <= 180 * 4, `capsule exceeded budget: ${injected.length}`);
