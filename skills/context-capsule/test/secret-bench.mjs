/**
 * Secret / credential redaction battery — defense-in-depth across EVERY surface.
 *
 * Threat model: the capsule object (injected text AND the zlib audit blob AND
 * topics/superseded/facts) can be persisted or logged by the host. NO secret may
 * survive in ANY of those surfaces. Equally important: legitimate look-alikes
 * (git SHAs, UUIDs, PUBLIC chain addresses, semver) must NOT be redacted, or
 * fidelity collapses. Secrets are identified by SHAPE/PREFIX/CONTEXT, never by
 * raw entropy.
 *
 * Checks:
 *   inject-leak    no planted secret appears in the injected capsule text
 *   blob-leak      no planted secret survives in the DECOMPRESSED audit blob
 *   false-positive every legitimate look-alike still appears (not over-redacted)
 *   fingerprint    redactions carry a one-way SHA-256 tag  [REDACTED_*#abcd1234]
 *   determinism    identical output across runs
 */
import { inflateSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { compressContext, injectCapsule } from '../dist/compression.js';

// ---- planted secrets that MUST be redacted everywhere ---------------------
const SECRETS = {
  openai_proj: 'sk-'+'proj-Ab12Cd34Ef56Gh78Ij90Kl12Mn34Op56Qr78St90Uv12Wx',
  anthropic: 'sk-ant-'+'api03-Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp9Oo8Nn7Mm6',
  generic_sk: 'sk'+'-1234567890ABCDEFghijklmnop',
  aws_akia: 'AK'+'IAIOSFODNN7EXAMPLE',
  aws_asia: 'AS'+'IA1234567890ABCDEF',
  github_classic: 'ghp'+'_AbCdEf0123456789AbCdEf0123456789abcd',
  github_fine: 'github'+'_pat_11ABCDEF0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEF',
  gitlab: 'glp'+'at-Ab12Cd34Ef56Gh78Ij90',
  npm: 'npm'+'_AbCdEf0123456789AbCdEf0123456789abcd',
  google: 'AI'+'zaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q',
  slack: 'xo'+'xb-1234567890-0987654321-AbCdEfGhIjKlMnOp',
  stripe_live: 'sk_'+'live_Ab12Cd34Ef56Gh78Ij90Kl12',
  sendgrid: 'SG'+'.Ab12Cd34Ef56Gh78.Ij90Kl12Mn34Op56Qr78St90Uv12Wx34Yz56Ab78',
  jwt: 'ey'+'JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N',
  url_basic_auth: 'https://admin:'+'S3cr3tP@ssw0rd@db.internal.example.com:5432',
  db_url: 'DATABASE_URL=postgres://dbuser:'+'hunter2secret@10.0.0.5:5432/prod',
  password_kv: 'pass'+'word = correcthorsebatterystaple99',
  api_key_kv: 'api' + '_key: "Zz1234567890abcdefXYZ"',
  pem: '-----'+'BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdEFGH\n-----END RSA PRIVATE KEY-----',
};

// ---- legitimate look-alikes that MUST survive (no over-redaction) ---------
const LEGIT = {
  git_sha: 'a1b2c3d4e5f6789012345678901234567890abcd',
  uuid: '123e4567-e89b-12d3-a456-426614174000',
  sol_pubkey: '9stSimAbCdEfGh1234567890XyZpQrStUvWxYz12345',  // PUBLIC address
  semver: 'v2.13.4',
  port: '8096',
  file: 'src/core/context_window.ts',
};

const msgs = [
  { role: 'user', content: `Deploy creds: ${SECRETS.openai_proj} ${SECRETS.anthropic} ${SECRETS.generic_sk}` },
  { role: 'assistant', content: `aws ${SECRETS.aws_akia} ${SECRETS.aws_asia}; gh ${SECRETS.github_classic} ${SECRETS.github_fine}` },
  { role: 'user', content: `more: ${SECRETS.gitlab} ${SECRETS.npm} ${SECRETS.google} ${SECRETS.slack} ${SECRETS.stripe_live} ${SECRETS.sendgrid}` },
  { role: 'assistant', content: `auth ${SECRETS.jwt}; ${SECRETS.url_basic_auth}` },
  { role: 'user', content: `${SECRETS.db_url}; ${SECRETS.password_kv}; ${SECRETS.api_key_kv}` },
  { role: 'assistant', content: SECRETS.pem },
  { role: 'user', content: `Legit refs: commit ${LEGIT.git_sha}, id ${LEGIT.uuid}, mint ${LEGIT.sol_pubkey}, ${LEGIT.semver} on port ${LEGIT.port}, edit ${LEGIT.file}` },
  { role: 'assistant', content: `Recorded commit ${LEGIT.git_sha} and mint ${LEGIT.sol_pubkey}; building on ${LEGIT.semver}.` },
  { role: 'user', content: 'Add a healthcheck and a readme, then ship.' },
  { role: 'assistant', content: 'Healthcheck and README added; ready to ship.' },
];

const cap = compressContext(msgs, { sessionId: 'secret', maxOutputTokens: 1400 });
const injected = injectCapsule(cap, { maxOutputTokens: 1400 });
const blob = inflateSync(Buffer.from(cap.compressedBase64, 'base64')).toString('utf8');

const injLeaks = Object.entries(SECRETS).filter(([, v]) => injected.includes(v.split('\n')[1] || v));
const blobLeaks = Object.entries(SECRETS).filter(([, v]) => blob.includes(v.split('\n')[1] || v));
// false positives: a legit token that is GONE from BOTH injected and blob, while
// it was present in source, signals over-redaction. We check the blob (lossless
// audit) — every legit token should survive there.
const overRedacted = Object.entries(LEGIT).filter(([, v]) => !blob.includes(v));
const fpFmt = /\[REDACTED_[A-Z_]*#[0-9a-f]{6,}\]/.test(injected);

const d2 = injectCapsule(compressContext(msgs, { sessionId: 'secret', maxOutputTokens: 1400 }), { maxOutputTokens: 1400 });
const determ = d2 === injected;

const checks = [
  { name: 'inject-leak (none in capsule text)', pass: injLeaks.length === 0, detail: injLeaks.map((x) => x[0]).join(', ') },
  { name: 'blob-leak (none in decompressed audit blob)', pass: blobLeaks.length === 0, detail: blobLeaks.map((x) => x[0]).join(', ') },
  { name: 'no over-redaction of legit look-alikes', pass: overRedacted.length === 0, detail: overRedacted.map((x) => x[0]).join(', ') },
  { name: 'one-way SHA-256 fingerprint on redactions', pass: fpFmt, detail: fpFmt ? '' : 'no [REDACTED_*#hash] tag found' },
  { name: 'determinism', pass: determ, detail: '' },
];

const JSON_OUT = process.argv.includes('--json');
const fails = checks.filter((c) => !c.pass);
if (JSON_OUT) {
  console.log(JSON.stringify({ total: checks.length, passed: checks.length - fails.length, checks }));
} else {
  console.log('Secret / credential redaction battery\n');
  for (const c of checks) console.log(`  [${c.pass ? 'PASS' : 'FAIL'}] ${c.name}${c.detail ? '  -> ' + c.detail : ''}`);
  console.log(`\n${checks.length - fails.length}/${checks.length} checks pass`);
}
process.exit(fails.length);
