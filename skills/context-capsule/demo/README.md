# Context Capsule — in-browser demo

The **same** capsule core that runs in NULLA (Node) running in a browser tab:
redaction + compression + merkle root, entirely on-device, zero install.

Open it by serving this folder over HTTP (ES modules need `http://`, not
`file://`):

```bash
# any static server rooted at this folder, e.g.
npx serve .        # or: python3 -m http.server 8791
# then open http://localhost:8791
```

## Two lanes

1. **Transcript → Capsule (no GPU, zero network).** Paste an agent transcript
   (array of `{role, content}`); the capsule compresses + redacts + builds its
   merkle root in-tab in a couple milliseconds. History never leaves the page.
2. **Answer with a local LLM (WebGPU).** Optionally loads a small q4 model with
   [WebLLM](https://github.com/mlc-ai/web-llm) and answers using **only** the
   injected capsule as context — a fully local agent in a webpage. Downloads the
   WebLLM runtime + model weights on first use; needs a WebGPU browser
   (Chrome/Edge, or Safari Technology Preview).

## How it's built (reproducible)

Nothing here is hand-edited — every file is generated from the plugin's own
compiled `dist/`:

| file | provenance |
|------|------------|
| `platform.browser.js` | `tsc src/platform.browser.ts` (the browser crypto/compression shim) |
| `compression.js` | `dist/compression.js` with its `./platform.js` import repointed to `./platform.browser.js` |
| `vendor/noble-hashes/` | pinned copy of `@noble/hashes@2.2.0` ESM (SHA-256) |
| `vendor/pako.esm.mjs` | pinned copy of `pako@2.1.0` ESM (deflate) |

Regenerate after a source change:

```bash
npm run build
npx tsc src/platform.browser.ts --outDir demo --module esnext \
  --target es2022 --moduleResolution bundler --skipLibCheck --declaration false
node -e 'const fs=require("fs");let s=fs.readFileSync("dist/compression.js","utf8").replace(/from "\.\/platform\.js"/g,"from \"./platform.browser.js\"");fs.writeFileSync("demo/compression.js",s)'
mkdir -p demo/vendor/noble-hashes && cp node_modules/@noble/hashes/*.js demo/vendor/noble-hashes/
cp node_modules/pako/dist/pako.esm.mjs demo/vendor/pako.esm.mjs
```

The deps are **vendored on purpose**: the capsule lane runs with no network at
all (a stronger privacy claim than loading libraries from a CDN), and a pinned,
reviewed copy is a smaller supply-chain surface than a live CDN fetch.

## Parity guarantee

The browser backend (`@noble/hashes` + `pako`) and the Node backend
(`node:crypto` + `node:zlib`) agree on everything that matters, enforced by
`../test/platform-parity.test.mjs`:

- **Byte-identical** integrity + injected memory: a capsule's `merkleRoot`,
  `capsuleId`, and the injected text the model sees are identical in a browser
  and in Node (the SHA-256 path is byte-for-byte equal). Verified end-to-end on a
  live in-tab capsule — same 64-char merkle root both sides.
- **Round-trip-identical** audit blob: `pako` and `node:zlib` each inflate the
  other's output back to the exact original. The compressed *bytes* can differ on
  highly repetitive input, which never affects integrity (the merkle root is over
  the SHA-256 leaves, not the compressed blob).

This folder is repo-only; it is **not** shipped in the npm package (`files` in
`package.json` ships only `dist/` + the plugin manifest).
