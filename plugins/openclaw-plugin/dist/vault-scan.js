/**
 * vault-scan.js
 * =============
 * PII and secret redaction gate for the Liquefy OpenClaw plugin.
 *
 * Ported from tools/liquefy_redact.py (the canonical Python implementation).
 * Applied BEFORE any session history is passed to compressContext() or the
 * Liquefy CLI, so sensitive values never enter the compression surface.
 *
 * Rules:
 *   - Never throw on bad input; always return a best-effort result.
 *   - Never log matched values — only category names + counts.
 *   - All patterns are compiled once at module load (synchronous scan).
 */

// ── PII / Secret patterns (mirrors liquefy_redact.py PII_PATTERNS) ──────────

const PATTERNS = [
  // PEM private key block
  {
    key: "private_key",
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/gi,
    placeholder: "[REDACTED_PRIVATE_KEY_BLOCK]",
  },
  // Anthropic API key (sk-ant- prefix — must come before generic sk-)
  {
    key: "anthropic_key",
    re: /sk-ant-[A-Za-z0-9\-_]{20,}/g,
    placeholder: "[REDACTED_ANTHROPIC_KEY]",
  },
  // OpenAI API key (classic format)
  {
    key: "openai_key",
    re: /sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}/g,
    placeholder: "[REDACTED_OPENAI_KEY]",
  },
  // Generic sk- API key (catchall after named providers)
  {
    key: "generic_sk_key",
    re: /\bsk-[A-Za-z0-9]{20,}\b/g,
    placeholder: "[REDACTED_SK_KEY]",
  },
  // GitHub tokens
  {
    key: "github_token",
    re: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    placeholder: "[REDACTED_GITHUB_TOKEN]",
  },
  {
    key: "github_pat",
    re: /github_pat_[A-Za-z0-9_]{82,}/g,
    placeholder: "[REDACTED_GITHUB_PAT]",
  },
  // Slack tokens
  {
    key: "slack_token",
    re: /xox[bpras]-[A-Za-z0-9\-]{10,}/g,
    placeholder: "[REDACTED_SLACK_TOKEN]",
  },
  // AWS access key
  {
    key: "aws_key",
    re: /AKIA[0-9A-Z]{16}/g,
    placeholder: "[REDACTED_AWS_KEY]",
  },
  // Stripe keys
  {
    key: "stripe_key",
    re: /(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}/g,
    placeholder: "[REDACTED_STRIPE_KEY]",
  },
  // Google API key
  {
    key: "google_key",
    re: /AIza[0-9A-Za-z\-_]{35}/g,
    placeholder: "[REDACTED_GOOGLE_KEY]",
  },
  // JWT (three base64url segments)
  {
    key: "jwt",
    re: /eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}/g,
    placeholder: "[REDACTED_JWT]",
  },
  // Bearer token
  {
    key: "bearer_token",
    re: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
    placeholder: "[REDACTED_BEARER]",
  },
  // Generic key=value credential assignments
  {
    key: "credential_assignment",
    re: /(?:password|passwd|secret|token|api[_\-]?key|access[_\-]?key|auth[_\-]?token|private[_\-]?key)\s*[=:]\s*["']?([A-Za-z0-9/+=\-_.]{8,})["']?/gi,
    placeholder: "[REDACTED_SECRET]",
    captureGroup: 1,
  },
  // Emails
  {
    key: "email",
    re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    placeholder: "[REDACTED_EMAIL]",
  },
  // IPv4
  {
    key: "ipv4",
    re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    placeholder: "[REDACTED_IP]",
  },
  // Credit card (basic pattern)
  {
    key: "credit_card",
    re: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b/g,
    placeholder: "[REDACTED_CC]",
  },
  // US SSN
  {
    key: "ssn",
    re: /\b\d{3}-\d{2}-\d{4}\b/g,
    placeholder: "[REDACTED_SSN]",
  },
  // Ethereum address
  {
    key: "eth_address",
    re: /\b0x[0-9a-fA-F]{40}\b/g,
    placeholder: "[REDACTED_ETH_ADDR]",
  },
];

// ── Core scan ────────────────────────────────────────────────────────────────

/**
 * Scan and redact sensitive values from `text`.
 *
 * @param {unknown} text  Any value — non-strings are coerced.
 * @returns {{ redacted: string, findings: Record<string,number>, clean: boolean, totalRedactions: number }}
 */
export function vaultScan(text) {
  const input = typeof text === "string" ? text : String(text ?? "");
  let redacted = input;
  /** @type {Record<string,number>} */
  const findings = {};
  let totalRedactions = 0;

  for (const { key, re, placeholder, captureGroup } of PATTERNS) {
    re.lastIndex = 0;
    const matches = [...redacted.matchAll(new RegExp(re.source, re.flags))];
    if (!matches.length) continue;

    findings[key] = (findings[key] ?? 0) + matches.length;
    totalRedactions += matches.length;

    if (captureGroup) {
      // Replace only the captured group (e.g. the value in password=VALUE)
      re.lastIndex = 0;
      redacted = redacted.replace(re, (match, ...groups) => {
        const val = groups[captureGroup - 1];
        return val ? match.replace(val, placeholder) : match;
      });
    } else {
      re.lastIndex = 0;
      redacted = redacted.replace(re, placeholder);
    }
  }

  return {
    redacted,
    findings,
    clean: totalRedactions === 0,
    totalRedactions,
  };
}

/**
 * Return a loggable summary (no values, only categories + counts).
 * Returns null when nothing was redacted.
 *
 * @param {{ clean: boolean, totalRedactions: number, findings: Record<string,number> }} result
 * @returns {string|null}
 */
export function vaultSummary(result) {
  if (result.clean) return null;
  const parts = Object.entries(result.findings).map(([k, n]) => `${k}x${n}`);
  return `vault-scan: redacted ${result.totalRedactions} — ${parts.join(", ")}`;
}

/**
 * Gate helper: scan `text`, log any findings, return the safe copy.
 * Never throws. Drop-in replacement for the raw value.
 *
 * @param {unknown} text
 * @param {string}  [label]  Label for the log line (e.g. "context history")
 * @returns {string}
 */
export function vaultGuard(text, label = "input") {
  const result = vaultScan(text);
  const summary = vaultSummary(result);
  if (summary) {
    // No values in the log — only categories and counts.
    console.warn(`[liquefy-vault] ${label}: ${summary}`);
  }
  return result.redacted;
}
