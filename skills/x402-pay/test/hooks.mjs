/**
 * Module resolve hook for the node:test runner.
 *
 * x402-pay source uses extensionless relative imports (TypeScript "bundler"
 * moduleResolution, since the plugin is loaded by OpenClaw's bundler-aware
 * loader, not raw Node). Node ESM needs explicit `.js`, so append it for
 * relative specifiers that lack an extension — letting the built dist/ run
 * under `node --test`. Test files themselves already use explicit `.js`.
 */
export async function resolve(specifier, context, nextResolve) {
  if (
    (specifier.startsWith("./") || specifier.startsWith("../")) &&
    !/\.[cm]?js$/.test(specifier)
  ) {
    try {
      return await nextResolve(specifier + ".js", context);
    } catch {
      /* fall through to the default resolver */
    }
  }
  return nextResolve(specifier, context);
}
