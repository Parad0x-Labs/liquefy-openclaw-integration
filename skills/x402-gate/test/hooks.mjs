/**
 * Module resolve hook for the node:test runner.
 *
 * The skill sources use extensionless relative imports (TypeScript "bundler"
 * moduleResolution, since the plugin is loaded by OpenClaw's bundler-aware
 * loader, not raw Node). Node ESM needs an explicit extension, so for relative
 * specifiers that lack one, try the `.ts` source first (Node strips its types),
 * then fall back to a compiled `.js`. Lets the wire tests run against the real
 * source with no build step. Test files themselves use explicit `.ts`.
 */
export async function resolve(specifier, context, nextResolve) {
  if (
    (specifier.startsWith("./") || specifier.startsWith("../")) &&
    !/\.[cm]?[jt]s$/.test(specifier)
  ) {
    for (const ext of [".ts", ".js"]) {
      try {
        return await nextResolve(specifier + ext, context);
      } catch {
        /* try the next candidate extension */
      }
    }
  }
  return nextResolve(specifier, context);
}
