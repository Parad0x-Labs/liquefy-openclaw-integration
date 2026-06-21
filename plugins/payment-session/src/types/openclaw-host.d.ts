/**
 * Typecheck-only ambient declaration for the OpenClaw host-runtime module.
 * Resolved by the OpenClaw plugin loader at runtime; this `any` shim lets the
 * plugin typecheck standalone (the openclaw-skills modularity contract).
 */
declare module "openclaw/plugin-sdk/plugin-entry" {
  export function definePluginEntry(entry: any): any;
}
