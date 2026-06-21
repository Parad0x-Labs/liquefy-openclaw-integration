/**
 * Typecheck-only ambient declarations for OpenClaw host-runtime modules.
 *
 * At runtime these specifiers are resolved by the OpenClaw plugin loader —
 * they are not npm packages and publish no typings. These `any`-level shims
 * exist so the plugin typechecks standalone (the openclaw-skills modularity
 * contract: every module builds in isolation). Inside a real OpenClaw
 * workspace the host's actual types take precedence.
 */
declare module "openclaw/plugin-sdk/plugin-entry" {
  export function definePluginEntry(entry: any): any;
}
