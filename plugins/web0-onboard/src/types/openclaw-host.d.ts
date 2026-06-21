/**
 * Typecheck-only ambient declarations for the OpenClaw host-runtime SDK.
 *
 * At runtime these specifiers are resolved by the OpenClaw plugin loader; the host
 * supplies the real implementations. These declarations are FAITHFUL to the real
 * SDK contract at `openclaw/plugin-sdk/tool-plugin` (verified by typechecking this
 * skill against the real `openclaw` + `typebox` types), and exist so the skill
 * keeps building standalone (the openclaw-skills modularity contract). Inside a real
 * OpenClaw workspace the host's actual types take precedence.
 *
 * NOTE: this is intentionally a precise, non-`any` contract — an earlier loose shim
 * let a hallucinated tool shape (`{ parameters: Record, handler }`) slip through.
 */
declare module "openclaw/plugin-sdk/tool-plugin" {
  import type { TSchema, Static } from "typebox";

  export const toolPluginMetadataSymbol: unique symbol;

  export type ToolPluginExecutionContext = {
    api: unknown;
    signal?: AbortSignal;
    toolCallId: string;
    onUpdate?: (update: unknown) => void;
  };

  type ToolPluginToolDefinition<TConfig, P extends TSchema> = {
    name: string;
    label?: string;
    description: string;
    parameters: P;
    optional?: boolean;
  } & (
    | {
        execute: (params: Static<P>, config: TConfig, context: ToolPluginExecutionContext) => unknown;
        factory?: never;
      }
    | {
        factory: (context: { api: unknown; config: TConfig; toolContext: unknown }) => unknown;
        execute?: never;
      }
  );

  type ToolPluginToolFactory<TConfig> = <P extends TSchema>(
    definition: ToolPluginToolDefinition<TConfig, P>,
  ) => unknown;

  export type DefinedToolPluginEntry = {
    register: (api: unknown) => void;
    readonly [toolPluginMetadataSymbol]: {
      id: string;
      name: string;
      description: string;
      tools: { name: string; label: string; description: string; parameters: unknown; optional?: boolean }[];
    };
  };

  export function defineToolPlugin<TConfigSchema extends TSchema | undefined = undefined>(definition: {
    id: string;
    name: string;
    description: string;
    activation?: unknown;
    configSchema?: TConfigSchema;
    tools: (
      tool: ToolPluginToolFactory<TConfigSchema extends TSchema ? Static<TConfigSchema> : Record<string, never>>,
    ) => readonly unknown[];
  }): DefinedToolPluginEntry;
}
