/**
 * Configuration schema and loading for Aegis-DAST.
 *
 * Config can come from (in order of increasing precedence):
 *   defaults  <  config file (aegis.config.json)  <  CLI flags
 */
import { z } from 'zod';
import { readFile } from 'node:fs/promises';

export const AiProviderName = z.enum(['auto', 'claude', 'openai', 'none']);
export type AiProviderName = z.infer<typeof AiProviderName>;

export const ReportFormat = z.enum(['console', 'json', 'html', 'sarif']);
export type ReportFormat = z.infer<typeof ReportFormat>;

export const ConfigSchema = z.object({
  /** Seed URL to start scanning. */
  target: z.string().url(),

  /**
   * Scope allowlist. A request is only sent if its host (or host:port) matches
   * one of these entries, OR its URL starts with one of these as a prefix.
   * If empty, scope defaults to the target's host (safe default).
   */
  scope: z.array(z.string()).default([]),

  /**
   * Explicit authorization. Active (attack) checks only run when this is true.
   * This is a deliberate safety gate — never scan systems you do not own or
   * have written permission to test.
   */
  authorized: z.boolean().default(false),

  /** Run active (attack) checks. Requires `authorized: true`. */
  active: z.boolean().default(false),

  /** Crawl limits. */
  maxDepth: z.number().int().min(0).max(20).default(3),
  maxUrls: z.number().int().min(1).max(5000).default(200),

  /** Networking. */
  concurrency: z.number().int().min(1).max(50).default(8),
  /** Minimum delay between requests to a single host, in ms (politeness). */
  requestDelayMs: z.number().int().min(0).max(60000).default(0),
  timeoutMs: z.number().int().min(100).max(120000).default(15000),
  userAgent: z.string().default('Aegis-DAST/0.1 (+https://github.com/Upadhyay123a/aegis-dast)'),
  respectRobots: z.boolean().default(true),
  followRedirects: z.boolean().default(true),

  /** Extra headers (e.g. a session cookie or bearer token) sent with requests. */
  headers: z.record(z.string()).default({}),

  /** Rule selection. Empty `include` means "all". */
  includeRules: z.array(z.string()).default([]),
  excludeRules: z.array(z.string()).default([]),

  /** AI engine. */
  ai: AiProviderName.default('auto'),
  aiModel: z.string().optional(),
  /** Only run the AI verifier on findings at/above this severity. */
  aiMinSeverity: z.enum(['info', 'low', 'medium', 'high', 'critical']).default('low'),

  /** Reporting. */
  reports: z.array(ReportFormat).default(['console']),
  outDir: z.string().default('./aegis-report'),

  /** Fail the process (non-zero exit) if a finding at/above this severity exists. */
  failOn: z.enum(['never', 'low', 'medium', 'high', 'critical']).default('never'),

  /**
   * Collapse identical site-wide findings (same rule, title and evidence across
   * many URLs) into one entry that notes how many locations are affected. Keeps
   * reports readable on large sites. Per-URL findings (e.g. distinct XSS points)
   * are never merged because their evidence differs.
   */
  aggregate: z.boolean().default(true),
});

export type Config = z.infer<typeof ConfigSchema>;
export type ConfigInput = z.input<typeof ConfigSchema>;

/** Parse and validate a raw config object, applying defaults. */
export function parseConfig(input: ConfigInput): Config {
  return ConfigSchema.parse(input);
}

/** Load a JSON config file and merge it under the given overrides. */
export async function loadConfigFile(path: string): Promise<Partial<ConfigInput>> {
  const raw = await readFile(path, 'utf8');
  return JSON.parse(raw) as Partial<ConfigInput>;
}

/** Merge partial configs left-to-right (later wins), then validate. */
export function mergeConfig(...parts: Array<Partial<ConfigInput>>): Config {
  const merged = parts.reduce<Partial<ConfigInput>>((acc, part) => {
    for (const [k, v] of Object.entries(part)) {
      if (v !== undefined) (acc as Record<string, unknown>)[k] = v;
    }
    return acc;
  }, {});
  return ConfigSchema.parse(merged);
}
