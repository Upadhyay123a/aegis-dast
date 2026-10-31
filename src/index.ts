/**
 * Aegis-DAST — programmatic API.
 *
 * @example
 * import { scan } from 'aegis-dast';
 * const result = await scan({ target: 'https://example.com', scope: ['example.com'] });
 */
export { Engine, shouldFail } from './core/engine.js';
export { Scope, ScopeError } from './core/scope.js';
export { HttpClient } from './core/http-client.js';
export { Crawler } from './crawler/crawler.js';
export { ConfigSchema, parseConfig, mergeConfig, loadConfigFile } from './config.js';
export type { Config, ConfigInput, ReportFormat, AiProviderName } from './config.js';
export { ALL_CHECKS, selectChecks, checkById } from './checks/registry.js';
export type { Check, CheckContext } from './checks/context.js';
export { emitReports, renderConsole, renderJson, renderSarif, renderHtml } from './report/index.js';
export { createProvider } from './ai/factory.js';
export * from './types.js';

import type { ConfigInput } from './config.js';
import { parseConfig } from './config.js';
import { Engine, type EngineHooks } from './core/engine.js';
import type { ScanResult } from './types.js';

/** Convenience: validate config and run a full scan. */
export async function scan(input: ConfigInput, hooks?: EngineHooks): Promise<ScanResult> {
  const config = parseConfig(input);
  const engine = new Engine(config, hooks);
  return engine.run();
}
