/**
 * Scan engine — orchestrates the full pipeline:
 *   scope + auth gate -> crawl -> run checks per endpoint -> AI verify -> score.
 */
import pLimit from 'p-limit';
import type { Config } from '../config.js';
import type {
  AttackSurface,
  Endpoint,
  Finding,
  HttpExchange,
  ScanResult,
  Severity,
} from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { Scope } from './scope.js';
import { HttpClient } from './http-client.js';
import { Crawler } from '../crawler/crawler.js';
import { selectChecks } from '../checks/registry.js';
import type { Check, CheckContext } from '../checks/context.js';
import { createProvider } from '../ai/factory.js';
import { verifyFindings } from '../ai/verifier.js';
import { logger } from '../util/logger.js';

export interface EngineHooks {
  onPhase?: (phase: string, detail?: string) => void;
}

export class Engine {
  private readonly scope: Scope;
  private readonly http: HttpClient;

  constructor(
    private readonly config: Config,
    private readonly hooks: EngineHooks = {},
  ) {
    this.scope = new Scope(config.scope, config.target);
    this.http = new HttpClient(config, this.scope);
  }

  async run(): Promise<ScanResult> {
    const start = Date.now();
    const startedAt = new Date().toISOString();

    // --- Safety gate ---
    if (this.config.active && !this.config.authorized) {
      logger.warn(
        'Active scanning requested without authorization — running PASSIVE checks only. ' +
          'Pass --i-have-authorization to enable active checks (only on systems you may test).',
      );
    }
    logger.info(`Scope: ${this.scope.describe().join(', ')}`);

    // --- AI provider ---
    const ai = await createProvider(this.config);

    // --- Crawl ---
    this.hooks.onPhase?.('crawl', this.config.target);
    logger.info(`Crawling ${this.config.target} ...`);
    const crawler = new Crawler(this.config, this.scope, this.http);
    const surface: AttackSurface = await crawler.crawl();
    logger.success(`Discovered ${surface.endpoints.length} endpoint(s) in ${surface.requestCount} request(s)`);

    // --- Run checks ---
    this.hooks.onPhase?.('scan');
    const checks = selectChecks(this.config);
    logger.info(
      `Running ${checks.length} check(s): ${checks.map((c) => c.id).join(', ') || '(none)'}`,
    );
    const rawFindings = await this.runChecks(surface, checks, ai);
    const deduped = dedupe(rawFindings);
    logger.success(`Collected ${deduped.length} candidate finding(s)`);

    // --- AI verification (false-positive reduction) ---
    this.hooks.onPhase?.('verify');
    const { kept, suppressed } = await verifyFindings(deduped, ai, this.config);

    // --- Score & assemble ---
    const findings = sortFindings(kept);
    const finishedAt = new Date().toISOString();
    const result: ScanResult = {
      target: this.config.target,
      startedAt,
      finishedAt,
      durationMs: Date.now() - start,
      requestCount: this.http.requestCount,
      aiProvider: ai.enabled ? `${ai.name}:${ai.model}` : 'none',
      findings,
      stats: {
        endpoints: surface.endpoints.length,
        bySeverity: countBySeverity(findings),
        suppressedFalsePositives: suppressed,
      },
    };
    return result;
  }

  private async runChecks(
    surface: AttackSurface,
    checks: Check[],
    ai: CheckContext['ai'],
  ): Promise<Finding[]> {
    const limit = pLimit(this.config.concurrency);
    const all: Finding[] = [];

    await Promise.all(
      surface.endpoints.map((endpoint) =>
        limit(async () => {
          const baseline = await this.baselineFor(endpoint);
          const ctx: CheckContext = { config: this.config, http: this.http, ai, endpoint, baseline };
          for (const check of checks) {
            try {
              const found = await check.run(ctx);
              all.push(...found);
            } catch (err) {
              logger.debug(`check ${check.id} failed on ${endpoint.url}: ${(err as Error).message}`);
            }
          }
        }),
      ),
    );

    return all;
  }

  private async baselineFor(endpoint: Endpoint): Promise<HttpExchange> {
    if (endpoint.exchange) return endpoint.exchange;
    return this.http.fetch(endpoint.url);
  }
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Map<string, Finding>();
  for (const f of findings) {
    if (!seen.has(f.id)) seen.set(f.id, f);
  }
  return [...seen.values()];
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sev = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    if (sev !== 0) return sev;
    return a.ruleId.localeCompare(b.ruleId);
  });
}

function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

/** Returns true if any finding meets/exceeds the fail-on threshold. */
export function shouldFail(result: ScanResult, failOn: Config['failOn']): boolean {
  if (failOn === 'never') return false;
  const threshold = SEVERITY_ORDER[failOn as Severity];
  return result.findings.some((f) => SEVERITY_ORDER[f.severity] >= threshold);
}
