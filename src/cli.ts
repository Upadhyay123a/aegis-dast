#!/usr/bin/env node
/**
 * Aegis-DAST command-line interface.
 */
import { Command, Option } from 'commander';
import chalk from 'chalk';
import { loadDotenv } from './util/env.js';
import { logger } from './util/logger.js';
import { mergeConfig, loadConfigFile, type ConfigInput } from './config.js';
import { Engine, shouldFail } from './core/engine.js';
import { emitReports } from './report/index.js';
import { ALL_CHECKS } from './checks/registry.js';

loadDotenv();

const program = new Command();

program
  .name('aegis')
  .description('Aegis-DAST — an AI-augmented, safe-by-default web application security scanner.')
  .version('0.1.0');

program
  .command('scan')
  .argument('<target>', 'target URL to scan, e.g. https://example.com')
  .description('Crawl and scan a target for security issues')
  .option('-s, --scope <hosts>', 'comma-separated scope allowlist (hosts or URL prefixes)', collectList, [])
  .option('-a, --active', 'enable active (attack) checks — requires --i-have-authorization', false)
  .option('--i-have-authorization', 'confirm you are authorized to actively test the target', false)
  .addOption(new Option('--ai <provider>', 'AI engine').choices(['auto', 'claude', 'openai', 'none']).default('auto'))
  .option('--ai-model <model>', 'override the AI model id')
  .option('--ai-min-severity <sev>', 'only AI-verify findings at/above this severity', 'low')
  .option('-r, --report <formats>', 'comma-separated: console,json,html,sarif', collectList, ['console'])
  .option('-o, --out <dir>', 'output directory for file reports', './aegis-report')
  .option('-d, --depth <n>', 'max crawl depth', toInt, 3)
  .option('--max-urls <n>', 'max URLs to crawl', toInt, 200)
  .option('-c, --concurrency <n>', 'concurrent requests', toInt, 8)
  .option('--delay <ms>', 'min delay between requests to a host (ms)', toInt, 0)
  .option('--timeout <ms>', 'per-request timeout (ms)', toInt, 15000)
  .option('-H, --header <header>', 'extra request header "Name: value" (repeatable)', collectHeader, {})
  .option('--include <rules>', 'only run these rule ids (comma-separated)', collectList, [])
  .option('--exclude <rules>', 'skip these rule ids (comma-separated)', collectList, [])
  .option('--no-robots', 'do not fetch/respect robots.txt')
  .addOption(
    new Option('--fail-on <sev>', 'exit non-zero if a finding at/above this severity exists')
      .choices(['never', 'low', 'medium', 'high', 'critical'])
      .default('never'),
  )
  .option('--config <path>', 'load a JSON config file')
  .option('-v, --verbose', 'verbose (debug) logging', false)
  .option('-q, --quiet', 'only errors', false)
  .action(async (target: string, opts: Record<string, any>) => {
    if (opts.verbose) logger.setLevel('debug');
    else if (opts.quiet) logger.setLevel('error');

    printBanner();

    try {
      const fileConfig = opts.config ? await loadConfigFile(opts.config) : {};
      const cliConfig: Partial<ConfigInput> = {
        target,
        scope: opts.scope,
        active: opts.active,
        authorized: opts.iHaveAuthorization,
        ai: opts.ai,
        aiModel: opts.aiModel,
        aiMinSeverity: opts.aiMinSeverity,
        reports: opts.report,
        outDir: opts.out,
        maxDepth: opts.depth,
        maxUrls: opts.maxUrls,
        concurrency: opts.concurrency,
        requestDelayMs: opts.delay,
        timeoutMs: opts.timeout,
        headers: opts.header,
        includeRules: opts.include,
        excludeRules: opts.exclude,
        respectRobots: opts.robots,
        failOn: opts.failOn,
      };

      const config = mergeConfig(fileConfig, cliConfig);

      if (config.active && !config.authorized) {
        logger.warn(
          'You requested --active without --i-have-authorization. ' +
            'Active checks are disabled. Only scan systems you own or have permission to test.',
        );
      }

      const engine = new Engine(config, {
        onPhase: (phase, detail) => logger.debug(`phase: ${phase}${detail ? ` (${detail})` : ''}`),
      });
      const result = await engine.run();
      await emitReports(result, config);

      if (shouldFail(result, config.failOn)) {
        logger.error(`Failing: findings at/above severity "${config.failOn}" were detected.`);
        process.exitCode = 2;
      }
    } catch (err) {
      logger.error((err as Error).message);
      if (opts.verbose) console.error(err);
      process.exitCode = 1;
    }
  });

program
  .command('checks')
  .description('List available checks')
  .action(() => {
    printBanner();
    const byKind = { passive: ALL_CHECKS.filter((c) => c.kind === 'passive'), active: ALL_CHECKS.filter((c) => c.kind === 'active') };
    for (const kind of ['passive', 'active'] as const) {
      console.log(chalk.bold(`\n${kind.toUpperCase()} checks`));
      for (const c of byKind[kind]) {
        console.log(`  ${chalk.cyan(c.id.padEnd(16))} ${c.description}`);
      }
    }
    console.log(
      chalk.gray('\nActive checks only run with both --active and --i-have-authorization.\n'),
    );
  });

program.parseAsync(process.argv).catch((err) => {
  logger.error((err as Error).message);
  process.exitCode = 1;
});

// --- option parsers ---
function collectList(value: string, prev: string[]): string[] {
  const items = value.split(',').map((s) => s.trim()).filter(Boolean);
  return [...prev, ...items];
}

function collectHeader(value: string, prev: Record<string, string>): Record<string, string> {
  const idx = value.indexOf(':');
  if (idx === -1) return prev;
  const name = value.slice(0, idx).trim();
  const val = value.slice(idx + 1).trim();
  return { ...prev, [name]: val };
}

function toInt(value: string): number {
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) throw new Error(`Expected a number, got "${value}"`);
  return n;
}

function printBanner(): void {
  logger.info(chalk.bold('Aegis-DAST') + chalk.gray(' — AI-augmented DAST scanner'));
}
