/**
 * Console reporter — a readable summary printed to stdout.
 */
import chalk from 'chalk';
import type { ScanResult, Severity, Finding } from '../types.js';

const SEV_COLOR: Record<Severity, (s: string) => string> = {
  critical: (s) => chalk.bgRed.white.bold(` ${s} `),
  high: (s) => chalk.red.bold(s),
  medium: (s) => chalk.yellow.bold(s),
  low: (s) => chalk.blue(s),
  info: (s) => chalk.gray(s),
};

export function renderConsole(result: ScanResult): string {
  const lines: string[] = [];
  lines.push('');
  lines.push(chalk.bold(`Aegis-DAST scan report`));
  lines.push(chalk.gray(`Target: ${result.target}`));
  lines.push(
    chalk.gray(
      `Endpoints: ${result.stats.endpoints} · Requests: ${result.requestCount} · ` +
        `Duration: ${(result.durationMs / 1000).toFixed(1)}s · AI: ${result.aiProvider}`,
    ),
  );
  if (result.stats.suppressedFalsePositives > 0) {
    lines.push(chalk.gray(`AI suppressed ${result.stats.suppressedFalsePositives} likely false positive(s)`));
  }
  lines.push('');

  const s = result.stats.bySeverity;
  lines.push(
    'Summary: ' +
      [
        SEV_COLOR.critical(`critical ${s.critical}`),
        SEV_COLOR.high(`high ${s.high}`),
        SEV_COLOR.medium(`medium ${s.medium}`),
        SEV_COLOR.low(`low ${s.low}`),
        SEV_COLOR.info(`info ${s.info}`),
      ].join('  '),
  );
  lines.push('');

  if (result.findings.length === 0) {
    lines.push(chalk.green('No findings. ✔'));
    return lines.join('\n');
  }

  for (const f of result.findings) {
    lines.push(renderFinding(f));
    lines.push('');
  }
  return lines.join('\n');
}

function renderFinding(f: Finding): string {
  const badge = SEV_COLOR[f.severity](f.severity.toUpperCase());
  const head = `${badge} ${chalk.bold(f.title)} ${chalk.gray(`[${f.ruleId}]`)}`;
  const loc = `  ${chalk.gray('at')} ${f.evidence.method} ${f.evidence.url}${
    f.evidence.param ? chalk.gray(` (param: ${f.evidence.param})`) : ''
  }`;
  const conf = `  ${chalk.gray('confidence:')} ${f.confidence}${
    f.aiReview ? chalk.gray(` · AI: ${f.aiReview.verdict} (${f.aiReview.exploitabilityScore.toFixed(2)})`) : ''
  }`;
  const ev = f.evidence.snippet ? `  ${chalk.gray('evidence:')} ${truncateLine(f.evidence.snippet)}` : '';
  const fix = `  ${chalk.gray('fix:')} ${truncateLine(f.remediation, 160)}`;
  return [head, loc, conf, ev, fix].filter(Boolean).join('\n');
}

function truncateLine(s: string, max = 120): string {
  const flat = s.replace(/\s+/g, ' ').trim();
  return flat.length > max ? `${flat.slice(0, max)}…` : flat;
}
