/**
 * Report dispatcher — writes the requested report formats to disk and prints the
 * console report. Returns the paths written.
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import type { Config, ReportFormat } from '../config.js';
import type { ScanResult } from '../types.js';
import { renderConsole } from './console.js';
import { renderJson } from './json.js';
import { renderSarif } from './sarif.js';
import { renderHtml } from './html.js';
import { logger } from '../util/logger.js';

export { renderConsole, renderJson, renderSarif, renderHtml };

const FILE_FORMATS: Record<Exclude<ReportFormat, 'console'>, { ext: string; render: (r: ScanResult) => string }> = {
  json: { ext: 'json', render: renderJson },
  sarif: { ext: 'sarif', render: renderSarif },
  html: { ext: 'html', render: renderHtml },
};

export async function emitReports(result: ScanResult, config: Config): Promise<string[]> {
  const written: string[] = [];

  if (config.reports.includes('console')) {
    // Console report goes to stdout (everything else from the logger is stderr).
    process.stdout.write(renderConsole(result) + '\n');
  }

  const fileFormats = config.reports.filter((f): f is Exclude<ReportFormat, 'console'> => f !== 'console');
  if (fileFormats.length === 0) return written;

  const base = config.outDir;
  await mkdir(dirname(join(base, 'x')), { recursive: true }).catch(() => undefined);
  await mkdir(base, { recursive: true }).catch(() => undefined);

  for (const fmt of fileFormats) {
    const spec = FILE_FORMATS[fmt];
    const path = join(base, `report.${spec.ext}`);
    await writeFile(path, spec.render(result), 'utf8');
    written.push(path);
    logger.success(`Wrote ${fmt.toUpperCase()} report: ${path}`);
  }

  return written;
}
