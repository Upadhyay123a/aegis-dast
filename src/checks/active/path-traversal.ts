/**
 * Active check: path traversal / local file inclusion (read-only probe).
 *
 * SAFE BY DESIGN: payloads only attempt to *read* well-known, non-sensitive
 * system markers (`/etc/passwd` root line, Windows `boot.ini`/hosts markers).
 * Detection relies on signature strings appearing in the response. No files are
 * written or modified.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { injectionPoints } from './inject.js';
import { snippetAround } from '../../util/text.js';

const PAYLOADS = [
  '../../../../../../etc/passwd',
  '....//....//....//....//etc/passwd',
  '..%2f..%2f..%2f..%2fetc%2fpasswd',
  '../../../../../../windows/win.ini',
];

const SIGNATURES: Array<{ os: string; re: RegExp }> = [
  { os: 'Linux', re: /root:.*:0:0:/ },
  { os: 'Windows', re: /\[fonts\]|\[extensions\]|for 16-bit app support/i },
];

const FILE_PARAM_HINTS = /^(file|path|page|template|doc|document|download|filename|dir|folder|include|view|load)$/i;

export const pathTraversalCheck: Check = {
  id: 'path-traversal',
  title: 'Path traversal',
  kind: 'active',
  description: 'Probes file/path parameters for local file inclusion (read-only).',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const points = injectionPoints(ctx.endpoint);
    const findings: Finding[] = [];

    for (const point of points) {
      // Prioritize parameters that look file-related; skip others to limit noise
      // unless there are very few params overall.
      const looksFileRelated = FILE_PARAM_HINTS.test(point.param.name);
      if (!looksFileRelated && points.length > 3) continue;

      let reported = false;
      for (const payload of PAYLOADS) {
        if (reported) break;
        const exchange = await point.send(ctx.http, payload);
        if (exchange.status === 0) continue;
        const sig = SIGNATURES.find((s) => s.re.test(exchange.body));
        if (!sig) continue;

        const where = point.describe();
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: `Path traversal / local file inclusion (${sig.os})`,
            severity: 'critical',
            confidence: 'firm',
            kind: 'active',
            description:
              `The "${where.param}" parameter allowed reading a local system file (${sig.os} signature matched). ` +
              'This can expose source code, credentials, and other sensitive files.',
            remediation:
              'Never pass user input to filesystem APIs. Canonicalize and validate against an allowlist of permitted ' +
              'files/paths. Serve files by opaque identifier, not by path.',
            references: ['CWE-22', 'CWE-98', 'https://owasp.org/www-community/attacks/Path_Traversal'],
            evidence: {
              url: where.url,
              method: where.method,
              param: where.param,
              payload,
              responseStatus: exchange.status,
              snippet: snippetAround(exchange.body, sig.os === 'Linux' ? 'root:' : '[') ?? '(signature matched)',
            },
          }),
        );
        reported = true;
      }
    }

    return findings;
  },
};
