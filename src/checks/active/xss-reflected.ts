/**
 * Active check: reflected Cross-Site Scripting (XSS).
 *
 * SAFE BY DESIGN: we inject a unique, inert marker wrapped in HTML-significant
 * characters (e.g. `"<aegXXXX>`). We never execute script; we only observe
 * whether the marker is reflected *without encoding*, which indicates the
 * response is vulnerable to script injection at that point.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { injectionPoints } from './inject.js';
import { marker, snippetAround } from '../../util/text.js';

export const xssReflectedCheck: Check = {
  id: 'xss-reflected',
  title: 'Reflected XSS',
  kind: 'active',
  description: 'Injects an inert marker and detects unencoded reflection in the response.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const points = injectionPoints(ctx.endpoint);
    if (points.length === 0) return [];

    const findings: Finding[] = [];

    for (const point of points) {
      const tag = marker('aegx');
      // Characters that must survive un-encoded for script injection to work.
      const probe = `"'><${tag}>`;
      const exchange = await point.send(ctx.http, probe);
      if (exchange.status === 0) continue;

      const body = exchange.body;
      const reflectedRaw = body.includes(`<${tag}>`);
      const reflectedEncoded = body.includes(`&lt;${tag}&gt;`) || body.includes(`&#60;${tag}`);

      if (reflectedRaw && !reflectedEncoded) {
        const where = point.describe();
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: 'Reflected XSS — unencoded input reflected in response',
            severity: 'high',
            confidence: 'firm',
            kind: 'active',
            description:
              'User-controlled input was reflected into the HTML response without output encoding. ' +
              'An attacker can inject arbitrary markup/script that executes in a victim’s browser.',
            remediation:
              'Context-aware output encoding (HTML-encode by default), a strict Content-Security-Policy, ' +
              'and input validation. Prefer framework auto-escaping over manual string building.',
            references: ['CWE-79', 'A03:2021-Injection', 'https://owasp.org/www-community/attacks/xss/'],
            evidence: {
              url: where.url,
              method: where.method,
              param: where.param,
              payload: probe,
              responseStatus: exchange.status,
              snippet: snippetAround(body, `<${tag}>`) ?? `<${tag}>`,
            },
          }),
        );
      }
    }

    return findings;
  },
};
