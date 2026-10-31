/**
 * Active check: CRLF / HTTP response header injection.
 *
 * SAFE BY DESIGN: injects an encoded CRLF followed by a benign marker header into
 * each parameter and checks whether that marker appears as a real response
 * header. If it does, the app lets user input split the response — enabling
 * header injection, cache poisoning, and some XSS.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { injectionPoints } from './inject.js';
import { marker } from '../../util/text.js';

export const crlfInjectionCheck: Check = {
  id: 'crlf-injection',
  title: 'CRLF / header injection',
  kind: 'active',
  description: 'Detects response-splitting via CRLF sequences in parameters.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const points = injectionPoints(ctx.endpoint);
    const findings: Finding[] = [];
    const headerName = 'x-aegis-crlf';

    for (const point of points) {
      const token = marker('crlf');
      // Several encodings — servers decode differently.
      const payloads = [
        `aegis%0d%0a${headerName}%3a%20${token}`,
        `aegis\r\n${headerName}: ${token}`,
        `aegis%0d%0a${headerName}:${token}`,
      ];

      let reported = false;
      for (const payload of payloads) {
        if (reported) break;
        const res = await point.send(ctx.http, payload);
        if (res.status === 0) continue;
        const injected = res.responseHeaders[headerName];
        if (injected && injected.includes(token)) {
          const where = point.describe();
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: 'CRLF injection / HTTP response splitting',
              severity: 'medium',
              confidence: 'firm',
              kind: 'active',
              description:
                `Input to "${where.param}" was able to inject a new HTTP response header (${headerName}). ` +
                'This enables response splitting, header injection, and cache poisoning.',
              remediation:
                'Strip or reject CR (%0d) and LF (%0a) characters in any value placed into response headers ' +
                '(redirect locations, cookies, custom headers). Use framework APIs that encode header values.',
              references: ['CWE-113', 'CWE-93', 'https://owasp.org/www-community/attacks/HTTP_Response_Splitting'],
              evidence: {
                url: where.url,
                method: where.method,
                param: where.param,
                payload,
                responseStatus: res.status,
                snippet: `${headerName}: ${injected}`,
              },
            }),
          );
          reported = true;
        }
      }
    }

    return findings;
  },
};
