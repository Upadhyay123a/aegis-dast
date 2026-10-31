/**
 * Active check: open redirect.
 *
 * SAFE BY DESIGN: we point a redirect parameter at a benign external canary host
 * and observe whether the application issues a 3xx redirect to it (via the
 * Location header) or emits a meta/JS redirect to it. No request is made to the
 * canary host itself.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { injectionPoints } from './inject.js';

const CANARY = 'https://aegis-canary.example.net/';
const REDIRECT_PARAM_HINTS = /^(url|redirect|redir|next|return|returnurl|dest|destination|continue|to|r|u)$/i;

export const openRedirectCheck: Check = {
  id: 'open-redirect',
  title: 'Open redirect',
  kind: 'active',
  description: 'Detects unvalidated redirects to attacker-controlled URLs.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const points = injectionPoints(ctx.endpoint);
    const findings: Finding[] = [];

    for (const point of points) {
      // Only test parameters whose names suggest a redirect target (reduces noise).
      if (!REDIRECT_PARAM_HINTS.test(point.param.name)) continue;

      const exchange = await point.send(ctx.http, CANARY);
      if (exchange.status === 0) continue;

      const location = exchange.responseHeaders['location'] ?? '';
      const where = point.describe();
      const inLocation = exchange.status >= 300 && exchange.status < 400 && pointsTo(location, CANARY);
      const inBody =
        /<meta[^>]+http-equiv=["']?refresh/i.test(exchange.body) && exchange.body.includes(CANARY);

      if (inLocation || inBody) {
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: 'Open redirect',
            severity: 'medium',
            confidence: inLocation ? 'firm' : 'tentative',
            kind: 'active',
            description:
              `The "${where.param}" parameter controls a redirect to an external URL without validation. ` +
              'Attackers can abuse this for phishing and OAuth token theft.',
            remediation:
              'Allowlist redirect targets (relative paths or a fixed set of hosts). Reject absolute URLs to ' +
              'untrusted hosts. Do not reflect user input directly into Location.',
            references: ['CWE-601', 'https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards'],
            evidence: {
              url: where.url,
              method: where.method,
              param: where.param,
              payload: CANARY,
              responseStatus: exchange.status,
              snippet: inLocation ? `Location: ${location}` : 'meta refresh to canary in body',
            },
          }),
        );
      }
    }

    return findings;
  },
};

function pointsTo(location: string, canary: string): boolean {
  if (!location) return false;
  if (location.startsWith(canary)) return true;
  // Also catch scheme-relative or host-only forms.
  try {
    return new URL(location, 'https://placeholder.invalid').host === new URL(canary).host;
  } catch {
    return location.includes('aegis-canary.example.net');
  }
}
