/**
 * Passive check: insecure cookie attributes (missing HttpOnly / Secure /
 * SameSite on Set-Cookie headers).
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';

export const cookieFlagsCheck: Check = {
  id: 'cookie-flags',
  title: 'Insecure cookie attributes',
  kind: 'passive',
  description: 'Flags Set-Cookie headers missing HttpOnly, Secure, or SameSite.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const { baseline, endpoint } = ctx;
    const raw = baseline.responseHeaders['set-cookie'];
    if (!raw) return [];

    // undici joins multiple Set-Cookie values with ", " — split carefully on
    // cookie boundaries (a comma followed by a token and "=").
    const cookies = raw.split(/,(?=\s*[A-Za-z0-9_.-]+=)/);
    const findings: Finding[] = [];

    for (const cookie of cookies) {
      const name = cookie.split('=')[0]?.trim() ?? 'cookie';
      const lc = cookie.toLowerCase();
      const missing: string[] = [];
      if (!lc.includes('httponly')) missing.push('HttpOnly');
      if (!lc.includes('secure')) missing.push('Secure');
      if (!lc.includes('samesite')) missing.push('SameSite');
      if (missing.length === 0) continue;

      findings.push(
        makeFinding({
          ruleId: this.id,
          title: `Cookie "${name}" missing ${missing.join(', ')}`,
          severity: missing.includes('HttpOnly') ? 'medium' : 'low',
          confidence: 'firm',
          kind: 'passive',
          description: `The Set-Cookie for "${name}" is missing the ${missing.join(
            ', ',
          )} attribute(s), which weakens protection against theft (XSS) and CSRF.`,
          remediation:
            'Set HttpOnly (blocks JS access), Secure (HTTPS-only), and SameSite=Lax or Strict on session cookies.',
          references: ['CWE-1004', 'CWE-614', 'https://owasp.org/www-community/controls/SecureCookieAttribute'],
          evidence: {
            url: endpoint.url,
            method: baseline.method,
            param: name,
            responseStatus: baseline.status,
            snippet: cookie.trim().slice(0, 200),
          },
        }),
      );
    }

    return findings;
  },
};
