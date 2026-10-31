/**
 * Passive check: forms that change state without an anti-CSRF token.
 *
 * Looks at HTML forms discovered on the page. A POST form with no hidden field
 * that looks like a CSRF token is a candidate for Cross-Site Request Forgery,
 * especially when session cookies lack SameSite.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';

const TOKEN_FIELD = /csrf|xsrf|token|authenticity|nonce|_token|verification/i;

export const csrfCheck: Check = {
  id: 'csrf',
  title: 'Missing CSRF protection',
  kind: 'passive',
  description: 'Flags state-changing forms that lack an anti-CSRF token field.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const { endpoint, baseline } = ctx;
    const findings: Finding[] = [];

    const cookies = baseline.responseHeaders['set-cookie'] ?? '';
    const sameSiteMissing = cookies !== '' && !/samesite/i.test(cookies);

    for (const form of endpoint.forms) {
      if (form.method !== 'POST') continue; // GET forms are not state-changing by convention
      const hasToken = form.params.some((p) => TOKEN_FIELD.test(p.name));
      if (hasToken) continue;

      findings.push(
        makeFinding({
          ruleId: this.id,
          title: 'Form without anti-CSRF token',
          severity: sameSiteMissing ? 'medium' : 'low',
          confidence: 'tentative',
          kind: 'passive',
          description:
            `A POST form (action ${form.action}) has no hidden anti-CSRF token field` +
            (sameSiteMissing ? ', and session cookies are not SameSite-protected' : '') +
            '. It may be forgeable from another site.',
          remediation:
            'Add a per-session/per-request CSRF token to state-changing forms and verify it server-side. ' +
            'Set SameSite=Lax or Strict on session cookies as defense-in-depth.',
          references: ['CWE-352', 'https://owasp.org/www-community/attacks/csrf'],
          evidence: {
            url: endpoint.url,
            method: 'POST',
            responseStatus: baseline.status,
            // Stable snippet (field names, not the per-page action URL) so the
            // same recurring form across many pages aggregates into one finding.
            snippet: `POST form fields=[${form.params.map((p) => p.name).join(', ')}]`,
          },
        }),
      );
    }

    return findings;
  },
};
