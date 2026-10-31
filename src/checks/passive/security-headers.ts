/**
 * Passive check: missing or weak HTTP security headers.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding, Severity } from '../../types.js';

interface HeaderRule {
  header: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  references: string[];
  /** Only applies to HTML responses. */
  htmlOnly?: boolean;
}

const RULES: HeaderRule[] = [
  {
    header: 'content-security-policy',
    severity: 'medium',
    title: 'Missing Content-Security-Policy header',
    description:
      'No Content-Security-Policy (CSP) header was returned. CSP is a strong defense-in-depth control against cross-site scripting and data injection.',
    remediation:
      "Add a restrictive CSP, e.g. `Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'`.",
    references: ['CWE-693', 'https://owasp.org/www-project-secure-headers/'],
    htmlOnly: true,
  },
  {
    header: 'strict-transport-security',
    severity: 'medium',
    title: 'Missing Strict-Transport-Security header',
    description:
      'HSTS is not set. Without it, browsers may connect over plaintext HTTP and be exposed to downgrade/SSL-strip attacks.',
    remediation: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` (HTTPS only).',
    references: ['CWE-319', 'https://owasp.org/www-project-secure-headers/'],
  },
  {
    header: 'x-content-type-options',
    severity: 'low',
    title: 'Missing X-Content-Type-Options header',
    description: 'Responses do not send `X-Content-Type-Options: nosniff`, allowing MIME sniffing.',
    remediation: 'Add `X-Content-Type-Options: nosniff`.',
    references: ['CWE-693', 'https://owasp.org/www-project-secure-headers/'],
  },
  {
    header: 'x-frame-options',
    severity: 'low',
    title: 'Missing clickjacking protection',
    description:
      'Neither `X-Frame-Options` nor a CSP `frame-ancestors` directive is present, so the page may be framed by attackers (clickjacking).',
    remediation: "Set `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'`.",
    references: ['CWE-1021', 'https://owasp.org/www-project-secure-headers/'],
    htmlOnly: true,
  },
  {
    header: 'referrer-policy',
    severity: 'info',
    title: 'Missing Referrer-Policy header',
    description: 'No Referrer-Policy is set; full URLs may leak to third parties via the Referer header.',
    remediation: 'Add `Referrer-Policy: strict-origin-when-cross-origin` or stricter.',
    references: ['https://owasp.org/www-project-secure-headers/'],
    htmlOnly: true,
  },
];

export const securityHeadersCheck: Check = {
  id: 'security-headers',
  title: 'HTTP security headers',
  kind: 'passive',
  description: 'Flags missing or weak HTTP security response headers.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const { baseline, endpoint } = ctx;
    if (baseline.status === 0) return [];
    const headers = baseline.responseHeaders;
    const isHtml = (headers['content-type'] ?? '').includes('html');
    const findings: Finding[] = [];

    for (const rule of RULES) {
      if (rule.htmlOnly && !isHtml) continue;
      const present = headers[rule.header] !== undefined;
      // Clickjacking is also satisfied by CSP frame-ancestors.
      if (
        rule.header === 'x-frame-options' &&
        (headers['content-security-policy'] ?? '').includes('frame-ancestors')
      ) {
        continue;
      }
      if (present) continue;

      findings.push(
        makeFinding({
          ruleId: this.id,
          title: rule.title,
          severity: rule.severity,
          confidence: 'firm',
          kind: 'passive',
          description: rule.description,
          remediation: rule.remediation,
          references: rule.references,
          evidence: {
            url: endpoint.url,
            method: baseline.method,
            responseStatus: baseline.status,
            snippet: `Response headers present: ${Object.keys(headers).join(', ') || '(none)'}`,
          },
        }),
      );
    }

    return findings;
  },
};
