/**
 * Passive check: information disclosure — verbose server/version banners,
 * directory listings, and sensitive tokens echoed in responses.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { snippetAround } from '../../util/text.js';

const VERSION_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];

const SENSITIVE_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: 'AWS access key', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'Private key block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { name: 'Generic API key assignment', re: /(?:api[_-]?key|secret|token)["']?\s*[:=]\s*["'][A-Za-z0-9_-]{16,}["']/i },
  { name: 'JWT', re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
];

export const infoLeakCheck: Check = {
  id: 'info-leak',
  title: 'Information disclosure',
  kind: 'passive',
  description: 'Flags version banners, directory listings, and secrets echoed in responses.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const { baseline, endpoint } = ctx;
    if (baseline.status === 0) return [];
    const findings: Finding[] = [];

    // 1) Verbose version banners.
    for (const h of VERSION_HEADERS) {
      const v = baseline.responseHeaders[h];
      if (v && /\d/.test(v)) {
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: `Version disclosure via "${h}" header`,
            severity: 'info',
            confidence: 'firm',
            kind: 'passive',
            description: `The "${h}" header reveals software/version details ("${v}"), aiding targeted attacks.`,
            remediation: `Suppress or genericize the "${h}" header at the server/proxy layer.`,
            references: ['CWE-200'],
            evidence: {
              url: endpoint.url,
              method: baseline.method,
              param: h,
              responseStatus: baseline.status,
              snippet: `${h}: ${v}`,
            },
          }),
        );
      }
    }

    // 2) Directory listing.
    if (/<title>\s*Index of \//i.test(baseline.body) || /Directory listing for/i.test(baseline.body)) {
      findings.push(
        makeFinding({
          ruleId: this.id,
          title: 'Directory listing enabled',
          severity: 'low',
          confidence: 'firm',
          kind: 'passive',
          description: 'The server returned an auto-generated directory index, exposing file names.',
          remediation: 'Disable automatic directory indexing (e.g. Apache `Options -Indexes`).',
          references: ['CWE-548'],
          evidence: {
            url: endpoint.url,
            method: baseline.method,
            responseStatus: baseline.status,
            snippet: snippetAround(baseline.body, 'Index of') ?? 'Index of /',
          },
        }),
      );
    }

    // 3) Secrets echoed in the body.
    for (const { name, re } of SENSITIVE_PATTERNS) {
      const m = baseline.body.match(re);
      if (m) {
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: `Possible secret exposed in response (${name})`,
            severity: 'high',
            confidence: 'tentative',
            kind: 'passive',
            description: `A pattern matching a ${name} was found in the response body. If genuine, this is a serious disclosure.`,
            remediation: 'Remove secrets from responses; rotate any exposed credential immediately.',
            references: ['CWE-200', 'CWE-312'],
            evidence: {
              url: endpoint.url,
              method: baseline.method,
              responseStatus: baseline.status,
              // Redact: show only the type, not the full secret.
              snippet: `${name} pattern matched (value redacted)`,
            },
          }),
        );
      }
    }

    return findings;
  },
};
