/**
 * Passive deep-analysis checks: JWT weaknesses, Content-Security-Policy quality,
 * DOM-XSS source→sink indicators, and mixed (HTTP-on-HTTPS) content.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { truncate } from '../../util/text.js';

const JWT_RE = /eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{0,}/;

function decodeJwtHeader(token: string): any | undefined {
  try {
    const part = token.split('.')[0]!;
    const json = Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    return JSON.parse(json);
  } catch {
    return undefined;
  }
}

export const jwtAnalysisCheck: Check = {
  id: 'jwt-analysis',
  title: 'JSON Web Token weaknesses',
  kind: 'passive',
  description: 'Finds JWTs in responses and flags weak algorithms (alg:none).',
  async run(ctx: CheckContext): Promise<Finding[]> {
    const { baseline, endpoint } = ctx;
    const haystacks = [
      baseline.responseHeaders['set-cookie'] ?? '',
      baseline.responseHeaders['authorization'] ?? '',
      baseline.body,
    ].join('\n');
    const m = haystacks.match(JWT_RE);
    if (!m) return [];
    const header = decodeJwtHeader(m[0]);
    const alg = header?.alg ? String(header.alg) : undefined;
    const noneAlg = alg && alg.toLowerCase() === 'none';
    return [
      makeFinding({
        ruleId: 'jwt-analysis',
        title: noneAlg ? 'JWT with "alg: none" (signature bypass)' : 'JWT exposed in response',
        severity: noneAlg ? 'high' : 'low',
        confidence: noneAlg ? 'firm' : 'tentative',
        kind: 'passive',
        description: noneAlg
          ? 'A JSON Web Token using "alg: none" was observed, meaning the signature is not verified — tokens can be forged for auth bypass.'
          : `A JSON Web Token (alg: ${alg ?? 'unknown'}) was returned in the response. Verify it is not sensitive and is validated server-side.`,
        remediation:
          'Reject "none" and algorithm confusion; pin an allowed algorithm set server-side; keep tokens out of URLs and non-HttpOnly storage; use short expiry.',
        references: ['CWE-347', 'https://owasp.org/www-project-web-security-testing-guide/'],
        evidence: { url: endpoint.url, method: baseline.method, responseStatus: baseline.status, snippet: `alg=${alg ?? '?'} token=${m[0].slice(0, 24)}…(redacted)` },
      }),
    ];
  },
};

export const cspAnalysisCheck: Check = {
  id: 'csp-analysis',
  title: 'Weak Content-Security-Policy',
  kind: 'passive',
  description: 'Evaluates a present CSP for weaknesses (unsafe-inline, wildcards).',
  async run(ctx: CheckContext): Promise<Finding[]> {
    const csp = ctx.baseline.responseHeaders['content-security-policy'];
    if (!csp) return []; // "missing CSP" is handled by security-headers
    const lc = csp.toLowerCase();
    const issues: string[] = [];
    if (lc.includes("'unsafe-inline'")) issues.push("'unsafe-inline' (allows inline script/style — defeats XSS protection)");
    if (lc.includes("'unsafe-eval'")) issues.push("'unsafe-eval' (allows eval())");
    if (/(?:script-src|default-src)[^;]*\*/.test(lc)) issues.push('wildcard * source in script/default-src');
    if (/script-src[^;]*\bdata:/.test(lc)) issues.push('data: allowed in script-src');
    if (!lc.includes('object-src') && !lc.includes("default-src 'none'")) issues.push("no object-src 'none'");
    if (!lc.includes('frame-ancestors')) issues.push('no frame-ancestors (clickjacking)');
    if (!lc.includes('base-uri')) issues.push('no base-uri (base-tag injection)');
    if (issues.length === 0) return [];
    return [
      makeFinding({
        ruleId: 'csp-analysis',
        title: `Weak Content-Security-Policy (${issues.length} issue${issues.length > 1 ? 's' : ''})`,
        severity: lc.includes("'unsafe-inline'") ? 'medium' : 'low',
        confidence: 'firm',
        kind: 'passive',
        description: `The CSP is present but weak: ${issues.join('; ')}.`,
        remediation: "Use a nonce/hash-based policy, remove 'unsafe-inline'/'unsafe-eval' and wildcards, and set object-src 'none', base-uri 'self' and frame-ancestors 'none'.",
        references: ['CWE-693', 'https://owasp.org/www-project-secure-headers/'],
        evidence: { url: ctx.endpoint.url, method: ctx.baseline.method, responseStatus: ctx.baseline.status, snippet: truncate(csp, 200) },
      }),
    ];
  },
};

const DOM_SOURCES = /(location\.(?:hash|search|href|pathname)|document\.(?:URL|documentURI|referrer|cookie)|window\.name)/;
const DOM_SINKS = /(\.innerHTML|\.outerHTML|document\.write|\.insertAdjacentHTML|eval\(|setTimeout\(\s*['"]|new Function\(|\$\(\s*(?:location|document))/;

export const domXssCheck: Check = {
  id: 'dom-xss-indicators',
  title: 'DOM-based XSS indicators',
  kind: 'passive',
  description: 'Statically flags inline scripts that route a URL source into a DOM sink.',
  async run(ctx: CheckContext): Promise<Finding[]> {
    const body = ctx.baseline.body;
    if (!(ctx.baseline.responseHeaders['content-type'] ?? '').includes('html')) return [];
    const scripts = [...body.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1] ?? '');
    for (const s of scripts) {
      if (DOM_SOURCES.test(s) && DOM_SINKS.test(s)) {
        const sink = s.match(DOM_SINKS)?.[0] ?? 'sink';
        return [
          makeFinding({
            ruleId: 'dom-xss-indicators',
            title: 'Possible DOM-based XSS (URL source flows to HTML sink)',
            severity: 'medium',
            confidence: 'tentative',
            kind: 'passive',
            description: `An inline script reads a URL-controlled source and writes to a dangerous sink (${sink}). This is a common DOM-XSS pattern; confirm the data path manually.`,
            remediation: 'Avoid dangerous sinks with untrusted data; use textContent/safe DOM APIs, sanitize with a trusted library (e.g. DOMPurify), and set a strict CSP.',
            references: ['CWE-79', 'https://owasp.org/www-community/attacks/DOM_Based_XSS'],
            evidence: { url: ctx.endpoint.url, method: ctx.baseline.method, responseStatus: ctx.baseline.status, snippet: truncate(s.replace(/\s+/g, ' '), 180) },
          }),
        ];
      }
    }
    return [];
  },
};

export const mixedContentCheck: Check = {
  id: 'mixed-content',
  title: 'Mixed content',
  kind: 'passive',
  description: 'Flags HTTPS pages that load resources over plaintext HTTP.',
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!ctx.endpoint.url.startsWith('https://')) return [];
    const body = ctx.baseline.body;
    const m = body.match(/(?:src|href)\s*=\s*["'](http:\/\/[^"']+\.(?:js|css|png|jpg|gif|svg|woff2?|ico))/i);
    if (!m) return [];
    return [
      makeFinding({
        ruleId: 'mixed-content',
        title: 'Mixed content (HTTP resource on HTTPS page)',
        severity: 'low',
        confidence: 'firm',
        kind: 'passive',
        description: 'An HTTPS page references a subresource over plaintext HTTP, which can be intercepted or modified in transit and weakens the page.',
        remediation: 'Load all subresources over HTTPS, add upgrade-insecure-requests to the CSP, and fix hard-coded http:// URLs.',
        references: ['CWE-311', 'https://developer.mozilla.org/docs/Web/Security/Mixed_content'],
        evidence: { url: ctx.endpoint.url, method: ctx.baseline.method, responseStatus: ctx.baseline.status, snippet: truncate(m[1] ?? m[0], 160) },
      }),
    ];
  },
};
