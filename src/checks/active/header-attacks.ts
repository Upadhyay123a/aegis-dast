/**
 * Header-based attacks: Host header injection and web cache poisoning.
 *
 * SAFE BY DESIGN: we send a unique canary host in Host/X-Forwarded-Host and only
 * observe whether it is reflected (in the body or a redirect). We never target a
 * real third-party host.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { marker, snippetAround } from '../../util/text.js';

export const hostHeaderCheck: Check = {
  id: 'host-header-injection',
  title: 'Host header injection',
  kind: 'active',
  description: 'Detects reflected/overridable Host via Host and X-Forwarded-Host.',
  async run(ctx: CheckContext): Promise<Finding[]> {
    const url = ctx.endpoint.url;
    const canary = `aegis-${marker('hh')}.example`;
    const findings: Finding[] = [];

    for (const header of ['x-forwarded-host', 'x-forwarded-server', 'forwarded']) {
      const value = header === 'forwarded' ? `host=${canary}` : canary;
      const res = await ctx.http.fetch(url, { headers: { [header]: value } });
      if (res.status === 0) continue;
      const inBody = res.body.includes(canary);
      const inLocation = (res.responseHeaders['location'] ?? '').includes(canary);
      if (inBody || inLocation) {
        findings.push(
          makeFinding({
            ruleId: 'host-header-injection',
            title: `Host header injection via ${header}`,
            severity: 'medium',
            confidence: inLocation ? 'firm' : 'tentative',
            kind: 'active',
            description:
              `The application reflected an attacker-controlled "${header}" value (${canary}) into its ` +
              `${inLocation ? 'redirect Location' : 'response body'}. This enables password-reset poisoning, ` +
              'cache poisoning and routing-based attacks.',
            remediation:
              'Validate the Host against an allowlist of expected hostnames, ignore client-supplied forwarding ' +
              'headers unless from a trusted proxy, and build absolute URLs from a fixed configured base.',
            references: ['CWE-20', 'https://portswigger.net/web-security/host-header'],
            evidence: { url, method: 'GET', param: header, payload: value, responseStatus: res.status, snippet: inLocation ? `Location: ${res.responseHeaders['location']}` : snippetAround(res.body, canary) ?? canary },
          }),
        );
        break;
      }
    }
    return findings;
  },
};

export const cachePoisoningCheck: Check = {
  id: 'web-cache-poisoning',
  title: 'Web cache poisoning',
  kind: 'active',
  description: 'Detects unkeyed input reflected into a cacheable response.',
  async run(ctx: CheckContext): Promise<Finding[]> {
    const url = ctx.endpoint.url;
    const canary = `aegis-${marker('cp')}.example`;
    // Unkeyed headers commonly used for cache-poisoning gadgets.
    const res = await ctx.http.fetch(url, {
      headers: { 'x-forwarded-host': canary, 'x-forwarded-scheme': 'nothttps', 'x-host': canary },
    });
    if (res.status === 0) return [];
    if (!res.body.includes(canary)) return [];

    const cc = (res.responseHeaders['cache-control'] ?? '').toLowerCase();
    const vary = (res.responseHeaders['vary'] ?? '').toLowerCase();
    const cacheable =
      !cc.includes('no-store') && !cc.includes('private') &&
      (cc.includes('public') || cc.includes('max-age') || res.responseHeaders['x-cache'] !== undefined || cc === '');
    const variesOnHeader = vary.includes('x-forwarded-host') || vary.includes('x-host');

    if (cacheable && !variesOnHeader) {
      return [
        makeFinding({
          ruleId: 'web-cache-poisoning',
          title: 'Potential web cache poisoning (unkeyed header reflected)',
          severity: 'high',
          confidence: 'tentative',
          kind: 'active',
          description:
            `An unkeyed request header (X-Forwarded-Host) was reflected into a seemingly cacheable response ` +
            `(Cache-Control: "${cc || '(none)'}", no Vary on the header). An attacker may poison the cache so other ` +
            'users receive attacker-controlled content.',
          remediation:
            'Do not reflect unkeyed request headers into responses. Add them to the cache key (Vary) or strip them, ' +
            'and scope caching with correct Cache-Control.',
          references: ['CWE-444', 'https://portswigger.net/web-security/web-cache-poisoning'],
          evidence: { url, method: 'GET', param: 'x-forwarded-host', payload: canary, responseStatus: res.status, snippet: snippetAround(res.body, canary) ?? canary },
        }),
      ];
    }
    return [];
  },
};
