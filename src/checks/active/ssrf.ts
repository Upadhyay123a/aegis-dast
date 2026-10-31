/**
 * Active check: Server-Side Request Forgery (SSRF) — safe probe.
 *
 * SAFE BY DESIGN: we point URL-like parameters at a NON-ROUTABLE canary host
 * (`*.invalid`, which by RFC 6761 never resolves). We never target internal IPs
 * or metadata endpoints. If the server tries to fetch our canary, its response
 * tends to leak a resolver/connection error that references the canary host or a
 * classic network error — strong evidence the parameter drives a server-side
 * request. Confirming full SSRF impact still requires manual/OAST testing.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { injectionPoints } from './inject.js';
import { snippetAround } from '../../util/text.js';

const URL_PARAM_HINTS =
  /^(url|uri|link|src|source|dest|destination|redirect|redir|callback|webhook|fetch|load|proxy|feed|host|domain|site|target|image|img|avatar|next|out|view|content|path|file|resource|endpoint|api)$/i;

const FETCH_ERROR_SIGNATURES = [
  /getaddrinfo\s+ENOTFOUND/i,
  /ENOTFOUND/i,
  /EAI_AGAIN/i,
  /could not resolve host/i,
  /name or service not known/i,
  /nodename nor servname/i,
  /failed to connect/i,
  /connection refused/i,
  /ECONNREFUSED/i,
  /curl: \(\d+\)/i,
  /unable to connect/i,
];

export const ssrfCheck: Check = {
  id: 'ssrf',
  title: 'Server-Side Request Forgery',
  kind: 'active',
  description: 'Probes URL-like parameters for server-side request forgery using a non-routable canary.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const points = injectionPoints(ctx.endpoint);
    const findings: Finding[] = [];

    for (const point of points) {
      const value = point.param.value ?? '';
      const looksUrlish = URL_PARAM_HINTS.test(point.param.name) || /^https?:\/\//i.test(value);
      if (!looksUrlish) continue;

      const rand = Math.random().toString(36).slice(2, 8);
      const canaryHost = `aegis-ssrf-${rand}.invalid`;
      const canary = `http://${canaryHost}/probe`;

      const res = await point.send(ctx.http, canary);
      if (res.status === 0 || !res.body) continue;

      const mentionsCanary = res.body.includes(canaryHost);
      const sig = FETCH_ERROR_SIGNATURES.find((re) => re.test(res.body));
      if (!mentionsCanary && !sig) continue;

      const where = point.describe();
      const firm = mentionsCanary; // canary host echoed in an error == high confidence
      findings.push(
        makeFinding({
          ruleId: this.id,
          title: firm ? 'Server-Side Request Forgery (SSRF)' : 'Possible SSRF (server fetched our URL)',
          severity: 'high',
          confidence: firm ? 'firm' : 'tentative',
          kind: 'active',
          description:
            `The "${where.param}" parameter appears to trigger a server-side HTTP request to a URL we control ` +
            `(canary ${canaryHost}). SSRF can expose internal services and cloud metadata. ` +
            'Confirm reachable internal targets with an out-of-band (OAST) test.',
          remediation:
            'Validate and allowlist outbound URLs (scheme + host). Block private/link-local/metadata ranges, ' +
            'disable unneeded URL schemes, resolve and re-check the IP after DNS, and require egress via a proxy.',
          references: ['CWE-918', 'A10:2021-SSRF', 'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
          evidence: {
            url: where.url,
            method: where.method,
            param: where.param,
            payload: canary,
            responseStatus: res.status,
            snippet: snippetAround(res.body, mentionsCanary ? canaryHost : (res.body.match(sig!)?.[0] ?? '')) ?? 'fetch error signature',
          },
        }),
      );
    }

    return findings;
  },
};
