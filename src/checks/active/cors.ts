/**
 * Active check: CORS misconfiguration.
 *
 * Sends a crafted Origin header and inspects the Access-Control-Allow-Origin
 * (ACAO) and Access-Control-Allow-Credentials (ACAC) response headers. Reflecting
 * an arbitrary Origin while allowing credentials is a serious misconfiguration.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';

const EVIL_ORIGIN = 'https://aegis-evil.example';

export const corsCheck: Check = {
  id: 'cors-misconfig',
  title: 'CORS misconfiguration',
  kind: 'active',
  description: 'Detects permissive/ reflected CORS Access-Control-Allow-Origin policies.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const url = ctx.endpoint.url;
    const res = await ctx.http.fetch(url, { headers: { origin: EVIL_ORIGIN } });
    if (res.status === 0) return [];

    const acao = res.responseHeaders['access-control-allow-origin'];
    const acac = (res.responseHeaders['access-control-allow-credentials'] ?? '').toLowerCase() === 'true';
    if (!acao) return [];

    const reflectsEvil = acao === EVIL_ORIGIN;
    const wildcard = acao === '*';
    if (!reflectsEvil && !wildcard) return [];

    let severity: Finding['severity'] = 'low';
    let title = 'Permissive CORS policy (wildcard origin)';
    let description =
      'The endpoint returns Access-Control-Allow-Origin: * . This is only safe for truly public, ' +
      'non-credentialed data.';

    if (reflectsEvil && acac) {
      severity = 'high';
      title = 'CORS misconfiguration — arbitrary origin reflected with credentials';
      description =
        `The endpoint reflected an attacker-supplied Origin (${EVIL_ORIGIN}) in Access-Control-Allow-Origin ` +
        'AND allows credentials. Any website can read authenticated responses from this endpoint.';
    } else if (reflectsEvil) {
      severity = 'medium';
      title = 'CORS misconfiguration — arbitrary origin reflected';
      description =
        `The endpoint reflected an attacker-supplied Origin (${EVIL_ORIGIN}) in Access-Control-Allow-Origin, ` +
        'allowing cross-origin reads from any site.';
    }

    return [
      makeFinding({
        ruleId: this.id,
        title,
        severity,
        confidence: reflectsEvil ? 'firm' : 'tentative',
        kind: 'active',
        description,
        remediation:
          'Validate Origin against a strict allowlist and echo back only approved origins. Never combine a ' +
          'reflected/`*` ACAO with Access-Control-Allow-Credentials: true.',
        references: ['CWE-942', 'https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny'],
        evidence: {
          url,
          method: 'GET',
          responseStatus: res.status,
          snippet: `Origin: ${EVIL_ORIGIN} -> ACAO: ${acao}; ACAC: ${acac}`,
        },
      }),
    ];
  },
};
