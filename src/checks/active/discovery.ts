/**
 * Discovery attacks: exposed sensitive files, dangerous HTTP methods, and
 * GraphQL introspection. These act once per origin (only on the site root) to
 * avoid duplicate probing, and use content signatures to avoid soft-404 noise.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { truncate } from '../../util/text.js';

function origin(url: string): string | undefined {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}`;
  } catch {
    return undefined;
  }
}
function isRoot(url: string): boolean {
  try {
    return new URL(url).pathname === '/';
  } catch {
    return false;
  }
}

const SENSITIVE: Array<{ path: string; sig: RegExp; name: string; sev: Finding['severity'] }> = [
  { path: '/.git/config', sig: /\[core\]|repositoryformatversion/i, name: '.git repository', sev: 'high' },
  { path: '/.git/HEAD', sig: /ref:\s*refs\//i, name: '.git HEAD', sev: 'high' },
  { path: '/.env', sig: /^[A-Z0-9_]+=/m, name: '.env file', sev: 'critical' },
  { path: '/.svn/entries', sig: /^\d+\s*$|svn:/im, name: '.svn metadata', sev: 'medium' },
  { path: '/.DS_Store', sig: /Bud1|\x00\x00\x00/i, name: '.DS_Store', sev: 'low' },
  { path: '/phpinfo.php', sig: /phpinfo\(\)|PHP Version/i, name: 'phpinfo()', sev: 'medium' },
  { path: '/server-status', sig: /Apache Server Status|Scoreboard/i, name: 'Apache server-status', sev: 'medium' },
  { path: '/.aws/credentials', sig: /aws_access_key_id/i, name: 'AWS credentials', sev: 'critical' },
  { path: '/docker-compose.yml', sig: /services:\s|image:\s/i, name: 'docker-compose.yml', sev: 'medium' },
  { path: '/wp-config.php.bak', sig: /DB_PASSWORD|DB_NAME/i, name: 'WordPress config backup', sev: 'critical' },
  { path: '/backup.zip', sig: /PK\x03\x04/, name: 'backup archive', sev: 'medium' },
];

export const sensitiveFilesCheck: Check = {
  id: 'sensitive-files',
  title: 'Exposed sensitive files',
  kind: 'active',
  description: 'Probes for exposed VCS metadata, env files, backups and config.',
  async run(ctx: CheckContext): Promise<Finding[]> {
    const base = origin(ctx.endpoint.url);
    if (!base || !isRoot(ctx.endpoint.url)) return [];
    // Soft-404 baseline: a random path that should not exist.
    const ctrl = await ctx.http.fetch(`${base}/aegis-does-not-exist-${Date.now()}.txt`);
    const softNotFoundLen = ctrl.status === 200 ? ctrl.body.length : -1;

    const findings: Finding[] = [];
    for (const f of SENSITIVE) {
      const res = await ctx.http.fetch(base + f.path);
      if (res.status !== 200 || !res.body) continue;
      // Guard against soft-404s that return 200 for everything.
      if (softNotFoundLen >= 0 && Math.abs(res.body.length - softNotFoundLen) < 32) continue;
      if (!f.sig.test(res.body)) continue;
      findings.push(
        makeFinding({
          ruleId: 'sensitive-files',
          title: `Exposed ${f.name}`,
          severity: f.sev,
          confidence: 'firm',
          kind: 'active',
          description: `${f.path} is publicly accessible and matches a ${f.name} signature. It may leak source code, credentials or configuration.`,
          remediation: `Block access to ${f.path} at the web server, remove it from the web root, and rotate any exposed secrets.`,
          references: ['CWE-538', 'CWE-200'],
          evidence: { url: base + f.path, method: 'GET', responseStatus: res.status, snippet: truncate(res.body.replace(/\s+/g, ' '), 160) },
        }),
      );
    }
    return findings;
  },
};

export const httpMethodsCheck: Check = {
  id: 'http-methods',
  title: 'Dangerous HTTP methods',
  kind: 'active',
  description: 'Checks for enabled TRACE/PUT/DELETE and lists allowed methods.',
  async run(ctx: CheckContext): Promise<Finding[]> {
    if (!isRoot(ctx.endpoint.url)) return [];
    const url = ctx.endpoint.url;
    const findings: Finding[] = [];

    const options = await ctx.http.fetch(url, { method: 'OPTIONS' });
    const allow = options.responseHeaders['allow'] ?? '';
    const risky = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'].filter((m) => allow.toUpperCase().includes(m));

    const trace = await ctx.http.fetch(url, { method: 'TRACE' });
    const xst = trace.status === 200 && /TRACE\s+\//i.test(trace.body);

    if (xst) {
      findings.push(
        makeFinding({
          ruleId: 'http-methods',
          title: 'HTTP TRACE enabled (Cross-Site Tracing)',
          severity: 'medium',
          confidence: 'firm',
          kind: 'active',
          description: 'The server echoes requests via the TRACE method, enabling Cross-Site Tracing to read sensitive headers.',
          remediation: 'Disable the TRACE method at the web server/proxy.',
          references: ['CWE-693', 'https://owasp.org/www-community/attacks/Cross_Site_Tracing'],
          evidence: { url, method: 'TRACE', responseStatus: trace.status, snippet: truncate(trace.body, 120) },
        }),
      );
    }
    if (risky.length) {
      findings.push(
        makeFinding({
          ruleId: 'http-methods',
          title: `Risky HTTP methods advertised: ${risky.join(', ')}`,
          severity: 'low',
          confidence: 'tentative',
          kind: 'active',
          description: `The Allow header advertises potentially dangerous methods (${risky.join(', ')}). If not needed they widen the attack surface.`,
          remediation: 'Restrict allowed methods to those required (usually GET/POST/HEAD) and verify write methods enforce authn/authz.',
          references: ['CWE-650'],
          evidence: { url, method: 'OPTIONS', responseStatus: options.status, snippet: `Allow: ${allow}` },
        }),
      );
    }
    return findings;
  },
};

const INTROSPECTION = JSON.stringify({ query: '{__schema{queryType{name} types{name}}}' });

export const graphqlCheck: Check = {
  id: 'graphql-introspection',
  title: 'GraphQL introspection enabled',
  kind: 'active',
  description: 'Detects GraphQL endpoints with introspection enabled.',
  async run(ctx: CheckContext): Promise<Finding[]> {
    const base = origin(ctx.endpoint.url);
    if (!base || !isRoot(ctx.endpoint.url)) return [];
    const paths = ['/graphql', '/api/graphql', '/v1/graphql', '/graphql/console', '/query'];
    const findings: Finding[] = [];
    for (const p of paths) {
      const res = await ctx.http.fetch(base + p, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: INTROSPECTION,
      });
      if (res.status === 0 || !res.body) continue;
      if (/"__schema"|"queryType"|"types"\s*:/.test(res.body)) {
        findings.push(
          makeFinding({
            ruleId: 'graphql-introspection',
            title: 'GraphQL introspection enabled',
            severity: 'medium',
            confidence: 'firm',
            kind: 'active',
            description: `The GraphQL endpoint at ${p} answers introspection queries, exposing the full schema (types, fields, mutations) to attackers.`,
            remediation: 'Disable introspection in production, require authentication, and add query depth/complexity limits and rate limiting.',
            references: ['CWE-200', 'https://owasp.org/www-project-web-security-testing-guide/'],
            evidence: { url: base + p, method: 'POST', responseStatus: res.status, snippet: truncate(res.body.replace(/\s+/g, ' '), 160) },
          }),
        );
        break;
      }
    }
    return findings;
  },
};
