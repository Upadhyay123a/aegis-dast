import { describe, it, expect } from 'vitest';
import { securityHeadersCheck } from '../src/checks/passive/security-headers.js';
import { cookieFlagsCheck } from '../src/checks/passive/cookie-flags.js';
import type { CheckContext } from '../src/checks/context.js';
import type { Endpoint, HttpExchange } from '../src/types.js';

function ctxWith(responseHeaders: Record<string, string>): CheckContext {
  const endpoint: Endpoint = { url: 'http://localhost/', method: 'GET', params: [], forms: [] };
  const baseline: HttpExchange = {
    url: 'http://localhost/',
    method: 'GET',
    requestHeaders: {},
    status: 200,
    statusText: '',
    responseHeaders: { 'content-type': 'text/html', ...responseHeaders },
    body: '<html></html>',
    elapsedMs: 1,
    finalUrl: 'http://localhost/',
  };
  return { config: {} as any, http: {} as any, ai: {} as any, endpoint, baseline };
}

describe('security-headers check', () => {
  it('flags missing CSP and HSTS on an HTML response with no headers', async () => {
    const findings = await securityHeadersCheck.run(ctxWith({}));
    const titles = findings.map((f) => f.title);
    expect(titles).toContain('Missing Content-Security-Policy header');
    expect(titles).toContain('Missing Strict-Transport-Security header');
  });

  it('does not flag headers that are present', async () => {
    const findings = await securityHeadersCheck.run(
      ctxWith({
        'content-security-policy': "default-src 'self'",
        'strict-transport-security': 'max-age=31536000',
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
        'referrer-policy': 'no-referrer',
      }),
    );
    expect(findings).toHaveLength(0);
  });
});

describe('cookie-flags check', () => {
  it('flags a cookie missing HttpOnly/Secure/SameSite', async () => {
    const findings = await cookieFlagsCheck.run(ctxWith({ 'set-cookie': 'session=abc123; Path=/' }));
    expect(findings).toHaveLength(1);
    expect(findings[0]!.title).toMatch(/HttpOnly/);
  });

  it('does not flag a fully-hardened cookie', async () => {
    const findings = await cookieFlagsCheck.run(
      ctxWith({ 'set-cookie': 'session=abc; HttpOnly; Secure; SameSite=Strict' }),
    );
    expect(findings).toHaveLength(0);
  });
});
