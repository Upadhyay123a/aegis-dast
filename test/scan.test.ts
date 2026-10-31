import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { Server } from 'node:http';
import { startVulnServer } from './fixtures/vuln-server.js';
import { scan } from '../src/index.js';
import { HttpClient } from '../src/core/http-client.js';
import { Scope, ScopeError } from '../src/core/scope.js';
import { parseConfig } from '../src/config.js';

let server: Server;
let baseUrl: string;

beforeAll(async () => {
  const started = await startVulnServer(0);
  server = started.server;
  baseUrl = started.url;
});

afterAll(() => {
  server.close();
});

describe('end-to-end scan against the vulnerable test server', () => {
  it('finds passive issues (missing headers, insecure cookie) without active checks', async () => {
    const result = await scan({
      target: baseUrl,
      scope: ['127.0.0.1'],
      ai: 'none',
      active: false,
    });
    const rules = new Set(result.findings.map((f) => f.ruleId));
    expect(rules.has('security-headers')).toBe(true);
    expect(rules.has('cookie-flags')).toBe(true);
    // No active checks ran.
    expect(rules.has('xss-reflected')).toBe(false);
    expect(rules.has('sqli')).toBe(false);
  });

  it('finds reflected XSS and SQLi when active + authorized', async () => {
    const result = await scan({
      target: baseUrl,
      scope: ['127.0.0.1'],
      ai: 'none',
      active: true,
      authorized: true,
    });
    const rules = new Set(result.findings.map((f) => f.ruleId));
    expect(rules.has('xss-reflected')).toBe(true);
    expect(rules.has('sqli')).toBe(true);
    expect(rules.has('open-redirect')).toBe(true);

    const sqli = result.findings.find((f) => f.ruleId === 'sqli');
    expect(sqli?.severity).toBe('critical');

    const xss = result.findings.find((f) => f.ruleId === 'xss-reflected');
    expect(xss?.evidence.param).toBe('q');
    expect(xss?.severity).toBe('high');
  });

  it('refuses active checks when not authorized (safety gate)', async () => {
    const result = await scan({
      target: baseUrl,
      scope: ['127.0.0.1'],
      ai: 'none',
      active: true,
      authorized: false, // gate closed
    });
    const rules = new Set(result.findings.map((f) => f.ruleId));
    expect(rules.has('xss-reflected')).toBe(false);
    expect(rules.has('sqli')).toBe(false);
  });

  it('never sends requests outside scope', async () => {
    const config = parseConfig({ target: baseUrl, scope: ['127.0.0.1'] });
    const scope = new Scope(config.scope, config.target);
    const http = new HttpClient(config, scope);
    await expect(http.fetch('http://169.254.169.254/latest/meta-data/')).rejects.toBeInstanceOf(ScopeError);
    expect(http.requestCount).toBe(0);
  });
});
