/**
 * Scope-enforcing HTTP client with concurrency limiting, per-host politeness
 * delay, timeouts, and redirect handling. Built on undici.
 *
 * SAFETY: every request passes through `scope.assertAllowed()` before it is
 * sent. There is no code path that bypasses this guard.
 */
import { request } from 'undici';
import pLimit from 'p-limit';
import type { Config } from '../config.js';
import type { HttpExchange } from '../types.js';
import { Scope } from './scope.js';
import { logger } from '../util/logger.js';

export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

export class HttpClient {
  private readonly limit: ReturnType<typeof pLimit>;
  private readonly lastHostHit = new Map<string, number>();
  private requests = 0;

  constructor(
    private readonly config: Config,
    private readonly scope: Scope,
  ) {
    this.limit = pLimit(config.concurrency);
  }

  get requestCount(): number {
    return this.requests;
  }

  /** Perform a scope-checked HTTP request and return a normalized exchange. */
  async fetch(url: string, opts: RequestOptions = {}): Promise<HttpExchange> {
    this.scope.assertAllowed(url); // hard safety guard
    return this.limit(() => this.doFetch(url, opts));
  }

  private async doFetch(url: string, opts: RequestOptions): Promise<HttpExchange> {
    await this.politenessDelay(url);

    const method = (opts.method ?? 'GET').toUpperCase();
    const headers: Record<string, string> = {
      'user-agent': this.config.userAgent,
      accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      ...lower(this.config.headers),
      ...lower(opts.headers ?? {}),
    };

    const started = Date.now();
    this.requests += 1;

    try {
      const res = await request(url, {
        method: method as any,
        headers,
        body: opts.body,
        // SAFETY: never auto-follow redirects. undici would follow a Location to
        // ANY host, bypassing our scope allowlist. Redirects are surfaced to the
        // caller (crawler follows them manually, scope-checked; the open-redirect
        // check inspects the Location header directly).
        maxRedirections: 0,
        headersTimeout: this.config.timeoutMs,
        bodyTimeout: this.config.timeoutMs,
      });

      const body = await res.body.text();
      const elapsedMs = Date.now() - started;
      const responseHeaders = flattenHeaders(res.headers);
      const location = responseHeaders['location'];
      const finalUrl = location ? safeResolve(url, location) : url;

      logger.debug(`${method} ${url} -> ${res.statusCode} (${elapsedMs}ms)`);

      return {
        url,
        method,
        requestHeaders: headers,
        requestBody: opts.body,
        status: res.statusCode,
        statusText: '',
        responseHeaders,
        body,
        elapsedMs,
        finalUrl,
      };
    } catch (err) {
      const elapsedMs = Date.now() - started;
      logger.debug(`${method} ${url} -> ERROR ${(err as Error).message} (${elapsedMs}ms)`);
      // Represent transport failures as a synthetic 0-status exchange so checks
      // can decide what to do without the whole scan crashing.
      return {
        url,
        method,
        requestHeaders: headers,
        requestBody: opts.body,
        status: 0,
        statusText: (err as Error).message,
        responseHeaders: {},
        body: '',
        elapsedMs,
        finalUrl: url,
      };
    }
  }

  private async politenessDelay(url: string): Promise<void> {
    const delay = this.config.requestDelayMs;
    if (delay <= 0) return;
    let host: string;
    try {
      host = new URL(url).host;
    } catch {
      return;
    }
    const last = this.lastHostHit.get(host) ?? 0;
    const wait = last + delay - Date.now();
    if (wait > 0) await sleep(wait);
    this.lastHostHit.set(host, Date.now());
  }
}

function lower(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

function flattenHeaders(h: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    if (v === undefined) continue;
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(', ') : v;
  }
  return out;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function safeResolve(base: string, location: string): string {
  try {
    return new URL(location, base).toString();
  } catch {
    return base;
  }
}
