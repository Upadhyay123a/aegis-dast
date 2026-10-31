/**
 * HTTP crawler. Discovers the attack surface (URLs, query params, forms) within
 * scope, honoring depth / URL-count limits and (optionally) robots.txt.
 *
 * This MVP crawler parses static HTML. A JS-rendering crawler (Playwright) can
 * be slotted in later behind the same `Crawler.crawl()` contract.
 */
import * as cheerio from 'cheerio';
import type { Config } from '../config.js';
import type { AttackSurface, Endpoint, FormTarget, Param } from '../types.js';
import { HttpClient } from '../core/http-client.js';
import { Scope } from '../core/scope.js';
import { logger } from '../util/logger.js';
import { RobotsRules } from './robots.js';

export class Crawler {
  constructor(
    private readonly config: Config,
    private readonly scope: Scope,
    private readonly http: HttpClient,
  ) {}

  async crawl(): Promise<AttackSurface> {
    const startedAt = new Date().toISOString();
    const robots = this.config.respectRobots
      ? await RobotsRules.load(this.http, this.config.target, this.config.userAgent)
      : RobotsRules.allowAll();

    const seen = new Set<string>();
    const endpoints = new Map<string, Endpoint>();
    const queue: Array<{ url: string; depth: number }> = [{ url: this.config.target, depth: 0 }];

    while (queue.length > 0 && endpoints.size < this.config.maxUrls) {
      const { url, depth } = queue.shift()!;
      const norm = normalizeUrl(url);
      if (seen.has(norm)) continue;
      seen.add(norm);

      if (!this.scope.allows(url)) continue;
      if (!robots.allowed(url)) {
        logger.debug(`robots.txt disallows ${url}`);
        continue;
      }

      const exchange = await this.http.fetch(url);
      const endpoint = this.toEndpoint(url, exchange);
      endpoints.set(endpoint.url, endpoint);
      logger.debug(`crawled ${url} (depth ${depth}, ${endpoints.size}/${this.config.maxUrls})`);

      // Follow redirects manually so scope is always enforced on the target.
      if (this.config.followRedirects && exchange.status >= 300 && exchange.status < 400) {
        const loc = exchange.finalUrl;
        const n = normalizeUrl(loc);
        if (loc && loc !== url && !seen.has(n) && this.scope.allows(loc) && endpoints.size < this.config.maxUrls) {
          queue.push({ url: loc, depth: depth + 1 });
        }
        continue; // a redirect has no HTML body to parse
      }

      const contentType = exchange.responseHeaders['content-type'] ?? '';
      if (!contentType.includes('html') || depth >= this.config.maxDepth) continue;

      const { links, forms } = this.parseHtml(url, exchange.body);
      endpoint.forms = forms;

      for (const link of links) {
        const n = normalizeUrl(link);
        if (!seen.has(n) && this.scope.allows(link) && endpoints.size < this.config.maxUrls) {
          queue.push({ url: link, depth: depth + 1 });
        }
      }
    }

    return {
      seed: this.config.target,
      endpoints: [...endpoints.values()],
      startedAt,
      finishedAt: new Date().toISOString(),
      requestCount: this.http.requestCount,
    };
  }

  private toEndpoint(url: string, exchange: AttackSurface['endpoints'][number]['exchange']): Endpoint {
    const params = queryParams(url);
    return {
      url,
      method: 'GET',
      params,
      forms: [],
      exchange,
    };
  }

  private parseHtml(baseUrl: string, html: string): { links: string[]; forms: FormTarget[] } {
    const $ = cheerio.load(html);
    const links: string[] = [];

    $('a[href]').each((_, el) => {
      const href = $(el).attr('href');
      const abs = resolveUrl(baseUrl, href);
      if (abs) links.push(abs);
    });

    const forms: FormTarget[] = [];
    $('form').each((_, el) => {
      const action = resolveUrl(baseUrl, $(el).attr('action') ?? baseUrl) ?? baseUrl;
      const method = ($(el).attr('method') ?? 'GET').toUpperCase();
      const params: Param[] = [];
      $(el)
        .find('input[name], textarea[name], select[name]')
        .each((_i, input) => {
          const name = $(input).attr('name');
          if (!name) return;
          params.push({
            name,
            value: $(input).attr('value') ?? 'test',
            location: method === 'GET' ? 'query' : 'body',
          });
        });
      forms.push({ action, method, params });
    });

    return { links, forms };
  }
}

function queryParams(url: string): Param[] {
  try {
    const u = new URL(url);
    return [...u.searchParams.entries()].map(([name, value]) => ({
      name,
      value,
      location: 'query' as const,
    }));
  } catch {
    return [];
  }
}

function resolveUrl(base: string, href: string | undefined): string | undefined {
  if (!href) return undefined;
  const trimmed = href.trim();
  if (
    trimmed === '' ||
    trimmed.startsWith('#') ||
    trimmed.startsWith('javascript:') ||
    trimmed.startsWith('mailto:') ||
    trimmed.startsWith('tel:') ||
    trimmed.startsWith('data:')
  ) {
    return undefined;
  }
  try {
    return new URL(trimmed, base).toString();
  } catch {
    return undefined;
  }
}

/** Drop the fragment and normalize for dedup purposes. */
function normalizeUrl(url: string): string {
  try {
    const u = new URL(url);
    u.hash = '';
    return u.toString();
  } catch {
    return url;
  }
}
