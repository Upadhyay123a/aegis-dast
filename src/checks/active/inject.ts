/**
 * Shared helpers for active checks: enumerate injectable parameters for an
 * endpoint and build a request that sets one parameter to a payload value.
 */
import type { Endpoint, HttpExchange, Param } from '../../types.js';
import type { HttpClient } from '../../core/http-client.js';

export interface InjectionPoint {
  param: Param;
  /** Send a request where this injection point carries `payload`. */
  send(http: HttpClient, payload: string): Promise<HttpExchange>;
  /** Describe the location for evidence/reporting. */
  describe(): { url: string; method: string; param: string };
}

/** Collect all injectable points for an endpoint (query params + form fields). */
export function injectionPoints(endpoint: Endpoint): InjectionPoint[] {
  const points: InjectionPoint[] = [];

  // Query parameters on the endpoint URL (GET).
  for (const param of endpoint.params) {
    if (param.location !== 'query') continue;
    points.push({
      param,
      describe: () => ({ url: endpoint.url, method: 'GET', param: param.name }),
      send: (http, payload) => http.fetch(buildQueryUrl(endpoint.url, param.name, payload)),
    });
  }

  // Form fields (GET or POST).
  for (const form of endpoint.forms) {
    for (const param of form.params) {
      points.push({
        param,
        describe: () => ({ url: form.action, method: form.method, param: param.name }),
        send: (http, payload) => {
          if (form.method === 'POST') {
            const body = encodeForm(form.params, param.name, payload);
            return http.fetch(form.action, {
              method: 'POST',
              headers: { 'content-type': 'application/x-www-form-urlencoded' },
              body,
            });
          }
          const url = buildQueryFromForm(form.action, form.params, param.name, payload);
          return http.fetch(url);
        },
      });
    }
  }

  return points;
}

function buildQueryUrl(baseUrl: string, name: string, value: string): string {
  const u = new URL(baseUrl);
  u.searchParams.set(name, value);
  return u.toString();
}

function buildQueryFromForm(action: string, params: Param[], target: string, value: string): string {
  const u = new URL(action);
  for (const p of params) u.searchParams.set(p.name, p.name === target ? value : p.value || 'test');
  return u.toString();
}

function encodeForm(params: Param[], target: string, value: string): string {
  const usp = new URLSearchParams();
  for (const p of params) usp.set(p.name, p.name === target ? value : p.value || 'test');
  return usp.toString();
}
