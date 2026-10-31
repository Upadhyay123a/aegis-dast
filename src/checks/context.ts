/**
 * The context handed to every check when it runs against one endpoint.
 */
import type { Config } from '../config.js';
import type { Endpoint, Finding, HttpExchange, CheckKind } from '../types.js';
import type { HttpClient } from '../core/http-client.js';
import type { AIProvider } from '../ai/provider.js';

export interface CheckContext {
  config: Config;
  http: HttpClient;
  ai: AIProvider;
  /** The endpoint under test. */
  endpoint: Endpoint;
  /** The baseline response for the endpoint (already fetched by the engine). */
  baseline: HttpExchange;
}

export interface Check {
  /** Stable rule identifier, e.g. "security-headers", "xss-reflected". */
  id: string;
  title: string;
  kind: CheckKind;
  /** Short description of what the rule looks for. */
  description: string;
  /** Run the check and return any findings. */
  run(ctx: CheckContext): Promise<Finding[]>;
}

/** Helper used by checks to build a well-formed Finding. */
export function makeFinding(
  partial: Omit<Finding, 'id'> & { id?: string },
): Finding {
  const id =
    partial.id ??
    `${partial.ruleId}:${partial.evidence.method} ${partial.evidence.url}${
      partial.evidence.param ? `#${partial.evidence.param}` : ''
    }`;
  return { ...partial, id };
}
