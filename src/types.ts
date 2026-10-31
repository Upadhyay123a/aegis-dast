/**
 * Core domain types shared across Aegis-DAST.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export type CheckKind = 'passive' | 'active';

export type Confidence = 'tentative' | 'firm' | 'confirmed';

/** A single HTTP request/response pair observed during a scan. */
export interface HttpExchange {
  url: string;
  method: string;
  requestHeaders: Record<string, string>;
  requestBody?: string;
  status: number;
  statusText: string;
  responseHeaders: Record<string, string>;
  body: string;
  /** Milliseconds elapsed for the request. */
  elapsedMs: number;
  /** Final URL after redirects (if any). */
  finalUrl: string;
}

/** A discovered injectable parameter. */
export interface Param {
  name: string;
  value: string;
  /** Where the parameter lives. */
  location: 'query' | 'body' | 'header' | 'cookie' | 'path';
}

/** An HTML form discovered while crawling. */
export interface FormTarget {
  action: string;
  method: string;
  params: Param[];
}

/** One addressable point of the application discovered by the crawler. */
export interface Endpoint {
  url: string;
  method: string;
  params: Param[];
  forms: FormTarget[];
  /** The exchange that first revealed this endpoint, if available. */
  exchange?: HttpExchange;
}

/** The full attack surface produced by crawling. */
export interface AttackSurface {
  seed: string;
  endpoints: Endpoint[];
  startedAt: string;
  finishedAt: string;
  requestCount: number;
}

/** Evidence attached to a finding (what we saw and where). */
export interface Evidence {
  url: string;
  method: string;
  param?: string;
  payload?: string;
  /** A short, redacted snippet of the response that triggered the finding. */
  snippet?: string;
  requestHeaders?: Record<string, string>;
  responseStatus?: number;
}

/** A potential vulnerability reported by a check. */
export interface Finding {
  /** Stable id for dedup: `${ruleId}:${location}`. */
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  kind: CheckKind;
  description: string;
  remediation: string;
  /** OWASP / CWE references, e.g. "CWE-79", "A03:2021". */
  references: string[];
  evidence: Evidence;
  /** Set by the AI verifier when it reviews this finding. */
  aiReview?: AiReview;
  /** Populated when a verifier drops confidence to near-zero. */
  falsePositive?: boolean;
}

/** Result of the optional AI second-pass review. */
export interface AiReview {
  provider: string;
  model: string;
  /** 0..1 — the model's estimated likelihood the finding is a true positive. */
  exploitabilityScore: number;
  verdict: 'confirmed' | 'likely' | 'uncertain' | 'false-positive';
  rationale: string;
  /** Optional improved remediation text written by the model. */
  remediation?: string;
}

/** The complete output of a scan. */
export interface ScanResult {
  target: string;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  requestCount: number;
  aiProvider: string;
  findings: Finding[];
  stats: {
    endpoints: number;
    bySeverity: Record<Severity, number>;
    suppressedFalsePositives: number;
  };
}
