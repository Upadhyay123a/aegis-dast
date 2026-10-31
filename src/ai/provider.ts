/**
 * Pluggable AI provider abstraction.
 *
 * The AI engine is OPTIONAL. When no provider is configured, a no-op provider is
 * used and Aegis-DAST runs purely rule-based. When a provider is available it is
 * used for two things:
 *   1. suggestPayloads() — context-aware payload ideas for a check/param.
 *   2. verifyFinding()   — a skeptical second-pass that estimates whether a
 *      finding is a true positive, cutting false positives.
 */
import type { Finding } from '../types.js';

export interface PayloadRequest {
  ruleId: string;
  param: string;
  url: string;
  /** A short description of the response context (e.g. reflected in HTML attr). */
  context?: string;
}

export interface VerifyRequest {
  finding: Finding;
  /** A redacted snippet of the evidence/response for the model to reason over. */
  evidenceSnippet: string;
}

export interface VerifyResponse {
  exploitabilityScore: number; // 0..1
  verdict: 'confirmed' | 'likely' | 'uncertain' | 'false-positive';
  rationale: string;
  remediation?: string;
}

export interface AIProvider {
  readonly name: string;
  readonly model: string;
  /** Whether this provider will actually call a model (false for no-op). */
  readonly enabled: boolean;

  suggestPayloads(req: PayloadRequest): Promise<string[]>;
  verifyFinding(req: VerifyRequest): Promise<VerifyResponse>;
}

/** Shared system prompt used by model-backed providers. */
export const VERIFY_SYSTEM_PROMPT = `You are a precise application-security analyst reviewing candidate findings from a DAST scanner.
Your job is to reduce false positives. Be skeptical: a finding is only a true positive if the evidence clearly supports it.
Respond ONLY with compact JSON of the form:
{"exploitabilityScore": <0..1 number>, "verdict": "confirmed|likely|uncertain|false-positive", "rationale": "<one or two sentences>", "remediation": "<optional improved fix advice>"}
Do not include any text outside the JSON.`;

export const PAYLOAD_SYSTEM_PROMPT = `You are a web application security testing assistant generating NON-DESTRUCTIVE, detection-oriented test payloads for authorized DAST scanning.
Rules: payloads must be safe to send (no data deletion/modification, no DoS, no destructive commands). Prefer marker-based detection payloads.
Respond ONLY with a JSON array of strings, e.g. ["payload1","payload2"]. No commentary.`;

/** Parse the first JSON object/array found in a model's text output. */
export function extractJson<T>(text: string): T | undefined {
  const trimmed = text.trim();
  // Try direct parse first.
  try {
    return JSON.parse(trimmed) as T;
  } catch {
    /* fall through */
  }
  const match = trimmed.match(/[[{][\s\S]*[\]}]/);
  if (!match) return undefined;
  try {
    return JSON.parse(match[0]) as T;
  } catch {
    return undefined;
  }
}
