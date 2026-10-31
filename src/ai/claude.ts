/**
 * Anthropic Claude AI provider (default). The SDK is imported lazily so the tool
 * runs without it installed; if the import or API call fails, callers fall back
 * to heuristics rather than crashing the scan.
 */
import type {
  AIProvider,
  PayloadRequest,
  VerifyRequest,
  VerifyResponse,
} from './provider.js';
import {
  extractJson,
  PAYLOAD_SYSTEM_PROMPT,
  VERIFY_SYSTEM_PROMPT,
} from './provider.js';
import { logger } from '../util/logger.js';

const DEFAULT_MODEL = process.env.AEGIS_CLAUDE_MODEL || 'claude-opus-4-8';

export class ClaudeProvider implements AIProvider {
  readonly name = 'claude';
  readonly model: string;
  readonly enabled = true;
  private client: any;

  private constructor(client: any, model: string) {
    this.client = client;
    this.model = model;
  }

  /** Create a provider, or return undefined if unavailable. */
  static async create(apiKey: string, model = DEFAULT_MODEL): Promise<ClaudeProvider | undefined> {
    if (!apiKey) return undefined;
    try {
      const mod: any = await import('@anthropic-ai/sdk');
      const Anthropic = mod.default ?? mod.Anthropic;
      const client = new Anthropic({ apiKey });
      return new ClaudeProvider(client, model);
    } catch (err) {
      logger.warn(`Claude SDK unavailable (${(err as Error).message}); AI features disabled.`);
      return undefined;
    }
  }

  private async complete(system: string, user: string, maxTokens = 512): Promise<string> {
    const res = await this.client.messages.create({
      model: this.model,
      max_tokens: maxTokens,
      system,
      messages: [{ role: 'user', content: user }],
    });
    const parts = res.content ?? [];
    return parts
      .filter((p: any) => p.type === 'text')
      .map((p: any) => p.text)
      .join('\n');
  }

  async suggestPayloads(req: PayloadRequest): Promise<string[]> {
    try {
      const user = `Rule: ${req.ruleId}\nParameter: ${req.param}\nURL: ${req.url}\nContext: ${
        req.context ?? 'unknown'
      }\nProduce up to 6 safe detection payloads.`;
      const text = await this.complete(PAYLOAD_SYSTEM_PROMPT, user, 400);
      const arr = extractJson<string[]>(text);
      return Array.isArray(arr) ? arr.filter((s) => typeof s === 'string').slice(0, 6) : [];
    } catch (err) {
      logger.debug(`Claude suggestPayloads failed: ${(err as Error).message}`);
      return [];
    }
  }

  async verifyFinding(req: VerifyRequest): Promise<VerifyResponse> {
    const f = req.finding;
    const user = [
      `Finding: ${f.title}`,
      `Rule: ${f.ruleId}`,
      `Reported severity: ${f.severity}`,
      `Scanner confidence: ${f.confidence}`,
      `URL: ${f.evidence.url}`,
      `Param: ${f.evidence.param ?? '(none)'}`,
      `Payload: ${f.evidence.payload ?? '(none)'}`,
      `Evidence snippet: ${req.evidenceSnippet}`,
      '',
      'Assess whether this is a true positive and how exploitable it is.',
    ].join('\n');

    try {
      const text = await this.complete(VERIFY_SYSTEM_PROMPT, user, 400);
      const parsed = extractJson<VerifyResponse>(text);
      if (!parsed || typeof parsed.exploitabilityScore !== 'number') {
        return fallback(f.confidence);
      }
      return {
        exploitabilityScore: clamp01(parsed.exploitabilityScore),
        verdict: parsed.verdict ?? 'uncertain',
        rationale: parsed.rationale ?? 'No rationale provided.',
        remediation: parsed.remediation,
      };
    } catch (err) {
      logger.debug(`Claude verifyFinding failed: ${(err as Error).message}`);
      return fallback(f.confidence);
    }
  }
}

function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

function fallback(confidence: string): VerifyResponse {
  const score = confidence === 'firm' ? 0.65 : confidence === 'confirmed' ? 0.85 : 0.4;
  return { exploitabilityScore: score, verdict: 'uncertain', rationale: 'AI verification unavailable; heuristic used.' };
}
