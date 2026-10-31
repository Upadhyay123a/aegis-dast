/**
 * OpenAI AI provider (optional alternative). SDK imported lazily; failures fall
 * back to heuristics.
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

const DEFAULT_MODEL = process.env.AEGIS_OPENAI_MODEL || 'gpt-4o-mini';

export class OpenAIProvider implements AIProvider {
  readonly name = 'openai';
  readonly model: string;
  readonly enabled = true;
  private client: any;

  private constructor(client: any, model: string) {
    this.client = client;
    this.model = model;
  }

  static async create(apiKey: string, model = DEFAULT_MODEL): Promise<OpenAIProvider | undefined> {
    if (!apiKey) return undefined;
    try {
      const mod: any = await import('openai');
      const OpenAI = mod.default ?? mod.OpenAI;
      const client = new OpenAI({ apiKey });
      return new OpenAIProvider(client, model);
    } catch (err) {
      logger.warn(`OpenAI SDK unavailable (${(err as Error).message}); AI features disabled.`);
      return undefined;
    }
  }

  private async complete(system: string, user: string, maxTokens = 512): Promise<string> {
    const res = await this.client.chat.completions.create({
      model: this.model,
      max_tokens: maxTokens,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    });
    return res.choices?.[0]?.message?.content ?? '';
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
      logger.debug(`OpenAI suggestPayloads failed: ${(err as Error).message}`);
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
      if (!parsed || typeof parsed.exploitabilityScore !== 'number') return fallback(f.confidence);
      return {
        exploitabilityScore: Math.max(0, Math.min(1, parsed.exploitabilityScore)),
        verdict: parsed.verdict ?? 'uncertain',
        rationale: parsed.rationale ?? 'No rationale provided.',
        remediation: parsed.remediation,
      };
    } catch (err) {
      logger.debug(`OpenAI verifyFinding failed: ${(err as Error).message}`);
      return fallback(f.confidence);
    }
  }
}

function fallback(confidence: string): VerifyResponse {
  const score = confidence === 'firm' ? 0.65 : confidence === 'confirmed' ? 0.85 : 0.4;
  return { exploitabilityScore: score, verdict: 'uncertain', rationale: 'AI verification unavailable; heuristic used.' };
}
