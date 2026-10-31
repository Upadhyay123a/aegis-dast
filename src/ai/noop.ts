/**
 * No-op AI provider. Used when no API key is configured. It performs a light,
 * deterministic heuristic verification so the pipeline shape stays identical
 * whether or not a real model is present — but it never calls a network model.
 */
import type { AIProvider, PayloadRequest, VerifyRequest, VerifyResponse } from './provider.js';

export class NoopProvider implements AIProvider {
  readonly name = 'none';
  readonly model = 'heuristic';
  readonly enabled = false;

  async suggestPayloads(_req: PayloadRequest): Promise<string[]> {
    return [];
  }

  async verifyFinding(req: VerifyRequest): Promise<VerifyResponse> {
    // Map existing confidence to a score; do not invent exploitability.
    const conf = req.finding.confidence;
    const score = conf === 'confirmed' ? 0.9 : conf === 'firm' ? 0.7 : 0.4;
    return {
      exploitabilityScore: score,
      verdict: conf === 'tentative' ? 'uncertain' : 'likely',
      rationale: 'Heuristic assessment (no AI provider configured).',
    };
  }
}
