/**
 * Selects and constructs the AI provider based on config and environment.
 *
 * Resolution order for `ai: 'auto'`:
 *   1. ANTHROPIC_API_KEY present -> Claude
 *   2. OPENAI_API_KEY present    -> OpenAI
 *   3. otherwise                 -> no-op (rule-based only)
 */
import type { Config } from '../config.js';
import type { AIProvider } from './provider.js';
import { NoopProvider } from './noop.js';
import { ClaudeProvider } from './claude.js';
import { OpenAIProvider } from './openai.js';
import { logger } from '../util/logger.js';

export async function createProvider(config: Config): Promise<AIProvider> {
  const choice = config.ai;
  const anthropicKey = process.env.ANTHROPIC_API_KEY ?? '';
  const openaiKey = process.env.OPENAI_API_KEY ?? '';

  if (choice === 'none') return new NoopProvider();

  if (choice === 'claude' || (choice === 'auto' && anthropicKey)) {
    const p = await ClaudeProvider.create(anthropicKey, config.aiModel);
    if (p) {
      logger.info(`AI engine: Claude (${p.model})`);
      return p;
    }
    if (choice === 'claude') logger.warn('Claude requested but unavailable; using heuristic engine.');
  }

  if (choice === 'openai' || (choice === 'auto' && openaiKey)) {
    const p = await OpenAIProvider.create(openaiKey, config.aiModel);
    if (p) {
      logger.info(`AI engine: OpenAI (${p.model})`);
      return p;
    }
    if (choice === 'openai') logger.warn('OpenAI requested but unavailable; using heuristic engine.');
  }

  logger.info('AI engine: none (rule-based heuristics)');
  return new NoopProvider();
}
