/**
 * Second-pass verifier. Runs each finding (at/above the configured minimum
 * severity) through the AI provider's skeptical review. Findings judged
 * false-positive are suppressed; others are annotated with the AI's reasoning
 * and (optionally) improved remediation.
 *
 * This is the core false-positive-reduction mechanism described in the README.
 */
import pLimit from 'p-limit';
import type { AIProvider } from './provider.js';
import type { Config } from '../config.js';
import type { Finding, Severity } from '../types.js';
import { SEVERITY_ORDER } from '../types.js';
import { truncate } from '../util/text.js';
import { logger } from '../util/logger.js';

export interface VerifyOutcome {
  kept: Finding[];
  suppressed: number;
}

/** Score threshold below which a finding is treated as a false positive. */
const FP_THRESHOLD = 0.3;

export async function verifyFindings(
  findings: Finding[],
  ai: AIProvider,
  config: Config,
): Promise<VerifyOutcome> {
  if (findings.length === 0) return { kept: [], suppressed: 0 };

  const minRank = SEVERITY_ORDER[config.aiMinSeverity as Severity];
  const limit = pLimit(Math.min(config.concurrency, 4));
  let suppressed = 0;

  const reviewed = await Promise.all(
    findings.map((finding) =>
      limit(async () => {
        // Skip AI review below the configured severity; keep as-is.
        if (SEVERITY_ORDER[finding.severity] < minRank) return finding;

        const snippet = truncate(finding.evidence.snippet ?? '', 500);
        const review = await ai.verifyFinding({ finding, evidenceSnippet: snippet });

        finding.aiReview = {
          provider: ai.name,
          model: ai.model,
          exploitabilityScore: review.exploitabilityScore,
          verdict: review.verdict,
          rationale: review.rationale,
          remediation: review.remediation,
        };

        if (review.remediation && ai.enabled) {
          finding.remediation = review.remediation;
        }

        // Only an *enabled* model may suppress; heuristics never silently drop.
        if (ai.enabled && (review.verdict === 'false-positive' || review.exploitabilityScore < FP_THRESHOLD)) {
          finding.falsePositive = true;
          suppressed += 1;
          logger.debug(`AI suppressed likely FP: ${finding.title} (${finding.evidence.url})`);
        }

        return finding;
      }),
    ),
  );

  const kept = reviewed.filter((f) => !f.falsePositive);
  if (ai.enabled) {
    logger.info(`AI verification complete: ${kept.length} kept, ${suppressed} suppressed as likely false positives`);
  }
  return { kept, suppressed };
}
