/**
 * SARIF 2.1.0 reporter — compatible with the GitHub code-scanning / Security tab.
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
import type { ScanResult, Finding, Severity } from '../types.js';
import { ALL_CHECKS } from '../checks/registry.js';

const LEVEL: Record<Severity, 'none' | 'note' | 'warning' | 'error'> = {
  info: 'note',
  low: 'note',
  medium: 'warning',
  high: 'error',
  critical: 'error',
};

// GitHub uses this 0..10 property to bucket severity.
const SECURITY_SEVERITY: Record<Severity, string> = {
  info: '0.0',
  low: '3.0',
  medium: '5.5',
  high: '8.0',
  critical: '9.5',
};

export function renderSarif(result: ScanResult): string {
  const usedRuleIds = new Set(result.findings.map((f) => f.ruleId));
  const rules = ALL_CHECKS.filter((c) => usedRuleIds.has(c.id)).map((c) => ({
    id: c.id,
    name: c.title.replace(/\s+/g, ''),
    shortDescription: { text: c.title },
    fullDescription: { text: c.description },
    helpUri: 'https://github.com/Upadhyay123a/aegis-dast#checks',
    properties: { kind: c.kind },
  }));

  const results = result.findings.map((f) => toSarifResult(f));

  const doc = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Aegis-DAST',
            informationUri: 'https://github.com/Upadhyay123a/aegis-dast',
            version: '0.1.0',
            rules,
          },
        },
        results,
        properties: {
          target: result.target,
          aiProvider: result.aiProvider,
          suppressedFalsePositives: result.stats.suppressedFalsePositives,
        },
      },
    ],
  };

  return JSON.stringify(doc, null, 2);
}

function toSarifResult(f: Finding) {
  const message = [
    f.description,
    f.aiReview ? `AI verdict: ${f.aiReview.verdict} (${f.aiReview.exploitabilityScore.toFixed(2)}). ${f.aiReview.rationale}` : '',
    `Remediation: ${f.remediation}`,
  ]
    .filter(Boolean)
    .join('\n\n');

  return {
    ruleId: f.ruleId,
    level: LEVEL[f.severity],
    message: { text: message },
    properties: {
      severity: f.severity,
      confidence: f.confidence,
      'security-severity': SECURITY_SEVERITY[f.severity],
      references: f.references,
    },
    locations: [
      {
        physicalLocation: {
          // DAST targets URLs; encode the tested URL as an artifact location.
          artifactLocation: { uri: f.evidence.url },
          region: { startLine: 1 },
        },
        logicalLocations: f.evidence.param
          ? [{ name: f.evidence.param, kind: 'parameter' }]
          : undefined,
      },
    ],
    partialFingerprints: { aegisId: f.id },
  };
}
