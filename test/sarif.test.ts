import { describe, it, expect } from 'vitest';
import { renderSarif } from '../src/report/sarif.js';
import type { ScanResult } from '../src/types.js';

const sampleResult: ScanResult = {
  target: 'http://localhost/',
  startedAt: new Date().toISOString(),
  finishedAt: new Date().toISOString(),
  durationMs: 10,
  requestCount: 3,
  aiProvider: 'none',
  findings: [
    {
      id: 'xss-reflected:GET http://localhost/search#q',
      ruleId: 'xss-reflected',
      title: 'Reflected XSS',
      severity: 'high',
      confidence: 'firm',
      kind: 'active',
      description: 'desc',
      remediation: 'fix',
      references: ['CWE-79'],
      evidence: { url: 'http://localhost/search', method: 'GET', param: 'q', payload: '<x>' },
    },
  ],
  stats: {
    endpoints: 1,
    bySeverity: { info: 0, low: 0, medium: 0, high: 1, critical: 0 },
    suppressedFalsePositives: 0,
  },
};

describe('SARIF reporter', () => {
  it('produces a valid SARIF 2.1.0 skeleton', () => {
    const doc = JSON.parse(renderSarif(sampleResult));
    expect(doc.version).toBe('2.1.0');
    expect(doc.runs).toHaveLength(1);
    expect(doc.runs[0].tool.driver.name).toBe('Aegis-DAST');
    expect(Array.isArray(doc.runs[0].tool.driver.rules)).toBe(true);
  });

  it('maps findings to results with level and security-severity', () => {
    const doc = JSON.parse(renderSarif(sampleResult));
    const result = doc.runs[0].results[0];
    expect(result.ruleId).toBe('xss-reflected');
    expect(result.level).toBe('error');
    expect(result.properties['security-severity']).toBe('8.0');
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe('http://localhost/search');
  });

  it('only includes rules that were actually triggered', () => {
    const doc = JSON.parse(renderSarif(sampleResult));
    const ruleIds = doc.runs[0].tool.driver.rules.map((r: any) => r.id);
    expect(ruleIds).toContain('xss-reflected');
    expect(ruleIds).not.toContain('sqli');
  });
});
