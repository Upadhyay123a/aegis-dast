import { describe, it, expect } from 'vitest';
import { ALL_CHECKS } from '../src/checks/registry.js';

describe('web check catalog', () => {
  it('registers a large set of checks with unique ids', () => {
    expect(ALL_CHECKS.length).toBeGreaterThanOrEqual(28);
    const ids = ALL_CHECKS.map((c) => c.id);
    expect(new Set(ids).size).toBe(ids.length); // all unique
  });

  it('every check is well-formed', () => {
    for (const c of ALL_CHECKS) {
      expect(c.id).toBeTruthy();
      expect(c.title).toBeTruthy();
      expect(['passive', 'active']).toContain(c.kind);
      expect(typeof c.run).toBe('function');
    }
  });

  it('covers the key advanced techniques', () => {
    const ids = new Set(ALL_CHECKS.map((c) => c.id));
    for (const id of [
      'sqli-time-based',
      'ssti',
      'ssi-injection',
      'nosql-injection',
      'ldap-injection',
      'xpath-injection',
      'host-header-injection',
      'web-cache-poisoning',
      'sensitive-files',
      'http-methods',
      'graphql-introspection',
      'jwt-analysis',
      'csp-analysis',
      'dom-xss-indicators',
      'mixed-content',
    ]) {
      expect(ids.has(id), `missing check: ${id}`).toBe(true);
    }
  });
});
