import { describe, it, expect } from 'vitest';
import { Scope, ScopeError } from '../src/core/scope.js';

describe('Scope', () => {
  it('always allows the seed host', () => {
    const scope = new Scope([], 'https://example.com/app');
    expect(scope.allows('https://example.com/other')).toBe(true);
  });

  it('denies hosts not in the allowlist', () => {
    const scope = new Scope([], 'https://example.com');
    expect(scope.allows('https://evil.com/')).toBe(false);
    expect(scope.allows('https://sub.example.com/')).toBe(false);
  });

  it('allows additional hosts and URL prefixes', () => {
    const scope = new Scope(['api.example.com', 'https://cdn.example.com/assets/'], 'https://example.com');
    expect(scope.allows('https://api.example.com/v1')).toBe(true);
    expect(scope.allows('https://cdn.example.com/assets/app.js')).toBe(true);
    expect(scope.allows('https://cdn.example.com/private')).toBe(false);
  });

  it('rejects non-http(s) protocols', () => {
    const scope = new Scope([], 'https://example.com');
    expect(scope.allows('file:///etc/passwd')).toBe(false);
    expect(scope.allows('ftp://example.com/')).toBe(false);
  });

  it('assertAllowed throws for out-of-scope URLs', () => {
    const scope = new Scope([], 'https://example.com');
    expect(() => scope.assertAllowed('https://evil.com')).toThrow(ScopeError);
    expect(() => scope.assertAllowed('https://example.com/ok')).not.toThrow();
  });

  it('honors port in host matching', () => {
    const scope = new Scope([], 'http://127.0.0.1:3000');
    expect(scope.allows('http://127.0.0.1:3000/x')).toBe(true);
    // Different port is a different origin and not auto-allowed.
    expect(scope.allows('http://127.0.0.1:9999/x')).toBe(false);
  });
});
