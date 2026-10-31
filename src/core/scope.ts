/**
 * Scope enforcement — the primary safety control of Aegis-DAST.
 *
 * Every outbound request is checked against an allowlist. A request is only
 * permitted when its host (or host:port) is explicitly in scope, or its URL
 * begins with an allowed prefix. Nothing outside scope is ever sent.
 */

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScopeError';
  }
}

export class Scope {
  private readonly hosts = new Set<string>();
  private readonly prefixes: string[] = [];

  /**
   * @param entries  Allowlist entries. Each may be:
   *   - a bare host: `example.com` or `example.com:8443`
   *   - a URL prefix: `https://example.com/app/`
   * @param seed  The target URL; its host is always added to scope.
   */
  constructor(entries: string[], seed: string) {
    const seedHost = safeHost(seed);
    if (seedHost) this.hosts.add(seedHost);

    for (const raw of entries) {
      const entry = raw.trim();
      if (!entry) continue;
      if (entry.includes('://')) {
        // URL prefix form — restricts to this path prefix only; the host is NOT
        // added to the host allowlist, so other paths on it stay out of scope.
        this.prefixes.push(entry);
      } else {
        // bare host (optionally host:port)
        this.hosts.add(entry.toLowerCase());
      }
    }
  }

  /** True when the given URL is allowed to be requested. */
  allows(url: string): boolean {
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      return false;
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;

    for (const prefix of this.prefixes) {
      if (url.startsWith(prefix)) return true;
    }

    const host = parsed.host.toLowerCase(); // includes port if present
    const hostname = parsed.hostname.toLowerCase();
    return this.hosts.has(host) || this.hosts.has(hostname);
  }

  /** Throw if the URL is out of scope. Used as a hard guard before sending. */
  assertAllowed(url: string): void {
    if (!this.allows(url)) {
      throw new ScopeError(`Refusing to request out-of-scope URL: ${url}`);
    }
  }

  describe(): string[] {
    return [...this.hosts, ...this.prefixes];
  }
}

function safeHost(url: string): string | undefined {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return undefined;
  }
}
