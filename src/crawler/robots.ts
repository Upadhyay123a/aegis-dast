/**
 * Minimal robots.txt handling. Parses `Disallow` rules for the matching
 * user-agent group (falling back to `*`). This is a politeness feature, enabled
 * by default and disableable with `--no-robots`.
 */
import type { HttpClient } from '../core/http-client.js';

export class RobotsRules {
  private constructor(private readonly disallow: string[]) {}

  static allowAll(): RobotsRules {
    return new RobotsRules([]);
  }

  static async load(http: HttpClient, target: string, userAgent: string): Promise<RobotsRules> {
    let robotsUrl: string;
    try {
      const u = new URL(target);
      robotsUrl = `${u.protocol}//${u.host}/robots.txt`;
    } catch {
      return RobotsRules.allowAll();
    }

    try {
      const res = await http.fetch(robotsUrl);
      if (res.status !== 200 || !res.body) return RobotsRules.allowAll();
      return RobotsRules.parse(res.body, userAgent);
    } catch {
      return RobotsRules.allowAll();
    }
  }

  static parse(text: string, userAgent: string): RobotsRules {
    const uaToken = userAgent.split('/')[0]?.toLowerCase() ?? 'aegis';
    const lines = text.split(/\r?\n/);
    const groups: Array<{ agents: string[]; disallow: string[] }> = [];
    let current: { agents: string[]; disallow: string[] } | null = null;
    let lastWasAgent = false;

    for (const rawLine of lines) {
      const line = rawLine.replace(/#.*$/, '').trim();
      if (!line) continue;
      const idx = line.indexOf(':');
      if (idx === -1) continue;
      const field = line.slice(0, idx).trim().toLowerCase();
      const value = line.slice(idx + 1).trim();

      if (field === 'user-agent') {
        if (!current || !lastWasAgent) {
          current = { agents: [], disallow: [] };
          groups.push(current);
        }
        current.agents.push(value.toLowerCase());
        lastWasAgent = true;
      } else if (field === 'disallow' && current) {
        if (value) current.disallow.push(value);
        lastWasAgent = false;
      } else {
        lastWasAgent = false;
      }
    }

    const match =
      groups.find((g) => g.agents.some((a) => a !== '*' && uaToken.includes(a))) ??
      groups.find((g) => g.agents.includes('*'));

    return new RobotsRules(match?.disallow ?? []);
  }

  allowed(url: string): boolean {
    let path: string;
    try {
      path = new URL(url).pathname;
    } catch {
      return true;
    }
    return !this.disallow.some((rule) => rule !== '' && path.startsWith(rule));
  }
}
