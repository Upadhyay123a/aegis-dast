/**
 * Time-based blind SQL injection.
 *
 * Detects SQLi where no error or content difference is visible, by injecting a
 * conditional time delay and measuring the response time. To avoid false
 * positives from network jitter it (1) takes a fast baseline, (2) confirms the
 * delay reproduces, and (3) checks a zero-delay control stays fast.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { injectionPoints } from './inject.js';

const DELAY_S = 5;
const DELAY_MS = DELAY_S * 1000;
const THRESHOLD_MS = DELAY_MS - 1500; // tolerate some overhead/jitter

function sleepPayloads(seconds: number): string[] {
  return [
    `1' AND SLEEP(${seconds})-- -`,
    `1" AND SLEEP(${seconds})-- -`,
    `1' AND pg_sleep(${seconds})-- -`,
    `1'; WAITFOR DELAY '0:0:${seconds}'-- -`,
    `1 AND SLEEP(${seconds})`,
  ];
}

export const blindSqliCheck: Check = {
  id: 'sqli-time-based',
  title: 'Blind (time-based) SQL injection',
  kind: 'active',
  description: 'Detects blind SQL injection by measuring injected time delays.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];

    for (const point of injectionPoints(ctx.endpoint)) {
      // Fast baseline.
      const base = await point.send(ctx.http, '1');
      if (base.status === 0) continue;

      const delayPayloads = sleepPayloads(DELAY_S);
      for (let i = 0; i < delayPayloads.length; i++) {
        const payload = delayPayloads[i]!;
        const r1 = await point.send(ctx.http, payload);
        if (r1.status === 0 || r1.elapsedMs < THRESHOLD_MS) continue;

        // Confirm it reproduces and that a zero-delay control is fast.
        const control = await point.send(ctx.http, sleepPayloads(0)[i]!);
        const r2 = await point.send(ctx.http, payload);
        const delayed = r1.elapsedMs >= THRESHOLD_MS && r2.elapsedMs >= THRESHOLD_MS;
        const controlFast = control.elapsedMs < THRESHOLD_MS;

        if (delayed && controlFast) {
          const w = point.describe();
          findings.push(
            makeFinding({
              ruleId: 'sqli-time-based',
              title: 'Blind (time-based) SQL injection',
              severity: 'critical',
              confidence: 'firm',
              kind: 'active',
              description:
                `A ${DELAY_S}s conditional delay injected into "${w.param}" reproducibly slowed the response ` +
                `(${Math.round(r1.elapsedMs)}ms / ${Math.round(r2.elapsedMs)}ms vs control ${Math.round(control.elapsedMs)}ms). ` +
                'This indicates the input is executed as SQL even though no error/content is shown.',
              remediation:
                'Use parameterized queries / prepared statements everywhere. Never concatenate input into SQL. Apply ' +
                'least-privilege DB accounts and query timeouts.',
              references: ['CWE-89', 'A03:2021-Injection', 'https://owasp.org/www-community/attacks/Blind_SQL_Injection'],
              evidence: {
                url: w.url,
                method: w.method,
                param: w.param,
                payload,
                responseStatus: r1.status,
                snippet: `delayed ${Math.round(r1.elapsedMs)}ms & ${Math.round(r2.elapsedMs)}ms; control ${Math.round(control.elapsedMs)}ms`,
              },
            }),
          );
          break;
        }
      }
    }

    return findings;
  },
};
