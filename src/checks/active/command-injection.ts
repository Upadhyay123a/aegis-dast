/**
 * Active check: OS command injection (output-based).
 *
 * SAFE BY DESIGN: payloads only attempt to run a harmless `echo` of a random
 * marker via common shell separators. Detection relies on the unique marker
 * appearing in the response. The marker is split (MRK + rand) so that a plain
 * reflection of the raw payload does not by itself match the assembled marker
 * string we search for. No destructive commands are ever used.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { injectionPoints } from './inject.js';
import { snippetAround } from '../../util/text.js';

export const commandInjectionCheck: Check = {
  id: 'command-injection',
  title: 'OS command injection',
  kind: 'active',
  description: 'Detects command injection by echoing a unique marker via shell separators.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const points = injectionPoints(ctx.endpoint);
    const findings: Finding[] = [];

    for (const point of points) {
      const rand = Math.random().toString(36).slice(2, 8).toUpperCase();
      // The marker we SEARCH for ("AEGIS<rand>") is NOT present verbatim in the
      // payload: the echo argument breaks it up with empty quotes (AEG""IS""<rand>).
      // A shell strips the quotes and prints the joined marker, so only genuine
      // command execution produces it — a plain reflection of the raw payload won't.
      const needle = `AEGIS${rand}`;
      const arg = `AEG""IS""${rand}`;
      const command = `echo ${arg}`;
      const payloads = [
        `; ${command}`,
        `| ${command}`,
        `& ${command}`,
        `&& ${command}`,
        `$(${command})`,
        `\`${command}\``,
        `; ${command} #`,
        `' ; ${command} ; '`,
        `" ; ${command} ; "`,
      ];

      let reported = false;
      for (const payload of payloads) {
        if (reported) break;
        const res = await point.send(ctx.http, payload);
        if (res.status === 0 || !res.body) continue;
        if (res.body.includes(needle)) {
          const where = point.describe();
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: 'OS command injection',
              severity: 'critical',
              confidence: 'firm',
              kind: 'active',
              description:
                `Input to "${where.param}" was executed by a system shell (our echoed marker ${needle} appeared ` +
                'in the response). This typically allows full remote command execution on the server.',
              remediation:
                'Never pass user input to a shell. Use APIs that take an argument array (no shell), validate against ' +
                'strict allowlists, and run with least privilege. Avoid system()/exec() with concatenated strings.',
              references: ['CWE-78', 'A03:2021-Injection', 'https://owasp.org/www-community/attacks/Command_Injection'],
              evidence: {
                url: where.url,
                method: where.method,
                param: where.param,
                payload,
                responseStatus: res.status,
                snippet: snippetAround(res.body, needle) ?? needle,
              },
            }),
          );
          reported = true;
        }
      }
    }

    return findings;
  },
};
