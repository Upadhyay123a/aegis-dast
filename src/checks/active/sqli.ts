/**
 * Active check: SQL injection (error-based + boolean-differential).
 *
 * SAFE BY DESIGN: payloads are non-destructive. Error-based detection appends a
 * single quote and looks for database error signatures. The boolean test sends
 * a always-true vs always-false pair and compares response similarity — it does
 * not modify data.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding, HttpExchange } from '../../types.js';
import { injectionPoints } from './inject.js';
import { snippetAround } from '../../util/text.js';

const SQL_ERRORS: Array<{ db: string; re: RegExp }> = [
  { db: 'MySQL', re: /SQL syntax.*MySQL|valid MySQL result|MySqlClient\.|com\.mysql\.jdbc/i },
  { db: 'PostgreSQL', re: /PostgreSQL.*ERROR|pg_query\(\)|PG::SyntaxError|org\.postgresql\.util\.PSQLException/i },
  { db: 'MSSQL', re: /Microsoft SQL Server|ODBC SQL Server Driver|System\.Data\.SqlClient|Unclosed quotation mark/i },
  { db: 'Oracle', re: /ORA-\d{5}|Oracle error|quoted string not properly terminated/i },
  { db: 'SQLite', re: /SQLite\/JDBCDriver|SQLite\.Exception|org\.sqlite\.|sqlite3\.OperationalError/i },
  { db: 'Generic', re: /SQL syntax|syntax error at or near|unterminated quoted string/i },
];

export const sqliCheck: Check = {
  id: 'sqli',
  title: 'SQL injection',
  kind: 'active',
  description: 'Detects error-based and boolean-based SQL injection in parameters.',

  async run(ctx: CheckContext): Promise<Finding[]> {
    const points = injectionPoints(ctx.endpoint);
    if (points.length === 0) return [];
    const findings: Finding[] = [];

    for (const point of points) {
      const where = point.describe();

      // --- Error-based ---
      const errRes = await point.send(ctx.http, "aegis'\"");
      if (errRes.status !== 0) {
        const hit = SQL_ERRORS.find((e) => e.re.test(errRes.body));
        if (hit) {
          findings.push(
            makeFinding({
              ruleId: this.id,
              title: `SQL injection (error-based, ${hit.db})`,
              severity: 'critical',
              confidence: 'firm',
              kind: 'active',
              description:
                `Injecting a quote produced a ${hit.db} database error, indicating the input is concatenated ` +
                'into a SQL query. This can lead to data theft, authentication bypass, or full database compromise.',
              remediation:
                'Use parameterized queries / prepared statements for all database access. Never build SQL by string ' +
                'concatenation. Apply least-privilege database accounts.',
              references: ['CWE-89', 'A03:2021-Injection', 'https://owasp.org/www-community/attacks/SQL_Injection'],
              evidence: {
                url: where.url,
                method: where.method,
                param: where.param,
                payload: "aegis'\"",
                responseStatus: errRes.status,
                snippet: firstErrorSnippet(errRes.body, hit.re),
              },
            }),
          );
          continue; // already confirmed for this point
        }
      }

      // --- Boolean-based differential ---
      const truePayload = "aegis' OR '1'='1";
      const falsePayload = "aegis' AND '1'='2";
      const [tRes, fRes] = await Promise.all([
        point.send(ctx.http, truePayload),
        point.send(ctx.http, falsePayload),
      ]);
      if (tRes.status === 0 || fRes.status === 0) continue;

      const sim = similarity(tRes, fRes);
      // A large divergence between logically-true and logically-false inputs is
      // a classic boolean-SQLi signal. Threshold kept conservative to limit FPs.
      if (sim < 0.6 && tRes.status === fRes.status) {
        findings.push(
          makeFinding({
            ruleId: this.id,
            title: 'Possible boolean-based SQL injection',
            severity: 'high',
            confidence: 'tentative',
            kind: 'active',
            description:
              'Logically-true and logically-false SQL conditions produced significantly different responses, ' +
              'suggesting the input influences a SQL query. Confirm before relying on this result.',
            remediation:
              'Use parameterized queries / prepared statements. Validate and canonicalize input. Apply least privilege.',
            references: ['CWE-89', 'A03:2021-Injection'],
            evidence: {
              url: where.url,
              method: where.method,
              param: where.param,
              payload: `${truePayload}  vs  ${falsePayload}`,
              responseStatus: tRes.status,
              snippet: `response similarity true/false = ${sim.toFixed(2)} (lower = more suspicious)`,
            },
          }),
        );
      }
    }

    return findings;
  },
};

function firstErrorSnippet(body: string, re: RegExp): string {
  const m = body.match(re);
  if (!m) return '(error matched)';
  return snippetAround(body, m[0]) ?? m[0];
}

/** Crude length-based similarity in [0,1]; 1 = identical size. */
function similarity(a: HttpExchange, b: HttpExchange): number {
  const la = a.body.length;
  const lb = b.body.length;
  if (la === 0 && lb === 0) return 1;
  const max = Math.max(la, lb);
  const min = Math.min(la, lb);
  return max === 0 ? 1 : min / max;
}
