/**
 * Advanced injection checks: Server-Side Template Injection (SSTI), Server-Side
 * Includes (SSI), NoSQL, LDAP and XPath injection.
 *
 * SAFE BY DESIGN: SSTI/SSI use arithmetic or quote-split echo canaries whose
 * answer is NOT present in the payload, so a plain reflection can never match.
 * The NoSQL/LDAP/XPath probes are error-signature based and non-destructive.
 */
import type { Check, CheckContext } from '../context.js';
import { makeFinding } from '../context.js';
import type { Finding } from '../../types.js';
import { injectionPoints } from './inject.js';
import { snippetAround } from '../../util/text.js';

const A = () => 10000 + Math.floor(Math.random() * 89999);
const B = () => 3 + Math.floor(Math.random() * 7);

/** Server-Side Template Injection — {{7*7}} style across engines. */
export const sstiCheck: Check = {
  id: 'ssti',
  title: 'Server-side template injection',
  kind: 'active',
  description: 'Injects template expressions and detects server-side evaluation.',
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const point of injectionPoints(ctx.endpoint)) {
      const a = A();
      const b = B();
      const product = String(a * b);
      const payloads = [
        `{{${a}*${b}}}`, // Jinja2/Twig/Nunjucks
        `\${${a}*${b}}`, // Java EL / Spring / Thymeleaf
        `#{${a}*${b}}`, // Ruby / JSF
        `<%= ${a}*${b} %>`, // ERB / EJS
        `{${a}*${b}}`, // misc
      ];
      for (const payload of payloads) {
        if (payload.includes(product)) continue;
        const res = await point.send(ctx.http, payload);
        if (res.status === 0) continue;
        if (res.body.includes(product)) {
          const w = point.describe();
          findings.push(
            makeFinding({
              ruleId: 'ssti',
              title: 'Server-side template injection',
              severity: 'critical',
              confidence: 'firm',
              kind: 'active',
              description:
                `The "${w.param}" parameter is evaluated by a server-side template engine (our expression ` +
                `resolved to ${product}). SSTI commonly leads to remote code execution.`,
              remediation:
                'Never place user input into template source. Use logic-less templates or a sandbox, and pass user ' +
                'data strictly as bound variables, not as template text.',
              references: ['CWE-1336', 'CWE-94', 'https://portswigger.net/web-security/server-side-template-injection'],
              evidence: { url: w.url, method: w.method, param: w.param, payload, responseStatus: res.status, snippet: snippetAround(res.body, product) ?? product },
            }),
          );
          break;
        }
      }
    }
    return findings;
  },
};

/** Server-Side Includes injection. */
export const ssiCheck: Check = {
  id: 'ssi-injection',
  title: 'Server-side includes (SSI) injection',
  kind: 'active',
  description: 'Injects SSI directives and detects server-side execution.',
  async run(ctx: CheckContext): Promise<Finding[]> {
    const findings: Finding[] = [];
    for (const point of injectionPoints(ctx.endpoint)) {
      const rand = Math.random().toString(36).slice(2, 8).toUpperCase();
      const needle = `SSI${rand}MARK`;
      // Split so a raw reflection of the payload can't contain the joined needle.
      const payload = `<!--#exec cmd="echo SSI""${rand}""MARK"-->`;
      const res = await point.send(ctx.http, payload);
      if (res.status === 0) continue;
      if (res.body.includes(needle)) {
        const w = point.describe();
        findings.push(
          makeFinding({
            ruleId: 'ssi-injection',
            title: 'Server-side includes (SSI) injection',
            severity: 'critical',
            confidence: 'firm',
            kind: 'active',
            description: `The "${w.param}" parameter is processed as an SSI directive, allowing command execution on the server.`,
            remediation: 'Disable SSI where not needed, and never pass user input into SSI-parsed output. Encode < > # characters.',
            references: ['CWE-97', 'https://owasp.org/www-community/attacks/Server-Side_Includes_(SSI)_Injection'],
            evidence: { url: w.url, method: w.method, param: w.param, payload, responseStatus: res.status, snippet: snippetAround(res.body, needle) ?? needle },
          }),
        );
      }
    }
    return findings;
  },
};

function errorCheck(
  id: string,
  title: string,
  payloads: string[],
  signatures: Array<{ name: string; re: RegExp }>,
  severity: Finding['severity'],
  cwe: string,
  ref: string,
  remediation: string,
): Check {
  return {
    id,
    title,
    kind: 'active',
    description: `Detects ${title.toLowerCase()} via error signatures.`,
    async run(ctx: CheckContext): Promise<Finding[]> {
      const findings: Finding[] = [];
      for (const point of injectionPoints(ctx.endpoint)) {
        for (const payload of payloads) {
          const res = await point.send(ctx.http, payload);
          if (res.status === 0) continue;
          const hit = signatures.find((s) => s.re.test(res.body));
          if (hit) {
            const w = point.describe();
            findings.push(
              makeFinding({
                ruleId: id,
                title: `${title} (${hit.name})`,
                severity,
                confidence: 'firm',
                kind: 'active',
                description: `Injecting into "${w.param}" produced a ${hit.name} error, indicating the input reaches a backend query unsanitized.`,
                remediation,
                references: [cwe, ref],
                evidence: { url: w.url, method: w.method, param: w.param, payload, responseStatus: res.status, snippet: (res.body.match(hit.re)?.[0] ?? '').slice(0, 160) },
              }),
            );
            break;
          }
        }
      }
      return findings;
    },
  };
}

export const nosqlCheck = errorCheck(
  'nosql-injection',
  'NoSQL injection',
  ["'||'1'=='1", '"||"1"=="1', '{"$gt":""}', "'; return true; var x='"],
  [
    { name: 'MongoDB', re: /MongoError|E11000|BSONError|MongoServerError|CastError.*Mongo/i },
    { name: 'Mongoose', re: /ValidatorError|Cast to (?:ObjectId|Number) failed/i },
  ],
  'high',
  'CWE-943',
  'https://owasp.org/www-community/attacks/NoSQL_injection',
  'Use typed query builders / parameterized queries, validate and cast input types, and reject query operators in user input.',
);

export const ldapCheck = errorCheck(
  'ldap-injection',
  'LDAP injection',
  ['*)(uid=*))(|(uid=*', '*)(|(cn=*', 'admin)(|(password=*'],
  [
    { name: 'LDAP', re: /javax\.naming|LDAPException|com\.sun\.jndi|invalid DN syntax|OperationNotSupportedException/i },
  ],
  'high',
  'CWE-90',
  'https://owasp.org/www-community/attacks/LDAP_Injection',
  'Escape LDAP special characters, use parameterized LDAP APIs, and validate input against an allowlist.',
);

export const xpathCheck = errorCheck(
  'xpath-injection',
  'XPath injection',
  ["'", "']", "' or '1'='1", 'x\'] | //*['],
  [
    { name: 'XPath', re: /XPathException|xmlXPathEval|Invalid (?:XPath|expression)|unterminated|SXXP0003|XPST0003/i },
  ],
  'high',
  'CWE-643',
  'https://owasp.org/www-community/attacks/XPATH_Injection',
  'Use parameterized XPath (variable binding), validate input, and avoid building XPath from strings.',
);
