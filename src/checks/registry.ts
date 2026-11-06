/**
 * Central registry of all built-in checks. Add new checks here to make them
 * available to the engine and CLI.
 */
import type { Check } from './context.js';
import type { Config } from '../config.js';

import { securityHeadersCheck } from './passive/security-headers.js';
import { cookieFlagsCheck } from './passive/cookie-flags.js';
import { infoLeakCheck } from './passive/info-leak.js';
import { csrfCheck } from './passive/csrf.js';
import {
  jwtAnalysisCheck,
  cspAnalysisCheck,
  domXssCheck,
  mixedContentCheck,
} from './passive/analysis.js';

import { xssReflectedCheck } from './active/xss-reflected.js';
import { sqliCheck } from './active/sqli.js';
import { blindSqliCheck } from './active/blind-sqli.js';
import { openRedirectCheck } from './active/open-redirect.js';
import { pathTraversalCheck } from './active/path-traversal.js';
import { corsCheck } from './active/cors.js';
import { crlfInjectionCheck } from './active/crlf-injection.js';
import { commandInjectionCheck } from './active/command-injection.js';
import { ssrfCheck } from './active/ssrf.js';
import { promptInjectionCheck } from './active/prompt-injection.js';
import {
  sstiCheck,
  ssiCheck,
  nosqlCheck,
  ldapCheck,
  xpathCheck,
} from './active/injection-advanced.js';
import { hostHeaderCheck, cachePoisoningCheck } from './active/header-attacks.js';
import {
  sensitiveFilesCheck,
  httpMethodsCheck,
  graphqlCheck,
} from './active/discovery.js';

export const ALL_CHECKS: Check[] = [
  // passive
  securityHeadersCheck,
  cookieFlagsCheck,
  infoLeakCheck,
  csrfCheck,
  jwtAnalysisCheck,
  cspAnalysisCheck,
  domXssCheck,
  mixedContentCheck,
  // active
  xssReflectedCheck,
  sqliCheck,
  blindSqliCheck,
  openRedirectCheck,
  pathTraversalCheck,
  corsCheck,
  crlfInjectionCheck,
  commandInjectionCheck,
  ssrfCheck,
  promptInjectionCheck,
  sstiCheck,
  ssiCheck,
  nosqlCheck,
  ldapCheck,
  xpathCheck,
  hostHeaderCheck,
  cachePoisoningCheck,
  sensitiveFilesCheck,
  httpMethodsCheck,
  graphqlCheck,
];

/**
 * Select the checks to run given the config and the authorization/active gates.
 * Active checks are only returned when both `active` and `authorized` are true.
 */
export function selectChecks(config: Config): Check[] {
  const activeAllowed = config.active && config.authorized;
  return ALL_CHECKS.filter((check) => {
    if (check.kind === 'active' && !activeAllowed) return false;
    if (config.includeRules.length > 0 && !config.includeRules.includes(check.id)) return false;
    if (config.excludeRules.includes(check.id)) return false;
    return true;
  });
}

export function checkById(id: string): Check | undefined {
  return ALL_CHECKS.find((c) => c.id === id);
}
