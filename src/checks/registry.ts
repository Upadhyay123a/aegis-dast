/**
 * Central registry of all built-in checks. Add new checks here to make them
 * available to the engine and CLI.
 */
import type { Check } from './context.js';
import type { Config } from '../config.js';

import { securityHeadersCheck } from './passive/security-headers.js';
import { cookieFlagsCheck } from './passive/cookie-flags.js';
import { infoLeakCheck } from './passive/info-leak.js';

import { xssReflectedCheck } from './active/xss-reflected.js';
import { sqliCheck } from './active/sqli.js';
import { openRedirectCheck } from './active/open-redirect.js';
import { pathTraversalCheck } from './active/path-traversal.js';

export const ALL_CHECKS: Check[] = [
  // passive
  securityHeadersCheck,
  cookieFlagsCheck,
  infoLeakCheck,
  // active
  xssReflectedCheck,
  sqliCheck,
  openRedirectCheck,
  pathTraversalCheck,
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
