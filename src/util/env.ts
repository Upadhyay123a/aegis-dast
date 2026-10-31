/**
 * Tiny zero-dependency .env loader. Loads KEY=VALUE pairs from a .env file in the
 * current working directory into process.env (without overwriting existing vars).
 * Silently does nothing if the file is absent.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export function loadDotenv(path = resolve(process.cwd(), '.env')): void {
  let content: string;
  try {
    content = readFileSync(path, 'utf8');
  } catch {
    return;
  }
  for (const line of content.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let value = trimmed.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }
    if (key && process.env[key] === undefined) process.env[key] = value;
  }
}
