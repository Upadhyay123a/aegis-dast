/**
 * JSON reporter — the full machine-readable scan result.
 */
import type { ScanResult } from '../types.js';

export function renderJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
