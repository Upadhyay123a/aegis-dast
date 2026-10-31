/** Small text helpers used by checks and reporters. */

/** Truncate a string to `max` chars with an ellipsis marker. */
export function truncate(s: string, max = 240): string {
  if (s.length <= max) return s;
  return `${s.slice(0, max)}…`;
}

/** Extract a short snippet of `body` around the first occurrence of `needle`. */
export function snippetAround(body: string, needle: string, radius = 80): string | undefined {
  const idx = body.indexOf(needle);
  if (idx === -1) return undefined;
  const start = Math.max(0, idx - radius);
  const end = Math.min(body.length, idx + needle.length + radius);
  return `${start > 0 ? '…' : ''}${body.slice(start, end)}${end < body.length ? '…' : ''}`;
}

/** Generate a random, URL-safe marker token for reflection-based checks. */
export function marker(prefix = 'aeg'): string {
  const rand = Math.random().toString(36).slice(2, 10);
  return `${prefix}${rand}`;
}
