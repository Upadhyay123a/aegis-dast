import { defineConfig } from 'vitest/config';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

/**
 * Source files use `.js` import specifiers (required by TypeScript's NodeNext
 * resolution for Node ESM output). This plugin lets Vitest resolve those back to
 * the `.ts` sources during testing.
 */
const resolveJsToTs = {
  name: 'aegis-resolve-js-to-ts',
  enforce: 'pre' as const,
  resolveId(source: string, importer: string | undefined) {
    if (importer && /\.js$/.test(source) && (source.startsWith('./') || source.startsWith('../'))) {
      const candidate = resolve(dirname(importer), source.replace(/\.js$/, '.ts'));
      if (existsSync(candidate)) return candidate;
    }
    return null;
  },
};

export default defineConfig({
  plugins: [resolveJsToTs],
  test: {
    environment: 'node',
    include: ['test/**/*.test.ts'],
    testTimeout: 30000,
    hookTimeout: 30000,
  },
});
