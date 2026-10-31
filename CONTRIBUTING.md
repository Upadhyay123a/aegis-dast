# Contributing to Aegis-DAST

Thanks for your interest! Contributions of checks, reporters, and fixes are
welcome.

## Development setup

```bash
git clone https://github.com/Upadhyay123a/aegis-dast.git
cd aegis-dast
npm install
npm run build
npm test
```

Run the scanner against the bundled (intentionally vulnerable) test server:

```bash
npm run demo:server        # terminal 1 — starts http://127.0.0.1:3000
npm run demo:scan          # terminal 2 — scans it and writes ./aegis-report
```

## Writing a new check

1. Create a file under `src/checks/passive/` or `src/checks/active/`.
2. Export a `Check` object (`id`, `title`, `kind`, `description`, `run`).
3. Build findings with `makeFinding()` from `src/checks/context.ts`.
4. Register it in `src/checks/registry.ts`.
5. Add a test under `test/`.

**Safety rules for active checks:** payloads must be non-destructive. Prefer
marker-based detection. Never delete/modify data, cause denial of service, or
exfiltrate real secrets.

## Standards

- TypeScript, ESM, `.js` import specifiers (NodeNext).
- `npm run lint`, `npm run typecheck`, and `npm test` must pass.
- Keep findings actionable: clear title, severity, evidence, and remediation.

## Commit messages

Conventional-ish prefixes are appreciated: `feat:`, `fix:`, `docs:`, `test:`,
`refactor:`, `chore:`.
