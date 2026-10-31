# 🛡️ Aegis-DAST

**An AI-augmented, safe-by-default Dynamic Application Security Testing (DAST) scanner.**

Aegis-DAST crawls a running web application, probes it for common vulnerability
classes, and uses an optional AI engine to generate smarter payloads and — most
importantly — to **verify findings and cut false positives**. Reports export to
console, HTML, JSON, and **SARIF** (for the GitHub Security tab and CI gates).

> ⚠️ **Only scan systems you own or are explicitly authorized to test.**
> Active (attack) checks are disabled unless you pass `--i-have-authorization`.

---

## Why Aegis-DAST

Traditional DAST tools are noisy: they fire fixed payload lists and report
everything that looks suspicious, leaving humans to triage mountains of false
positives. Aegis-DAST follows the pattern that modern research and tooling have
converged on:

1. **Rule-based detection** finds candidate issues fast and deterministically.
2. **An AI "skeptic" second pass** reviews each candidate, estimates real
   exploitability, and suppresses likely false positives — the mechanism shown
   to reduce FP rates substantially.
3. **Context-aware AI payloads** (optional) augment the built-in probes.

The AI layer is **completely optional and pluggable**. With no API key, Aegis
runs fully rule-based. Add a key and it gets smarter.

---

## Features

- 🕸️ **Crawler** — discovers URLs, query parameters, and forms within scope.
- 🔎 **Passive checks** — security headers, insecure cookies, information
  disclosure (version banners, directory listings, leaked secrets).
- 💥 **Active checks** — reflected XSS, SQL injection (error + boolean), open
  redirect, path traversal. All **non-destructive, marker-based**.
- 🤖 **Pluggable AI engine** — Claude (default), OpenAI, or none. Used for
  payload suggestions and false-positive-reducing verification.
- 🔒 **Safe by default** — scope allowlist, authorization gate, rate limiting,
  `robots.txt` awareness.
- 📊 **Reports** — console, HTML (self-contained), JSON, and SARIF 2.1.0.
- 🧩 **Extensible** — add a check in one file and register it.
- ⚙️ **CI-ready** — `--fail-on <severity>` for pipeline gates; SARIF upload to
  GitHub code scanning.

---

## Install

Requires **Node.js ≥ 18.17**.

```bash
git clone https://github.com/Upadhyay123a/aegis-dast.git
cd aegis-dast
npm install
npm run build
npm link     # optional: makes the `aegis` command global
```

---

## Quick start

Try it against the bundled, intentionally vulnerable test server:

```bash
# Terminal 1 — start the deliberately-vulnerable demo app
npm run demo:server          # http://127.0.0.1:3000

# Terminal 2 — scan it (active checks + authorization, all report formats)
npm run demo:scan
# or directly:
npx tsx src/cli.ts scan http://127.0.0.1:3000 \
  --active --i-have-authorization \
  --scope 127.0.0.1 \
  --report console,html,json,sarif --out ./aegis-report
```

Open `./aegis-report/report.html` to see the findings.

---

## Usage

```
aegis scan <target> [options]

Options:
  -s, --scope <hosts>          comma-separated scope allowlist (hosts or URL prefixes)
  -a, --active                 enable active (attack) checks — requires authorization
      --i-have-authorization   confirm you may actively test the target
      --ai <provider>          auto | claude | openai | none           (default: auto)
      --ai-model <model>       override the AI model id
      --ai-min-severity <sev>  only AI-verify findings at/above this severity (default: low)
  -r, --report <formats>       console,json,html,sarif                  (default: console)
  -o, --out <dir>              output directory for file reports        (default: ./aegis-report)
  -d, --depth <n>              max crawl depth                          (default: 3)
      --max-urls <n>           max URLs to crawl                        (default: 200)
  -c, --concurrency <n>        concurrent requests                      (default: 8)
      --delay <ms>             min delay between requests to a host     (default: 0)
      --timeout <ms>           per-request timeout                      (default: 15000)
  -H, --header <header>        extra request header "Name: value" (repeatable)
      --include <rules>        only run these rule ids (comma-separated)
      --exclude <rules>        skip these rule ids (comma-separated)
      --no-robots              do not fetch/respect robots.txt
      --fail-on <sev>          exit non-zero if a finding at/above this severity exists
      --config <path>          load a JSON config file
  -v, --verbose                verbose (debug) logging
  -q, --quiet                  only errors

aegis checks                   list available checks
```

### Authenticated scans

Pass a session cookie or token via headers:

```bash
aegis scan https://app.example --scope app.example \
  -H "Cookie: session=..." -H "Authorization: Bearer ..."
```

### Config file

See [`examples/aegis.config.json`](examples/aegis.config.json). CLI flags
override config-file values.

---

## The AI engine

Set a key (either one) to enable AI features — see [`.env.example`](.env.example):

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # Claude (default)
# or
export OPENAI_API_KEY=sk-...             # OpenAI
```

- `--ai auto` (default): use Claude if its key is set, else OpenAI, else none.
- `--ai none`: force pure rule-based mode.

**What the AI does:**
- `verifyFinding()` — a skeptical review of each candidate finding; low
  exploitability scores are suppressed as false positives and the rationale is
  attached to the report.
- `suggestPayloads()` — context-aware, non-destructive payload ideas.

If the SDK isn't installed or an API call fails, Aegis falls back to heuristics
without crashing the scan.

---

## Checks

| Rule id            | Kind    | Severity (max) | Detects |
|--------------------|---------|----------------|---------|
| `security-headers` | passive | medium         | Missing CSP/HSTS/X-CTO/X-Frame/Referrer-Policy |
| `cookie-flags`     | passive | medium         | Cookies missing HttpOnly/Secure/SameSite |
| `info-leak`        | passive | high           | Version banners, directory listing, leaked secrets |
| `xss-reflected`    | active  | high           | Reflected cross-site scripting |
| `sqli`             | active  | critical       | Error-based & boolean SQL injection |
| `open-redirect`    | active  | medium         | Unvalidated redirects |
| `path-traversal`   | active  | critical       | Local file inclusion / directory traversal |

---

## GitHub code scanning (SARIF)

Produce SARIF and upload it so findings appear in the **Security** tab:

```yaml
- run: npx aegis scan https://staging.example --scope staging.example \
         --active --i-have-authorization --report sarif --out ./aegis-report
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./aegis-report/report.sarif
```

---

## Architecture

```
 target + scope ──► Crawler ──► Attack Surface (endpoints, params, forms)
                                   │
                    ┌──────────────┼───────────────┐
                    ▼              ▼                ▼
             Passive checks   Active checks   AI payload gen (optional)
             (headers,cookies  (plugin modules)
              info leak)            │
                    └──────► Raw findings ──► AI verifier (optional, 2nd pass)
                                               │
                                        Deduped & scored findings
                                               │
                              Reporters: console · JSON · HTML · SARIF
```

Key modules: [`src/core/engine.ts`](src/core/engine.ts) (orchestration),
[`src/core/scope.ts`](src/core/scope.ts) (safety), [`src/crawler/`](src/crawler/),
[`src/checks/`](src/checks/), [`src/ai/`](src/ai/), [`src/report/`](src/report/).

---

## Roadmap

- [ ] Playwright-based crawling for JS-heavy SPAs
- [ ] Authenticated session recording / replay
- [ ] More active checks (SSRF, CSRF, XXE, command injection)
- [ ] Prompt-injection module for AI-enabled apps & MCP tools
- [ ] Baseline diffing (only report *new* findings)
- [ ] Distributed scanning & a web dashboard

---

## Development

```bash
npm run dev -- scan http://127.0.0.1:3000   # run from source (tsx)
npm run lint
npm run typecheck
npm test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) to add checks.

---

## Legal & safety

Aegis-DAST is for **authorized** security testing and education only. You are
responsible for ensuring you have permission to test any target. See
[SECURITY.md](SECURITY.md). Licensed under the [MIT License](LICENSE).
