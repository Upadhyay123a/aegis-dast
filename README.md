# 🛡️ Aegis-DAST

**An AI-augmented, safe-by-default security scanner — for web apps _and_ AI models.**

Aegis-DAST is a two-part toolkit:

| Tool | Language | Scans | Where |
|------|----------|-------|-------|
| **Aegis-DAST** | TypeScript / Node | Running **websites & web APIs** — crawls them and probes for web vulnerabilities | this repo root |
| **Aegis-AI** | Python | **Any AI model or LLM endpoint** — prompt injection, jailbreaks, data leakage, and more | [`python/`](python/) |

Use one or both. The web scanner adds an optional AI engine that verifies
findings to cut false positives; the Python scanner red-teams the AI model
itself. Together they cover a modern app end to end: the web layer **and** the AI
layer behind it.

> ⚠️ **Only scan systems and models you own or are authorized to test.**
> Both tools gate their active/attack behaviour behind an explicit
> authorization flag.

---

## Why Aegis-DAST

Traditional scanners are noisy — fixed payloads, mountains of false positives.
Aegis follows the pattern modern tooling has converged on:

1. **Rule-based detection** finds candidate issues fast and deterministically.
2. **An AI "skeptic" second pass** reviews each candidate, estimates real
   exploitability, and suppresses likely false positives.
3. **Canary-based probes** confirm an effect actually happened (e.g. the model
   returned a value that could only come from obeying an injected instruction),
   instead of guessing from reflection.

---

# Part 1 — Aegis-DAST (web scanner)

Crawls a target within scope and runs passive + active checks, then optional AI
verification, then reports to console, HTML, JSON and **SARIF**.

### Install & quick start

Requires **Node.js ≥ 20**.

```bash
git clone https://github.com/Upadhyay123a/aegis-dast.git
cd aegis-dast
npm install
npm run build

# Try it against the bundled, intentionally-vulnerable demo app:
npm run demo:server          # terminal 1 → http://127.0.0.1:3000
npm run demo:scan            # terminal 2 → writes ./aegis-report/report.html
```

### Usage

```bash
aegis scan <target> --scope <hosts> [--active --i-have-authorization] \
  [--ai auto|claude|openai|none] [--report console,json,html,sarif] [--out dir] \
  [--fail-on low|medium|high|critical]

aegis checks                 # list all checks
```

Key flags: `--scope` (allowlist), `--active` + `--i-have-authorization` (enable
attack checks), `-H "Cookie: ..."` (authenticated scans), `--fail-on` (CI gate).
Full reference: run `aegis scan --help`. Example config:
[`examples/aegis.config.json`](examples/aegis.config.json).

### Web checks

| Rule id | Kind | Max severity | Detects |
|---------|------|--------------|---------|
| `security-headers` | passive | medium | Missing CSP / HSTS / X-CTO / X-Frame / Referrer-Policy |
| `cookie-flags` | passive | medium | Cookies missing HttpOnly / Secure / SameSite |
| `info-leak` | passive | high | Version banners, directory listing, leaked secrets |
| `csrf` | passive | medium | State-changing forms with no anti-CSRF token |
| `xss-reflected` | active | high | Reflected cross-site scripting |
| `sqli` | active | critical | Error-based & boolean SQL injection |
| `command-injection` | active | critical | OS command injection (quote-split echo marker) |
| `path-traversal` | active | critical | Local file inclusion / directory traversal |
| `ssrf` | active | high | Server-side request forgery (non-routable canary) |
| `open-redirect` | active | medium | Unvalidated redirects |
| `crlf-injection` | active | medium | HTTP response splitting / header injection |
| `cors-misconfig` | active | high | Reflected Origin / credentials misconfig |

### The AI engine (optional)

Set a key to turn it on (see [`.env.example`](.env.example)); without one the
scanner runs fully rule-based.

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # Claude (default)
# or OPENAI_API_KEY=sk-...            # OpenAI
```

- `verifyFinding()` — a skeptical review of each candidate; low-exploitability
  findings are suppressed and the AI's rationale is attached to the report.
- `suggestPayloads()` — context-aware, non-destructive payload ideas.

### SARIF → GitHub Security tab

```yaml
- run: npx aegis scan https://staging.example --scope staging.example \
         --active --i-have-authorization --report sarif --out ./aegis-report
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: ./aegis-report/report.sarif }
```

### Architecture

```
 target + scope ──► Crawler ──► Attack Surface (endpoints, params, forms)
                                   │
                    ┌──────────────┼───────────────┐
                    ▼              ▼                ▼
             Passive checks   Active checks   AI payload gen (optional)
             (headers,cookies  (plugin modules)
              info leak, csrf)      │
                    └──────► Raw findings ──► AI verifier (optional, 2nd pass)
                                               │
                                        Deduped & scored findings
                                               │
                              Reporters: console · JSON · HTML · SARIF
```

Key modules: [`src/core/engine.ts`](src/core/engine.ts),
[`src/core/scope.ts`](src/core/scope.ts) (safety),
[`src/crawler/`](src/crawler/), [`src/checks/`](src/checks/),
[`src/ai/`](src/ai/), [`src/report/`](src/report/).

---

# Part 2 — Aegis-AI (AI/LLM scanner)

Security-tests **any AI model or endpoint**. Full docs: [`python/README.md`](python/README.md).

### Install & quick start

Requires **Python ≥ 3.9**. No third-party dependencies.

```bash
cd python
pip install -e ".[dev]"
aegis-ai probes               # list probes

# Scan an OpenAI model
export OPENAI_API_KEY=sk-...
aegis-ai scan --provider openai --model gpt-4o-mini \
  --i-have-authorization --report console,html,sarif --out ./aegis-ai-report

# Scan a LOCAL model (Ollama / LM Studio / vLLM)
aegis-ai scan --provider openai --model llama3 \
  --base-url http://localhost:11434/v1 --i-have-authorization

# Scan ANY JSON chat API
aegis-ai scan --provider http --url https://api.example.com/chat \
  --body-template '{"message":"{prompt}"}' --response-path reply \
  --i-have-authorization
```

Test any Python model in code:

```python
from aegis_ai import Scanner, CallableTarget
result = Scanner().scan(CallableTarget(my_model_fn, name="my-model"))
print(result.counts())
```

### AI probes (OWASP LLM Top 10)

| Probe id | Tests for | OWASP |
|----------|-----------|-------|
| `prompt-injection` | Instruction override via user input | LLM01 |
| `jailbreak` | Guardrail bypass via jailbreak wrappers | LLM01 |
| `system-prompt-leak` | Disclosure of hidden system instructions | LLM07 |
| `sensitive-info-disclosure` | Extraction of secrets planted in context | LLM02 |
| `insecure-output-handling` | Emitting raw script/SQL payloads verbatim | LLM05 |

---

## Development

```bash
# Web scanner
npm run lint && npm run typecheck && npm test

# AI scanner
cd python && ruff check . && pytest
```

CI runs both suites on every push/PR (see [`.github/workflows/`](.github/workflows/)).
See [CONTRIBUTING.md](CONTRIBUTING.md) to add a web check or an AI probe.

## Roadmap

- [x] Core web DAST (XSS, SQLi, SSRF, CSRF, CORS, CRLF, cmd-injection, traversal, open-redirect)
- [x] AI/LLM scanner (prompt injection, jailbreak, leakage, insecure output)
- [ ] Playwright crawling for JS-heavy SPAs
- [ ] Authenticated session recording / replay
- [ ] Baseline diffing (report only *new* findings)
- [ ] More AI probes: tool/function-call abuse, multi-turn attacks, RAG poisoning
- [ ] Web dashboard

## Legal & safety

For **authorized** security testing and education only. You are responsible for
having permission to test any target or model. See [SECURITY.md](SECURITY.md).
Licensed under the [MIT License](LICENSE).
