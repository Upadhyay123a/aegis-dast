# Aegis-AI 🤖🛡️

**DAST-style security scanner for AI/LLM models and endpoints.**

Aegis-AI is the AI-testing half of [Aegis-DAST](https://github.com/Upadhyay123a/aegis-dast).
It probes **any model or AI endpoint** for the issues that matter for LLM apps —
prompt injection, jailbreaks, system-prompt leakage, sensitive-data disclosure,
and insecure output handling — and reports each with evidence and a fix.

> ⚠️ Probes send adversarial prompts. Only test models/endpoints you own or are
> authorized to assess. The CLI requires `--i-have-authorization`.

## Test *any* model

| Target | Use it for |
|--------|-----------|
| `OpenAICompatTarget` | OpenAI, Azure OpenAI, Groq, Together, **and local servers** (Ollama, LM Studio, vLLM) via `--base-url` |
| `HTTPTarget` | Any JSON chat API — give it a body template and the path to the reply |
| `CallableTarget` | Any Python `str -> str` function (HuggingFace pipeline, LangChain chain, your own app) |

Zero required dependencies — pure standard library.

## Install

```bash
cd python
pip install -e ".[dev]"      # editable + test tools
# or just: pip install .
```

## CLI

```bash
# List probes
aegis-ai probes

# Scan an OpenAI model
export OPENAI_API_KEY=sk-...
aegis-ai scan --provider openai --model gpt-4o-mini \
  --i-have-authorization --report console,html,sarif --out ./aegis-ai-report

# Scan a local model (Ollama)
aegis-ai scan --provider openai --model llama3 \
  --base-url http://localhost:11434/v1 --i-have-authorization

# Scan any JSON HTTP chat API
aegis-ai scan --provider http --url https://api.example.com/chat \
  --body-template '{"message":"{prompt}"}' --response-path reply \
  --i-have-authorization
```

Useful flags: `--probes`, `--exclude`, `--attempts`, `--fail-on {low,medium,high,critical}`
(non-zero exit for CI gates), `--report console,json,sarif,html`.

## Python API

```python
from aegis_ai import Scanner, ScanConfig, OpenAICompatTarget, CallableTarget, render_html

# Any OpenAI-compatible endpoint
target = OpenAICompatTarget("gpt-4o-mini", api_key="sk-...")

# ...or any Python callable
target = CallableTarget(lambda prompt: my_model(prompt), name="my-model", supports_roles=False)

result = Scanner(ScanConfig()).scan(target)
print(result.counts())
open("report.html", "w").write(render_html(result))
```

## Probes (23, across the OWASP LLM Top 10)

| Probe id | Tests for | OWASP |
|----------|-----------|-------|
| `prompt-injection` | Direct instruction override via user input | LLM01 |
| `indirect-injection` | Instruction smuggled through retrieved/RAG content | LLM01 |
| `encoding-injection` | Base64/ROT13-obfuscated injection past plaintext filters | LLM01 |
| `special-token-injection` | Fake chat-template role tokens | LLM01 |
| `unicode-obfuscation` | Zero-width / unicode-hidden instructions | LLM01 |
| `payload-splitting` | Trigger split across variables | LLM01 |
| `jailbreak` | Guardrail bypass via jailbreak wrappers | LLM01 |
| `many-shot-jailbreak` | Context flooded with fake compliant examples | LLM01 |
| `refusal-suppression` | Forbidding refusal language | LLM01 |
| `multilingual-bypass` | Attack in a low-resource language | LLM01 |
| `adversarial-suffix` | GCG-style adversarial suffix | LLM01 |
| `context-overflow` | Instruction buried after filler | LLM01 |
| `virtualization-jailbreak` | Request nested in a fictional simulation | LLM01 |
| `goal-hijacking` | Pivot from a benign task mid-prompt | LLM01 |
| `multi-turn-escalation` | "Crescendo" attacks over a conversation | LLM01 |
| `system-prompt-leak` | Disclosure of hidden system instructions | LLM07 |
| `prefill-extraction` | Extraction via completion-prefill priming | LLM07 |
| `translation-leak` | System prompt leaked via translation | LLM07 |
| `sensitive-info-disclosure` | Extraction of secrets planted in context | LLM02 |
| `markdown-data-exfil` | Secret exfiltrated via markdown image/link URL | LLM02 |
| `excessive-agency` | Taking/confirming destructive actions | LLM06 |
| `insecure-output-handling` | Emitting raw script/SQL payloads verbatim | LLM05 |
| `unbounded-consumption` | No output cap → denial of wallet | LLM10 |

Every scan also produces a **risk score (0-100) and letter grade (A-F)** for
quick triage and dashboards.

### Built for live models

- **Multi-turn conversations** — `converse()` drives real chat history (used by
  the crescendo probe); native for OpenAI-compatible targets.
- **Resilience** — HTTP targets retry transient errors (429/5xx) with backoff and
  support client-side rate limiting (`rate_limit_per_min`) so you can safely scan
  real, rate-limited APIs.
- **Reusable detectors** — shared refusal detection and PII/secret regexes keep
  detection consistent and false positives low across probes.

Probes that need privileged **system/user role separation**
(`system-prompt-leak`, `sensitive-info-disclosure`) are skipped automatically for
targets that don't support it (e.g. a plain callable), and the report says so.

### How false positives are avoided

Detection is **canary-based**: injection and jailbreak probes ask the model to
return the product of two random numbers. That answer is never in the prompt, so
a model that merely echoes input can't produce it — only one that actually obeyed
the injected instruction will.

## Tests

```bash
cd python
pytest
```

## License

MIT — see [../LICENSE](../LICENSE).
