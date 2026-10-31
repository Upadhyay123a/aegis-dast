"""Target abstraction — lets Aegis-AI test *any* model or AI endpoint.

Three ready-made targets:

* :class:`OpenAICompatTarget` — any OpenAI-compatible ``/chat/completions`` API
  (OpenAI, Azure OpenAI, Together, Groq, Ollama, LM Studio, vLLM, ...). Supports
  real system/user role separation.
* :class:`HTTPTarget` — any JSON HTTP API: give it a URL, a request body
  template with a ``{prompt}`` placeholder, and a dotted path to the reply.
* :class:`CallableTarget` — wrap any Python function ``str -> str`` (a local
  HuggingFace pipeline, a LangChain chain, your own app, ...).

All targets implement the same :class:`Target` interface, so every probe works
against every target.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable


class TargetError(RuntimeError):
    """Raised when a target cannot produce a response."""


class Target:
    """Base class for anything Aegis-AI can send prompts to."""

    name: str = "target"
    #: Whether the target separates privileged (system) content from user input.
    #: Probes that plant a secret in the system prompt only run when this is True.
    supports_roles: bool = False

    def generate(
        self,
        prompt: str,
        *,
        system: str | None = None,
        context: str | None = None,
    ) -> str:
        """Return the model's text reply for ``prompt``.

        ``system`` is privileged instruction content; ``context`` is extra
        reference text. Targets without role support fold them into the prompt.
        """
        raise NotImplementedError


def _merge_prompt(prompt: str, system: str | None, context: str | None) -> str:
    parts = []
    if system:
        parts.append(system)
    if context:
        parts.append(context)
    parts.append(prompt)
    return "\n\n".join(parts)


class CallableTarget(Target):
    """Wrap any ``callable(str) -> str`` (e.g. a local model or your own app)."""

    def __init__(self, fn: Callable[[str], str], name: str = "callable", supports_roles: bool = False):
        self._fn = fn
        self.name = name
        self.supports_roles = supports_roles

    def generate(self, prompt: str, *, system: str | None = None, context: str | None = None) -> str:
        try:
            return str(self._fn(_merge_prompt(prompt, system, context)))
        except Exception as exc:  # noqa: BLE001 - surface any model error uniformly
            raise TargetError(f"callable target failed: {exc}") from exc


class OpenAICompatTarget(Target):
    """Any OpenAI-compatible chat-completions endpoint."""

    supports_roles = True

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "https://api.openai.com/v1",
        api_key: str = "",
        temperature: float = 0.0,
        max_tokens: int = 512,
        timeout: float = 30.0,
        extra_headers: dict | None = None,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.extra_headers = extra_headers or {}
        self.name = f"openai:{model}"

    def generate(self, prompt: str, *, system: str | None = None, context: str | None = None) -> str:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        if context:
            messages.append({"role": "system", "content": context})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        data = _http_post_json(f"{self.base_url}/chat/completions", payload, headers, self.timeout)
        try:
            return data["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise TargetError(f"unexpected OpenAI-compatible response shape: {exc}") from exc


class HTTPTarget(Target):
    """Generic JSON HTTP target.

    ``body_template`` is a JSON string containing ``{prompt}`` (and optionally
    ``{system}``/``{context}``) which are substituted with JSON-escaped values.
    ``response_path`` is a dotted path into the JSON response, e.g.
    ``"choices.0.message.content"`` or ``"reply"``.
    """

    def __init__(
        self,
        url: str,
        *,
        body_template: str,
        response_path: str,
        method: str = "POST",
        headers: dict | None = None,
        timeout: float = 30.0,
        name: str | None = None,
        supports_roles: bool = False,
    ):
        self.url = url
        self.body_template = body_template
        self.response_path = response_path
        self.method = method.upper()
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout
        self.name = name or f"http:{url}"
        self.supports_roles = supports_roles or ("{system}" in body_template)

    def generate(self, prompt: str, *, system: str | None = None, context: str | None = None) -> str:
        body = self.body_template
        body = body.replace("{prompt}", _json_escape(prompt))
        body = body.replace("{system}", _json_escape(system or ""))
        body = body.replace("{context}", _json_escape(context or ""))
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise TargetError(f"body_template did not render to valid JSON: {exc}") from exc

        data = _http_post_json(self.url, payload, self.headers, self.timeout, method=self.method)
        return _dig(data, self.response_path)


def _json_escape(value: str) -> str:
    # json.dumps a string yields a quoted, escaped literal; strip the surrounding
    # quotes so it drops into the template inside existing quotes.
    return json.dumps(value)[1:-1]


def _dig(data: Any, path: str) -> str:
    cur = data
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise TargetError(f"response_path '{path}' does not match response")
    return "" if cur is None else str(cur)


def _http_post_json(url: str, payload: dict, headers: dict, timeout: float, method: str = "POST") -> Any:
    raw = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=raw, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - user-supplied target
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise TargetError(f"HTTP {exc.code} from {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise TargetError(f"could not reach {url}: {exc.reason}") from exc
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise TargetError(f"non-JSON response from {url}: {body[:200]}") from exc
