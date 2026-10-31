"""Command-line interface for Aegis-AI.

Examples
--------
List probes:
    aegis-ai probes

Scan an OpenAI-compatible model (OpenAI, or a local server via --base-url):
    aegis-ai scan --provider openai --model gpt-4o-mini --i-have-authorization \\
        --report console,html --out ./aegis-ai-report

Scan a local model served by Ollama/LM Studio/vLLM:
    aegis-ai scan --provider openai --model llama3 \\
        --base-url http://localhost:11434/v1 --i-have-authorization

Scan any JSON HTTP chat API:
    aegis-ai scan --provider http --url https://api.example.com/chat \\
        --body-template '{"message":"{prompt}"}' --response-path reply \\
        --i-have-authorization
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .models import HTTPTarget, OpenAICompatTarget, Target
from .probes import ALL_PROBES
from .report import render_console, render_html, render_json, render_sarif
from .scanner import ScanConfig, Scanner, should_fail

REPORTERS = {
    "json": ("report.json", render_json),
    "sarif": ("report.sarif", render_sarif),
    "html": ("report.html", render_html),
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis-ai", description="DAST-style security scanner for AI/LLM targets.")
    sub = parser.add_subparsers(dest="command", required=True)

    p_probes = sub.add_parser("probes", help="list available probes")
    p_probes.set_defaults(func=_cmd_probes)

    s = sub.add_parser("scan", help="scan an AI model/endpoint")
    s.add_argument("--provider", choices=["openai", "http"], required=True)
    s.add_argument(
        "--i-have-authorization",
        action="store_true",
        help="confirm you are authorized to test this model/endpoint (required)",
    )
    # OpenAI-compatible
    s.add_argument("--model", help="model id (openai provider)")
    s.add_argument("--base-url", default="https://api.openai.com/v1", help="API base URL (openai provider)")
    s.add_argument("--api-key", default=None, help="API key; falls back to OPENAI_API_KEY / AEGIS_AI_API_KEY")
    s.add_argument("--temperature", type=float, default=0.0)
    s.add_argument("--max-tokens", type=int, default=512)
    # Generic HTTP
    s.add_argument("--url", help="endpoint URL (http provider)")
    s.add_argument("--body-template", help="JSON body with {prompt} placeholder, or @file (http provider)")
    s.add_argument("--response-path", help="dotted path to the reply text, e.g. choices.0.message.content")
    s.add_argument("--header", action="append", default=[], help='extra header "Name: value" (repeatable)')
    # Common
    s.add_argument("--probes", default="", help="comma-separated probe ids to include (default: all)")
    s.add_argument("--exclude", default="", help="comma-separated probe ids to skip")
    s.add_argument("--attempts", type=int, default=1, help="randomized attempts per probe")
    s.add_argument("--timeout", type=float, default=30.0)
    s.add_argument("--report", default="console", help="comma-separated: console,json,sarif,html")
    s.add_argument("--out", default="./aegis-ai-report", help="output dir for file reports")
    s.add_argument("--fail-on", choices=["never", "low", "medium", "high", "critical"], default="never")
    s.set_defaults(func=_cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_probes(_args) -> int:
    print("Available Aegis-AI probes:\n")
    for p in ALL_PROBES:
        roles = " (needs system/user roles)" if p.requires_roles else ""
        print(f"  {p.id:<26} {p.title}{roles}")
    print("\nActive probes send adversarial prompts; only scan models you are authorized to test.\n")
    return 0


def _build_target(args) -> Target:
    if args.provider == "openai":
        if not args.model:
            _fail("--model is required for --provider openai")
        api_key = args.api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("AEGIS_AI_API_KEY") or ""
        return OpenAICompatTarget(
            args.model,
            base_url=args.base_url,
            api_key=api_key,
            temperature=args.temperature,
            max_tokens=args.max_tokens,
            timeout=args.timeout,
            extra_headers=_parse_headers(args.header),
        )
    # http
    if not (args.url and args.body_template and args.response_path):
        _fail("--url, --body-template and --response-path are required for --provider http")
    template = args.body_template
    if template.startswith("@"):
        template = Path(template[1:]).read_text(encoding="utf-8")
    return HTTPTarget(
        args.url,
        body_template=template,
        response_path=args.response_path,
        headers=_parse_headers(args.header),
        timeout=args.timeout,
    )


def _cmd_scan(args) -> int:
    if not args.i_have_authorization:
        _fail(
            "Refusing to scan: pass --i-have-authorization to confirm you may test this target. "
            "Only test models/endpoints you own or have written permission to assess."
        )

    target = _build_target(args)
    config = ScanConfig(
        include=_split(args.probes),
        exclude=_split(args.exclude),
        attempts=args.attempts,
        timeout=args.timeout,
        fail_on=args.fail_on,
    )

    def on_event(kind: str, msg: str) -> None:
        if kind == "probe":
            print(f"  running probe: {msg}", file=sys.stderr)
        elif kind == "skip":
            print(f"  skipped: {msg}", file=sys.stderr)
        elif kind == "error":
            print(f"  probe error: {msg}", file=sys.stderr)

    print(f"Aegis-AI scanning {target.name} ...", file=sys.stderr)
    result = Scanner(config, on_event=on_event).scan(target)

    formats = _split(args.report)
    if "console" in formats or not formats:
        print(render_console(result))
    file_formats = [f for f in formats if f in REPORTERS]
    if file_formats:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for fmt in file_formats:
            fname, render = REPORTERS[fmt]
            path = out / fname
            path.write_text(render(result), encoding="utf-8")
            print(f"wrote {fmt.upper()} report: {path}", file=sys.stderr)

    if should_fail(result, args.fail_on):
        print(f"Failing: findings at/above '{args.fail_on}' detected.", file=sys.stderr)
        return 2
    return 0


def _parse_headers(items: list[str]) -> dict:
    out = {}
    for item in items:
        if ":" in item:
            k, v = item.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _split(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


def _fail(message: str) -> None:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(2)


if __name__ == "__main__":
    raise SystemExit(main())
