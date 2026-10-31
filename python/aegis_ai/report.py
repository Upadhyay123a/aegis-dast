"""Reporters for AI scan results: console, JSON, SARIF, HTML."""

from __future__ import annotations

import html
import json

from .scanner import ScanResult

_SEV_LABEL = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}
_SEV_COLOR_HTML = {
    "critical": "#b4232a",
    "high": "#d1453b",
    "medium": "#c77d0a",
    "low": "#2d72d9",
    "info": "#6b7280",
}
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SARIF_SECSEV = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}


def render_console(result: ScanResult, color: bool = True) -> str:
    lines = ["", "Aegis-AI scan report", f"Target: {result.target}"]
    c = result.counts()
    lines.append(f"Risk score: {result.risk_score()}/100 (grade {result.grade()})")
    lines.append(
        f"Summary: critical {c['critical']}  high {c['high']}  medium {c['medium']}  "
        f"low {c['low']}  info {c['info']}"
    )
    if result.skipped_probes:
        lines.append(f"Skipped (need role separation): {', '.join(result.skipped_probes)}")
    lines.append("")
    if not result.findings:
        lines.append("No findings.")
        return "\n".join(lines)
    for f in result.findings:
        lines.append(f"[{_SEV_LABEL.get(f.severity, f.severity)}] {f.title}  [{f.probe_id}]")
        lines.append(f"    confidence: {f.confidence}")
        if f.prompt:
            lines.append(f"    prompt:   {_one_line(f.prompt, 140)}")
        if f.response_snippet:
            lines.append(f"    response: {_one_line(f.response_snippet, 140)}")
        lines.append(f"    fix:      {_one_line(f.remediation, 160)}")
        lines.append("")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_sarif(result: ScanResult) -> str:
    rule_ids = {f.probe_id for f in result.findings}
    rules = [{"id": rid, "name": rid, "shortDescription": {"text": rid}} for rid in sorted(rule_ids)]
    results = []
    for f in result.findings:
        results.append(
            {
                "ruleId": f.probe_id,
                "level": _SARIF_LEVEL.get(f.severity, "note"),
                "message": {"text": f"{f.description}\n\nRemediation: {f.remediation}"},
                "properties": {
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "security-severity": _SARIF_SECSEV.get(f.severity, "0.0"),
                    "references": f.references,
                },
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": result.target}, "region": {"startLine": 1}}}
                ],
            }
        )
    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Aegis-AI",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Upadhyay123a/aegis-dast",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def render_html(result: ScanResult) -> str:
    c = result.counts()
    cards = []
    for f in result.findings:
        color = _SEV_COLOR_HTML.get(f.severity, "#6b7280")
        cards.append(
            f"""<div class="card" style="border-left-color:{color}">
      <h3><span class="tag" style="background:{color}">{html.escape(f.severity.upper())}</span>{html.escape(f.title)}</h3>
      <div class="kv"><b>Probe:</b> <code>{html.escape(f.probe_id)}</code> · <b>Confidence:</b> {html.escape(f.confidence)}</div>
      <div class="kv">{html.escape(f.description)}</div>
      {f'<div class="kv"><b>Prompt:</b></div><pre>{html.escape(f.prompt)}</pre>' if f.prompt else ''}
      {f'<div class="kv"><b>Response:</b></div><pre>{html.escape(f.response_snippet)}</pre>' if f.response_snippet else ''}
      <div class="kv"><b>Remediation:</b> {html.escape(f.remediation)}</div>
      <div class="refs">{' '.join(html.escape(r) for r in f.references)}</div>
    </div>"""
        )
    body = "\n".join(cards) if cards else '<p class="empty">No findings.</p>'
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Aegis-AI Report — {html.escape(result.target)}</title>
<style>
  :root {{ --bg:#fff; --fg:#1a1a1a; --muted:#6b7280; --card:#f7f7f8; --border:#e5e7eb; --code:#f0f0f2; }}
  @media (prefers-color-scheme: dark) {{ :root:not([data-theme="light"]) {{
    --bg:#0f1115; --fg:#e6e6e6; --muted:#9aa0aa; --card:#171a21; --border:#272b33; --code:#1d2129; }} }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg); font:15px/1.6 system-ui,Segoe UI,Roboto,sans-serif; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:32px 16px 64px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }} .sub {{ color:var(--muted); margin:0 0 20px; }}
  .card {{ border:1px solid var(--border); border-left-width:4px; border-radius:10px; background:var(--card); padding:16px 18px; margin-bottom:16px; }}
  .card h3 {{ margin:0 0 6px; font-size:16px; }}
  .tag {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:6px; margin-right:8px; }}
  .kv {{ color:var(--muted); font-size:13px; margin:4px 0; }} .kv b {{ color:var(--fg); }}
  pre {{ background:var(--code); padding:10px 12px; border-radius:6px; overflow-x:auto; white-space:pre-wrap; word-break:break-word; font-size:12.5px; }}
  code {{ background:var(--code); padding:1px 5px; border-radius:6px; }}
  .refs {{ color:var(--muted); font-size:12px; margin-top:6px; }}
  footer {{ color:var(--muted); font-size:12px; border-top:1px solid var(--border); padding-top:16px; margin-top:32px; }}
</style></head><body><div class="wrap">
  <h1>Aegis-AI Scan Report</h1>
  <p class="sub">{html.escape(result.target)} · <b>risk {result.risk_score()}/100 (grade {result.grade()})</b> · critical {c['critical']} · high {c['high']} · medium {c['medium']} · low {c['low']} · info {c['info']}</p>
  {body}
  <footer>Generated by Aegis-AI. Only test models/endpoints you are authorized to assess.</footer>
</div></body></html>"""


def _one_line(s: str, n: int) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n] + "…"
