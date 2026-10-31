"""End-to-end scanner and reporter tests."""

from __future__ import annotations

import json

from aegis_ai import (
    CallableTarget,
    ScanConfig,
    Scanner,
    render_html,
    render_json,
    render_sarif,
    should_fail,
)


def test_scan_vulnerable_finds_all_classes(vulnerable):
    result = Scanner(ScanConfig()).scan(vulnerable)
    found = {f.probe_id for f in result.findings}
    expected = {
        "prompt-injection",
        "indirect-injection",
        "encoding-injection",
        "jailbreak",
        "multi-turn-escalation",
        "system-prompt-leak",
        "sensitive-info-disclosure",
        "excessive-agency",
        "insecure-output-handling",
        "unbounded-consumption",
    }
    assert expected.issubset(found), f"missing: {expected - found}"


def test_vulnerable_risk_score_is_high(vulnerable):
    result = Scanner(ScanConfig()).scan(vulnerable)
    assert result.risk_score() == 100  # multiple high/critical findings
    assert result.grade() == "F"


def test_secure_risk_score_is_zero(secure):
    result = Scanner(ScanConfig()).scan(secure)
    assert result.risk_score() == 0
    assert result.grade() == "A"


def test_scan_secure_is_clean(secure):
    result = Scanner(ScanConfig()).scan(secure)
    assert result.findings == []


def test_role_probes_skipped_without_roles(echo):
    result = Scanner(ScanConfig()).scan(echo)
    assert "system-prompt-leak" in result.skipped_probes
    assert "sensitive-info-disclosure" in result.skipped_probes


def test_include_exclude(vulnerable):
    result = Scanner(ScanConfig(include=["prompt-injection"])).scan(vulnerable)
    assert set(result.probes_run) == {"prompt-injection"}

    result2 = Scanner(ScanConfig(exclude=["prompt-injection"])).scan(vulnerable)
    assert "prompt-injection" not in result2.probes_run


def test_callable_target_works():
    # A tiny "model" that obeys injected math == vulnerable to prompt injection.
    import re

    def model(text: str) -> str:
        m = re.search(r"(\d+)\s*multiplied by\s*(\d+)", text, re.I)
        return str(int(m.group(1)) * int(m.group(2))) if m else "hi"

    result = Scanner(ScanConfig(include=["prompt-injection"])).scan(CallableTarget(model, name="fn"))
    assert any(f.probe_id == "prompt-injection" for f in result.findings)


def test_should_fail_threshold(vulnerable):
    result = Scanner(ScanConfig()).scan(vulnerable)
    assert should_fail(result, "high") is True
    assert should_fail(result, "never") is False


def test_reporters_render(vulnerable):
    result = Scanner(ScanConfig()).scan(vulnerable)

    doc = json.loads(render_json(result))
    assert doc["target"] == "vulnerable-model"
    assert len(doc["findings"]) >= 5

    sarif = json.loads(render_sarif(result))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Aegis-AI"
    assert len(sarif["runs"][0]["results"]) >= 5

    html = render_html(result)
    assert "<html" in html.lower()
    assert "Aegis-AI Scan Report" in html
