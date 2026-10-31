"""Per-probe behaviour: true positives on the vulnerable model, no false
positives on the secure or echo models."""

from __future__ import annotations

from aegis_ai.probes import (
    InsecureOutputProbe,
    JailbreakProbe,
    PromptInjectionProbe,
    SensitiveInfoProbe,
    SystemPromptLeakProbe,
)
from aegis_ai.probes.base import ProbeContext

CTX = ProbeContext()


def test_prompt_injection_detected(vulnerable):
    findings = PromptInjectionProbe().run(vulnerable, CTX)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_prompt_injection_no_false_positive_on_secure(secure):
    assert PromptInjectionProbe().run(secure, CTX) == []


def test_prompt_injection_no_false_positive_on_echo(echo):
    # Echo reflects the prompt (which names the factors) but not the product.
    assert PromptInjectionProbe().run(echo, CTX) == []


def test_jailbreak_detected(vulnerable):
    findings = JailbreakProbe().run(vulnerable, CTX)
    assert len(findings) == 1
    assert "bypassed" in findings[0].title.lower()


def test_jailbreak_resisted_by_secure(secure):
    assert JailbreakProbe().run(secure, CTX) == []


def test_jailbreak_no_false_positive_on_echo(echo):
    assert JailbreakProbe().run(echo, CTX) == []


def test_system_prompt_leak_detected(vulnerable):
    findings = SystemPromptLeakProbe().run(vulnerable, CTX)
    assert len(findings) == 1
    assert findings[0].probe_id == "system-prompt-leak"


def test_system_prompt_leak_skipped_without_roles(echo):
    # Echo target has no role separation, so the probe cannot run meaningfully.
    assert SystemPromptLeakProbe().run(echo, CTX) == []


def test_sensitive_info_detected(vulnerable):
    findings = SensitiveInfoProbe().run(vulnerable, CTX)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_sensitive_info_resisted_by_secure(secure):
    assert SensitiveInfoProbe().run(secure, CTX) == []


def test_insecure_output_detected(vulnerable):
    findings = InsecureOutputProbe().run(vulnerable, CTX)
    assert len(findings) >= 1
    assert any("script" in f.title.lower() or "SQL" in f.title for f in findings)


def test_insecure_output_safe_on_secure(secure):
    assert InsecureOutputProbe().run(secure, CTX) == []
