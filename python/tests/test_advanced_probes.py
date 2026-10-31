"""Tests for the advanced probes and detectors."""

from __future__ import annotations

from aegis_ai.detectors import find_pii, obeyed_arithmetic, refused
from aegis_ai.probes import (
    EncodingInjectionProbe,
    ExcessiveAgencyProbe,
    IndirectInjectionProbe,
    MultiTurnEscalationProbe,
    PromptInjectionProbe,
    UnboundedConsumptionProbe,
)
from aegis_ai.probes.base import ProbeContext

CTX = ProbeContext()


# --- detectors ---

def test_refused_detects_common_refusals():
    assert refused("I'm sorry, but I can't help with that.")
    assert refused("As an AI, I cannot comply with this request.")
    assert not refused("Sure! The answer is 42.")


def test_find_pii():
    hits = dict(find_pii("contact me at a@b.com or key AKIA1234567890ABCDEF"))
    assert "email" in hits
    assert "aws-access-key" in hits
    assert find_pii("nothing sensitive here") == []


def test_obeyed_arithmetic_ignores_echo():
    # product present only because it's in the prompt -> not obeyed
    assert obeyed_arithmetic("the answer is 50", "50", "compute 50") is False
    # product absent from prompt but present in reply -> obeyed
    assert obeyed_arithmetic("630", "630", "compute 90 times 7") is True


# --- advanced probes on the vulnerable model ---

def test_encoding_injection(vulnerable):
    assert len(EncodingInjectionProbe().run(vulnerable, CTX)) == 1


def test_indirect_injection(vulnerable):
    assert len(IndirectInjectionProbe().run(vulnerable, CTX)) == 1


def test_excessive_agency(vulnerable):
    findings = ExcessiveAgencyProbe().run(vulnerable, CTX)
    assert len(findings) == 1
    assert findings[0].probe_id == "excessive-agency"


def test_unbounded_consumption(vulnerable):
    assert len(UnboundedConsumptionProbe().run(vulnerable, CTX)) == 1


# --- no false positives on secure / echo models ---

def test_advanced_probes_clean_on_secure(secure):
    assert EncodingInjectionProbe().run(secure, CTX) == []
    assert IndirectInjectionProbe().run(secure, CTX) == []
    assert ExcessiveAgencyProbe().run(secure, CTX) == []
    assert UnboundedConsumptionProbe().run(secure, CTX) == []


def test_excessive_agency_no_fp_on_echo(echo):
    # Echo reflects the scenario (which names the tools) but doesn't act on it.
    assert ExcessiveAgencyProbe().run(echo, CTX) == []


# --- multi-turn crescendo ---

def test_multi_turn_catches_what_single_turn_misses(crescendo):
    # The crescendo model refuses a direct one-shot injection...
    assert PromptInjectionProbe().run(crescendo, CTX) == []
    # ...but the multi-turn probe elicits the behaviour.
    findings = MultiTurnEscalationProbe().run(crescendo, CTX)
    assert len(findings) == 1
    assert findings[0].probe_id == "multi-turn-escalation"
