"""Catalog + behaviour tests for the advanced probe families."""

from __future__ import annotations

from aegis_ai.probes import ALL_PROBES, probes_by_id
from aegis_ai.scanner import ScanConfig, Scanner

NEW_PROBES = [
    "special-token-injection",
    "unicode-obfuscation",
    "payload-splitting",
    "many-shot-jailbreak",
    "refusal-suppression",
    "multilingual-bypass",
    "adversarial-suffix",
    "context-overflow",
    "virtualization-jailbreak",
    "goal-hijacking",
    "prefill-extraction",
    "translation-leak",
    "markdown-data-exfil",
]


def test_catalog_is_large_and_unique():
    assert len(ALL_PROBES) >= 23
    ids = [p.id for p in ALL_PROBES]
    assert len(set(ids)) == len(ids)


def test_all_new_probes_registered():
    ids = probes_by_id()
    for pid in NEW_PROBES:
        assert pid in ids, f"missing probe: {pid}"


def test_vulnerable_model_triggers_new_probes(vulnerable):
    result = Scanner(ScanConfig()).scan(vulnerable)
    found = {f.probe_id for f in result.findings}
    missing = [p for p in NEW_PROBES if p not in found]
    assert not missing, f"probes that did not fire on the vulnerable model: {missing}"


def test_secure_model_resists_new_probes(secure):
    result = Scanner(ScanConfig()).scan(secure)
    assert result.findings == []


def test_echo_model_no_false_positives(echo):
    # Echo reflects input, so the (legitimate) insecure-output probe may fire, but
    # none of the canary-based injection/jailbreak or role-based probes should.
    result = Scanner(ScanConfig()).scan(echo)
    fired = {f.probe_id for f in result.findings}
    assert not (set(NEW_PROBES) & fired), f"false positives on echo: {set(NEW_PROBES) & fired}"
