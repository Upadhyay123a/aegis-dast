"""Built-in probe registry."""

from __future__ import annotations

from .base import Finding, Probe, ProbeContext
from .insecure_output import InsecureOutputProbe
from .jailbreak import JailbreakProbe
from .prompt_injection import PromptInjectionProbe
from .sensitive_info import SensitiveInfoProbe
from .system_prompt_leak import SystemPromptLeakProbe

ALL_PROBES: list[Probe] = [
    PromptInjectionProbe(),
    JailbreakProbe(),
    SystemPromptLeakProbe(),
    SensitiveInfoProbe(),
    InsecureOutputProbe(),
]


def probes_by_id() -> dict[str, Probe]:
    return {p.id: p for p in ALL_PROBES}


def select_probes(include: list[str], exclude: list[str]) -> list[Probe]:
    probes = ALL_PROBES
    if include:
        probes = [p for p in probes if p.id in include]
    if exclude:
        probes = [p for p in probes if p.id not in exclude]
    return probes


__all__ = [
    "Finding",
    "Probe",
    "ProbeContext",
    "ALL_PROBES",
    "probes_by_id",
    "select_probes",
    "PromptInjectionProbe",
    "JailbreakProbe",
    "SystemPromptLeakProbe",
    "SensitiveInfoProbe",
    "InsecureOutputProbe",
]
