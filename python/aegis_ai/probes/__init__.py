"""Built-in probe registry."""

from __future__ import annotations

from .base import Finding, Probe, ProbeContext
from .encoding_injection import EncodingInjectionProbe
from .excessive_agency import ExcessiveAgencyProbe
from .indirect_injection import IndirectInjectionProbe
from .insecure_output import InsecureOutputProbe
from .jailbreak import JailbreakProbe
from .multi_turn_escalation import MultiTurnEscalationProbe
from .prompt_injection import PromptInjectionProbe
from .sensitive_info import SensitiveInfoProbe
from .system_prompt_leak import SystemPromptLeakProbe
from .unbounded_consumption import UnboundedConsumptionProbe

ALL_PROBES: list[Probe] = [
    PromptInjectionProbe(),
    IndirectInjectionProbe(),
    EncodingInjectionProbe(),
    JailbreakProbe(),
    MultiTurnEscalationProbe(),
    SystemPromptLeakProbe(),
    SensitiveInfoProbe(),
    ExcessiveAgencyProbe(),
    InsecureOutputProbe(),
    UnboundedConsumptionProbe(),
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
    "IndirectInjectionProbe",
    "EncodingInjectionProbe",
    "JailbreakProbe",
    "MultiTurnEscalationProbe",
    "SystemPromptLeakProbe",
    "SensitiveInfoProbe",
    "ExcessiveAgencyProbe",
    "InsecureOutputProbe",
    "UnboundedConsumptionProbe",
]
