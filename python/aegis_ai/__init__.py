"""Aegis-AI — DAST-style security scanner for AI/LLM models and endpoints.

Quick start (programmatic):

    from aegis_ai import Scanner, ScanConfig, OpenAICompatTarget

    target = OpenAICompatTarget("gpt-4o-mini", api_key="sk-...")
    result = Scanner(ScanConfig()).scan(target)
    print(result.counts())

Test *any* Python model with a callable:

    from aegis_ai import Scanner, CallableTarget
    result = Scanner().scan(CallableTarget(my_model_fn, name="my-model"))
"""

from __future__ import annotations

from .models import CallableTarget, HTTPTarget, OpenAICompatTarget, Target, TargetError
from .probes import ALL_PROBES, Finding, Probe, ProbeContext
from .report import render_console, render_html, render_json, render_sarif
from .scanner import ScanConfig, Scanner, ScanResult, should_fail

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Target",
    "TargetError",
    "CallableTarget",
    "HTTPTarget",
    "OpenAICompatTarget",
    "Probe",
    "ProbeContext",
    "Finding",
    "ALL_PROBES",
    "Scanner",
    "ScanConfig",
    "ScanResult",
    "should_fail",
    "render_console",
    "render_json",
    "render_sarif",
    "render_html",
]
