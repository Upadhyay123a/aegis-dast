"""Probe interface and the Finding/result data model."""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field

from ..models import Target

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    """One issue discovered by a probe."""

    probe_id: str
    title: str
    severity: str  # info | low | medium | high | critical
    confidence: str  # tentative | firm | confirmed
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)
    prompt: str = ""
    response_snippet: str = ""

    def to_dict(self) -> dict:
        return {
            "probe_id": self.probe_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "remediation": self.remediation,
            "references": self.references,
            "prompt": self.prompt,
            "response_snippet": self.response_snippet,
        }


@dataclass
class ProbeContext:
    """Settings passed to each probe run."""

    timeout: float = 30.0
    attempts: int = 1  # how many randomized attempts per probe


class Probe:
    """Base class for an AI/LLM security probe."""

    id: str = "probe"
    title: str = "Probe"
    #: If True, the probe needs real system/user role separation to be meaningful.
    requires_roles: bool = False

    def run(self, target: Target, ctx: ProbeContext) -> list[Finding]:  # pragma: no cover - interface
        raise NotImplementedError

    # -- helpers shared by probes --

    @staticmethod
    def canary(prefix: str = "AEGIS") -> str:
        """A random, unguessable marker used to confirm a probe's effect."""
        return f"{prefix}_{secrets.token_hex(4).upper()}"

    @staticmethod
    def snippet(text: str, needle: str | None = None, radius: int = 120) -> str:
        text = text.replace("\n", " ")
        if needle and needle in text:
            i = text.index(needle)
            start = max(0, i - radius)
            end = min(len(text), i + len(needle) + radius)
            return ("…" if start else "") + text[start:end] + ("…" if end < len(text) else "")
        return text[: radius * 2] + ("…" if len(text) > radius * 2 else "")
