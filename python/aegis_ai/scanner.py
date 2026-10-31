"""Scan orchestration — run probes against a target and collect findings."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Target
from .probes import Finding, ProbeContext, select_probes
from .probes.base import SEVERITY_ORDER


@dataclass
class ScanConfig:
    include: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=list)
    attempts: int = 1
    timeout: float = 30.0
    fail_on: str = "never"  # never|low|medium|high|critical


@dataclass
class ScanResult:
    target: str
    findings: list[Finding]
    probes_run: list[str]
    skipped_probes: list[str] = field(default_factory=list)

    def counts(self) -> dict:
        c = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            c[f.severity] = c.get(f.severity, 0) + 1
        return c

    def risk_score(self) -> int:
        """A 0-100 risk score: a single critical maxes it out; otherwise a
        saturating weighted sum of findings. Useful for dashboards and gates."""
        weights = {"info": 0, "low": 3, "medium": 8, "high": 20, "critical": 45}
        total = sum(weights.get(f.severity, 0) for f in self.findings)
        if any(f.severity == "critical" for f in self.findings):
            total = max(total, 90)
        return min(100, total)

    def grade(self) -> str:
        s = self.risk_score()
        return "A" if s == 0 else "B" if s < 10 else "C" if s < 25 else "D" if s < 50 else "F"

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "risk_score": self.risk_score(),
            "grade": self.grade(),
            "probes_run": self.probes_run,
            "skipped_probes": self.skipped_probes,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
        }


class Scanner:
    def __init__(self, config: ScanConfig | None = None, on_event=None):
        self.config = config or ScanConfig()
        # on_event(kind, message) is an optional progress callback.
        self._on_event = on_event or (lambda kind, msg: None)

    def scan(self, target: Target) -> ScanResult:
        probes = select_probes(self.config.include, self.config.exclude)
        ctx = ProbeContext(timeout=self.config.timeout, attempts=self.config.attempts)

        findings: list[Finding] = []
        run: list[str] = []
        skipped: list[str] = []

        for probe in probes:
            if probe.requires_roles and not target.supports_roles:
                skipped.append(probe.id)
                self._on_event("skip", f"{probe.id} (target has no system/user role separation)")
                continue
            self._on_event("probe", probe.id)
            try:
                probe_findings = probe.run(target, ctx)
            except Exception as exc:  # noqa: BLE001 - a bad probe must not abort the scan
                self._on_event("error", f"{probe.id}: {exc}")
                probe_findings = []
            run.append(probe.id)
            findings.extend(probe_findings)

        findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 0), reverse=True)
        return ScanResult(target=target.name, findings=findings, probes_run=run, skipped_probes=skipped)


def should_fail(result: ScanResult, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    threshold = SEVERITY_ORDER.get(fail_on, 99)
    return any(SEVERITY_ORDER.get(f.severity, 0) >= threshold for f in result.findings)
