"""Glue: deps -> OSV -> sorted findings."""

from __future__ import annotations

from .models import SEVERITIES, Dep, Finding
from .osv import OsvClient
from .severity import to_finding


def unique(deps: list[Dep]) -> list[Dep]:
    return list({(d.ecosystem, d.name, d.version): d for d in deps}.values())


def find_vulnerabilities(deps: list[Dep], osv: OsvClient) -> list[Finding]:
    findings = []
    for dep, ids in osv.vuln_ids(unique(deps)).items():
        for vid in ids:
            findings.append(to_finding(osv.vuln(vid), dep))
    return sorted(
        findings,
        key=lambda f: (SEVERITIES.index(f.severity), f.dep.name, f.vuln_id),
    )


def at_or_above(findings: list[Finding], level: str) -> list[Finding]:
    """Findings at `level` or worse (CRITICAL is worst)."""
    cutoff = SEVERITIES.index(level.upper())
    return [f for f in findings if SEVERITIES.index(f.severity) <= cutoff]
