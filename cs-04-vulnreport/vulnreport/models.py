"""Shared data types."""

from __future__ import annotations

from dataclasses import dataclass

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")  # worst first


@dataclass(frozen=True)
class Dep:
    name: str
    version: str
    ecosystem: str  # OSV ecosystem name: "PyPI" or "npm"
    source: str = ""  # lockfile it came from


@dataclass(frozen=True)
class Finding:
    dep: Dep
    vuln_id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str
    score: float | None
    fixed: tuple[str, ...]  # fixed versions for this package, may be empty
