"""Shared data types."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Issue:
    check: str  # e.g. "HSTS"
    penalty: int  # points lost out of 100
    reason: str
    fix: str
    fatal: bool = False  # caps the grade at F regardless of points


@dataclass(frozen=True)
class TlsInfo:
    version: str  # e.g. "TLSv1.3"
    days_left: int  # days until the certificate expires (negative if expired)


@dataclass
class SiteResult:
    domain: str
    issues: list[Issue] = field(default_factory=list)
    tls: TlsInfo | None = None
    error: str | None = None
    score: int = 0
    grade: str = "F"
