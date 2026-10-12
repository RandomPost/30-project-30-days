"""Group failures and flag brute-force sources with a sliding window."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Iterable

from .parser import Failure


@dataclass
class Finding:
    ip: str
    failures: int
    usernames: dict[str, int] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    max_in_window: int = 0
    flagged: bool = False


def max_in_window(times: list[datetime], window: timedelta) -> int:
    """Largest number of events in any span of length `window` (times sorted)."""
    best, start = 0, 0
    for end, t in enumerate(times):
        while t - times[start] > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def detect(
    failures: Iterable[Failure], threshold: int = 5, window_seconds: int = 60
) -> list[Finding]:
    """Return findings ranked by failure count; flagged when > threshold in window."""
    by_ip: dict[str, list[Failure]] = defaultdict(list)
    for f in failures:
        by_ip[f.ip].append(f)
    window = timedelta(seconds=window_seconds)
    findings = []
    for ip, items in by_ip.items():
        items.sort(key=lambda f: f.time)
        users: dict[str, int] = defaultdict(int)
        for f in items:
            users[f.user] += 1
        peak = max_in_window([f.time for f in items], window)
        findings.append(
            Finding(
                ip=ip,
                failures=len(items),
                usernames=dict(users),
                first_seen=items[0].time,
                last_seen=items[-1].time,
                max_in_window=peak,
                flagged=peak > threshold,
            )
        )
    findings.sort(key=lambda x: (not x.flagged, -x.failures, x.ip))
    return findings
