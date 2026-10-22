"""Pure statistics over probe samples."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Sample:
    ts: float
    ok: bool
    latency_ms: float | None


@dataclass(frozen=True)
class Summary:
    count: int
    ok_count: int
    loss_pct: float
    avg_ms: float | None
    min_ms: float | None
    max_ms: float | None
    p95_ms: float | None
    jitter_ms: float | None


def percentile(values: list[float], pct: float) -> float:
    """Linear-interpolated percentile (pct in 0..100) of a non-empty list."""
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * pct / 100
    lo = int(rank)
    hi = min(lo + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (rank - lo)


def jitter(latencies: list[float]) -> float | None:
    """Mean absolute difference between consecutive successful probes.

    This is the simple "mean delta" definition, not the smoothed RFC 3550 estimator.
    It needs at least two successes.
    """
    if len(latencies) < 2:
        return None
    deltas = [abs(b - a) for a, b in zip(latencies, latencies[1:])]
    return sum(deltas) / len(deltas)


def summarize(samples: list[Sample]) -> Summary:
    lat = [s.latency_ms for s in samples if s.ok and s.latency_ms is not None]
    n = len(samples)
    return Summary(
        count=n,
        ok_count=len(lat),
        loss_pct=100.0 * (n - len(lat)) / n if n else 0.0,
        avg_ms=sum(lat) / len(lat) if lat else None,
        min_ms=min(lat) if lat else None,
        max_ms=max(lat) if lat else None,
        p95_ms=percentile(lat, 95) if lat else None,
        jitter_ms=jitter(lat),
    )
