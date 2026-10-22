"""Edge-triggered threshold alerts over a rolling window of samples."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .stats import Sample, summarize


@dataclass(frozen=True)
class Thresholds:
    max_latency_ms: float = 200.0
    max_jitter_ms: float = 50.0
    max_loss_pct: float = 20.0
    window: int = 10  # probes per rolling window


@dataclass(frozen=True)
class AlertEvent:
    state: str  # "ALERT" or "RECOVERED"
    metric: str  # "loss" | "latency" | "jitter"
    value: float
    limit: float

    def __str__(self) -> str:
        unit = "%" if self.metric == "loss" else " ms"
        return (
            f"{self.state} {self.metric} {self.value:.1f}{unit} "
            f"(limit {self.limit:g}{unit})"
        )


class AlertTracker:
    """One per target. Emits an event when a metric crosses its limit, and again
    when it comes back, never repeating while the state is unchanged."""

    def __init__(self, thresholds: Thresholds):
        self.t = thresholds
        self.window: deque[Sample] = deque(maxlen=thresholds.window)
        self.firing: set[str] = set()

    def add(self, sample: Sample) -> list[AlertEvent]:
        self.window.append(sample)
        # Judge nothing until there is a meaningful amount of evidence.
        if len(self.window) < min(self.t.window, 5):
            return []
        s = summarize(list(self.window))
        readings = {
            "loss": (s.loss_pct, self.t.max_loss_pct),
            "latency": (s.avg_ms, self.t.max_latency_ms),
            "jitter": (s.jitter_ms, self.t.max_jitter_ms),
        }
        events = []
        for metric, (value, limit) in readings.items():
            if value is None:  # no successes in the window: loss already covers it
                continue
            over = value > limit
            if over and metric not in self.firing:
                self.firing.add(metric)
                events.append(AlertEvent("ALERT", metric, value, limit))
            elif not over and metric in self.firing:
                self.firing.discard(metric)
                events.append(AlertEvent("RECOVERED", metric, value, limit))
        return events
