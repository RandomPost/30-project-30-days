"""Target parsing and the asyncio probe loop."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Awaitable, Callable

from .alerts import AlertTracker, Thresholds
from .probes import Result, icmp_probe, tcp_probe
from .stats import Sample, summarize
from .store import Store


@dataclass(frozen=True)
class Target:
    kind: str  # "ping" | "tcp"
    host: str
    port: int | None = None

    @property
    def label(self) -> str:
        return (
            f"ping:{self.host}"
            if self.kind == "ping"
            else f"tcp:{self.host}:{self.port}"
        )


def parse_target(spec: str) -> Target:
    """`ping:HOST`, `tcp:HOST:PORT`, `HOST:PORT` (tcp) or bare `HOST` (ping)."""
    spec = spec.strip()
    if not spec:
        raise ValueError("empty target")
    if spec.startswith("ping:"):
        host = spec[5:]
        if not host:
            raise ValueError(f"missing host in {spec!r}")
        return Target("ping", host)
    if spec.startswith("tcp:"):
        spec = spec[4:]
    elif ":" not in spec:
        return Target("ping", spec)
    host, _, port_text = spec.rpartition(":")
    if not host or not port_text.isdigit() or not 0 < int(port_text) < 65536:
        raise ValueError(f"bad target {spec!r}: expected HOST:PORT with PORT 1-65535")
    return Target("tcp", host, int(port_text))


ProbeFn = Callable[[Target, float], Awaitable[Result]]


async def default_probe(target: Target, timeout: float) -> Result:
    if target.kind == "ping":
        return await icmp_probe(target.host, timeout)
    assert target.port is not None
    return await tcp_probe(target.host, target.port, timeout)


async def _target_loop(
    target: Target,
    store: Store,
    interval: float,
    timeout: float,
    thresholds: Thresholds,
    probe: ProbeFn,
    stop: asyncio.Event,
    out: Callable[[str], None],
    verbose: bool,
    offset: float,
) -> None:
    tracker = AlertTracker(thresholds)
    label = target.label
    loop = asyncio.get_running_loop()
    next_at = loop.time() + offset
    while not stop.is_set():
        delay = next_at - loop.time()
        if delay > 0:
            try:
                await asyncio.wait_for(stop.wait(), delay)
                return
            except asyncio.TimeoutError:
                pass
        try:
            # The probe has its own timeout; this outer one is a safety net.
            result = await asyncio.wait_for(probe(target, timeout), timeout + 2)
        except asyncio.TimeoutError:
            result = Result(False, None, "timeout")
        except Exception as exc:  # a broken probe must never kill the monitor
            result = Result(False, None, f"probe-error:{exc.__class__.__name__}")
        ts = time.time()
        store.add(label, result.ok, result.latency_ms, result.error, ts)
        stamp = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
        if verbose:
            shown = (
                f"{result.latency_ms:.1f} ms" if result.ok else f"LOST ({result.error})"
            )
            out(f"{stamp} {label} {shown}")
        for event in tracker.add(Sample(ts, result.ok, result.latency_ms)):
            out(f"{stamp} {label} {event}")
        next_at += interval
        while next_at <= loop.time():  # overran: drop missed slots, keep the phase
            next_at += interval


async def run_monitor(
    targets: list[Target],
    store: Store,
    interval: float = 5.0,
    timeout: float = 2.0,
    thresholds: Thresholds | None = None,
    duration: float | None = None,
    summary_every: float = 60.0,
    probe: ProbeFn = default_probe,
    out: Callable[[str], None] = print,
    verbose: bool = False,
    stop: asyncio.Event | None = None,
) -> None:
    """Probe every target each `interval` seconds until `duration` elapses or `stop`."""
    thresholds = thresholds or Thresholds()
    stop = stop or asyncio.Event()
    n = len(targets)
    tasks = [
        asyncio.create_task(
            _target_loop(
                t,
                store,
                interval,
                timeout,
                thresholds,
                probe,
                stop,
                out,
                verbose,
                offset=i * interval / n,  # spread probes so they do not burst together
            )
        )
        for i, t in enumerate(targets)
    ]
    started = time.time()

    async def summaries() -> None:
        while not stop.is_set():
            try:
                await asyncio.wait_for(stop.wait(), summary_every)
                return
            except asyncio.TimeoutError:
                pass
            since = time.time() - summary_every
            for t in targets:
                out(format_summary(t.label, summarize(store.samples(t.label, since))))

    tasks.append(asyncio.create_task(summaries()))
    try:
        if duration is not None:
            try:
                await asyncio.wait_for(stop.wait(), duration)
            except asyncio.TimeoutError:
                pass
        else:
            await stop.wait()
    finally:
        stop.set()
        for task in tasks:  # do not wait on probes still in flight
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    out(f"stopped after {time.time() - started:.0f}s")


def format_summary(label: str, s) -> str:
    if s.count == 0:
        return f"{label}: no samples"
    if s.avg_ms is None:
        return f"{label}: {s.count} probes, loss {s.loss_pct:.0f}% (no replies)"
    jit = f"{s.jitter_ms:.1f}" if s.jitter_ms is not None else "n/a"
    return (
        f"{label}: {s.count} probes, loss {s.loss_pct:.0f}%, avg {s.avg_ms:.1f} ms, "
        f"p95 {s.p95_ms:.1f} ms, jitter {jit} ms"
    )
