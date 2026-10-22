"""PNG chart: one panel per target with latency (median and p95 band) and loss."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass

import matplotlib

matplotlib.use("Agg")  # no display needed
import matplotlib.dates as mdates  # noqa: E402
import matplotlib.pyplot as plt  # noqa: E402
from datetime import datetime  # noqa: E402

from .stats import Sample, percentile, summarize  # noqa: E402


@dataclass(frozen=True)
class Bucket:
    start: float
    count: int
    loss_pct: float
    median_ms: float | None
    p95_ms: float | None


def bucketize(samples: list[Sample], width: float) -> list[Bucket]:
    """Group samples into fixed-width time buckets (width in seconds)."""
    groups: dict[int, list[Sample]] = {}
    for s in samples:
        groups.setdefault(int(s.ts // width), []).append(s)
    out = []
    for key in sorted(groups):
        group = groups[key]
        lat = [s.latency_ms for s in group if s.ok and s.latency_ms is not None]
        out.append(
            Bucket(
                start=key * width,
                count=len(group),
                loss_pct=100.0 * (len(group) - len(lat)) / len(group),
                median_ms=percentile(lat, 50) if lat else None,
                p95_ms=percentile(lat, 95) if lat else None,
            )
        )
    return out


def bucket_width(
    span_seconds: float, interval_hint: float, max_buckets: int = 300
) -> float:
    """Wide enough for about 5 probes per bucket (so one-probe-too-many aliasing does
    not draw stripes) and for no more than `max_buckets` buckets across the window."""
    return max(5 * interval_hint, span_seconds / max_buckets, 1.0)


def render_chart(
    data: dict[str, list[Sample]],
    out_path: str,
    hours: float = 24.0,
    now: float | None = None,
) -> None:
    """Write the chart for `data` (target -> samples) covering the last `hours`."""
    if not data:
        raise ValueError("no targets to chart")
    now = time.time() if now is None else now
    since = now - hours * 3600
    fig, axes = plt.subplots(
        len(data), 1, figsize=(10, 2.8 * len(data)), squeeze=False, sharex=True
    )
    for ax, (label, samples) in zip(axes[:, 0], sorted(data.items())):
        samples = [s for s in samples if since <= s.ts <= now]
        summary = summarize(samples)
        if samples:
            gaps = [b.ts - a.ts for a, b in zip(samples, samples[1:])]
            interval = percentile(gaps, 50) if gaps else 1.0
        else:
            interval = 1.0
        width = bucket_width(hours * 3600, interval)
        buckets = bucketize(samples, width)
        loss_ax = ax.twinx()
        loss_ax.set_ylim(0, 100)
        loss_ax.set_ylabel("loss %", color="#c0392b")
        loss_ax.tick_params(axis="y", colors="#c0392b")
        if buckets:
            xs = [datetime.fromtimestamp(b.start + width / 2) for b in buckets]
            loss_ax.bar(
                xs,
                [b.loss_pct for b in buckets],
                width=width / 86400 * 0.9,
                color="#c0392b",
                alpha=0.35,
            )
            lx, med, p95 = [], [], []
            prev = None
            for x, b in zip(xs, buckets):
                if prev is not None and b.start - prev > 1.5 * width:
                    lx.append(x)  # no samples at all for a stretch: break the line
                    med.append(math.nan)
                    p95.append(math.nan)
                prev = b.start
                lx.append(x)
                med.append(math.nan if b.median_ms is None else b.median_ms)
                p95.append(math.nan if b.p95_ms is None else b.p95_ms)
            if any(not math.isnan(v) for v in med):
                ax.fill_between(
                    lx, med, p95, color="#2e6fba", alpha=0.2, label="median to p95"
                )
                ax.plot(
                    lx,
                    med,
                    color="#2e6fba",
                    linewidth=1.4,
                    marker="o",
                    markersize=2.5,
                    label="median latency",
                )
            else:
                ax.text(
                    0.5,
                    0.5,
                    "no replies",
                    ha="center",
                    va="center",
                    transform=ax.transAxes,
                    color="#c0392b",
                )
        else:
            ax.text(
                0.5,
                0.5,
                "no data in this window",
                ha="center",
                va="center",
                transform=ax.transAxes,
            )
        ax.set_ylim(bottom=0)
        ax.set_ylabel("latency (ms)")
        ax.set_zorder(loss_ax.get_zorder() + 1)  # draw latency above the loss bars
        ax.patch.set_visible(False)
        stats = f"{summary.count} probes, loss {summary.loss_pct:.1f}%" + (
            f", avg {summary.avg_ms:.1f} ms, jitter {summary.jitter_ms:.1f} ms"
            if summary.avg_ms is not None and summary.jitter_ms is not None
            else (
                f", avg {summary.avg_ms:.1f} ms" if summary.avg_ms is not None else ""
            )
        )
        ax.set_title(f"{label}   ({stats})", loc="left", fontsize=10)
        ax.grid(alpha=0.25)
        if ax.get_legend_handles_labels()[0]:
            ax.legend(loc="upper right", fontsize=8, frameon=False)
    start = datetime.fromtimestamp(since)
    end = datetime.fromtimestamp(now)
    axes[0, 0].set_xlim(start, end)
    axes[-1, 0].xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
    axes[-1, 0].set_xlabel(f"local time, last {hours:g} h")
    fig.tight_layout()
    fig.savefig(out_path, dpi=110)
    plt.close(fig)
