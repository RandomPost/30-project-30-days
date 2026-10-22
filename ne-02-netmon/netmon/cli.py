"""netmon command line: run | report | chart."""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
import time
from pathlib import Path

from .alerts import Thresholds
from .chart import render_chart
from .monitor import format_summary, parse_target, run_monitor
from .probes import icmp_available
from .stats import summarize
from .store import Store


def _targets(args: argparse.Namespace) -> list:
    specs = list(args.targets)
    if args.file:
        for line in Path(args.file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                specs.append(line)
    if not specs:
        raise ValueError("give at least one target (see --help)")
    return [parse_target(s) for s in specs]


def cmd_run(a: argparse.Namespace) -> int:
    targets = _targets(a)
    if any(t.kind == "ping" for t in targets):
        problem = icmp_available()
        if problem:
            raise ValueError(problem)
    if a.timeout > a.interval:
        raise ValueError("--timeout must not exceed --interval")
    thresholds = Thresholds(a.max_latency, a.max_jitter, a.max_loss, a.window)
    store = Store(a.db)

    async def main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        print(f"monitoring {len(targets)} targets every {a.interval:g}s -> {a.db}")
        await run_monitor(
            targets,
            store,
            a.interval,
            a.timeout,
            thresholds,
            a.duration,
            a.summary_every,
            verbose=a.verbose,
            stop=stop,
        )

    try:
        asyncio.run(main())
    finally:
        store.close()
    return 0


def cmd_report(a: argparse.Namespace) -> int:
    store = Store(a.db)
    since = time.time() - a.hours * 3600
    labels = store.targets()
    if not labels:
        print("no data in database")
        return 1
    for label in labels:
        s = summarize(store.samples(label, since))
        print(format_summary(label, s))
        errors = store.errors(label, since)
        if errors:
            print(
                "    failures: "
                + ", ".join(f"{k} x{v}" for k, v in sorted(errors.items()))
            )
    store.close()
    return 0


def cmd_chart(a: argparse.Namespace) -> int:
    store = Store(a.db)
    since = time.time() - a.hours * 3600
    labels = store.targets()
    if a.target:
        labels = [t for t in labels if t in a.target]
    data = {label: store.samples(label, since) for label in labels}
    store.close()
    if not data:
        print("error: no matching targets in database", file=sys.stderr)
        return 2
    render_chart(data, a.out, a.hours)
    print(f"wrote {a.out} ({len(data)} targets, last {a.hours:g} h)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netmon", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="probe targets until stopped (Ctrl-C) or --duration")
    r.add_argument(
        "targets", nargs="*", help="ping:HOST, tcp:HOST:PORT, HOST:PORT or HOST"
    )
    r.add_argument("-f", "--file", help="file with one target per line, # comments")
    r.add_argument("--db", default="netmon.db")
    r.add_argument(
        "-i", "--interval", type=float, default=5.0, help="seconds between probes"
    )
    r.add_argument("-t", "--timeout", type=float, default=2.0)
    r.add_argument("--duration", type=float, help="stop after this many seconds")
    r.add_argument("--window", type=int, default=10, help="probes per alert window")
    r.add_argument(
        "--max-latency", type=float, default=200.0, help="ms, window average"
    )
    r.add_argument(
        "--max-jitter", type=float, default=50.0, help="ms, window mean delta"
    )
    r.add_argument("--max-loss", type=float, default=20.0, help="percent in window")
    r.add_argument("--summary-every", type=float, default=60.0, help="seconds")
    r.add_argument("-v", "--verbose", action="store_true", help="print every probe")
    r.set_defaults(fn=cmd_run)

    s = sub.add_parser("report", help="print loss/latency/jitter per target")
    s.add_argument("--db", default="netmon.db")
    s.add_argument("--hours", type=float, default=24.0)
    s.set_defaults(fn=cmd_report)

    c = sub.add_parser("chart", help="write a PNG chart per target")
    c.add_argument("--db", default="netmon.db")
    c.add_argument("--hours", type=float, default=24.0)
    c.add_argument("-o", "--out", default="netmon.png")
    c.add_argument("--target", action="append", help="limit to this label (repeatable)")
    c.set_defaults(fn=cmd_chart)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
