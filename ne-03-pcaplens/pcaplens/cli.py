"""pcaplens command line: analyze | make-samples."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from .analyze import analyze
from .detect import Thresholds, detect_all
from .models import SEVERITY_ORDER
from .reader import read_packets
from .report import render_html


def cmd_analyze(a: argparse.Namespace) -> int:
    packets = list(read_packets(a.capture))
    if not packets:
        raise ValueError(f"no analysable packets in {a.capture}")
    t = Thresholds(scan_targets=a.scan_targets, scan_window=a.scan_window)
    result = analyze(packets)
    findings = detect_all(packets, result, t)
    if a.out:
        Path(a.out).write_text(render_html(result, findings, a.capture, a.top))
    if a.json:
        Path(a.json).write_text(
            json.dumps(
                {
                    "findings": [asdict(f) for f in findings],
                    "packets": result.packets,
                    "bytes": result.bytes,
                },
                indent=2,
                default=str,
            )
        )
    print(
        f"{result.packets} packets, {len(result.hosts)} hosts, {len(findings)} findings"
    )
    for f in findings:
        print(f"  [{f.severity}] {f.kind}: {f.summary}")
    if a.out:
        print(f"report: {a.out}")
    if a.fail_on:
        limit = SEVERITY_ORDER[a.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= limit for f in findings):
            return 1
    return 0


def cmd_make_samples(a: argparse.Namespace) -> int:
    from .samples import make_samples

    for name, path in make_samples(a.dir).items():
        print(f"{name}: {path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pcaplens", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("analyze", help="analyse a pcap/pcapng and write an HTML report")
    s.add_argument("capture")
    s.add_argument("-o", "--out", default="report.html")
    s.add_argument("--json", help="also write findings as JSON")
    s.add_argument("--top", type=int, default=10, help="rows in top-N tables")
    s.add_argument(
        "--scan-targets",
        type=int,
        default=20,
        help="distinct host:port probes that make a scan",
    )
    s.add_argument("--scan-window", type=float, default=60.0, help="seconds")
    s.add_argument(
        "--fail-on",
        choices=["high", "medium", "low"],
        help="exit 1 if a finding is at least this severe",
    )
    s.set_defaults(fn=cmd_analyze)
    m = sub.add_parser(
        "make-samples", help="write crafted benign/scan/sweep/tunnel/mixed pcaps"
    )
    m.add_argument("dir")
    m.set_defaults(fn=cmd_make_samples)
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
