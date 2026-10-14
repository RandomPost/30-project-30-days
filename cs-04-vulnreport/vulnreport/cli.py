"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import httpx

from .cache import Cache
from .models import SEVERITIES
from .osv import BASE, OsvClient, OsvError
from .parsers import parse_lockfile
from .report import to_json, to_markdown, to_text
from .scan import at_or_above, find_vulnerabilities, unique

LEVELS = [s.lower() for s in SEVERITIES[:-1]]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="vulnreport", description=__doc__)
    p.add_argument("lockfiles", nargs="+", type=Path)
    p.add_argument("--fail-on", choices=LEVELS, help="exit 1 if a finding is this bad")
    p.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    p.add_argument("--cache-dir", type=Path, default=Path(".vulnreport-cache"))
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("--cache-ttl-hours", type=float, default=24)
    return p


def run(args: argparse.Namespace, transport: httpx.BaseTransport | None = None) -> int:
    deps = []
    for path in args.lockfiles:
        deps += parse_lockfile(str(path), path.read_text())
    deps = unique(deps)
    cache = Cache(
        None if args.no_cache else args.cache_dir, args.cache_ttl_hours * 3600
    )
    http = httpx.Client(base_url=BASE, timeout=30, transport=transport)
    try:
        findings = find_vulnerabilities(deps, OsvClient(cache, http))
    except OsvError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    render = {
        "text": lambda: to_text(findings, len(deps)),
        "json": lambda: to_json(findings),
    }
    print(render.get(args.format, lambda: to_markdown(findings, len(deps)))())
    if args.fail_on and at_or_above(findings, args.fail_on):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    return run(build_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
