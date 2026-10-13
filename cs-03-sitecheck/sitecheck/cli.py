"""Command line entry point."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .checker import check_all
from .report import to_csv, to_markdown, to_table


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sitecheck", description=__doc__)
    p.add_argument("domains", nargs="*", help="domains to audit (sites you own!)")
    p.add_argument("-f", "--file", type=Path, help="file with one domain per line")
    p.add_argument("--timeout", type=float, default=10.0, help="seconds per request")
    p.add_argument("--concurrency", type=int, default=10)
    p.add_argument("--md", type=Path, help="write a Markdown report here")
    p.add_argument("--csv", type=Path, help="write a CSV report here")
    p.add_argument("--fail-below", default="", help="exit 1 if any grade is below")
    return p


def read_domains(args: argparse.Namespace) -> list[str]:
    domains = list(args.domains)
    if args.file:
        for line in args.file.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                domains.append(line)
    return domains


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    domains = read_domains(args)
    if not domains:
        print("no domains given", file=sys.stderr)
        return 2
    results = asyncio.run(
        check_all(domains, timeout=args.timeout, concurrency=args.concurrency)
    )
    print(to_table(results))
    if args.md:
        args.md.write_text(to_markdown(results))
    if args.csv:
        args.csv.write_text(to_csv(results))
    if args.fail_below:
        return 1 if any(r.grade > args.fail_below.upper() for r in results) else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
