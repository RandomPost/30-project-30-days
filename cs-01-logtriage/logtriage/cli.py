"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .detector import detect
from .parser import parse_lines
from .report import to_json, to_table
from .sample import generate


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logtriage", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("analyze", help="analyze an auth log")
    a.add_argument("logfile", type=Path)
    a.add_argument("-n", "--threshold", type=int, default=5, help="flag if > N fails")
    a.add_argument("-w", "--window", type=int, default=60, help="window in seconds")
    a.add_argument("--year", type=int, default=datetime.now().year)
    a.add_argument("--json", type=Path, help="also write a JSON report here")

    g = sub.add_parser("generate", help="write a sample auth.log")
    g.add_argument("output", type=Path)
    g.add_argument("--seed", type=int, default=1)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "generate":
        args.output.write_text("\n".join(generate(args.seed)) + "\n")
        print(f"wrote {args.output}")
        return 0
    with args.logfile.open(errors="replace") as fh:
        findings = detect(parse_lines(fh, args.year), args.threshold, args.window)
    print(to_table(findings))
    if args.json:
        args.json.write_text(to_json(findings))
    return 1 if any(f.flagged for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
