"""purplelab command line: emulate | coverage | diff | techniques."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def cmd_coverage(a: argparse.Namespace) -> int:
    from . import coverage

    tag_map = coverage.load_rule_tags(a.rules)
    matrix = coverage.build_matrix(
        coverage.load_emulation(a.emulation),
        coverage.load_alerts(a.db),
        tag_map,
        lambda start, end: coverage.count_events(a.db, start, end),
        slack=a.slack,
        run_id=a.run_id,
    )
    report = coverage.render_markdown(matrix)
    if a.md:
        Path(a.md).write_text(report)
    if a.json:
        Path(a.json).write_text(json.dumps(coverage.render_json(matrix), indent=2))
    if not a.md:
        print(report)
    missed = sum(1 for r in matrix.rows if r.status == coverage.MISSED)
    return 1 if (a.fail_on_missed and missed) else 0


def cmd_diff(a: argparse.Namespace) -> int:
    from . import coverage

    before = json.loads(Path(a.before).read_text())
    after = json.loads(Path(a.after).read_text())
    text = coverage.render_diff_markdown(before, after)
    if a.md:
        Path(a.md).write_text(text)
    else:
        print(text)
    return 0


def cmd_techniques(_a: argparse.Namespace) -> int:
    from .techniques import REGISTRY

    for t in REGISTRY.values():
        print(f"{t.id:<10} {t.channel:<4} {t.tactic:<22} {t.name}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="purplelab", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("emulate", help="run the benign adversary emulation (see --help)")

    c = sub.add_parser("coverage", help="ATT&CK coverage matrix from SIEM alerts")
    c.add_argument("--db", required=True, help="minisiem SQLite database")
    c.add_argument("--emulation", required=True, help="emulation.jsonl")
    c.add_argument("--rules", required=True, help="minisiem rules directory")
    c.add_argument("--md", help="write the Markdown report here")
    c.add_argument("--json", help="write the JSON report here")
    c.add_argument("--slack", type=float, default=3.0, help="window slack, seconds")
    c.add_argument("--run-id", help="report this run (default: latest)")
    c.add_argument("--fail-on-missed", action="store_true")
    c.set_defaults(fn=cmd_coverage)

    d = sub.add_parser("diff", help="compare two JSON coverage reports")
    d.add_argument("before")
    d.add_argument("after")
    d.add_argument("--md")
    d.set_defaults(fn=cmd_diff)

    t = sub.add_parser("techniques", help="list the emulated techniques")
    t.set_defaults(fn=cmd_techniques)
    return p


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "emulate":
        from . import emulate

        return emulate.main(argv[1:])
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
