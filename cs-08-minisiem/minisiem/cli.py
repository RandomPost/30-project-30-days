"""Command line interface: generate, ingest, detect, schedule, serve, hunt, ..."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .db import SEVERITIES, connect, schema_text
from .engine import run_rules
from .hunt import DEFAULT_LIMIT, HuntError, format_table, run_query
from .ingest import current_year, guess_source, ingest_file
from .rules import RuleError, load_rules
from .ruletest import coverage_problems, run_rule_tests
from .sample import generate
from .scheduler import run_schedule
from .web import make_server

DEFAULT_RULES = str(Path(__file__).resolve().parent.parent / "rules")


def _load(rules_dir: str):
    try:
        return load_rules(rules_dir)
    except RuleError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


def cmd_generate(a) -> int:
    for p in generate(a.out_dir, a.seed, not a.benign_only):
        print(p)
    return 0


def cmd_ingest(a) -> int:
    conn = connect(a.db)
    year = a.year or current_year()
    status = 0
    for path in a.paths:
        source = a.type or guess_source(path)
        if source is None:
            print(f"{path}: cannot guess the log type, pass --type", file=sys.stderr)
            status = 2
            continue
        res = ingest_file(conn, path, source, year)
        print(f"{path}: {res.parsed} events ({source}), {res.skipped} unparsable")
    return status


def cmd_detect(a) -> int:
    rules = _load(a.rules)
    conn = connect(a.db)
    new = run_rules(conn, rules)
    total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    print(f"{len(rules)} rules run, {sum(new.values())} new alerts ({total} total)")
    for rid, n in new.items():
        if n:
            print(f"  {rid}: {n}")
    return 0


def cmd_alerts(a) -> int:
    conn = connect(a.db)
    sql = "SELECT severity, rule_id, group_key, first_ts, event_count FROM alerts"
    params: list = []
    if a.severity:
        sql += " WHERE severity = ?"
        params.append(a.severity)
    sql += " ORDER BY first_ts, id"
    rows = [tuple(r) for r in conn.execute(sql, params)]
    print(format_table(["severity", "rule", "group", "first_ts", "events"], rows))
    return 0


def cmd_schedule(a) -> int:
    try:
        run_schedule(
            a.db, a.rules, a.logs, a.year or current_year(), a.interval, a.iterations
        )
    except KeyboardInterrupt:
        pass
    return 0


def cmd_serve(a) -> int:
    server = make_server(a.db, a.port)
    print(f"dashboard on http://127.0.0.1:{server.server_port} (Ctrl-C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def cmd_schema(_a) -> int:
    print(schema_text())
    return 0


def cmd_hunt(a) -> int:
    sql = Path(a.file).read_text(encoding="utf-8") if a.file else a.sql
    if not sql or not sql.strip():
        print("error: give --sql or --file", file=sys.stderr)
        return 2
    try:
        cols, rows, truncated = run_query(a.db, sql, a.limit)
    except HuntError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps([dict(zip(cols, r)) for r in rows], indent=2))
    else:
        print(format_table(cols, rows))
        print(
            f"\n{len(rows)} row(s)"
            + (f" (truncated at {a.limit})" if truncated else "")
        )
    return 0


def cmd_validate(a) -> int:
    rules = _load(a.rules)
    print(f"{len(rules)} rules valid")
    problems = coverage_problems(rules)
    for p in problems:
        print(f"  {p}", file=sys.stderr)
    return 1 if problems else 0


def cmd_test_rules(a) -> int:
    rules = _load(a.rules)
    outcomes = run_rule_tests(rules)
    for o in outcomes:
        if not o.ok or a.verbose:
            mark = "ok  " if o.ok else "FAIL"
            print(f"{mark} {o.rule_id}: {o.test} (expected {o.expected}, got {o.got})")
    bad = [o for o in outcomes if not o.ok]
    problems = coverage_problems(rules)
    for p in problems:
        print(f"FAIL {p}")
    print(f"{len(outcomes) - len(bad)}/{len(outcomes)} rule tests passed")
    return 1 if bad or problems else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="minisiem", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def add(name, fn, help_, db=True, rules=False):
        sp = sub.add_parser(name, help=help_)
        if db:
            sp.add_argument(
                "--db",
                default=os.environ.get("SIEM_DB", "siem.db"),
                help="SQLite file (default: $SIEM_DB or siem.db)",
            )
        if rules:
            sp.add_argument("--rules", default=DEFAULT_RULES, help="rules directory")
        sp.set_defaults(fn=fn)
        return sp

    sp = add("generate", cmd_generate, "write synthetic attack logs", db=False)
    sp.add_argument("out_dir")
    sp.add_argument("--seed", type=int, default=1)
    sp.add_argument("--benign-only", action="store_true")

    sp = add("ingest", cmd_ingest, "load log files into the store")
    sp.add_argument("paths", nargs="+")
    sp.add_argument("--type", choices=["auth", "syslog", "nginx"])
    sp.add_argument("--year", type=int, help="year for syslog lines (default: now)")

    add("detect", cmd_detect, "run all rules once", rules=True)

    sp = add("alerts", cmd_alerts, "list stored alerts")
    sp.add_argument("--severity", choices=SEVERITIES)

    sp = add("schedule", cmd_schedule, "ingest and detect on an interval", rules=True)
    sp.add_argument("--logs", help="directory of log files to follow")
    sp.add_argument("--interval", type=float, default=60.0, help="seconds")
    sp.add_argument("--iterations", type=int, help="stop after N runs")
    sp.add_argument("--year", type=int)

    sp = add("serve", cmd_serve, "dashboard on 127.0.0.1")
    sp.add_argument("--port", type=int, default=8080)

    add("schema", cmd_schema, "print the events schema", db=False)

    sp = add("hunt", cmd_hunt, "run a read-only SELECT")
    sp.add_argument("--sql")
    sp.add_argument("--file", help="file containing the SELECT")
    sp.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    sp.add_argument("--json", action="store_true")

    add("validate", cmd_validate, "check rule files", db=False, rules=True)
    sp = add(
        "test-rules",
        cmd_test_rules,
        "run the tests in rule files",
        db=False,
        rules=True,
    )
    sp.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
