"""Run the whole rule pack against a target directory and summarise the findings.

usage: python scripts/scan.py TARGET [--json OUT.json] [--fail-on error|warning]

Exit code: 0 clean (or below --fail-on), 1 findings at/above --fail-on, 2 semgrep failed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

RULES = Path(__file__).resolve().parent.parent / "rules"
RANK = {"INFO": 0, "WARNING": 1, "ERROR": 2}


def run_semgrep(target: Path) -> dict:
    proc = subprocess.run(
        [
            "semgrep",
            "--config",
            str(RULES),
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            str(target),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode not in (0, 1) and not proc.stdout:
        raise RuntimeError(proc.stderr.strip() or "semgrep failed")
    return json.loads(proc.stdout)


def summarize(data: dict, target: Path) -> str:
    results = sorted(
        data["results"],
        key=lambda r: (-RANK[r["extra"]["severity"]], r["path"], r["start"]["line"]),
    )
    if not results:
        return f"No findings in {target}."
    by_rule = Counter(r["check_id"].split(".")[-1] for r in results)
    lines = [f"{len(results)} finding(s) in {target}", ""]
    lines += [f"  {n:>3}  {rule}" for rule, n in by_rule.most_common()]
    lines.append("")
    for r in results:
        rule = r["check_id"].split(".")[-1]
        sev = r["extra"]["severity"]
        lines.append(f"{sev:<7} {r['path']}:{r['start']['line']}  {rule}")
    return "\n".join(lines)


def exit_code(data: dict, fail_on: str) -> int:
    floor = RANK[fail_on.upper()]
    hit = any(RANK[r["extra"]["severity"]] >= floor for r in data["results"])
    return 1 if hit else 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("target", type=Path)
    p.add_argument("--json", type=Path, help="also write raw semgrep JSON here")
    p.add_argument("--fail-on", choices=["warning", "error"], default="warning")
    args = p.parse_args(argv)
    try:
        data = run_semgrep(args.target)
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(summarize(data, args.target))
    if args.json:
        args.json.write_text(json.dumps(data, indent=2))
    return exit_code(data, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())
