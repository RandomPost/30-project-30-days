"""Rule tests. Fixtures annotate expectations the way Semgrep's own test runner does:

    # ruleid: <rule-id>   the next code line MUST be flagged by that rule
    # ok: <rule-id>       the next code line must NOT be flagged by that rule

Each fixture `tests/fixtures/<rule-id>.py` is run against `rules/<rule-id>.yaml`.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = sorted((ROOT / "tests" / "fixtures").glob("*.py"))
MARK = re.compile(r"#\s*(ruleid|ok):\s*(\S+)")


def expectations(fixture: Path, rule_id: str) -> tuple[set[int], set[int]]:
    """Return (lines that must be flagged, lines that must not be)."""
    must, must_not = set(), set()
    pending = None
    for lineno, line in enumerate(fixture.read_text().splitlines(), start=1):
        m = MARK.search(line)
        if m and m.group(2) == rule_id:
            pending = m.group(1)
        elif pending and line.strip() and not line.strip().startswith("#"):
            (must if pending == "ruleid" else must_not).add(lineno)
            pending = None
    return must, must_not


def flagged_lines(rule_file: Path, fixture: Path) -> dict[str, set[int]]:
    proc = subprocess.run(
        [
            "semgrep",
            "--config",
            str(rule_file),
            "--json",
            "--quiet",
            "--metrics=off",
            "--disable-version-check",
            str(fixture),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    data = json.loads(proc.stdout)
    assert not data["errors"], data["errors"]
    out: dict[str, set[int]] = {}
    for r in data["results"]:
        span = range(r["start"]["line"], r["end"]["line"] + 1)
        out.setdefault(r["check_id"].split(".")[-1], set()).update(span)
    return out


@pytest.mark.parametrize("fixture", FIXTURES, ids=lambda p: p.stem)
def test_rule_against_fixture(fixture):
    rule_id = fixture.stem
    rule_file = ROOT / "rules" / f"{rule_id}.yaml"
    assert rule_file.is_file(), f"no rule file for fixture {fixture.name}"
    must, must_not = expectations(fixture, rule_id)
    assert must and must_not, "fixture needs both ruleid and ok cases"
    found = flagged_lines(rule_file, fixture).get(rule_id, set())
    start_lines = found
    missed = sorted(n for n in must if n not in start_lines)
    false_pos = sorted(n for n in must_not if n in start_lines)
    assert not missed, f"vulnerable lines not flagged: {missed}"
    assert not false_pos, f"safe lines wrongly flagged: {false_pos}"


def test_every_rule_has_a_fixture():
    rules = {p.stem for p in (ROOT / "rules").glob("*.yaml")}
    assert rules == {p.stem for p in FIXTURES}
