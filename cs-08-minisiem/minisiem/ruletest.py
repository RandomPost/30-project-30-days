"""Run the sample-log tests embedded in each rule file."""

from __future__ import annotations

from dataclasses import dataclass

from .db import connect
from .engine import run_rules
from .ingest import ingest_lines
from .rules import Rule

TEST_YEAR = 2026  # embedded syslog lines have no year


@dataclass
class TestOutcome:
    rule_id: str
    test: str
    expected: int
    got: int

    @property
    def ok(self) -> bool:
        return self.expected == self.got


def run_rule_tests(rules: list[Rule]) -> list[TestOutcome]:
    """Each test gets a fresh in-memory store and only its own rule is evaluated."""
    outcomes = []
    for rule in rules:
        for t in rule.tests:
            conn = connect(":memory:")
            ingest_lines(conn, t.lines, t.source, TEST_YEAR)
            run_rules(conn, [rule])
            got = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE rule_id = ?", (rule.id,)
            ).fetchone()[0]
            conn.close()
            outcomes.append(TestOutcome(rule.id, t.name, t.alerts, got))
    return outcomes


def coverage_problems(rules: list[Rule]) -> list[str]:
    """Every rule needs one test that fires and one that stays quiet."""
    problems = []
    for r in rules:
        if not any(t.alerts > 0 for t in r.tests):
            problems.append(f"{r.id}: no test where the rule fires")
        if not any(t.alerts == 0 for t in r.tests):
            problems.append(f"{r.id}: no test where the rule must stay quiet")
    return problems
