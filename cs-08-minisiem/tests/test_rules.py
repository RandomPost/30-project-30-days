import pytest

from minisiem.db import connect
from minisiem.rules import RuleError, parse_rule

BASE = """
id: t-rule
title: t
severity: low
detection:
{body}
"""


def rule(body: str):
    indented = "\n".join("  " + l for l in body.strip().splitlines())
    return parse_rule(BASE.format(body=indented))


def match(r, rows):
    """Which of (user, src_ip, http_status, command) rows does the rule's WHERE hit?"""
    c = connect(":memory:")
    for i, (user, ip, status, cmd) in enumerate(rows):
        c.execute(
            "INSERT INTO events (ts, source, raw, user, src_ip, http_status, command) "
            "VALUES ('2026-10-18T00:00:00Z', 'auth', ?, ?, ?, ?, ?)",
            (f"r{i}", user, ip, status, cmd),
        )
    return [
        r_[0] for r_ in c.execute(f"SELECT raw FROM events WHERE {r.where}", r.params)
    ]


ROWS = [
    ("Alice", "10.0.0.1", 200, "/bin/ls"),
    ("bob", "203.0.113.4", 404, "/bin/bash -i"),
    (None, None, None, None),
]


def test_equality_is_case_insensitive_and_list_means_or():
    assert match(
        rule("selection:\n  user: [ALICE, carol]\ncondition: selection"), ROWS
    ) == ["r0"]


def test_modifiers():
    assert match(rule("s:\n  command|contains: BASH\ncondition: s"), ROWS) == ["r1"]
    assert match(rule("s:\n  src_ip|startswith: '10.'\ncondition: s"), ROWS) == ["r0"]
    assert match(rule("s:\n  command|endswith: ' -i'\ncondition: s"), ROWS) == ["r1"]
    assert match(rule("s:\n  command|re: '^/bin/sh'\ncondition: s"), ROWS) == []
    assert match(rule("s:\n  command|re: '^/bin/b?a?sh'\ncondition: s"), ROWS) == ["r1"]
    assert match(rule("s:\n  http_status|gte: 400\ncondition: s"), ROWS) == ["r1"]
    assert match(rule("s:\n  http_status: 200\ncondition: s"), ROWS) == ["r0"]
    assert match(rule("s:\n  user: null\ncondition: s"), ROWS) == ["r2"]


def test_not_over_null_columns_keeps_the_row():
    r = rule(
        "s:\n  http_status: 404\nf:\n  src_ip|startswith: '10.'\ncondition: s or not f"
    )
    assert match(r, ROWS) == ["r1", "r2"]


def test_condition_precedence_and_parentheses():
    body = "a:\n  user: alice\nb:\n  user: bob\nc:\n  http_status: 404\n"
    assert match(rule(body + "condition: a or b and c"), ROWS) == ["r0", "r1"]
    assert match(rule(body + "condition: (a or b) and c"), ROWS) == ["r1"]


def test_one_of_and_all_of_patterns():
    body = "sel_a:\n  user: alice\nsel_b:\n  http_status: 200\n"
    assert match(rule(body + "condition: 1 of sel_*"), ROWS) == ["r0"]
    assert match(rule(body + "condition: all of sel_*"), ROWS) == ["r0"]


def test_list_of_maps_is_or():
    r = rule("s:\n  - user: alice\n  - user: bob\ncondition: s")
    assert match(r, ROWS) == ["r0", "r1"]


def test_hostile_values_are_bound_not_interpolated():
    r = rule("s:\n  user: \"x' OR '1'='1\"\ncondition: s")
    assert "x'" not in r.where
    assert match(r, ROWS) == []


@pytest.mark.parametrize(
    "body, message",
    [
        ("s:\n  nope: 1\ncondition: s", "unknown field"),
        ("s:\n  user|bogus: 1\ncondition: s", "unknown modifier"),
        ("s:\n  user: a\ncondition: missing", "unknown selection"),
        ("s:\n  user: a\ncondition: s and", "ended unexpectedly"),
        ("s:\n  user: a\ncondition: (s s)", r"missing '\)'"),
        ("s:\n  user: a\ncondition: s s", "unexpected"),
        ("s:\n  user|re: '('\ncondition: s", "invalid regex"),
        ("s:\n  http_status|gt: high\ncondition: s", "needs a number"),
        ("s:\n  user: []\ncondition: s", "empty value list"),
        ("s:\n  user|contains: ''\ncondition: s", "non-empty"),
        (
            "s:\n  user: a\ncondition: s\nthreshold:\n  group_by: nope\n  count: 1\n  window: 1m",
            "unknown field",
        ),
        (
            "s:\n  user: a\ncondition: s\nthreshold:\n  group_by: user\n  count: 0\n  window: 1m",
            "count",
        ),
        (
            "s:\n  user: a\ncondition: s\nthreshold:\n  group_by: user\n  count: 1\n  window: soon",
            "bad window",
        ),
        ("s:\n  user: a", "'condition'"),
    ],
)
def test_invalid_rules_are_rejected_with_a_reason(body, message):
    with pytest.raises(RuleError, match=message):
        rule(body)


def test_field_names_cannot_smuggle_sql():
    with pytest.raises(RuleError, match="unknown field"):
        rule('s:\n  "user) OR 1=1 --": a\ncondition: s')


@pytest.mark.parametrize(
    "text, message",
    [
        (
            "id: Bad_ID\ntitle: t\nseverity: low\ndetection: {s: {user: a}, condition: s}",
            "id",
        ),
        (
            "id: ok\ntitle: t\nseverity: urgent\ndetection: {s: {user: a}, condition: s}",
            "severity",
        ),
        ("id: ok\nseverity: low\ndetection: {s: {user: a}, condition: s}", "title"),
        ("- just\n- a list", "mapping"),
        ("id: [unclosed", "invalid YAML"),
    ],
)
def test_invalid_rule_documents(text, message):
    with pytest.raises(RuleError, match=message):
        parse_rule(text)


def test_duplicate_ids_are_rejected(tmp_path):
    from minisiem.rules import load_rules

    doc = "id: dup\ntitle: t\nseverity: low\ndetection: {s: {user: a}, condition: s}\n"
    (tmp_path / "a.yml").write_text(doc)
    (tmp_path / "b.yml").write_text(doc)
    with pytest.raises(RuleError, match="duplicate rule id"):
        load_rules(tmp_path)
