"""Generated attack logs through ingest, detect, schedule and hunt."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from conftest import ROOT, load_logs
from minisiem import sample
from minisiem.cli import main
from minisiem.db import connect
from minisiem.engine import run_rules
from minisiem.hunt import HuntError, run_query
from minisiem.rules import load_rules
from minisiem.ruletest import coverage_problems, run_rule_tests
from minisiem.scheduler import run_schedule, tick

EXPECTED_RULES = {
    "cron-persistence",
    "ssh-brute-force",
    "ssh-password-spraying",
    "ssh-root-login",
    "su-failures",
    "sudo-auth-failures",
    "sudo-root-shell",
    "user-created",
    "web-404-flood",
    "web-login-brute-force",
    "web-path-traversal",
    "web-rce-probe",
    "web-scanner-user-agent",
    "web-sqli",
}


def fired(conn):
    return {r[0] for r in conn.execute("SELECT DISTINCT rule_id FROM alerts")}


def test_every_shipped_rule_has_a_firing_and_a_quiet_test(rules_dir):
    assert coverage_problems(load_rules(rules_dir)) == []


def test_embedded_rule_tests_pass(rules_dir):
    outcomes = run_rule_tests(load_rules(rules_dir))
    assert len(outcomes) >= 30
    assert [o for o in outcomes if not o.ok] == []


def test_all_rules_fire_on_generated_attack_logs(conn, rules_dir, tmp_path):
    load_logs(conn, None, True, tmp_path)
    rules = load_rules(rules_dir)
    run_rules(conn, rules)
    assert len(rules) >= 8 and {r.id for r in rules} == EXPECTED_RULES
    assert fired(conn) == EXPECTED_RULES


def test_benign_traffic_raises_no_alerts(conn, rules_dir, tmp_path):
    load_logs(conn, None, False, tmp_path)
    assert sum(run_rules(conn, load_rules(rules_dir)).values()) == 0


def test_attacks_are_attributed_to_the_right_entity(conn, rules_dir, tmp_path):
    load_logs(conn, None, True, tmp_path)
    run_rules(conn, load_rules(rules_dir))
    keys = dict(
        conn.execute("SELECT rule_id, group_concat(group_key) FROM alerts GROUP BY 1")
    )
    assert keys["ssh-brute-force"] == "src_ip=192.0.2.99"
    assert keys["ssh-password-spraying"] == "src_ip=198.51.100.23"
    assert keys["web-sqli"] == "src_ip=198.51.100.77"
    assert keys["su-failures"] == "user=www-data"
    assert keys["web-404-flood"] == "src_ip=203.0.113.9"


def test_generation_is_deterministic(tmp_path):
    a = sample.generate(str(tmp_path / "a"), seed=7)
    b = sample.generate(str(tmp_path / "b"), seed=7)
    assert [Path(p).read_text() for p in a] == [Path(p).read_text() for p in b]


def test_cli_end_to_end(tmp_path, capsys):
    logs, db = tmp_path / "logs", str(tmp_path / "siem.db")
    assert main(["generate", str(logs)]) == 0
    assert (
        main(
            ["ingest", *map(str, sorted(logs.iterdir())), "--db", db, "--year", "2026"]
        )
        == 0
    )
    assert main(["detect", "--db", db]) == 0
    out = capsys.readouterr().out
    assert f"{len(EXPECTED_RULES)} rules run" in out and " new alerts" in out
    assert main(["alerts", "--db", db, "--severity", "critical"]) == 0
    assert "web-rce-probe" in capsys.readouterr().out
    assert main(["validate"]) == 0 and main(["test-rules"]) == 0


def test_scheduler_ingests_incrementally_and_alerts_once(tmp_path, rules_dir):
    logs, db = tmp_path / "logs", str(tmp_path / "siem.db")
    sample.generate(str(logs), with_attacks=True)
    messages: list[str] = []
    run_schedule(
        db, rules_dir, str(logs), 2026, 0, 3, sleep=lambda _s: None, out=messages.append
    )
    assert len(messages) == 3
    assert "new alerts" in messages[0] and "0 new events, 0 new alerts" in messages[1]
    conn = connect(db)
    assert fired(conn) == EXPECTED_RULES
    # a new burst appended to a followed log is picked up on the next tick
    line = "Oct 18 20:00:{s:02d} web01 sshd[9]: Failed password for root from 203.0.113.99 port 1 ssh2\n"
    with open(logs / "auth.log", "a") as fh:
        fh.writelines(line.format(s=s) for s in range(10))
    res = tick(db, rules_dir, str(logs), 2026)
    assert res.ingested.parsed == 10 and res.new_alerts["ssh-brute-force"] == 1


def test_scheduler_survives_a_broken_rule_file(tmp_path, rules_dir):
    bad = tmp_path / "rules"
    bad.mkdir()
    (bad / "x.yml").write_text("id: BAD")
    messages: list[str] = []
    run_schedule(
        str(tmp_path / "s.db"),
        str(bad),
        None,
        2026,
        0,
        2,
        sleep=lambda _s: None,
        out=messages.append,
    )
    assert len(messages) == 2 and all("failed" in m for m in messages)


# --- hunting -------------------------------------------------------------------


def test_hunt_finds_the_success_after_failures_chain(attack_db):
    sql = (ROOT / "hunts" / "success-after-failures.sql").read_text()
    cols, rows, truncated = run_query(attack_db, sql)
    assert cols == ["src_ip", "user", "success_ts", "failures_before"]
    assert [(r[0], r[1]) for r in rows] == [("192.0.2.99", "deploy")]
    assert rows[0][3] == 14 and not truncated


def test_every_shipped_hunt_runs(attack_db):
    for path in sorted((ROOT / "hunts").glob("*.sql")):
        run_query(attack_db, path.read_text())


@pytest.mark.parametrize(
    "sql",
    [
        "DELETE FROM events",
        "DROP TABLE events",
        "UPDATE alerts SET severity = 'low'",
        "INSERT INTO events (ts, source, raw) VALUES ('x', 'y', 'z')",
        "ATTACH DATABASE '/tmp/x.db' AS x",
        "PRAGMA writable_schema = 1",
        "SELECT 1; DROP TABLE events",
        "CREATE TABLE t (a)",
        "VACUUM",
    ],
)
def test_hunt_runner_is_read_only(attack_db, sql):
    with pytest.raises(HuntError):
        run_query(attack_db, sql)
    cols, rows, _ = run_query(attack_db, "SELECT COUNT(*) FROM events")
    assert rows[0][0] > 0


def test_hunt_row_limit_and_regexp(attack_db):
    _, rows, truncated = run_query(attack_db, "SELECT id FROM events", limit=5)
    assert len(rows) == 5 and truncated
    _, rows, _ = run_query(
        attack_db, "SELECT COUNT(*) FROM events WHERE regexp('sqlmap', user_agent)"
    )
    assert rows[0][0] == 6


def test_hunt_runaway_query_is_stopped(attack_db):
    sql = (
        "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n) "
        "SELECT COUNT(*) FROM n"
    )
    with pytest.raises(HuntError):
        run_query(attack_db, sql)


def test_hunt_missing_database(tmp_path):
    with pytest.raises(HuntError, match="not found"):
        run_query(str(tmp_path / "nope.db"), "SELECT 1")


def test_hunt_cli_json_output(attack_db, capsys):
    assert (
        main(
            [
                "hunt",
                "--db",
                attack_db,
                "--json",
                "--sql",
                "SELECT COUNT(*) AS n FROM events WHERE action = 'user_created'",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == [{"n": 1}]
    assert main(["hunt", "--db", attack_db, "--sql", "DELETE FROM events"]) == 1


# --- the Claude Code skill and slash command ------------------------------------


def frontmatter(path: Path) -> dict[str, str]:
    text = path.read_text()
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m, f"{path} needs YAML frontmatter"
    return dict(re.findall(r"^([\w-]+):\s*(.+)$", m.group(1), re.M))


def test_hunt_slash_command_is_well_formed():
    path = ROOT / ".claude" / "commands" / "hunt.md"
    fm = frontmatter(path)
    assert fm["description"] and "argument-hint" in fm
    body = path.read_text()
    assert (
        "$ARGUMENTS" in body and "minisiem schema" in body and "minisiem hunt" in body
    )


def test_new_detection_skill_is_well_formed():
    path = ROOT / ".claude" / "skills" / "new-detection" / "SKILL.md"
    fm = frontmatter(path)
    assert fm["name"] == "new-detection" and "detection" in fm["description"]
    body = path.read_text()
    for needle in (
        "rules/",
        "minisiem validate",
        "minisiem test-rules",
        "pytest",
        "tests:",
    ):
        assert needle in body


def test_skill_template_parses_as_a_valid_rule():
    """The YAML example in the skill must itself be a loadable rule."""
    import yaml
    from minisiem.rules import parse_rule

    body = (ROOT / ".claude" / "skills" / "new-detection" / "SKILL.md").read_text()
    block = re.search(r"```yaml\n(.*?)```", body, re.S).group(1)
    doc = yaml.safe_load(block)
    doc["detection"]["selection"]["user|contains"] = ["admin"]
    rule = parse_rule(yaml.safe_dump(doc))
    assert rule.id == "example-rule" and rule.threshold.count == 8
