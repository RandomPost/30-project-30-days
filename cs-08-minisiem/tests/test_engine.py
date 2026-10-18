from minisiem.engine import run_rules
from minisiem.ingest import ingest_lines
from minisiem.rules import parse_rule


def fail(sec, user="root", ip="1.1.1.1"):
    return f"Oct 18 01:{sec // 60:02d}:{sec % 60:02d} h sshd[1]: Failed password for {user} from {ip} port 1 ssh2"


RULE = """
id: brute
title: brute
severity: high
detection:
  s: {action: login, outcome: failure}
  condition: s
  threshold: {group_by: src_ip, count: 3, window: 1m}
"""
SPRAY = RULE.replace("count: 3", "distinct: user, count: 3").replace(
    "id: brute", "id: spray"
)


def alerts(conn, rule_id=None):
    sql = "SELECT * FROM alerts" + (f" WHERE rule_id = '{rule_id}'" if rule_id else "")
    return conn.execute(sql + " ORDER BY first_ts, id").fetchall()


def test_threshold_boundaries(conn):
    r = parse_rule(RULE)
    ingest_lines(conn, [fail(0), fail(30)], "auth", 2026)
    assert run_rules(conn, [r]) == {"brute": 0}
    ingest_lines(conn, [fail(59)], "auth", 2026)  # third event inside 1m
    assert run_rules(conn, [r]) == {"brute": 1}


def test_events_just_outside_the_window_do_not_count(conn):
    r = parse_rule(RULE)
    ingest_lines(conn, [fail(0), fail(30), fail(61)], "auth", 2026)  # 0 -> 61 > 60s
    assert run_rules(conn, [r]) == {"brute": 0}


def test_a_long_attack_is_one_alert_that_grows(conn):
    r = parse_rule(RULE)
    ingest_lines(conn, [fail(s) for s in range(0, 100, 10)], "auth", 2026)
    run_rules(conn, [r])
    (a,) = alerts(conn)
    assert a["event_count"] == 10 and a["first_ts"].endswith("01:00:00Z")
    ingest_lines(conn, [fail(100), fail(110)], "auth", 2026)
    assert run_rules(conn, [r]) == {"brute": 0}  # same alert, updated
    (a,) = alerts(conn)
    assert a["event_count"] == 12


def test_rerunning_is_idempotent(conn):
    r = parse_rule(RULE)
    ingest_lines(conn, [fail(s) for s in (0, 5, 10)], "auth", 2026)
    assert run_rules(conn, [r]) == {"brute": 1}
    assert run_rules(conn, [r]) == {"brute": 0}
    assert len(alerts(conn)) == 1


def test_separate_bursts_make_separate_alerts(conn):
    r = parse_rule(RULE)
    burst = [fail(s) for s in (0, 5, 10)] + [fail(s) for s in (1000, 1005, 1010)]
    ingest_lines(conn, burst, "auth", 2026)
    assert run_rules(conn, [r]) == {"brute": 2}


def test_groups_are_tracked_per_entity(conn):
    r = parse_rule(RULE)
    mixed = [
        fail(0, ip="1.1.1.1"),
        fail(1, ip="2.2.2.2"),
        fail(2, ip="1.1.1.1"),
        fail(3, ip="2.2.2.2"),
        fail(4, ip="1.1.1.1"),
    ]
    ingest_lines(conn, mixed, "auth", 2026)
    run_rules(conn, [r])
    assert [a["group_key"] for a in alerts(conn)] == ["src_ip=1.1.1.1"]


def test_distinct_counts_values_not_events(conn):
    r = parse_rule(SPRAY)
    ingest_lines(conn, [fail(s, "root") for s in (0, 1, 2, 3)], "auth", 2026)
    assert run_rules(conn, [r]) == {"spray": 0}
    ingest_lines(conn, [fail(4, "a"), fail(5, "b")], "auth", 2026)
    assert run_rules(conn, [r]) == {"spray": 1}
    import json

    (a,) = alerts(conn)
    assert json.loads(a["details"])["distinct_values"] == ["a", "b", "root"]


def test_events_without_a_group_value_are_ignored(conn):
    r = parse_rule(RULE.replace("src_ip", "command"))
    ingest_lines(conn, [fail(s) for s in (0, 1, 2)], "auth", 2026)
    assert run_rules(conn, [r]) == {"brute": 0}


def test_non_threshold_rule_alerts_per_event(conn):
    r = parse_rule(
        "id: any\ntitle: t\nseverity: low\ndetection: {s: {action: login}, condition: s}"
    )
    ingest_lines(conn, [fail(0), fail(1)], "auth", 2026)
    assert run_rules(conn, [r]) == {"any": 2}
