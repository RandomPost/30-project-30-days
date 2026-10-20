from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "cs-08-minisiem"))

import pytest
from minisiem import db as sdb

from purplelab import coverage as cov

T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=timezone.utc)


def iso(offset: float) -> str:
    return (T0 + timedelta(seconds=offset)).strftime("%Y-%m-%dT%H:%M:%SZ")


def ex_line(tid, start, end, ok=True, run="r1", name="N", tactic="discovery"):
    return {
        "run_id": run,
        "technique_id": tid,
        "name": name,
        "tactic": tactic,
        "start": (T0 + timedelta(seconds=start)).isoformat(),
        "end": (T0 + timedelta(seconds=end)).isoformat(),
        "ok": ok,
        "target": "victim",
        "detail": "" if ok else "host unreachable",
    }


@pytest.fixture
def siem(tmp_path):
    path = str(tmp_path / "siem.db")
    conn = sdb.connect(path)
    conn.close()
    return path


def add_event(path, offset):
    conn = sdb.connect(path)
    conn.execute(
        "INSERT INTO events (ts, source, raw) VALUES (?, 'auth', 'x')", (iso(offset),)
    )
    conn.commit()
    conn.close()


def add_alert(path, rule, first, last, tags="attack.t1110.001"):
    conn = sdb.connect(path)
    conn.execute(
        "INSERT INTO alerts (rule_id, title, severity, tags, group_key, first_ts, "
        "last_ts, event_count, details, created_at, updated_at) "
        "VALUES (?, ?, 'high', ?, 'k', ?, ?, 3, '{}', ?, ?)",
        (rule, rule.upper(), tags, iso(first), iso(last), iso(0), iso(0)),
    )
    conn.commit()
    conn.close()


def matrix_for(lines, siem, rule_tags, **kw):
    log = Path(siem).parent / "emulation.jsonl"
    log.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    return cov.build_matrix(
        cov.load_emulation(log),
        cov.load_alerts(siem),
        rule_tags,
        lambda s, e: cov.count_events(siem, s, e),
        **kw,
    )


def only(m, tid):
    return next(r for r in m.rows if r.technique_id == tid)


def test_detected(siem):
    add_event(siem, 5)
    add_alert(siem, "ssh-brute-force", 2, 8)
    m = matrix_for(
        [ex_line("T1110.001", 0, 10)], siem, {"ssh-brute-force": {"T1110.001"}}
    )
    row = only(m, "T1110.001")
    assert (row.status, row.detected_by) == ("detected", ["ssh-brute-force"])
    assert m.unattributed == [] and m.untested == {}


def test_parent_tag_covers_subtechnique(siem):
    add_event(siem, 5)
    add_alert(siem, "brute", 5, 6, tags="attack.t1110")
    m = matrix_for([ex_line("T1110.003", 0, 10)], siem, {"brute": {"T1110"}})
    assert only(m, "T1110.003").status == "detected"


def test_sub_tag_does_not_cover_parent(siem):
    add_event(siem, 5)
    add_alert(siem, "spray", 5, 6, tags="attack.t1110.003")
    m = matrix_for([ex_line("T1110", 0, 10)], siem, {"spray": {"T1110.003"}})
    assert only(m, "T1110").reason == "no-rule"


def test_missed_reasons(siem):
    add_event(siem, 5)
    lines = [
        ex_line("T1082", 0, 10),
        ex_line("T1033", 100, 110),
        ex_line("T1053.003", 0, 10),
    ]
    m = matrix_for(lines, siem, {"cron": {"T1053.003"}})
    assert only(m, "T1033").reason == "no-telemetry"
    assert only(m, "T1082").reason == "no-rule"
    assert only(m, "T1053.003").reason == "rule-did-not-fire"
    assert all(r.status == "missed" for r in m.rows)


def test_not_run(siem):
    m = matrix_for([ex_line("T1078", 0, 1, ok=False)], siem, {})
    row = only(m, "T1078")
    assert (row.status, row.reason) == ("not-run", "host unreachable")
    assert m.summary == {
        "detected": 0,
        "missed": 0,
        "not_run": 1,
        "total": 1,
        "percent": 0.0,
    }


@pytest.mark.parametrize(
    "first,last,expected",
    [
        (13, 20, "detected"),
        (14, 20, "missed"),
        (-20, -3, "detected"),
        (-20, -4, "missed"),
    ],
)
def test_slack_window_edges(siem, first, last, expected):
    add_event(siem, 5)
    add_alert(siem, "r", first, last)
    m = matrix_for([ex_line("T1110.001", 0, 10)], siem, {"r": {"T1110.001"}})
    assert only(m, "T1110.001").status == expected


def test_custom_slack(siem):
    add_event(siem, 5)
    add_alert(siem, "r", 20, 25)
    args = ([ex_line("T1110.001", 0, 10)], siem, {"r": {"T1110.001"}})
    assert only(matrix_for(*args), "T1110.001").status == "missed"
    assert only(matrix_for(*args, slack=10), "T1110.001").status == "detected"


def test_event_telemetry_counted_inside_slack(siem):
    add_event(siem, 12)
    m = matrix_for([ex_line("T1082", 0, 10)], siem, {})
    assert only(m, "T1082").reason == "no-rule"


def test_untested_and_unattributed(siem):
    add_event(siem, 5)
    add_alert(siem, "stray", 5, 6, tags="attack.t1190")
    add_alert(siem, "late", 500, 501)
    rt = {"stray": {"T1190"}, "late": {"T1110.001"}, "cron": {"T1053.003"}}
    m = matrix_for([ex_line("T1082", 0, 10)], siem, rt)
    assert m.untested == {
        "cron": ["T1053.003"],
        "late": ["T1110.001"],
        "stray": ["T1190"],
    }
    assert {a.rule_id for a in m.unattributed} == {"stray", "late"}


def test_alert_tags_used_when_rule_unknown(siem):
    add_event(siem, 5)
    add_alert(siem, "ghost", 5, 6, tags="attack.persistence,attack.t1053.003")
    m = matrix_for([ex_line("T1053.003", 0, 10)], siem, {})
    assert only(m, "T1053.003").detected_by == ["ghost"]


def test_latest_run_only_and_explicit_run(siem):
    add_event(siem, 5)
    add_alert(siem, "r", 5, 6)
    lines = [
        ex_line("T1110.001", 0, 10, run="old"),
        ex_line("T1110.001", 1000, 1010, run="new"),
        ex_line("T1082", 0, 10, run="old"),
    ]
    rt = {"r": {"T1110.001"}}
    m = matrix_for(lines, siem, rt)
    assert m.run_id == "new"
    assert (
        only(m, "T1110.001").status == "missed" and only(m, "T1110.001").run_id == "new"
    )
    assert only(m, "T1082").run_id == "old"
    old = matrix_for(lines, siem, rt, run_id="old")
    assert old.run_id == "old" and len(old.rows) == 2
    assert only(old, "T1110.001").status == "detected"


def test_load_emulation_accepts_z_and_blank_lines(tmp_path):
    p = tmp_path / "e.jsonl"
    rec = ex_line("T1082", 0, 1)
    rec["start"], rec["end"] = "2026-10-20T12:00:00Z", "2026-10-20T12:00:01Z"
    p.write_text(json.dumps(rec) + "\n\n")
    (e,) = cov.load_emulation(p)
    assert e.start == T0 and e.tactic == "discovery"
    p.write_text("{not json\n")
    with pytest.raises(ValueError, match=":1:"):
        cov.load_emulation(p)


def test_load_rule_tags_with_minisiem_rules(tmp_path):
    rules = Path(__file__).resolve().parents[2] / "cs-08-minisiem" / "rules"
    tags = cov.load_rule_tags(rules)
    assert tags["ssh-brute-force"] == {"T1110.001"}
    assert tags["cron-persistence"] == {"T1053.003"}


def test_load_alerts_parses_tags(siem):
    add_alert(siem, "r", 1, 2, tags="attack.credential_access,attack.t1110.001")
    (a,) = cov.load_alerts(siem)
    assert a.tags == ["attack.credential_access", "attack.t1110.001"]
    assert a.first_ts == T0 + timedelta(seconds=1)


def test_count_events_bounds(siem):
    for off in (-1, 0, 10, 11):
        add_event(siem, off)
    assert cov.count_events(siem, T0, T0 + timedelta(seconds=10)) == 2


@pytest.fixture
def mixed(siem):
    add_event(siem, 5)
    add_alert(siem, "ssh-brute-force", 2, 8)
    lines = [
        ex_line("T1082", 0, 10, name="System Information Discovery"),
        ex_line(
            "T1110.001", 0, 10, name="Password Guessing", tactic="credential-access"
        ),
        ex_line(
            "T1078", 0, 1, ok=False, name="Valid Accounts", tactic="initial-access"
        ),
    ]
    return matrix_for(lines, siem, {"ssh-brute-force": {"T1110.001"}, "x": {"T1190"}})


def test_markdown(mixed):
    md = cov.render_markdown(mixed)
    assert "Run: `r1`" in md
    assert "**1 detected, 1 missed, 1 not run** of 3 techniques (50.0%" in md
    assert "| Technique | Name | Tactic | Status | Detected by / Reason |" in md
    assert (
        "| T1110.001 | Password Guessing | credential-access | detected | ssh-brute-force |"
        in md
    )
    assert (
        "| T1082 | System Information Discovery | discovery | missed | no-rule |" in md
    )
    assert (
        "| T1078 | Valid Accounts | initial-access | not-run | host unreachable |" in md
    )
    assert "- discovery: T1082 System Information Discovery (no-rule)" in md
    assert "## Untested detections" in md and "- x: T1190" in md
    assert "## Unattributed alerts" in md


def test_json(mixed):
    data = json.loads(json.dumps(cov.render_json(mixed)))
    assert data["run_id"] == "r1"
    assert data["summary"]["percent"] == 50.0
    assert [t["status"] for t in data["techniques"]] == [
        "missed",
        "detected",
        "not-run",
    ]
    assert data["gaps"] == [{"id": "T1082", "tactic": "discovery", "reason": "no-rule"}]
    assert data["untested_detections"] == [{"rule_id": "x", "techniques": ["T1190"]}]
    assert data["unattributed_alerts"] == []


def test_gaps_ordered_by_tactic(siem):
    add_event(siem, 5)
    lines = [
        ex_line("T1082", 0, 10, tactic="discovery"),
        ex_line("T1595.003", 0, 10, tactic="reconnaissance"),
        ex_line("T1053.003", 0, 10, tactic="persistence"),
    ]
    m = matrix_for(lines, siem, {})
    assert [r.tactic for r in m.gaps] == ["reconnaissance", "persistence", "discovery"]


def test_diff(siem, mixed):
    before = cov.render_json(mixed)
    after = json.loads(json.dumps(before))
    after["run_id"] = "r2"
    for t in after["techniques"]:
        if t["id"] == "T1082":
            t["status"], t["detected_by"], t["reason"] = "detected", ["new-rule"], ""
    after["summary"].update(detected=2, missed=0, percent=100.0)
    md = cov.render_diff_markdown(before, json.dumps(after))
    assert "Before: `r1`  After: `r2`" in md
    assert "| T1082 | System Information Discovery | missed | detected |" in md
    assert "T1110.001 |" not in md
    assert "| Detected | 1 | 2 | +1 |" in md
    assert "| Missed | 1 | 0 | -1 |" in md
    assert "| Detected % | 50.0 | 100.0 | +50 |" in md


def test_diff_no_changes(mixed):
    r = cov.render_json(mixed)
    assert "No technique changed status." in cov.render_diff_markdown(r, r)
