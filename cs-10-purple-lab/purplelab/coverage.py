"""Purple-team coverage: compare emulated techniques with what the SIEM alerted on."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

_SIEM = Path(__file__).resolve().parents[2] / "cs-08-minisiem"
try:
    from minisiem import db as _db
    from minisiem.rules import load_rules
except ImportError:
    sys.path.insert(0, str(_SIEM))
    from minisiem import db as _db
    from minisiem.rules import load_rules

from . import attack

DETECTED = "detected"
MISSED = "missed"
NOT_RUN = "not-run"
NO_TELEMETRY = "no-telemetry"
NO_RULE = "no-rule"
RULE_DID_NOT_FIRE = "rule-did-not-fire"

EventCounter = Callable[[datetime, datetime], int]


@dataclass
class Execution:
    run_id: str
    technique_id: str
    name: str
    tactic: str
    start: datetime
    end: datetime
    ok: bool
    target: str = ""
    detail: str = ""


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    tags: list[str]
    first_ts: datetime
    last_ts: datetime
    event_count: int


@dataclass
class Row:
    technique_id: str
    name: str
    tactic: str
    status: str
    run_id: str
    start: datetime
    end: datetime
    detected_by: list[str] = field(default_factory=list)
    reason: str = ""


@dataclass
class Matrix:
    run_id: str
    rows: list[Row]
    untested: dict[str, list[str]]
    unattributed: list[Alert]

    def count(self, status: str) -> int:
        return sum(1 for r in self.rows if r.status == status)

    @property
    def summary(self) -> dict:
        detected, missed = self.count(DETECTED), self.count(MISSED)
        executed = detected + missed
        percent = round(100 * detected / executed, 1) if executed else 0.0
        return {
            "detected": detected,
            "missed": missed,
            "not_run": self.count(NOT_RUN),
            "total": len(self.rows),
            "percent": percent,
        }

    @property
    def gaps(self) -> list[Row]:
        missed = [r for r in self.rows if r.status == MISSED]
        return sorted(
            missed, key=lambda r: (attack.tactic_rank(r.tactic), r.technique_id)
        )


def parse_ts(text: str) -> datetime:
    """Parse ISO 8601 (trailing Z accepted); naive values are taken as UTC."""
    dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _sql_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_emulation(path: str | Path) -> list[Execution]:
    """Read the runner's JSONL log; blank lines are skipped."""
    out: list[Execution] = []
    for n, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            d = json.loads(line)
            tid = d["technique_id"].upper()
            out.append(
                Execution(
                    run_id=str(d["run_id"]),
                    technique_id=tid,
                    name=d.get("name") or attack.name_of(tid),
                    tactic=d.get("tactic") or attack.tactic_of(tid),
                    start=parse_ts(d["start"]),
                    end=parse_ts(d["end"]),
                    ok=bool(d.get("ok", True)),
                    target=d.get("target", ""),
                    detail=d.get("detail", ""),
                )
            )
        except (KeyError, ValueError, AttributeError) as exc:
            raise ValueError(f"{path}:{n}: bad emulation record: {exc!r}") from exc
    return out


def load_alerts(db_path: str | Path) -> list[Alert]:
    conn = _db.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT rule_id, title, severity, tags, first_ts, last_ts, event_count "
            "FROM alerts ORDER BY first_ts, id"
        ).fetchall()
    finally:
        conn.close()
    return [
        Alert(
            rule_id=r["rule_id"],
            title=r["title"],
            severity=r["severity"],
            tags=[t for t in (r["tags"] or "").split(",") if t],
            first_ts=parse_ts(r["first_ts"]),
            last_ts=parse_ts(r["last_ts"]),
            event_count=r["event_count"],
        )
        for r in rows
    ]


def load_rule_tags(rules_dir: str | Path) -> dict[str, set[str]]:
    """rule_id -> ATT&CK technique ids from its tags (rules with none are omitted)."""
    result: dict[str, set[str]] = {}
    for rule in load_rules(rules_dir):
        ids = {t for t in map(attack.normalize_tag, rule.tags) if t}
        if ids:
            result[rule.id] = ids
    return result


def count_events(db_path: str | Path, start: datetime, end: datetime) -> int:
    conn = _db.connect(str(db_path))
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM events WHERE ts >= ? AND ts <= ?",
            (_sql_ts(start), _sql_ts(end)),
        ).fetchone()[0]
    finally:
        conn.close()


def _alert_ids(alert: Alert, rule_tags: dict[str, set[str]]) -> set[str]:
    ids = set(rule_tags.get(alert.rule_id, ()))
    ids |= {t for t in map(attack.normalize_tag, alert.tags) if t}
    return ids


def _select_executions(
    executions: list[Execution], run_id: str | None
) -> tuple[str, list[Execution]]:
    pool = [e for e in executions if run_id is None or e.run_id == run_id]
    if not pool:
        return run_id or "", []
    latest: dict[str, Execution] = {}
    for e in sorted(pool, key=lambda e: e.start):
        latest[e.technique_id] = e
    headline = run_id or max(pool, key=lambda e: e.start).run_id
    return headline, list(latest.values())


def build_matrix(
    executions: list[Execution],
    alerts: list[Alert],
    rule_tags: dict[str, set[str]],
    event_counter: EventCounter,
    slack: float = 3.0,
    run_id: str | None = None,
) -> Matrix:
    """Classify each emulated technique as detected, missed (with reason) or not-run."""
    headline, chosen = _select_executions(executions, run_id)
    pad = timedelta(seconds=slack)
    used: set[int] = set()
    rows: list[Row] = []
    for ex in chosen:
        row = Row(
            ex.technique_id, ex.name, ex.tactic, NOT_RUN, ex.run_id, ex.start, ex.end
        )
        rows.append(row)
        if not ex.ok:
            row.reason = ex.detail or "technique could not be executed"
            continue
        lo, hi = ex.start - pad, ex.end + pad
        hits = [
            i
            for i, a in enumerate(alerts)
            if a.first_ts <= hi
            and a.last_ts >= lo
            and any(attack.covers(t, ex.technique_id) for t in _alert_ids(a, rule_tags))
        ]
        if hits:
            row.status = DETECTED
            used.update(hits)
            row.detected_by = sorted({alerts[i].rule_id for i in hits})
            continue
        row.status = MISSED
        mapped = any(
            attack.covers(t, ex.technique_id) for ids in rule_tags.values() for t in ids
        )
        if event_counter(lo, hi) == 0:
            row.reason = NO_TELEMETRY
        elif not mapped:
            row.reason = NO_RULE
        else:
            row.reason = RULE_DID_NOT_FIRE
    emulated = [e.technique_id for e in executions]
    untested = {
        rid: sorted(ids)
        for rid, ids in sorted(rule_tags.items())
        if not any(attack.covers(t, e) for t in ids for e in emulated)
    }
    unattributed = [a for i, a in enumerate(alerts) if i not in used]
    return Matrix(headline, rows, untested, unattributed)


def _cell(row: Row) -> str:
    if row.status == DETECTED:
        return ", ".join(row.detected_by)
    return row.reason


def _fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def render_json(matrix: Matrix) -> dict:
    return {
        "run_id": matrix.run_id,
        "summary": matrix.summary,
        "techniques": [
            {
                "id": r.technique_id,
                "name": r.name,
                "tactic": r.tactic,
                "status": r.status,
                "detected_by": r.detected_by,
                "reason": r.reason,
                "run_id": r.run_id,
                "start": _fmt(r.start),
                "end": _fmt(r.end),
            }
            for r in matrix.rows
        ],
        "gaps": [
            {"id": r.technique_id, "tactic": r.tactic, "reason": r.reason}
            for r in matrix.gaps
        ],
        "untested_detections": [
            {"rule_id": rid, "techniques": ids} for rid, ids in matrix.untested.items()
        ],
        "unattributed_alerts": [
            {
                "rule_id": a.rule_id,
                "title": a.title,
                "severity": a.severity,
                "first_ts": _fmt(a.first_ts),
                "last_ts": _fmt(a.last_ts),
                "event_count": a.event_count,
            }
            for a in matrix.unattributed
        ],
    }


def _summary_line(s: dict) -> str:
    return (
        f"**{s['detected']} detected, {s['missed']} missed, {s['not_run']} not run** "
        f"of {s['total']} techniques ({s['percent']}% of executed techniques detected)"
    )


def render_markdown(matrix: Matrix) -> str:
    lines = [
        "# ATT&CK coverage report",
        "",
        f"Run: `{matrix.run_id}`",
        "",
        _summary_line(matrix.summary),
        "",
        "| Technique | Name | Tactic | Status | Detected by / Reason |",
        "|---|---|---|---|---|",
    ]
    for r in matrix.rows:
        lines.append(
            f"| {r.technique_id} | {r.name} | {r.tactic} | {r.status} | {_cell(r)} |"
        )
    lines += ["", "## Gaps by tactic", ""]
    if matrix.gaps:
        lines += [
            f"- {r.tactic}: {r.technique_id} {r.name} ({r.reason})" for r in matrix.gaps
        ]
    else:
        lines.append("No gaps: every executed technique was detected.")
    lines += ["", "## Untested detections", ""]
    if matrix.untested:
        lines += [f"- {rid}: {', '.join(ids)}" for rid, ids in matrix.untested.items()]
    else:
        lines.append("None.")
    lines += ["", "## Unattributed alerts", ""]
    if matrix.unattributed:
        lines += [
            f"- {a.rule_id} ({a.severity}) {_fmt(a.first_ts)} - {_fmt(a.last_ts)}, "
            f"{a.event_count} events"
            for a in matrix.unattributed
        ]
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def _as_report(report: dict | str) -> dict:
    return json.loads(report) if isinstance(report, str) else report


def render_diff_markdown(before_json: dict | str, after_json: dict | str) -> str:
    """Markdown listing techniques whose status changed between two JSON reports."""
    before, after = _as_report(before_json), _as_report(after_json)
    old = {t["id"]: t for t in before["techniques"]}
    new = {t["id"]: t for t in after["techniques"]}
    changes = []
    for tid in sorted(set(old) | set(new)):
        a, b = old.get(tid), new.get(tid)
        was = a["status"] if a else "absent"
        now = b["status"] if b else "absent"
        if was == now:
            continue
        ref = b or a
        changes.append((tid, ref["name"], was, now))
    sb, sa = before["summary"], after["summary"]
    lines = [
        "# ATT&CK coverage diff",
        "",
        f"Before: `{before['run_id']}`  After: `{after['run_id']}`",
        "",
        "| Metric | Before | After | Delta |",
        "|---|---|---|---|",
    ]
    for key, label in (
        ("detected", "Detected"),
        ("missed", "Missed"),
        ("not_run", "Not run"),
        ("percent", "Detected %"),
    ):
        d = round(sa[key] - sb[key], 1)
        lines.append(f"| {label} | {sb[key]} | {sa[key]} | {d:+g} |")
    lines += ["", "## Changed techniques", ""]
    if changes:
        lines += ["| Technique | Name | Before | After |", "|---|---|---|---|"]
        lines += [f"| {t} | {n} | {w} | {x} |" for t, n, w, x in changes]
    else:
        lines.append("No technique changed status.")
    return "\n".join(lines) + "\n"
