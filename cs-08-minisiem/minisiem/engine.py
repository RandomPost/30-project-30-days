"""Run rules against the event store and upsert alerts."""

from __future__ import annotations

import json
import sqlite3
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone

from .rules import Rule

SAMPLE_EVENTS = 3
MAX_EVENT_IDS = 20


@dataclass
class _Cluster:
    first_ts: str
    last_ts: str
    ids: list[int]
    raws: list[str]
    distinct: set
    count: int


def _parse_ts(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _upsert(
    conn: sqlite3.Connection,
    rule: Rule,
    group_key: str,
    cluster: _Cluster,
    group: dict,
) -> bool:
    """Insert or refresh an alert; True when it is new. The (rule, group, first_ts)
    key makes repeated runs idempotent: a growing attack updates its alert."""
    details = {
        "group": group,
        "event_ids": cluster.ids[:MAX_EVENT_IDS],
        "sample": cluster.raws[:SAMPLE_EVENTS],
    }
    if cluster.distinct:
        details["distinct_values"] = sorted(map(str, cluster.distinct))[:20]
    now = _now()
    existing = conn.execute(
        "SELECT id FROM alerts WHERE rule_id = ? AND group_key = ? AND first_ts = ?",
        (rule.id, group_key, cluster.first_ts),
    ).fetchone()
    conn.execute(
        "INSERT INTO alerts (rule_id, title, severity, tags, group_key, first_ts, "
        "last_ts, event_count, details, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(rule_id, group_key, first_ts) DO UPDATE SET "
        "last_ts = excluded.last_ts, event_count = excluded.event_count, "
        "details = excluded.details, title = excluded.title, "
        "severity = excluded.severity, updated_at = excluded.updated_at",
        (
            rule.id,
            rule.title,
            rule.severity,
            ",".join(rule.tags),
            group_key,
            cluster.first_ts,
            cluster.last_ts,
            cluster.count,
            json.dumps(details),
            now,
            now,
        ),
    )
    return existing is None


def _run_simple(conn: sqlite3.Connection, rule: Rule) -> int:
    new = 0
    rows = conn.execute(
        f"SELECT id, ts, raw FROM events WHERE {rule.where} ORDER BY ts, id",
        rule.params,
    ).fetchall()
    for r in rows:
        cluster = _Cluster(r["ts"], r["ts"], [r["id"]], [r["raw"]], set(), 1)
        new += _upsert(conn, rule, f"event:{r['id']}", cluster, {})
    return new


def _run_threshold(conn: sqlite3.Connection, rule: Rule) -> int:
    th = rule.threshold
    assert th is not None
    cols = list(dict.fromkeys([*th.group_by, *([th.distinct] if th.distinct else [])]))
    rows = conn.execute(
        f"SELECT id, ts, raw, {', '.join(cols)} FROM events "
        f"WHERE {rule.where} ORDER BY ts, id",
        rule.params,
    ).fetchall()
    groups: dict[tuple, list[sqlite3.Row]] = defaultdict(list)
    for r in rows:
        key = tuple(r[g] for g in th.group_by)
        if any(v is None for v in key):  # can't attribute events without a key
            continue
        groups[key].append(r)

    new = 0
    for key, events in groups.items():
        group = dict(zip(th.group_by, key))
        group_key = "|".join(f"{k}={v}" for k, v in group.items())
        window: deque = deque()
        cluster: _Cluster | None = None

        def measure() -> int:
            if th.distinct:
                return len(
                    {e[th.distinct] for e in window if e[th.distinct] is not None}
                )
            return len(window)

        def finish() -> int:
            return _upsert(conn, rule, group_key, cluster, group) if cluster else 0

        for e in events:
            t = _parse_ts(e["ts"])
            if cluster is not None and t - _parse_ts(cluster.last_ts) <= th.window:
                cluster.last_ts = e["ts"]
                cluster.ids.append(e["id"])
                cluster.raws.append(e["raw"])
                cluster.count += 1
                if th.distinct and e[th.distinct] is not None:
                    cluster.distinct.add(e[th.distinct])
                continue
            if cluster is not None:  # gap too long: close it and start fresh
                new += finish()
                cluster = None
                window.clear()
            window.append(e)
            while t - _parse_ts(window[0]["ts"]) > th.window:
                window.popleft()
            if measure() >= th.count:
                cluster = _Cluster(
                    window[0]["ts"],
                    e["ts"],
                    [w["id"] for w in window],
                    [w["raw"] for w in window],
                    {w[th.distinct] for w in window if th.distinct and w[th.distinct]},
                    len(window),
                )
        new += finish()
    return new


def run_rules(conn: sqlite3.Connection, rules: list[Rule]) -> dict[str, int]:
    """Evaluate every rule. Returns {rule_id: number of NEW alerts}."""
    out = {}
    for rule in rules:
        out[rule.id] = (
            _run_threshold(conn, rule) if rule.threshold else _run_simple(conn, rule)
        )
    conn.commit()
    return out
