"""SQLite store: the normalized event schema, alerts and ingest bookkeeping."""

from __future__ import annotations

import re
import sqlite3
from functools import lru_cache

# Column -> meaning. Rules and hunts may only reference these fields.
EVENT_FIELDS: dict[str, str] = {
    "ts": "event time, ISO-8601 UTC, e.g. 2026-10-18T02:00:00Z (sorts as text)",
    "source": "which log it came from: auth | syslog | nginx",
    "host": "host name from the syslog line (NULL for nginx)",
    "program": "syslog program, e.g. sshd, sudo, CRON (NULL for nginx)",
    "pid": "process id (integer, may be NULL)",
    "message": "syslog message text (NULL for nginx)",
    "src_ip": "client or remote IP address",
    "user": "account involved (login name, sudo caller, HTTP basic-auth user)",
    "action": "login | invalid_user | sudo | su | user_created | cron_change | "
    "cron_exec | command | http_request | other",
    "outcome": "success | failure | NULL when not applicable",
    "command": "command run through sudo, or audited remote shell command",
    "http_method": "GET, POST, ...",
    "http_path": "request path and query, URL-decoded",
    "http_status": "HTTP status code (integer)",
    "http_bytes": "response size in bytes (integer)",
    "user_agent": "HTTP User-Agent header",
    "raw": "the original log line",
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    source TEXT NOT NULL,
    host TEXT,
    program TEXT,
    pid INTEGER,
    message TEXT,
    src_ip TEXT,
    user TEXT,
    action TEXT,
    outcome TEXT,
    command TEXT,
    http_method TEXT,
    http_path TEXT,
    http_status INTEGER,
    http_bytes INTEGER,
    user_agent TEXT,
    raw TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_action ON events(action, outcome);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    tags TEXT NOT NULL DEFAULT '',
    group_key TEXT NOT NULL,
    first_ts TEXT NOT NULL,
    last_ts TEXT NOT NULL,
    event_count INTEGER NOT NULL,
    details TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (rule_id, group_key, first_ts)
);
CREATE INDEX IF NOT EXISTS idx_alerts_first_ts ON alerts(first_ts);

CREATE TABLE IF NOT EXISTS ingest_state (
    path TEXT PRIMARY KEY,
    offset INTEGER NOT NULL
);
"""

SEVERITIES = ("low", "medium", "high", "critical")


@lru_cache(maxsize=256)
def _compiled(pattern: str) -> re.Pattern[str] | None:
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None


def _regexp(pattern: str, value: object) -> int:
    """SQL REGEXP: case-insensitive search; NULL or a bad pattern never matches."""
    rx = _compiled(pattern) if isinstance(pattern, str) else None
    if rx is None or value is None:
        return 0
    return 1 if rx.search(str(value)) else 0


def connect(path: str = "siem.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.create_function("regexp", 2, _regexp, deterministic=True)
    conn.executescript(SCHEMA)
    return conn


def schema_text() -> str:
    """Human-readable description of the events table, for hunters and docs."""
    lines = ["Table events (one row per log line):"]
    width = max(len(k) for k in EVENT_FIELDS)
    for name, desc in EVENT_FIELDS.items():
        lines.append(f"  {name.ljust(width)}  {desc}")
    lines += [
        "",
        "Table alerts: rule_id, title, severity, tags, group_key, first_ts, last_ts,",
        "  event_count, details (JSON), created_at, updated_at",
        "",
        "SQL notes: regexp(pattern, value) is available (case-insensitive);",
        "  compare ts as text; shift it with",
        "  strftime('%Y-%m-%dT%H:%M:%SZ', ts, '-10 minutes').",
    ]
    return "\n".join(lines)
