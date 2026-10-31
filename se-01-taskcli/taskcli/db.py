"""SQLite connection and schema migrations.

The schema version lives in `PRAGMA user_version`. Each migration is applied once, in
order, inside one transaction, so a failed migration leaves the database untouched.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# (version, description, SQL). Never edit a released migration: add a new one.
MIGRATIONS: list[tuple[int, str, str]] = [
    (
        1,
        "create tasks",
        """
        CREATE TABLE tasks (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            done INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT (datetime('now')),
            completed_at TEXT
        );
        """,
    ),
    (
        2,
        "add due date and priority",
        """
        ALTER TABLE tasks ADD COLUMN due_date TEXT;
        ALTER TABLE tasks ADD COLUMN priority INTEGER NOT NULL DEFAULT 2;
        CREATE INDEX idx_tasks_due ON tasks(due_date);
        """,
    ),
    (
        3,
        "add tags",
        """
        CREATE TABLE tags (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
        CREATE TABLE task_tags (
            task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            PRIMARY KEY (task_id, tag_id)
        );
        """,
    ),
]

LATEST = MIGRATIONS[-1][0]


def schema_version(conn: sqlite3.Connection) -> int:
    return conn.execute("PRAGMA user_version").fetchone()[0]


def migrate(conn: sqlite3.Connection) -> list[int]:
    """Apply pending migrations; return the versions applied."""
    current = schema_version(conn)
    if current > LATEST:
        raise RuntimeError(
            f"database is at schema {current}, newer than this taskcli ({LATEST}); upgrade taskcli"
        )
    applied = []
    for version, _desc, sql in MIGRATIONS:
        if version <= current:
            continue
        try:
            conn.execute("BEGIN")
            for stmt in filter(None, (s.strip() for s in sql.split(";"))):
                conn.execute(stmt)
            conn.execute(f"PRAGMA user_version = {version}")  # int from our own list
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
        applied.append(version)
    return applied


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (creating if needed) the database and bring the schema up to date."""
    if str(path) != ":memory:":
        Path(path).expanduser().parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(path) if str(path) == ":memory:" else Path(path).expanduser()
    )
    conn.row_factory = sqlite3.Row
    conn.isolation_level = None  # we manage transactions explicitly
    conn.execute("PRAGMA foreign_keys = ON")
    migrate(conn)
    return conn
