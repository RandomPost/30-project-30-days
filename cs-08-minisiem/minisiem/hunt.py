"""Run an analyst's SQL against the store, read-only."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from .db import _regexp

ALLOWED_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
    sqlite3.SQLITE_RECURSIVE,
}
MAX_VM_STEPS = 50_000_000  # progress handler stops runaway queries
DEFAULT_LIMIT = 200


class HuntError(Exception):
    """The query was rejected or failed."""


def run_query(
    db_path: str, sql: str, limit: int = DEFAULT_LIMIT
) -> tuple[list[str], list[tuple], bool]:
    """Execute one SELECT. Returns (columns, rows, truncated).

    Safety: the file is opened read-only, an authorizer permits only SELECT/READ,
    a single statement is allowed, and the row count and VM steps are capped.
    """
    if not Path(db_path).exists():
        raise HuntError(f"database not found: {db_path}")
    uri = f"file:{Path(db_path).resolve().as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    steps = [0]

    def authorizer(action, *_args):
        return sqlite3.SQLITE_OK if action in ALLOWED_ACTIONS else sqlite3.SQLITE_DENY

    def progress() -> int:
        steps[0] += 1000
        return 1 if steps[0] > MAX_VM_STEPS else 0

    try:
        conn.create_function("regexp", 2, _regexp, deterministic=True)
        conn.set_authorizer(authorizer)
        conn.set_progress_handler(progress, 1000)
        cur = conn.execute(sql)
        cols = [d[0] for d in cur.description or []]
        rows = cur.fetchmany(limit + 1)
    except (sqlite3.Error, sqlite3.Warning) as exc:
        raise HuntError(str(exc)) from None
    finally:
        conn.close()
    return cols, rows[:limit], len(rows) > limit


def format_table(cols: list[str], rows: list[tuple]) -> str:
    if not cols:
        return "(no result columns)"
    cells = [[("" if v is None else str(v)) for v in row] for row in rows]
    widths = [
        min(60, max(len(c), *(len(r[i]) for r in cells))) if cells else len(c)
        for i, c in enumerate(cols)
    ]

    def fmt(vals):
        return "  ".join(v[:60].ljust(w) for v, w in zip(vals, widths)).rstrip()

    lines = [fmt(cols), fmt(["-" * w for w in widths])]
    lines += [fmt(r) for r in cells]
    return "\n".join(lines)
