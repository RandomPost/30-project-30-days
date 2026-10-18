"""Load log files or lines into the events table, incrementally."""

from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .db import EVENT_FIELDS
from .parsers import PARSERS

COLUMNS = ["ts", "source", *[c for c in EVENT_FIELDS if c not in ("ts", "source")]]
INSERT_SQL = (
    f"INSERT INTO events ({', '.join(COLUMNS)}) "
    f"VALUES ({', '.join(':' + c for c in COLUMNS)})"
)


@dataclass
class IngestResult:
    parsed: int = 0
    skipped: int = 0

    def __iadd__(self, other: "IngestResult") -> "IngestResult":
        self.parsed += other.parsed
        self.skipped += other.skipped
        return self


def current_year() -> int:
    return datetime.now(timezone.utc).year


def guess_source(filename: str) -> str | None:
    """Pick a parser from a file name: nginx*/access* -> nginx, auth* -> auth."""
    name = os.path.basename(filename).lower()
    if "nginx" in name or "access" in name:
        return "nginx"
    if "auth" in name or "secure" in name:
        return "auth"
    if "syslog" in name or "messages" in name:
        return "syslog"
    return None


def ingest_lines(
    conn: sqlite3.Connection, lines: Iterable[str], source: str, year: int
) -> IngestResult:
    if source not in PARSERS:
        raise ValueError(f"unknown source {source!r}; use one of {sorted(PARSERS)}")
    parse = PARSERS[source]
    result = IngestResult()
    rows = []
    for line in lines:
        if not line.strip():
            continue
        ev = parse(line, source, year)
        if ev is None:
            result.skipped += 1
            continue
        rows.append({c: ev.get(c) for c in COLUMNS})
        result.parsed += 1
    conn.executemany(INSERT_SQL, rows)
    conn.commit()
    return result


def ingest_file(
    conn: sqlite3.Connection, path: str, source: str, year: int
) -> IngestResult:
    """Read only the complete lines added since the last call for this path."""
    path = os.path.abspath(path)
    row = conn.execute("SELECT offset FROM ingest_state WHERE path = ?", (path,))
    found = row.fetchone()
    offset = found["offset"] if found else 0
    size = os.path.getsize(path)
    if size < offset:  # rotated or truncated: start over
        offset = 0
    with open(path, "rb") as fh:
        fh.seek(offset)
        data = fh.read()
    end = data.rfind(b"\n")
    if end == -1:  # no complete new line yet
        return IngestResult()
    chunk = data[: end + 1]
    lines = chunk.decode("utf-8", errors="replace").splitlines()
    result = ingest_lines(conn, lines, source, year)
    conn.execute(
        "INSERT INTO ingest_state (path, offset) VALUES (?, ?) "
        "ON CONFLICT(path) DO UPDATE SET offset = excluded.offset",
        (path, offset + len(chunk)),
    )
    conn.commit()
    return result
