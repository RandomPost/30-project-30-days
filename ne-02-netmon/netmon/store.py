"""SQLite storage for probe results."""

from __future__ import annotations

import sqlite3
import time

from .stats import Sample

SCHEMA = """
CREATE TABLE IF NOT EXISTS probes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    target TEXT NOT NULL,
    ok INTEGER NOT NULL,
    latency_ms REAL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS idx_probes_target_ts ON probes(target, ts);
"""


class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)

    def add(
        self,
        target: str,
        ok: bool,
        latency_ms: float | None,
        error: str | None = None,
        ts: float | None = None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO probes (ts, target, ok, latency_ms, error) VALUES (?,?,?,?,?)",
            (time.time() if ts is None else ts, target, int(ok), latency_ms, error),
        )
        self.conn.commit()

    def targets(self) -> list[str]:
        rows = self.conn.execute("SELECT DISTINCT target FROM probes ORDER BY target")
        return [r[0] for r in rows]

    def samples(self, target: str, since: float) -> list[Sample]:
        rows = self.conn.execute(
            "SELECT ts, ok, latency_ms FROM probes WHERE target=? AND ts>=? ORDER BY ts",
            (target, since),
        )
        return [Sample(ts, bool(ok), lat) for ts, ok, lat in rows]

    def errors(self, target: str, since: float) -> dict[str, int]:
        rows = self.conn.execute(
            "SELECT error, COUNT(*) FROM probes WHERE target=? AND ts>=? AND ok=0 "
            "GROUP BY error",
            (target, since),
        )
        return {e or "unknown": n for e, n in rows}

    def close(self) -> None:
        self.conn.close()
