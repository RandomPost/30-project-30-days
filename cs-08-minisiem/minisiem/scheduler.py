"""Scheduled run: pick up new log lines, then evaluate every rule."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .db import connect
from .engine import run_rules
from .ingest import IngestResult, guess_source, ingest_file
from .rules import load_rules


@dataclass
class TickResult:
    ingested: IngestResult
    new_alerts: dict[str, int]

    @property
    def total_new(self) -> int:
        return sum(self.new_alerts.values())


def tick(db_path: str, rules_dir: str, logs_dir: str | None, year: int) -> TickResult:
    """One scheduler pass. Rules are reloaded each time so edits take effect."""
    rules = load_rules(rules_dir)
    conn = connect(db_path)
    try:
        ingested = IngestResult()
        if logs_dir:
            for path in sorted(Path(logs_dir).iterdir()):
                source = guess_source(path.name)
                if path.is_file() and source:
                    ingested += ingest_file(conn, str(path), source, year)
        return TickResult(ingested, run_rules(conn, rules))
    finally:
        conn.close()


def run_schedule(
    db_path: str,
    rules_dir: str,
    logs_dir: str | None,
    year: int,
    interval: float = 60.0,
    iterations: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    out: Callable[[str], None] = print,
) -> None:
    n = 0
    while iterations is None or n < iterations:
        try:
            res = tick(db_path, rules_dir, logs_dir, year)
            fired = {k: v for k, v in res.new_alerts.items() if v}
            out(
                f"tick {n + 1}: {res.ingested.parsed} new events, "
                f"{res.total_new} new alerts {fired or ''}".rstrip()
            )
        except Exception as exc:  # keep the schedule alive; a bad rule edit is fixable
            out(f"tick {n + 1} failed: {exc}")
        n += 1
        if iterations is None or n < iterations:
            sleep(interval)
