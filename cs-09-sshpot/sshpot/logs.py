"""JSON-lines event log with field clipping and single-file rotation."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Callable

MAX_FIELD = 1024


def clip(value, limit: int = MAX_FIELD):
    """Bound attacker-supplied strings so one session cannot flood the log."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + f"...[+{len(value) - limit} chars]"
    return value


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class JsonlLogger:
    """Append one JSON object per line to `path` (and optionally to stdout).

    When the file passes `max_bytes` it is renamed to `<path>.1` (replacing any older
    one), so the writable volume cannot be filled by an attacker.
    """

    def __init__(
        self,
        path: str | None,
        max_bytes: int = 50 * 1024 * 1024,
        stdout: bool = False,
        clock: Callable[[], str] = utcnow,
    ):
        self.path = path
        self.max_bytes = max_bytes
        self.stdout = stdout
        self.clock = clock
        self._fh = None
        if path:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            self._open()

    def _open(self) -> None:
        self._fh = open(self.path, "a", encoding="utf-8")

    def _rotate_if_needed(self) -> None:
        if self._fh and self._fh.tell() >= self.max_bytes:
            self._fh.close()
            os.replace(self.path, self.path + ".1")
            self._open()

    def log(self, event: str, **fields) -> dict:
        record = {"ts": self.clock(), "event": event}
        record.update({k: clip(v) for k, v in fields.items()})
        line = json.dumps(record, ensure_ascii=True, separators=(",", ":"))
        if self._fh:
            self._rotate_if_needed()
            self._fh.write(line + "\n")
            self._fh.flush()
        if self.stdout:
            print(line, file=sys.stdout, flush=True)
        return record

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None
