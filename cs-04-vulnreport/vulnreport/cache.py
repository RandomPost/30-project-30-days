"""Tiny JSON file cache keyed by a string. I/O lives here, not in the client."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable


class Cache:
    def __init__(
        self,
        directory: Path | None,
        ttl: float = 24 * 3600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.dir = directory
        self.ttl = ttl
        self.clock = clock

    def _path(self, key: str) -> Path | None:
        if self.dir is None:
            return None
        return self.dir / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")

    def get(self, key: str) -> Any | None:
        p = self._path(key)
        if p is None or not p.is_file():
            return None
        try:
            entry = json.loads(p.read_text())
        except (OSError, ValueError):
            return None
        if self.clock() - entry["at"] > self.ttl:
            return None
        return entry["value"]

    def put(self, key: str, value: Any) -> None:
        p = self._path(key)
        if p is None:
            return
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"at": self.clock(), "value": value}))
