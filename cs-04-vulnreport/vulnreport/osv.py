"""OSV.dev client: batch query for ids, then fetch each vulnerability record.

API (https://google.github.io/osv.dev/api/):
  POST /v1/querybatch  {"queries":[{"package":{"name","ecosystem"},"version"}]}
       -> {"results":[{"vulns":[{"id","modified"}]}, ...]}  (same order as queries)
  GET  /v1/vulns/{id}  -> full record (severity, affected ranges, aliases...)
"""

from __future__ import annotations

import time
from typing import Any, Callable

import httpx

from .cache import Cache
from .models import Dep

BASE = "https://api.osv.dev"
BATCH_SIZE = 1000
MAX_RETRIES = 5


class OsvError(RuntimeError):
    pass


class OsvClient:
    def __init__(
        self,
        cache: Cache,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.cache = cache
        self.http = client or httpx.Client(base_url=BASE, timeout=30)
        self.sleep = sleep

    def _request(self, method: str, url: str, **kw: Any) -> Any:
        """Retry 429 and 5xx with Retry-After or exponential backoff."""
        for attempt in range(MAX_RETRIES):
            try:
                resp = self.http.request(method, url, **kw)
            except httpx.TransportError:
                resp = None
            if resp is not None and resp.status_code < 400:
                return resp.json()
            retryable = resp is None or resp.status_code in (429, 500, 502, 503, 504)
            if not retryable:
                raise OsvError(f"{method} {url} failed: HTTP {resp.status_code}")
            if attempt < MAX_RETRIES - 1:
                self.sleep(self._delay(resp, attempt))
        raise OsvError(f"{method} {url} failed after {MAX_RETRIES} attempts")

    @staticmethod
    def _delay(resp: httpx.Response | None, attempt: int) -> float:
        ra = resp.headers.get("retry-after", "") if resp is not None else ""
        return float(ra) if ra.isdigit() else float(2**attempt)

    def vuln_ids(self, deps: list[Dep]) -> dict[Dep, list[str]]:
        """Map each dependency to the ids of vulnerabilities affecting it."""
        found: dict[Dep, list[str]] = {}
        todo: list[Dep] = []
        for d in deps:
            cached = self.cache.get(_dep_key(d))
            if cached is None:
                todo.append(d)
            else:
                found[d] = cached
        for i in range(0, len(todo), BATCH_SIZE):
            chunk = todo[i : i + BATCH_SIZE]
            body = {"queries": [_query(d) for d in chunk]}
            results = self._request("POST", "/v1/querybatch", json=body)["results"]
            for d, res in zip(chunk, results):
                ids = [v["id"] for v in res.get("vulns", [])]
                self.cache.put(_dep_key(d), ids)
                found[d] = ids
        return found

    def vuln(self, vuln_id: str) -> dict:
        key = f"vuln:{vuln_id}"
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        record = self._request("GET", f"/v1/vulns/{vuln_id}")
        self.cache.put(key, record)
        return record


def _query(d: Dep) -> dict:
    return {
        "package": {"name": d.name, "ecosystem": d.ecosystem},
        "version": d.version,
    }


def _dep_key(d: Dep) -> str:
    return f"query:{d.ecosystem}:{d.name}:{d.version}"
