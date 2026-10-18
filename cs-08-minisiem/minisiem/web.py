"""Read-only alert dashboard on the standard library HTTP server.

Binds to 127.0.0.1 only and has no authentication, so it must not be exposed.
Everything shown comes from log files an attacker may control; the page builds its
DOM with textContent only and a strict CSP forbids inline script.
"""

from __future__ import annotations

import json
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .db import SEVERITIES, connect

STATIC = Path(__file__).parent / "static"
FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
HOST = "127.0.0.1"
MAX_LIMIT = 500


def summary(conn: sqlite3.Connection) -> dict:
    by_sev = {s: 0 for s in SEVERITIES}
    for r in conn.execute("SELECT severity, COUNT(*) c FROM alerts GROUP BY severity"):
        by_sev[r["severity"]] = r["c"]
    timeline: dict[str, dict] = {}
    for r in conn.execute(
        "SELECT substr(first_ts, 1, 13) || ':00:00Z' AS bucket, severity, COUNT(*) c "
        "FROM alerts GROUP BY bucket, severity ORDER BY bucket"
    ):
        row = timeline.setdefault(r["bucket"], {s: 0 for s in SEVERITIES})
        row[r["severity"]] = r["c"]
    by_rule = [
        dict(r)
        for r in conn.execute(
            "SELECT rule_id, title, severity, COUNT(*) AS alerts, "
            "SUM(event_count) AS events FROM alerts GROUP BY rule_id "
            "ORDER BY alerts DESC, rule_id"
        )
    ]
    return {
        "events_total": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "alerts_total": sum(by_sev.values()),
        "by_severity": by_sev,
        "timeline": [{"bucket": b, **v} for b, v in timeline.items()],
        "by_rule": by_rule,
    }


def alerts(conn: sqlite3.Connection, qs: dict) -> list[dict]:
    where, params = [], []
    sev = qs.get("severity", [""])[0]
    if sev:
        if sev not in SEVERITIES:
            raise ValueError("bad severity")
        where.append("severity = ?")
        params.append(sev)
    rule = qs.get("rule", [""])[0]
    if rule:
        where.append("rule_id = ?")
        params.append(rule)
    try:
        limit = int(qs.get("limit", ["100"])[0])
    except ValueError:
        raise ValueError("bad limit") from None
    limit = max(1, min(limit, MAX_LIMIT))
    sql = (
        "SELECT id, rule_id, title, severity, tags, group_key, first_ts, last_ts, "
        "event_count, details FROM alerts"
        + (" WHERE " + " AND ".join(where) if where else "")
        + " ORDER BY first_ts DESC, id DESC LIMIT ?"
    )
    out = []
    for r in conn.execute(sql, [*params, limit]):
        d = dict(r)
        d["details"] = json.loads(d["details"])
        d["tags"] = [t for t in d["tags"].split(",") if t]
        out.append(d)
    return out


def make_handler(db_path: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "minisiem"

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj).encode(), "application/json")

        def do_GET(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            if url.path in FILES:
                name, ctype = FILES[url.path]
                self._send(200, (STATIC / name).read_bytes(), ctype)
                return
            if url.path not in ("/api/summary", "/api/alerts"):
                self._json(404, {"error": "not found"})
                return
            conn = connect(db_path)
            try:
                if url.path == "/api/summary":
                    self._json(200, summary(conn))
                else:
                    self._json(200, alerts(conn, parse_qs(url.query)))
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
            finally:
                conn.close()

        def do_POST(self) -> None:  # noqa: N802
            self._json(405, {"error": "read-only"})

        do_PUT = do_DELETE = do_PATCH = do_POST

        def log_message(self, fmt, *args) -> None:
            pass

    return Handler


def make_server(db_path: str, port: int = 8080) -> ThreadingHTTPServer:
    connect(db_path).close()  # create tables if the database is new
    return ThreadingHTTPServer((HOST, port), make_handler(db_path))
