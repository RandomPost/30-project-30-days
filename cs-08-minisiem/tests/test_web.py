from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from conftest import load_logs
from minisiem.db import connect
from minisiem.engine import run_rules
from minisiem.rules import load_rules
from minisiem.web import make_server


@pytest.fixture
def server(tmp_path, rules_dir):
    db = str(tmp_path / "web.db")
    conn = connect(db)
    load_logs(conn, None, True, tmp_path)
    run_rules(conn, load_rules(rules_dir))
    conn.close()
    srv = make_server(db, 0)
    t = threading.Thread(
        target=lambda: srv.serve_forever(poll_interval=0.01), daemon=True
    )
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}", srv
    srv.shutdown()
    srv.server_close()


def fetch(url, method="GET"):
    req = urllib.request.Request(url, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_binds_to_loopback_only(server):
    _, srv = server
    assert srv.server_address[0] == "127.0.0.1"


def test_summary_counts_by_severity_and_timeline(server):
    base, _ = server
    status, headers, body = fetch(base + "/api/summary")
    data = json.loads(body)
    assert status == 200 and headers["Content-Type"] == "application/json"
    assert data["alerts_total"] >= 15 and data["by_severity"]["critical"] == 2
    assert sum(data["by_severity"].values()) == data["alerts_total"]
    assert data["events_total"] > 600
    assert len(data["timeline"]) >= 8 and data["timeline"] == sorted(
        data["timeline"], key=lambda r: r["bucket"]
    )
    assert {r["rule_id"] for r in data["by_rule"]} >= {"ssh-brute-force", "web-sqli"}


def test_alerts_endpoint_filters_and_limits(server):
    base, _ = server
    crit = json.loads(fetch(base + "/api/alerts?severity=critical")[2])
    assert len(crit) == 2 and all(a["severity"] == "critical" for a in crit)
    assert isinstance(crit[0]["details"]["sample"], list) and crit[0]["tags"]
    one = json.loads(fetch(base + "/api/alerts?limit=1")[2])
    assert len(one) == 1
    rule = json.loads(fetch(base + "/api/alerts?rule=ssh-brute-force")[2])
    assert [a["rule_id"] for a in rule] == ["ssh-brute-force"]


@pytest.mark.parametrize(
    "q", ["severity=%27%20OR%201=1--", "severity=bogus", "limit=abc"]
)
def test_bad_parameters_are_400_not_sql_errors(server, q):
    base, _ = server
    assert fetch(base + "/api/alerts?" + q)[0] == 400


def test_sql_in_rule_parameter_is_just_a_value(server):
    base, _ = server
    status, _, body = fetch(base + "/api/alerts?rule=x%27%20OR%201=1--")
    assert status == 200 and json.loads(body) == []


def test_security_headers_on_every_response(server):
    base, _ = server
    for path in ("/", "/app.js", "/style.css", "/api/summary", "/missing"):
        _, h, _ = fetch(base + path)
        assert "script-src 'self'" in h["Content-Security-Policy"]
        assert "unsafe-inline" not in h["Content-Security-Policy"]
        assert h["X-Content-Type-Options"] == "nosniff"


def test_static_files_served_with_correct_types(server):
    base, _ = server
    assert fetch(base + "/")[1]["Content-Type"].startswith("text/html")
    assert fetch(base + "/app.js")[1]["Content-Type"].startswith("text/javascript")
    assert fetch(base + "/style.css")[1]["Content-Type"].startswith("text/css")


def test_unknown_paths_and_traversal_are_404(server):
    base, _ = server
    for path in (
        "/nope",
        "/../pyproject.toml",
        "/%2e%2e/pyproject.toml",
        "/static/app.js",
    ):
        assert fetch(base + path)[0] == 404


def test_server_is_read_only(server):
    base, _ = server
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        assert fetch(base + "/api/alerts", method)[0] == 405


def test_attacker_controlled_text_is_returned_as_data_not_markup(server, tmp_path):
    """Log lines are hostile input: the API returns them inside JSON, and the page
    script never uses innerHTML / document.write / eval for them."""
    from pathlib import Path

    import minisiem.web as web

    js = (Path(web.STATIC) / "app.js").read_text()
    for banned in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "Function(",
    ):
        assert banned not in js
    html = (Path(web.STATIC) / "index.html").read_text()
    assert "<script>" not in html and " onclick=" not in html and "style=" not in html
