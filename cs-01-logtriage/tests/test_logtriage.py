from datetime import datetime, timedelta

from logtriage.cli import main
from logtriage.detector import detect, max_in_window
from logtriage.parser import parse_line, parse_lines
from logtriage.sample import generate

SYSLOG = "Oct 12 03:01:04 host sshd[12]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2"
ISO = "2026-10-12T03:01:04+00:00 host sshd[12]: Failed password for root from 5.6.7.8 port 22 ssh2"


def test_parse_syslog_invalid_user():
    f = parse_line(SYSLOG, 2026)
    assert (f.user, f.ip) == ("bob", "1.2.3.4")
    assert f.time == datetime(2026, 10, 12, 3, 1, 4)


def test_parse_iso_valid_user():
    f = parse_line(ISO, 2026)
    assert (f.user, f.ip) == ("root", "5.6.7.8")


def test_ignores_success_and_junk():
    ok = "Oct 12 03:01:04 host sshd[1]: Accepted password for bob from 1.2.3.4 port 22"
    assert parse_line(ok, 2026) is None
    assert parse_line("garbage", 2026) is None


def test_max_in_window():
    t0 = datetime(2026, 1, 1)
    times = [t0 + timedelta(seconds=s) for s in (0, 10, 20, 200)]
    assert max_in_window(times, timedelta(seconds=60)) == 3


def test_detect_flags_burst_only():
    findings = detect(parse_lines(generate(), 2026), threshold=5, window_seconds=60)
    flagged = {f.ip for f in findings if f.flagged}
    assert flagged == {"203.0.113.9", "198.51.100.23"}
    assert findings[0].ip == "203.0.113.9"
    assert not [f for f in findings if f.ip == "192.0.2.44"][0].flagged


def test_threshold_is_configurable():
    findings = detect(parse_lines(generate(), 2026), threshold=100)
    assert not any(f.flagged for f in findings)


def test_cli_end_to_end(tmp_path, capsys):
    log = tmp_path / "auth.log"
    out = tmp_path / "r.json"
    assert main(["generate", str(log)]) == 0
    assert main(["analyze", str(log), "--year", "2026", "--json", str(out)]) == 1
    assert "BRUTE-FORCE" in capsys.readouterr().out
    assert out.read_text().startswith("[")
