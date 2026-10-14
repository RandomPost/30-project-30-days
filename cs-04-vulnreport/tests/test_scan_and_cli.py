import json

import pytest

from vulnreport import cli
from vulnreport.report import to_json, to_markdown, to_text
from vulnreport.scan import at_or_above


def run(args, fake, capsys, tmp_path):
    ns = cli.build_parser().parse_args([*args, "--cache-dir", str(tmp_path / "cache")])
    code = cli.run(ns, transport=fake.transport())
    return code, capsys.readouterr()


def test_report_grouped_worst_first(fake_osv, capsys, tmp_path, fixtures_dir):
    code, out = run(
        [str(fixtures_dir / "requirements.txt")], fake_osv, capsys, tmp_path
    )
    text = out.out
    assert code == 0  # no --fail-on
    assert text.index("CRITICAL") < text.index("MEDIUM")
    assert "upgrade to 2.11.3" in text and "3 dependencies" in text


def test_fail_on_high_exits_1(fake_osv, capsys, tmp_path, fixtures_dir):
    args = [str(fixtures_dir / "requirements.txt"), "--fail-on", "high"]
    assert run(args, fake_osv, capsys, tmp_path)[0] == 1


def test_fail_on_critical_ignores_lower(fake_osv, capsys, tmp_path, fixtures_dir):
    # poetry.lock fixture only has flask (LOW) and requests (clean)
    args = [str(fixtures_dir / "poetry.lock"), "--fail-on", "high"]
    assert run(args, fake_osv, capsys, tmp_path)[0] == 0
    args = [str(fixtures_dir / "poetry.lock"), "--fail-on", "low"]
    assert run(args, fake_osv, capsys, tmp_path)[0] == 1


def test_npm_lockfile_critical(fake_osv, capsys, tmp_path, fixtures_dir):
    args = [str(fixtures_dir / "package-lock.json"), "--fail-on", "critical"]
    assert run(args, fake_osv, capsys, tmp_path)[0] == 1


def test_json_and_markdown_formats(fake_osv, capsys, tmp_path, fixtures_dir):
    path = str(fixtures_dir / "requirements.txt")
    _, out = run([path, "--format", "json"], fake_osv, capsys, tmp_path)
    data = json.loads(out.out)
    assert data[0]["severity"] == "CRITICAL" and data[0]["fixed"] == ["2.11.3"]
    _, out = run(
        [path, "--format", "markdown", "--no-cache"], fake_osv, capsys, tmp_path
    )
    assert "## CRITICAL (1)" in out.out and "| jinja2 | 2.4.1 |" in out.out


def test_clean_report(fake_osv, capsys, tmp_path):
    lock = tmp_path / "requirements.txt"
    lock.write_text("requests==2.31.0\n")
    code, out = run([str(lock), "--fail-on", "low"], fake_osv, capsys, tmp_path)
    assert code == 0 and "No known vulnerabilities in 1" in out.out


def test_api_failure_exit_2(capsys, tmp_path, fixtures_dir, monkeypatch):
    from conftest import FakeOsv

    monkeypatch.setattr("vulnreport.osv.MAX_RETRIES", 1)
    code, out = run(
        [str(fixtures_dir / "requirements.txt")],
        FakeOsv(fail_first=9, status=500),
        capsys,
        tmp_path,
    )
    assert code == 2 and "error:" in out.err


def test_report_helpers_empty():
    assert "No known" in to_text([], 4)
    assert "No known" in to_markdown([], 4)
    assert to_json([]) == "[]"
    assert at_or_above([], "high") == []
