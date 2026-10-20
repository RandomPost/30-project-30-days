"""Docker hardening settings and the command line."""

from __future__ import annotations

import json
import re
import subprocess
import sys

import pytest
import yaml

from conftest import ROOT
from sshpot.cli import main


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"][
        "sshpot"
    ]


def test_compose_runs_read_only_non_root_with_no_capabilities(compose):
    assert compose["read_only"] is True
    assert compose["cap_drop"] == ["ALL"] and "cap_add" not in compose
    assert "no-new-privileges:true" in compose["security_opt"]
    assert compose["user"] == "10001:10001"
    assert not compose.get("privileged")
    assert compose["pids_limit"] <= 256 and compose["mem_limit"]


def test_compose_publishes_loopback_only_and_mounts_only_the_data_volume(compose):
    assert compose["ports"] == ["127.0.0.1:2222:2222"]
    mounts = compose["volumes"]
    assert mounts == ["sshpot-data:/data"]
    assert not any("docker.sock" in m or m.startswith(("/", ".")) for m in mounts)
    assert all("noexec" in t for t in compose["tmpfs"])
    assert compose.get("network_mode") != "host" and compose.get("pid") != "host"


def test_dockerfile_drops_to_a_non_root_user_and_stays_minimal():
    text = (ROOT / "Dockerfile").read_text()
    users = re.findall(r"^USER\s+(\S+)", text, re.M)
    assert users and users[-1] == "10001:10001"
    assert text.index("USER 10001") > text.index("pip install")  # root only to install
    assert re.search(r"^HEALTHCHECK", text, re.M) and "EXPOSE 2222" in text
    assert "ADD http" not in text and "curl" not in text and "sudo" not in text
    assert "--privileged" not in text
    assert 'ENTRYPOINT ["sshpot"]' in text


def test_verify_script_checks_each_hardening_property():
    text = (ROOT / "scripts" / "verify-hardening.sh").read_text()
    for needle in (
        "ReadonlyRootfs",
        "CapDrop",
        "no-new-privileges",
        "CapEff",
        "10001",
        "noexec",
        "sshpot simulate",
        "sshpot analyze",
    ):
        assert needle in text
    assert (ROOT / "scripts" / "verify-hardening.sh").stat().st_mode & 0o111


def test_sample_then_analyze_text_json_and_markdown(tmp_path, capsys):
    log = str(tmp_path / "s.jsonl")
    assert main(["sample", log, "--seed", "3"]) == 0
    capsys.readouterr()
    assert main(["analyze", log]) == 0
    text = capsys.readouterr().out
    assert (
        "Top credential pairs" in text
        and "Source countries" in text
        and "Sample A" in text
    )
    assert main(["analyze", log, "--json", "--top", "2"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["summary"]["connections"] == 60 and len(rep["top_passwords"]) == 2
    assert main(["analyze", log, "--md"]) == 0
    assert capsys.readouterr().out.startswith("# Honeypot report")


def test_analyze_uses_a_custom_geoip_file(tmp_path, capsys):
    log, geo = str(tmp_path / "s.jsonl"), tmp_path / "geo.csv"
    main(["sample", log])
    geo.write_text(
        "192.0.2.0,192.0.2.255,US\n198.51.100.0,198.51.100.255,CN\n203.0.113.0,203.0.113.255,RU\n"
    )
    capsys.readouterr()
    main(["analyze", log, "--geoip", str(geo), "--json"])
    codes = {c["country"] for c in json.loads(capsys.readouterr().out)["countries"]}
    assert codes == {"US", "CN", "RU"}


def test_healthcheck_fails_when_nothing_listens():
    assert main(["healthcheck", "--port", "1"]) == 1


async def test_healthcheck_and_simulate_against_a_live_honeypot(make_pot):
    pot = await make_pot(quiet_loopback=False)
    loop = __import__("asyncio").get_running_loop()
    assert (
        await loop.run_in_executor(None, main, ["healthcheck", "--port", str(pot.port)])
        == 0
    )
    from sshpot.simulate import run

    stats = await run("127.0.0.1", pot.port)
    assert (
        stats["denied"] == 2
        and stats["sessions"] == 3
        and stats["forward_refused"] == 1
    )
    await pot.settle()
    from sshpot.analytics import analyze, read_events

    events, bad = read_events(open(pot.cfg.log_path))
    rep = analyze(events)
    assert bad == 0 and rep["summary"]["successful_logins"] == 1
    assert rep["summary"]["forward_attempts"] == 1
    assert {u["value"] for u in rep["indicator_urls"]} == {
        "http://203.0.113.9/x.sh",
        "http://198.51.100.4/payload",
    }
    assert len(rep["command_sequences"]) == 4  # three shells and one exec


def test_cli_help_lists_the_subcommands():
    r = subprocess.run(
        [sys.executable, "-m", "sshpot.cli", "--help"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert r.returncode == 0
    for cmd in ("serve", "analyze", "sample", "simulate", "healthcheck"):
        assert cmd in r.stdout


def test_serve_rejects_malformed_accept_pairs():
    with pytest.raises(SystemExit):
        main(["serve", "--accept", "nocolon"])
