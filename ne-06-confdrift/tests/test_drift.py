from pathlib import Path

import pytest

from confdrift import drift, normalize
from confdrift.redact import redact

FIX = Path(__file__).parent / "fixtures"


def fx(name):
    return (FIX / name).read_text()


@pytest.mark.parametrize("r", ["r1", "r2", "r3"])
def test_real_lab_configs_are_in_sync(r):
    """Fixtures are real `vtysh show running-config` output from the NE-04 lab and
    the matching netgen render; they must compare equal."""
    d = drift.compare(r, fx(f"{r}-intended.txt"), fx(f"{r}-running.txt"))
    assert not d.drifted, d.report()


def test_changed_value_is_reported_as_missing_plus_unexpected():
    running = fx("r1-running.txt").replace(
        "ip ospf cost 10\n ip ospf dead-interval 3",
        "ip ospf cost 100\n ip ospf dead-interval 3",
        1,
    )
    d = drift.compare("r1", fx("r1-intended.txt"), running)
    assert d.drifted and d.line_count == 2
    assert d.missing == {"interface eth1": ["ip ospf cost 10"]}
    assert d.extra == {"interface eth1": ["ip ospf cost 100"]}
    text = d.report()
    assert "r1: DRIFT (2 line(s) differ)" in text
    assert "\n- ip ospf cost 10\n" in text
    assert "+ ip ospf cost 100" in text
    assert "--- intended/r1" in text and "+++ running/r1" in text


def test_extra_line_on_device():
    running = fx("r2-running.txt").replace(
        "router ospf\n", "router ospf\n default-information originate always\n"
    )
    d = drift.compare("r2", fx("r2-intended.txt"), running)
    assert d.extra == {"router ospf": ["default-information originate always"]}
    assert not d.missing


def test_missing_and_extra_blocks():
    running = fx("r3-running.txt")
    # remove eth3 entirely, add a loopback1
    head, rest = running.split("interface eth3", 1)
    tail = rest.split("exit\n", 1)[1]
    running = head + tail + "\ninterface lo1\n ip address 1.1.1.1/32\nexit\n"
    d = drift.compare("r3", fx("r3-intended.txt"), running)
    assert "interface eth3" in d.missing_blocks
    assert d.extra_blocks == {"interface lo1": ["ip address 1.1.1.1/32"]}
    rep = d.report()
    assert "missing on device: interface eth3" in rep
    assert "unexpected on device: interface lo1" in rep


def test_hostname_change_is_drift():
    d = drift.compare(
        "r1",
        fx("r1-intended.txt"),
        fx("r1-running.txt").replace("hostname r1", "hostname r9"),
    )
    assert "hostname r1" in d.missing_blocks and "hostname r9" in d.extra_blocks


def test_order_and_noise_are_ignored():
    a = "hostname x\n!\ninterface eth1\n ip address 1.1.1.1/24\n description a\nexit\n"
    b = (
        "Building configuration...\n\n% Can't open configuration file\n"
        "frr version 8.4.4\nlog stdout informational\nhostname x\n!\n"
        "interface eth1\n description a\n ip address 1.1.1.1/24\nexit\nend\n"
    )
    assert not drift.compare("x", a, b).drifted


def test_secrets_are_masked_before_comparison_and_in_report():
    a = "hostname x\nusername admin secret 5 AAA\n"
    b = "hostname x\nusername admin secret 5 BBB\n"
    d = drift.compare("x", a, b)
    assert not d.drifted  # a rotated password is not config drift
    assert "BBB" not in d.report()


@pytest.mark.parametrize(
    "line,secret",
    [
        ("username admin privilege 15 secret 9 $9$abc", "$9$abc"),
        ("enable secret 5 $1$xyz", "$1$xyz"),
        ("enable password hunter2", "hunter2"),
        ("snmp-server community public RO", "public"),
        (" ip ospf message-digest-key 1 md5 sup3rsecret", "sup3rsecret"),
        ("tacacs-server host 10.0.0.1 key 7 0822455D0A16", "0822455D0A16"),
    ],
)
def test_redact(line, secret):
    out = redact(line + "\n")
    assert secret not in out and "<redacted>" in out


def test_redact_leaves_normal_lines_alone():
    text = (
        "interface eth1\n description password-vault uplink\n ip address 1.1.1.1/24\n"
    )
    assert redact(text) == text


def test_canonical_is_stable():
    blocks = normalize.parse("interface b\n y\n x\ninterface a\n z\n")
    assert normalize.canonical(blocks) == "interface a\n z\ninterface b\n x\n y\n"


def test_strip_chrome_removes_per_run_noise():
    raw = (
        "\n% Can't open configuration file /etc/frr/vtysh.conf\n"
        "Building configuration...\n\nCurrent configuration:\n!\n"
        "! Last configuration change at 10:01:02 UTC Mon Oct 26 2026\nhostname r1\n"
    )
    assert normalize.strip_chrome(raw) == "!\nhostname r1\n"
