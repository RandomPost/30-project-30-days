import subprocess
from pathlib import Path

import pytest

from confdrift import cli
from confdrift.config import ConfigError, credentials, load_config
from confdrift.fetch import FetchError

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"


class FakeFetcher:
    """Stands in for Netmiko: serves the real captured configs, optionally altered."""

    def __init__(self, overrides=None, down=()):
        self.overrides, self.down = overrides or {}, set(down)

    def fetch(self, device):
        if device.name in self.down:
            raise FetchError("timed out connecting to " + device.host)
        text = (FIX / f"{device.name}-running.txt").read_text()
        for old, new in self.overrides.get(device.name, []):
            assert old in text
            text = text.replace(old, new, 1)
        return text


@pytest.fixture
def cfg(tmp_path):
    (tmp_path / "devices.yml").write_text(
        f"intended: {ROOT / 'intended' / 'lab.yml'}\nbackups: {tmp_path / 'bk'}\n"
        "devices:\n  - {name: r1, host: h1}\n  - {name: r2, host: h2}\n  - {name: r3, host: h3}\n"
    )
    return load_config(tmp_path / "devices.yml")


def test_drift_clean(cfg, capsys):
    assert cli.run_drift(cfg, FakeFetcher()) == 0
    assert capsys.readouterr().out.count("in sync") == 3


def test_manual_change_shows_as_drift_per_device(cfg, capsys):
    f = FakeFetcher({"r2": [("ip ospf cost 10", "ip ospf cost 500")]})
    assert cli.run_drift(cfg, f) == 1
    out = capsys.readouterr().out
    assert "r1: in sync" in out and "r3: in sync" in out
    assert "r2: DRIFT" in out and "unexpected on device: ip ospf cost 500" in out


def test_unreachable_device_is_exit_2_and_not_called_in_sync(cfg, capsys):
    assert cli.run_drift(cfg, FakeFetcher(down=["r3"])) == 2
    cap = capsys.readouterr()
    assert "r3: in sync" not in cap.out and "FAILED r3: timed out" in cap.err


def test_backup_commits_once_per_run_and_only_on_change(cfg, capsys):
    assert cli.run_backup(cfg, FakeFetcher()) == 0
    assert "first snapshot of 3 device(s)" in capsys.readouterr().out
    assert cli.run_backup(cfg, FakeFetcher()) == 0
    assert "nothing committed" in capsys.readouterr().out
    f = FakeFetcher({"r1": [("ip ospf cost 10", "ip ospf cost 77")]})
    assert cli.run_backup(cfg, f) == 0
    assert "config changed on r1 (+1/-1 lines)" in capsys.readouterr().out
    log = subprocess.run(
        ["git", "-C", str(cfg.backups), "log", "--format=%s"],
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    assert len(log) == 2


def test_backup_survives_one_device_down_and_keeps_old_copy(cfg, capsys):
    cli.run_backup(cfg, FakeFetcher())
    f = FakeFetcher({"r1": [("ip ospf cost 10", "ip ospf cost 77")]}, down=["r2"])
    assert cli.run_backup(cfg, f) == 2
    assert (cfg.backups / "r2.cfg").exists()
    assert (
        "r2: timed out"
        in subprocess.run(
            ["git", "-C", str(cfg.backups), "log", "-1", "--format=%b"],
            capture_output=True,
            text=True,
        ).stdout
    )


def test_stored_backup_has_no_cli_chrome_and_no_secrets(cfg):
    class Noisy(FakeFetcher):
        def fetch(self, device):
            return (
                "Building configuration...\n"
                + super().fetch(device)
                + "\nenable secret 5 $1$abc\n"
            )

    cli.run_backup(cfg, Noisy())
    text = (cfg.backups / "r1.cfg").read_text()
    assert "Building configuration" not in text and "$1$abc" not in text
    assert "enable secret 5 <redacted>" in text


def test_main_requires_credentials_from_environment(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("CONFDRIFT_USER", raising=False)
    monkeypatch.delenv("CONFDRIFT_PASSWORD", raising=False)
    assert cli.main(["-c", str(ROOT / "devices.yml"), "drift"]) == 2
    assert "CONFDRIFT_USER and CONFDRIFT_PASSWORD" in capsys.readouterr().err


def test_credentials_helper():
    assert credentials({"CONFDRIFT_USER": "u", "CONFDRIFT_PASSWORD": "p"}) == ("u", "p")
    with pytest.raises(ConfigError, match="CONFDRIFT_PASSWORD"):
        credentials({"CONFDRIFT_USER": "u"})


@pytest.mark.parametrize("key", ["password", "enable_secret", "api_token", "ssh_key"])
def test_devices_file_rejects_credential_keys(tmp_path, key):
    p = tmp_path / "d.yml"
    p.write_text(
        f"intended: i.yml\ndevices:\n  - name: r1\n    host: h\n    {key}: hunter2\n"
    )
    with pytest.raises(ConfigError, match="never from files"):
        load_config(p)


def test_devices_file_rejects_duplicates_and_unknown_fields(tmp_path):
    p = tmp_path / "d.yml"
    p.write_text(
        "intended: i.yml\ndevices:\n  - {name: r1, host: a}\n  - {name: r1, host: b}\n"
    )
    with pytest.raises(ConfigError, match="duplicate"):
        load_config(p)
    p.write_text("intended: i.yml\ndevices:\n  - {name: r1, host: a, colour: red}\n")
    with pytest.raises(ConfigError, match="colour"):
        load_config(p)


def test_device_missing_from_intended_is_an_error(tmp_path, capsys):
    p = tmp_path / "d.yml"
    p.write_text(
        f"intended: {ROOT / 'intended' / 'lab.yml'}\ndevices:\n  - {{name: r9, host: a}}\n"
    )
    cfg = load_config(p)
    with pytest.raises(ConfigError, match="r9"):
        cli.run_drift(cfg, FakeFetcher())


def test_intended_command_renders_all_devices(capsys):
    assert cli.main(["-c", str(ROOT / "devices.yml"), "intended"]) == 0
    out = capsys.readouterr().out
    assert "### r1" in out and "### r3" in out and "ospf router-id 10.255.0.3" in out
