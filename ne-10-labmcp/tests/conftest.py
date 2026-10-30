from pathlib import Path

import pytest

from labmcp import tools

FIX = Path(__file__).parent / "fixtures"


class FakeRunner:
    """Records every command; answers from fixtures."""

    def __init__(self):
        self.vtysh_calls, self.pings = [], []

    def vtysh(self, device, command):
        from labmcp.runner import check_vtysh

        check_vtysh(command)  # the fake enforces the same allow-list as the real runner
        self.vtysh_calls.append((device, command))
        if command == "show running-config":
            return (FIX / "cust-running.conf").read_text()
        if command.endswith("json"):
            return (FIX / "cust-198.18.0.0.json").read_text()
        return f"output of {command}"

    def ping(self, device, target):
        self.pings.append((device, target))
        return "3 packets transmitted, 3 packets received"

    def is_running(self, device):
        return device != "rogue"


@pytest.fixture
def runner():
    return FakeRunner()


@pytest.fixture
def cfg(runner, tmp_path):
    lab = tmp_path / "lab"
    (lab / "designs" / "a").mkdir(parents=True)
    (lab / "designs" / "a" / "cust.conf").write_text(
        (FIX / "cust-intended.conf").read_text()
    )
    bf = tmp_path / "bf"
    (bf / "changes").mkdir(parents=True)
    (bf / "changes" / "bad-acl-name-typo.patch").write_text("")
    return tools.Config(runner=runner, lab_dir=lab, design="a", batfish_dir=bf)
