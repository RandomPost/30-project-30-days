import pytest

from labmcp.runner import CommandRefused, check_vtysh

OK = [
    "show ip route",
    "show ip route 203.0.113.0/24",
    "show bgp ipv4 unicast",
    "show bgp ipv4 unicast 203.0.113.0/24 json",
    "show bgp summary",
    "show bgp summary json",
    "show interface brief",
    "show running-config",
]
REFUSED = [
    "configure terminal",
    "conf t",
    "clear ip bgp *",
    "write memory",
    "show running-config; configure terminal",
    "show ip route 1.2.3.0/24\nconfigure terminal",
    "show ip route && reload",
    "shutdown",
    "no router bgp 65100",
    "enable",
    "show bgp ipv4 unicast 1.2.3.0/24 json | include x",
    "",
]


@pytest.mark.parametrize("cmd", OK)
def test_allowed(cmd):
    assert check_vtysh(cmd) == cmd


@pytest.mark.parametrize("cmd", REFUSED)
def test_refused(cmd):
    with pytest.raises(CommandRefused):
        check_vtysh(cmd)
