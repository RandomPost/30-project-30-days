from pathlib import Path

import pytest

from lldpmap.models import Neighbor
from lldpmap.parsers import ios

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return (FIX / name).read_text()


def test_contract_constants():
    assert ios.VENDOR == "ios"
    assert ios.NEIGHBOR_COMMAND == "show lldp neighbors detail"
    assert ios.CDP_COMMAND == "show cdp neighbors detail"
    assert ios.HOSTNAME_COMMAND == "show running-config | include ^hostname"


def test_lldp_two_neighbors():
    n = ios.parse_neighbors(load("ios-lldp-detail.txt"))
    assert len(n) == 2
    assert n[0] == Neighbor(
        "Gi0/1",
        "sw2",
        "Gi0/2",
        "10.0.0.2",
        n[0].remote_desc,
    )
    assert n[0].remote_desc.startswith("Cisco IOS Software, C3750E")
    assert "Copyright" in n[0].remote_desc
    assert "Time remaining" not in n[0].remote_desc
    assert n[1].local_port == "Gi0/3"
    assert n[1].remote_name == "R2"
    assert n[1].remote_port == "Ethernet1"
    assert n[1].remote_ip == "10.0.0.3"  # IPv4 preferred over IPV6


def test_lldp_without_system_name_uses_chassis_id():
    (n,) = ios.parse_neighbors(load("ios-lldp-noname.txt"))
    assert n.remote_name == "00a0.c9aa.bb01"
    assert n.local_port == "Gi0/5"
    assert n.remote_port == "00a0.c9aa.bb01"
    assert n.remote_ip is None
    assert n.remote_desc is None


def test_lldp_empty():
    assert ios.parse_neighbors(load("ios-lldp-empty.txt")) == []
    assert ios.parse_neighbors("") == []
    assert ios.parse_neighbors("  \n") == []


def test_lldp_not_enabled():
    assert ios.parse_neighbors("% LLDP is not enabled\n") == []


def test_lldp_rejects_garbage_and_cdp():
    with pytest.raises(ValueError):
        ios.parse_neighbors("% Invalid input detected at '^' marker.")
    with pytest.raises(ValueError):
        ios.parse_neighbors(load("ios-cdp-detail.txt"))


def test_cdp_two_neighbors():
    n = ios.parse_cdp_neighbors(load("ios-cdp-detail.txt"))
    assert len(n) == 2
    assert n[0].remote_name == "sw2"  # domain stripped
    assert n[0].local_port == "GigabitEthernet0/1"
    assert n[0].remote_port == "GigabitEthernet0/2"
    assert n[0].remote_ip == "10.0.0.2"
    assert n[0].remote_desc.startswith("Cisco IOS Software, C3750E")
    assert "advertisement" not in n[0].remote_desc
    assert n[1].remote_name == "R2"
    assert n[1].local_port == "GigabitEthernet0/3"
    assert n[1].remote_port == "GigabitEthernet0/0"
    assert n[1].remote_ip == "10.0.0.3"


def test_cdp_empty_and_errors():
    assert ios.parse_cdp_neighbors("") == []
    assert ios.parse_cdp_neighbors("\nTotal cdp entries displayed : 0\n") == []
    assert ios.parse_cdp_neighbors("% CDP is not enabled") == []
    with pytest.raises(ValueError):
        ios.parse_cdp_neighbors("% Invalid input detected at '^' marker.")


def test_hostname():
    assert ios.parse_hostname(load("ios-hostname.txt")) == "R1"
    assert ios.parse_hostname("hostname core-sw.lab\n") == "core-sw.lab"


def test_hostname_missing():
    with pytest.raises(ValueError):
        ios.parse_hostname("")
    with pytest.raises(ValueError):
        ios.parse_hostname("% Invalid input")
