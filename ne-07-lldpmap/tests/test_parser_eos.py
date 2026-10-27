from pathlib import Path

import pytest

from lldpmap.models import Neighbor
from lldpmap.parsers import eos

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return (FIX / name).read_text()


def test_constants():
    assert eos.VENDOR == "eos"
    assert eos.NEIGHBOR_COMMAND == "show lldp neighbors detail"
    assert eos.HOSTNAME_COMMAND == "show hostname"


def test_two_neighbors():
    got = eos.parse_neighbors(load("eos-two-neighbors.txt"))
    assert [(n.local_port, n.remote_name, n.remote_port) for n in got] == [
        ("Ethernet1", "spine1", "Ethernet49"),
        ("Ethernet2", "spine2", "Ethernet50"),
    ]
    assert got[0].remote_ip is None
    assert "EOS version 4.28.3M" in got[0].remote_desc


def test_mgmt_ips_prefers_ipv4():
    (n,) = eos.parse_neighbors(load("eos-mgmt-ips.txt"))
    assert n == Neighbor(
        "Ethernet3",
        "core1",
        "Ethernet6/25",
        "192.0.2.10",
        "Arista Networks EOS version 4.27.1F",
    )


def test_ipv6_only_falls_back():
    text = (
        load("eos-mgmt-ips.txt")
        .replace("IPv4 (1)", "Other (9)")
        .replace("192.0.2.10", "")
    )
    (n,) = eos.parse_neighbors(text)
    assert n.remote_ip == "2001:db8::1"


def test_no_sysname_and_multiple_per_port():
    got = eos.parse_neighbors(load("eos-no-sysname.txt"))
    assert len(got) == 2
    assert all(n.local_port == "Ethernet5" for n in got)
    assert got[0].remote_name == "0012.3456.789a"
    assert got[0].remote_port == "PC Port"  # MAC port id replaced by description
    assert got[0].remote_desc is None
    assert got[1].remote_name == "hub-sw"
    assert got[1].remote_port == "Ethernet7"


def test_empty():
    assert eos.parse_neighbors(load("eos-empty.txt")) == []
    assert eos.parse_neighbors("   \n") == []


def test_hostname():
    assert eos.parse_hostname(load("eos-hostname.txt")) == "leaf1"
    assert eos.parse_hostname("FQDN: a.b.c\n") == "a"


def test_malformed_neighbors():
    with pytest.raises(ValueError):
        eos.parse_neighbors("% Invalid input\n")


def test_malformed_hostname():
    with pytest.raises(ValueError):
        eos.parse_hostname("% Invalid input\n")
