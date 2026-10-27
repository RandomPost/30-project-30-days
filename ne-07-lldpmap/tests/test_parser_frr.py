import json
from pathlib import Path

import pytest

from lldpmap.models import Neighbor
from lldpmap.parsers import frr

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return (FIX / name).read_text()


def wrap(*ifaces, as_list=True):
    return json.dumps({"lldp": {"interface": list(ifaces) if as_list else ifaces[0]}})


def iface(name, chassis, port_id=("ifname", "Ethernet1"), descr=None):
    port = {"id": {"type": port_id[0], "value": port_id[1]}}
    if descr:
        port["descr"] = descr
    return {name: {"chassis": chassis, "port": port}}


def test_contract_constants():
    assert frr.VENDOR == "frr"
    assert frr.NEIGHBOR_COMMAND == "lldpcli show neighbors details -f json"
    assert frr.HOSTNAME_COMMAND == "hostname"


def test_two_neighbors_fixture():
    n = frr.parse_neighbors(load("frr-lldpd-two-neighbors.json"))
    assert [(x.local_port, x.remote_name, x.remote_port, x.remote_ip) for x in n] == [
        ("eth1", "r2", "eth1", "172.20.30.5"),
        ("eth2", "r3", "eth2", "172.20.30.6"),
    ]
    assert n[0].remote_desc.startswith("Ubuntu 24.04")


def test_one_neighbor_fixture_is_dict():
    n = frr.parse_neighbors(load("frr-lldpd-one-neighbor.json"))
    assert len(n) == 1
    assert isinstance(n[0], Neighbor)
    assert (n[0].local_port, n[0].remote_name, n[0].remote_port) == (
        "eth1",
        "r2",
        "eth1",
    )


def test_none_fixture():
    assert frr.parse_neighbors(load("frr-lldpd-none.json")) == []


def test_empty_text():
    assert frr.parse_neighbors("") == []
    assert frr.parse_neighbors("  \n") == []


@pytest.mark.parametrize("bad", ["% Invalid input", "[1, 2]", '{"foo": {}}', "{"])
def test_not_lldpcli_raises(bad):
    with pytest.raises(ValueError):
        frr.parse_neighbors(bad)


def test_hostname():
    assert frr.parse_hostname(load("frr-hostname.txt")) == "r1"
    assert frr.parse_hostname("r1.example.net\n") == "r1"
    with pytest.raises(ValueError):
        frr.parse_hostname("\n")


def test_chassis_key_without_sysname_is_chassis_id():
    ch = {"aa:bb:cc:dd:ee:ff": {"id": {"type": "mac", "value": "aa:bb:cc:dd:ee:ff"}}}
    [n] = frr.parse_neighbors(wrap(iface("eth0", ch), as_list=False))
    assert n.remote_name == "aa:bb:cc:dd:ee:ff"
    assert n.remote_ip is None and n.remote_desc is None
    assert n.remote_port == "Ethernet1"


def test_chassis_key_domain_stripped():
    ch = {"sw1.example.net": {"id": {"type": "mac", "value": "aa:bb:cc:dd:ee:ff"}}}
    [n] = frr.parse_neighbors(wrap(iface("eth0", ch)))
    assert n.remote_name == "sw1"


def test_mgmt_ip_list_prefers_ipv4():
    ch = {"r9": {"mgmt-ip": ["fe80::1", "10.1.1.9", "10.1.1.10"]}}
    [n] = frr.parse_neighbors(wrap(iface("eth0", ch)))
    assert n.remote_ip == "10.1.1.9"
    ch = {"r9": {"mgmt-ip": ["2001:db8::9"]}}
    [n] = frr.parse_neighbors(wrap(iface("eth0", ch)))
    assert n.remote_ip == "2001:db8::9"


def test_same_ifname_repeated():
    a = iface("eth0", {"a": {"mgmt-ip": "10.0.0.1"}})
    b = iface("eth0", {"b": {"mgmt-ip": "10.0.0.2"}})
    n = frr.parse_neighbors(wrap(a, b))
    assert [(x.local_port, x.remote_name) for x in n] == [("eth0", "a"), ("eth0", "b")]


def test_port_id_selection():
    ch = {"r": {}}
    [n] = frr.parse_neighbors(
        wrap(iface("e", ch, ("mac", "aa:bb:cc:dd:ee:ff"), descr="swp1"), as_list=False)
    )
    assert n.remote_port == "swp1"
    [n] = frr.parse_neighbors(
        wrap(iface("e", ch, ("mac", "aa:bb:cc:dd:ee:ff")), as_list=False)
    )
    assert n.remote_port == "aa:bb:cc:dd:ee:ff"
    [n] = frr.parse_neighbors(
        wrap(iface("e", ch, ("ifname", "Gi0/1"), descr="uplink"), as_list=False)
    )
    assert n.remote_port == "Gi0/1"
