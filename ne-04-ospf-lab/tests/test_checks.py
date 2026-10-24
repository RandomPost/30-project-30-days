import copy
import json
from pathlib import Path

from ospflab import checks, topology

FIX = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIX / name).read_text())


def test_neighbors_full():
    c = checks.check_neighbors("r1", load("r1-neighbors.json"))
    assert c.ok, c.detail


def test_neighbors_missing_one():
    data = load("r1-neighbors.json")
    data["neighbors"].pop(next(iter(data["neighbors"])))
    assert not checks.check_neighbors("r1", data).ok


def test_neighbor_not_full():
    data = load("r1-neighbors.json")
    for entries in data["neighbors"].values():
        entries[0]["nbrState"] = "ExStart/-"
        entries[0]["state"] = "ExStart/-"
    assert not checks.check_neighbors("r1", data).ok


def test_no_neighbors_at_all():
    assert not checks.check_neighbors("r1", {"neighbors": {}}).ok


def test_routes_complete():
    assert checks.check_routes("r1", load("r1-routes.json")).ok
    assert checks.check_routes("r3", load("r3-routes.json")).ok


def test_routes_missing_prefix():
    data = load("r1-routes.json")
    del data["192.168.3.0/24"]
    c = checks.check_routes("r1", data)
    assert not c.ok and "192.168.3.0/24" in c.detail


def test_routes_not_installed_do_not_count():
    data = copy.deepcopy(load("r1-routes.json"))
    for e in data["192.168.3.0/24"]:
        e["installed"] = False
        e["selected"] = False
        for nh in e["nexthops"]:
            nh["fib"] = False
    assert not checks.check_routes("r1", data).ok


def test_next_hop_of_remote_lan():
    assert checks.next_hops(load("r1-routes.json"), "192.168.3.0/24") == ["10.0.13.2"]


def test_expected_prefixes():
    assert set(topology.expected_prefixes("r1")) == {
        "10.255.0.2/32",
        "10.255.0.3/32",
        "192.168.3.0/24",
    }
    assert set(topology.expected_prefixes("r2")) == {
        "10.255.0.1/32",
        "10.255.0.3/32",
        "192.168.1.0/24",
        "192.168.3.0/24",
    }


def test_ping_parsing():
    assert checks.parse_ping((FIX / "ping-ok.txt").read_text()) == (3, 3)
    sent, got = checks.parse_ping((FIX / "ping-fail.txt").read_text())
    assert got == 0


def test_replied_sequences_and_outage():
    out = "\n".join(f"64 bytes from x: seq={i} ttl=62 time=1 ms" for i in (0, 1, 2, 5))
    assert checks.replied_sequences(out) == [0, 1, 2, 5]
