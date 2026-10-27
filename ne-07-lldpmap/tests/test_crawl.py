import json

import pytest

from lldpmap import diff, graph, parsers, topology
from lldpmap.cli import main
from lldpmap.collect import CollectError, merge
from lldpmap.crawl import crawl
from lldpmap.models import Neighbor
from lldpmap.topology import Link, Topology


class FakeNet:
    """A network as {address: (hostname, [Neighbor...])}; records who was visited."""

    def __init__(self, devices, down=()):
        self.devices, self.down, self.visits = devices, set(down), []

    def collect(self, host, vendor):
        self.visits.append((host, vendor))
        if host in self.down or host not in self.devices:
            raise CollectError(f"timed out connecting to {host}")
        return self.devices[host]


def nb(lp, name, rp, ip=None, desc=None):
    return Neighbor(lp, name, rp, ip, desc)


def triangle():
    return {
        "10.0.0.1": (
            "r1",
            [nb("e1", "r2", "e1", "10.0.0.2"), nb("e2", "r3", "e2", "10.0.0.3")],
        ),
        "10.0.0.2": (
            "r2",
            [nb("e1", "r1", "e1", "10.0.0.1"), nb("e2", "r3", "e1", "10.0.0.3")],
        ),
        "10.0.0.3": (
            "r3",
            [nb("e1", "r2", "e2", "10.0.0.2"), nb("e2", "r1", "e2", "10.0.0.1")],
        ),
    }


def test_triangle_is_found_with_each_link_once_and_each_device_visited_once():
    net = FakeNet(triangle())
    topo = crawl("10.0.0.1", "frr", net)
    assert sorted(topo.devices) == ["r1", "r2", "r3"]
    assert all(d.crawled for d in topo.devices.values())
    assert topo.links == {
        Link.of("r1", "e1", "r2", "e1"),
        Link.of("r1", "e2", "r3", "e2"),
        Link.of("r2", "e2", "r3", "e1"),
    }
    assert sorted(h for h, _ in net.visits) == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def test_link_is_the_same_whichever_end_reports_it():
    assert Link.of("a", "1", "b", "2") == Link.of("b", "2", "a", "1")


def chain(n):
    devs = {}
    for i in range(1, n + 1):
        neigh = []
        if i > 1:
            neigh.append(nb("up", f"s{i-1}", "down", f"10.1.0.{i-1}"))
        if i < n:
            neigh.append(nb("down", f"s{i+1}", "up", f"10.1.0.{i+1}"))
        devs[f"10.1.0.{i}"] = (f"s{i}", neigh)
    return devs


def test_depth_limit_stops_logins_but_still_records_the_next_device():
    net = FakeNet(chain(6))
    topo = crawl("10.1.0.1", "frr", net, max_depth=2)
    assert [h for h, _ in net.visits] == ["10.1.0.1", "10.1.0.2", "10.1.0.3"]
    assert topo.devices["s3"].crawled
    assert (
        not topo.devices["s4"].crawled
        and topo.devices["s4"].note == "beyond depth limit"
    )
    assert "s5" not in topo.devices
    assert Link.of("s3", "down", "s4", "up") in topo.links


def test_depth_zero_visits_only_the_seed():
    net = FakeNet(chain(3))
    topo = crawl("10.1.0.1", "frr", net, max_depth=0)
    assert len(net.visits) == 1 and not topo.devices["s2"].crawled


def test_unreachable_neighbour_is_recorded_not_fatal():
    net = FakeNet(triangle(), down=["10.0.0.3"])
    topo = crawl("10.0.0.1", "frr", net)
    assert topo.devices["r3"].note.startswith("unreachable")
    assert not topo.devices["r3"].crawled and topo.devices["r2"].crawled
    assert Link.of("r1", "e2", "r3", "e2") in topo.links


def test_unreachable_seed_gives_a_note_and_no_crash():
    topo = crawl("10.9.9.9", "frr", FakeNet({}))
    assert not topo.devices["10.9.9.9"].crawled and not topo.links


def test_neighbour_without_address_uses_resolver_or_is_skipped():
    devs = {
        "h1": ("r1", [nb("e1", "r2", "e1")]),
        "h-r2": ("r2", [nb("e1", "r1", "e1")]),
    }
    topo = crawl("h1", "frr", FakeNet(devs), resolve=lambda n: f"h-{n}")
    assert topo.devices["r2"].crawled
    topo = crawl("h1", "frr", FakeNet(devs))
    assert (
        not topo.devices["r2"].crawled
        and "no management address" in topo.devices["r2"].note
    )


def test_vendor_is_guessed_from_description_and_used_for_the_login():
    devs = {
        "1": (
            "core",
            [
                nb("e1", "arista1", "Et1", "2", "Arista Networks EOS version 4.30"),
                nb("e2", "cisco1", "Gi0/1", "3", "Cisco IOS Software, C2960"),
            ],
        ),
        "2": ("arista1", []),
        "3": ("cisco1", []),
    }
    net = FakeNet(devs)
    topo = crawl("1", "frr", net)
    assert dict(net.visits) == {"1": "frr", "2": "eos", "3": "ios"}
    assert (
        topo.devices["arista1"].vendor == "eos"
        and topo.devices["cisco1"].vendor == "ios"
    )


def test_same_device_reachable_by_two_addresses_is_visited_once_in_the_topology():
    devs = {
        "a": ("r1", [nb("e1", "r2", "e1", "b"), nb("e2", "r2", "e2", "b2")]),
        "b": ("r2", []),
        "b2": ("r2", []),
    }
    topo = crawl("a", "frr", FakeNet(devs))
    assert list(topo.devices) == ["r1", "r2"] and len(topo.links) == 2


def test_json_roundtrip_is_stable(tmp_path):
    topo = crawl("10.0.0.1", "frr", FakeNet(triangle()))
    path = tmp_path / "t.json"
    topology.save(topo, path)
    again = topology.load(path)
    assert again.links == topo.links and again.devices == topo.devices
    assert again.to_json() == topo.to_json()
    assert json.loads(path.read_text())["version"] == 1


def test_unknown_file_version_is_rejected():
    with pytest.raises(ValueError, match="version"):
        Topology.from_json('{"version": 99}')


def test_diff_finds_removed_and_added_links_and_devices():
    old = crawl("10.0.0.1", "frr", FakeNet(triangle()))
    smaller = triangle()
    smaller["10.0.0.1"] = ("r1", [nb("e1", "r2", "e1", "10.0.0.2")])
    smaller["10.0.0.3"] = ("r3", [nb("e1", "r2", "e2", "10.0.0.2")])
    new = crawl("10.0.0.1", "frr", FakeNet(smaller))
    d = diff.compare(old, new)
    assert d.links_removed == [Link.of("r1", "e2", "r3", "e2")]
    assert not d.links_added and not d.devices_removed
    assert "- link removed: r1:e2 <-> r3:e2" in d.report(old, new)
    back = diff.compare(new, old)
    assert back.links_added == d.links_removed
    assert not diff.compare(old, old).changed


def test_graph_is_self_contained_and_marks_changes(tmp_path):
    old = crawl("10.0.0.1", "frr", FakeNet(triangle()))
    smaller = triangle()
    smaller["10.0.0.1"] = ("r1", [nb("e1", "r2", "e1", "10.0.0.2")])
    smaller["10.0.0.3"] = ("r3", [nb("e1", "r2", "e2", "10.0.0.2")])
    new = crawl("10.0.0.1", "frr", FakeNet(smaller))
    out = tmp_path / "g.html"
    graph.render(new, out, previous=old)
    html = out.read_text()
    assert "cdn.jsdelivr" not in html and "<script src=" not in html
    for name in ("r1", "r2", "r3"):
        assert f'"id": "{name}"' in html
    assert "REMOVED since previous run" in html and graph.REMOVED in html
    plain = tmp_path / "p.html"
    graph.render(old, plain)
    assert "REMOVED" not in plain.read_text()


def test_merge_dedupes_lldp_and_cdp_views_of_one_link():
    a = [nb("Gi0/1", "sw2", "Gi0/2")]
    b = [nb("Gi0/1", "sw2", "Gi0/2", "10.0.0.2"), nb("Gi0/3", "sw3", "Gi0/1")]
    assert len(merge(a, b)) == 2


def test_vendor_registry():
    assert set(parsers.PARSERS) == {"frr", "eos", "ios"}
    with pytest.raises(ValueError, match="unknown vendor"):
        parsers.get("junos")
    assert parsers.guess_vendor(None, "frr") == "frr"
    assert parsers.guess_vendor("Linux 6.1 FRRouting", "frr") == "frr"


def test_every_vendor_module_follows_the_contract():
    for vendor, mod in parsers.PARSERS.items():
        assert mod.VENDOR == vendor
        assert mod.NEIGHBOR_COMMAND and mod.HOSTNAME_COMMAND
        assert callable(mod.parse_neighbors) and callable(mod.parse_hostname)


def test_cli_crawl_diff_flow(tmp_path, capsys):
    net = FakeNet(triangle())
    a = tmp_path / "a.json"
    assert (
        main(
            ["crawl", "10.0.0.1", "-o", str(a), "--html", str(tmp_path / "a.html")],
            collector=net,
        )
        == 0
    )
    assert "3 devices (3 crawled), 3 links" in capsys.readouterr().out
    smaller = triangle()
    smaller["10.0.0.1"] = ("r1", [nb("e1", "r2", "e1", "10.0.0.2")])
    smaller["10.0.0.3"] = ("r3", [nb("e1", "r2", "e2", "10.0.0.2")])
    b = tmp_path / "b.json"
    main(["crawl", "10.0.0.1", "-o", str(b)], collector=FakeNet(smaller))
    capsys.readouterr()
    assert main(["diff", str(a), str(b), "--html", str(tmp_path / "d.html")]) == 1
    assert "- link removed: r1:e2 <-> r3:e2" in capsys.readouterr().out
    assert main(["diff", str(a), str(a)]) == 0
    assert (tmp_path / "d.html").exists()


def test_cli_requires_credentials_from_environment(monkeypatch, tmp_path):
    monkeypatch.delenv("LLDPMAP_USER", raising=False)
    monkeypatch.delenv("LLDPMAP_PASSWORD", raising=False)
    with pytest.raises(SystemExit, match="LLDPMAP_USER and LLDPMAP_PASSWORD"):
        main(["crawl", "x", "-o", str(tmp_path / "o.json")])
