"""The snapshot builder: no Batfish needed."""

import pytest

from netcheck import expect, snapshot

SOURCE = snapshot.DEFAULT_SOURCE


def test_every_device_is_rendered_as_ios_for_batfish():
    inv = snapshot.load_inventory(SOURCE)
    configs = snapshot.render_for_batfish(inv)
    assert set(configs) == {d.name for s in inv.sites for d in s.devices}
    assert all("frr defaults" not in text for text in configs.values())
    assert "router ospf 1" in configs["branch-east-r1"]


def test_build_writes_configs_dir_and_appends_overlay(tmp_path):
    overlay = tmp_path / "ov"
    overlay.mkdir()
    (overlay / "hq-sw1.cfg").write_text(
        "ip access-list extended X\n permit ip any any\n"
    )
    out = snapshot.build(SOURCE, overlay, tmp_path / "snap")
    text = (out / "configs" / "hq-sw1.cfg").read_text()
    assert text.rstrip().endswith("permit ip any any")
    assert "hostname hq-sw1" in text
    assert (out / "configs" / "hq-sw2.cfg").exists()


def test_overlay_for_unknown_device_is_an_error(tmp_path):
    overlay = tmp_path / "ov"
    overlay.mkdir()
    (overlay / "no-such-device.cfg").write_text("!\n")
    with pytest.raises(ValueError, match="no-such-device"):
        snapshot.build(SOURCE, overlay, tmp_path / "snap")


def test_expected_ospf_pairs_come_from_the_source_of_truth():
    inv = snapshot.load_inventory(SOURCE)
    pairs = expect.ospf_pairs(inv)
    assert frozenset({"hq-r1", "hq-sw1"}) in pairs
    assert frozenset({"branch-east-r1", "branch-east-sw1"}) in pairs
    assert len(pairs) == 3  # one routed uplink per site


def test_vlan_subnets_by_name():
    inv = snapshot.load_inventory(SOURCE)
    assert expect.vlan_subnets(inv, "guest") == [
        ("branch-east", "10.2.2.0/24", "branch-east-sw1")
    ]
    users = {s for s, *_ in expect.vlan_subnets(inv, "users")}
    assert users == {"hq", "branch-east", "branch-west"}


def test_management_range_covers_every_loopback():
    inv = snapshot.load_inventory(SOURCE)
    import ipaddress

    rng = ipaddress.ip_network(expect.MGMT_RANGE)
    lo = [d.loopback for s in inv.sites for d in s.devices if d.loopback]
    assert lo and all(ipaddress.ip_interface(x).ip in rng for x in lo)
