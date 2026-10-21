import ipaddress

import pytest

from netplan.info import parse_network
from netplan.vlsm import (
    PlanError,
    Request,
    free_blocks,
    parse_requests,
    plan,
    prefix_for_hosts,
)


def net(text):
    return ipaddress.ip_network(text)


def test_hand_worked_example():
    """192.168.10.0/24: 100, 50, 25, 10 and 2 hosts.

    100 -> 7 host bits (126 usable) = /25      192.168.10.0/25
     50 -> 6 host bits (62)         = /26      192.168.10.128/26
     25 -> 5 host bits (30)         = /27      192.168.10.192/27
     10 -> 4 host bits (14)         = /28      192.168.10.224/28
      2 -> 2 host bits (2)          = /30      192.168.10.240/30
    Space left: 244-255, which is .244/30 and .248/29.
    """
    reqs = parse_requests(["Srv=10", "Link=2", "Sales=100", "Mgmt=25", "Eng=50"])
    result = plan(net("192.168.10.0/24"), reqs)
    got = [(a.name, str(a.network)) for a in result.allocations]
    assert got == [
        ("Sales", "192.168.10.0/25"),
        ("Eng", "192.168.10.128/26"),
        ("Mgmt", "192.168.10.192/27"),
        ("Srv", "192.168.10.224/28"),
        ("Link", "192.168.10.240/30"),
    ]
    assert [str(b) for b in result.free] == ["192.168.10.244/30", "192.168.10.248/29"]
    assert [a.spare for a in result.allocations] == [26, 12, 5, 4, 0]
    assert result.utilisation == pytest.approx(244 / 256)


@pytest.mark.parametrize(
    "hosts, prefix",
    [(1, 30), (2, 30), (3, 29), (6, 29), (7, 28), (254, 24), (255, 23), (65534, 16)],
)
def test_prefix_for_hosts_ipv4(hosts, prefix):
    assert prefix_for_hosts(4, hosts) == prefix


def test_prefix_boundaries_never_undersize():
    for hosts in range(1, 600):
        prefix = prefix_for_hosts(4, hosts)
        assert (1 << (32 - prefix)) - 2 >= hosts
        assert (1 << (32 - prefix - 1)) - 2 < hosts  # one bit smaller would not fit


def test_rfc3021_shrinks_point_to_point_links():
    assert prefix_for_hosts(4, 2, rfc3021=True) == 31
    assert prefix_for_hosts(4, 1, rfc3021=True) == 32
    assert prefix_for_hosts(4, 3, rfc3021=True) == 29  # no effect above 2 hosts


def test_rfc3021_plan_uses_slash_31_and_32():
    result = plan(
        net("10.0.0.0/29"), parse_requests(["a=2", "b=2", "c=1"]), rfc3021=True
    )
    assert [str(a.network) for a in result.allocations] == [
        "10.0.0.0/31",
        "10.0.0.2/31",
        "10.0.0.4/32",
    ]
    assert [a.usable for a in result.allocations] == [2, 2, 1]


def test_ipv6_prefixes():
    assert prefix_for_hosts(6, 1) == 127  # 1 host fits in a /127 without rfc3021
    assert prefix_for_hosts(6, 2) == 126  # /126 has 3 usable (anycast reserved)
    assert prefix_for_hosts(6, 2, rfc3021=True) == 127
    assert prefix_for_hosts(6, 2**64 - 1) == 64
    assert prefix_for_hosts(6, 2**64) == 63


def test_ipv6_plan_aligns_blocks():
    result = plan(net("2001:db8::/48"), parse_requests(["a=1000", "b=5"]))
    assert [str(a.network) for a in result.allocations] == [
        "2001:db8::/118",
        "2001:db8::400/125",
    ]


def test_ties_keep_input_order():
    result = plan(net("10.0.0.0/24"), parse_requests(["x=30", "y=30", "z=30"]))
    assert [a.name for a in result.allocations] == ["x", "y", "z"]
    assert [str(a.network) for a in result.allocations] == [
        "10.0.0.0/27",
        "10.0.0.32/27",
        "10.0.0.64/27",
    ]


def test_exact_fit_leaves_no_free_space():
    result = plan(net("10.0.0.0/24"), parse_requests(["a=126", "b=126"]))
    assert result.free == [] and result.utilisation == 1.0


def test_parent_with_nonzero_start_stays_inside_parent():
    parent = net("172.16.4.0/22")
    result = plan(parent, parse_requests(["a=500", "b=200", "c=60"]))
    assert all(a.network.subnet_of(parent) for a in result.allocations)
    nets = [a.network for a in result.allocations]
    assert not any(x.overlaps(y) for i, x in enumerate(nets) for y in nets[i + 1 :])


def test_too_much_demand_names_the_failing_request():
    with pytest.raises(PlanError, match=r"c: needs a /25"):
        plan(net("10.0.0.0/24"), parse_requests(["a=100", "b=100", "c=100"]))


def test_single_request_bigger_than_parent():
    with pytest.raises(PlanError, match="larger than the parent"):
        plan(net("10.0.0.0/28"), parse_requests(["big=100"]))


def test_free_blocks_cover_exactly_the_unused_space():
    parent = net("10.0.0.0/24")
    used = [net("10.0.0.0/26"), net("10.0.0.128/25")]
    free = free_blocks(parent, used)
    assert [str(b) for b in free] == ["10.0.0.64/26"]
    total = sum(b.num_addresses for b in free) + sum(u.num_addresses for u in used)
    assert total == parent.num_addresses
    assert free_blocks(parent, []) == [parent]


def test_parse_requests_forms_and_errors():
    assert parse_requests(["Sales=10", "20"]) == [
        Request("Sales", 10),
        Request("LAN2", 20),
    ]
    for bad in ("x=abc", "x=0", "-5", "x="):
        with pytest.raises(PlanError):
            parse_requests([bad])


def test_parse_network_accepts_host_bits_for_parent():
    assert plan(
        parse_network("192.168.10.5/24"), parse_requests(["a=10"])
    ).parent == net("192.168.10.0/24")
