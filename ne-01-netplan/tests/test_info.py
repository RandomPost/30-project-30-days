import pytest

from netplan.info import describe, parse_network, usable_hosts, usable_range


def test_classic_slash_24():
    i = describe("192.168.1.0/24")
    assert (i.network, i.netmask, i.wildcard) == (
        "192.168.1.0",
        "255.255.255.0",
        "0.0.0.255",
    )
    assert (i.broadcast, i.first_usable, i.last_usable) == (
        "192.168.1.255",
        "192.168.1.1",
        "192.168.1.254",
    )
    assert (i.total_addresses, i.usable_hosts, i.kind) == (256, 254, "normal")


def test_non_octet_boundary_slash_27():
    i = describe("10.20.30.64/27")
    assert i.broadcast == "10.20.30.95"
    assert (i.first_usable, i.last_usable) == ("10.20.30.65", "10.20.30.94")
    assert i.usable_hosts == 30
    assert i.netmask == "255.255.255.224" and i.wildcard == "0.0.0.31"


def test_slash_30_has_two_hosts():
    i = describe("10.0.0.4/30")
    assert (i.first_usable, i.last_usable, i.usable_hosts) == (
        "10.0.0.5",
        "10.0.0.6",
        2,
    )
    assert i.broadcast == "10.0.0.7"


def test_slash_31_is_point_to_point_with_two_usable_and_no_broadcast():
    i = describe("10.0.0.0/31")
    assert i.usable_hosts == 2 and i.total_addresses == 2
    assert (i.first_usable, i.last_usable) == ("10.0.0.0", "10.0.0.1")
    assert i.broadcast is None
    assert "RFC 3021" in i.kind


def test_slash_32_is_a_single_host():
    i = describe("203.0.113.9/32")
    assert i.usable_hosts == 1
    assert i.first_usable == i.last_usable == "203.0.113.9"
    assert i.broadcast is None and i.wildcard == "0.0.0.0"
    assert "host route" in i.kind


def test_slash_0_is_whole_space():
    i = describe("0.0.0.0/0")
    assert i.total_addresses == 2**32 and i.usable_hosts == 2**32 - 2
    assert i.netmask == "0.0.0.0" and i.wildcard == "255.255.255.255"


def test_host_bits_are_normalised_and_flagged():
    i = describe("192.168.1.77/24")
    assert i.cidr == "192.168.1.0/24" and i.input_had_host_bits
    assert not describe("192.168.1.0/24").input_had_host_bits


def test_ipv6_slash_64():
    i = describe("2001:db8:abcd:12::/64")
    assert i.version == 6 and i.broadcast is None and i.wildcard is None
    assert i.first_usable == "2001:db8:abcd:12::1"
    assert i.last_usable == "2001:db8:abcd:12:ffff:ffff:ffff:ffff"
    assert i.total_addresses == 2**64 and i.usable_hosts == 2**64 - 1
    assert i.netmask == "ffff:ffff:ffff:ffff::"


def test_ipv6_slash_127_and_128():
    p2p = describe("2001:db8::/127")
    assert p2p.usable_hosts == 2
    assert (p2p.first_usable, p2p.last_usable) == ("2001:db8::", "2001:db8::1")
    host = describe("2001:db8::5/128")
    assert host.usable_hosts == 1 and host.first_usable == host.last_usable


def test_ipv6_slash_126_reserves_anycast_address():
    i = describe("2001:db8::/126")
    assert i.usable_hosts == 3 and i.first_usable == "2001:db8::1"


@pytest.mark.parametrize(
    "cidr",
    [
        "10.0.0.0/24",
        "10.0.0.0/30",
        "10.0.0.0/31",
        "2001:db8::/120",
        "2001:db8::/126",
        "2001:db8::/127",
    ],
)
def test_usable_matches_stdlib_hosts(cidr):
    net = parse_network(cidr)
    hosts = list(net.hosts())
    assert usable_hosts(net) == len(hosts)
    assert usable_range(net) == (str(hosts[0]), str(hosts[-1]))


@pytest.mark.parametrize("bad", ["", "300.1.1.0/24", "10.0.0.0/33", "banana", "::/129"])
def test_invalid_input_raises_value_error(bad):
    with pytest.raises(ValueError, match="invalid network"):
        describe(bad)
