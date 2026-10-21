import ipaddress

from netplan.overlap import find_overlaps, parse_labelled


def pairs(items):
    return {
        (str(o.outer), str(o.inner), o.kind)
        for o in find_overlaps(parse_labelled(items))
    }


def test_disjoint_subnets_have_no_overlaps():
    assert pairs(["10.0.0.0/24", "10.0.1.0/24", "192.168.0.0/16"]) == set()


def test_adjacent_blocks_do_not_overlap():
    assert pairs(["10.0.0.0/25", "10.0.0.128/25"]) == set()


def test_nested_block_is_reported_with_outer_first():
    assert pairs(["10.1.0.0/16", "10.0.0.0/8"]) == {
        ("10.0.0.0/8", "10.1.0.0/16", "contains")
    }


def test_duplicates_are_flagged():
    assert pairs(["10.0.0.0/24", "10.0.0.0/24"]) == {
        ("10.0.0.0/24", "10.0.0.0/24", "duplicate")
    }


def test_chain_of_three_reports_every_pair():
    found = pairs(["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"])
    assert found == {
        ("10.0.0.0/8", "10.1.0.0/16", "contains"),
        ("10.0.0.0/8", "10.1.2.0/24", "contains"),
        ("10.1.0.0/16", "10.1.2.0/24", "contains"),
    }


def test_ipv4_and_ipv6_are_not_compared():
    assert pairs(["::/0", "0.0.0.0/0"]) == set()
    assert pairs(["2001:db8::/32", "2001:db8:1::/48"]) == {
        ("2001:db8::/32", "2001:db8:1::/48", "contains")
    }


def test_slash_32_inside_a_larger_block_and_host_bits_in_input():
    assert pairs(["10.0.0.7/32", "10.0.0.5/24"]) == {
        ("10.0.0.0/24", "10.0.0.7/32", "contains")
    }


def test_labels_survive():
    o = find_overlaps(parse_labelled(["core=10.0.0.0/8", "lab=10.9.0.0/16"]))[0]
    assert (o.outer_label, o.inner_label) == ("core", "lab")


def test_matches_brute_force_on_many_blocks():
    nets = [
        ipaddress.ip_network(f"10.{a}.{b}.0/{p}", strict=False)
        for a in range(3)
        for b in (0, 1, 128)
        for p in (16, 17, 24, 25)
    ]
    expected = sum(
        1 for i, x in enumerate(nets) for y in nets[i + 1 :] if x.overlaps(y)
    )
    got = find_overlaps([(str(n), n) for n in nets])
    assert len(got) == expected
