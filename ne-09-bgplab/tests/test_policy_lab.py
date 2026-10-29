"""Path choice on every router, normal and failure conditions. Needs `make up`."""

import pytest

from bgplab import lab
from bgplab.model import explain

from conftest import NORMAL, converged

pytestmark = pytest.mark.lab

CUST = "203.0.113.0/24"


# ---- normal operation ----------------------------------------------------------
def test_outbound_local_pref_prefers_isp1(up):
    """cust sets local-pref 200 on ISP1 and 100 on ISP2: all outbound goes via ISP1."""
    for prefix in ("198.18.0.0/24", "198.51.100.0/24", "198.51.101.0/24"):
        b = lab.best("cust", prefix)
        assert (b.peer, b.local_pref) == ("isp1", 200), explain(
            "cust", prefix, lab.paths("cust", prefix)
        )
    assert lab.best("cust", "198.18.0.0/24").reason == "Local Pref"


def test_inbound_prepend_steers_ixp_to_isp1(up):
    """The customer asks for a prepend towards ISP2 (A: itself, B: community 65002:3), so the route server sees 4 vs 2 AS hops."""
    ps = lab.paths("rs", CUST)
    b = next(p for p in ps if p.best)
    assert b.peer == "isp1" and b.aspath == "65001 65100" and b.reason == "AS Path"
    other = next(p for p in ps if not p.best)
    assert (
        other.first_as == "65002"
        and other.aspath.endswith("65100")
        and other.length == 4
    )


def test_isps_prefer_customer_route_over_ixp(up):
    """Customer local-pref 300 beats the IXP's 150, even when the customer path is longer."""
    for isp in ("isp1", "isp2"):
        b = lab.best(isp, CUST)
        assert (b.peer, b.local_pref) == ("cust", 300)
    assert any(not p.best for p in lab.paths("isp2", CUST))  # the IXP path lost


def test_prefix_filter_blocks_customer_leak(up):
    """cust originates 10.66.0.0/16 by mistake; neither ISP may carry it."""
    assert lab.best("cust", "10.66.0.0/16") is not None
    for node in ("isp1", "isp2", "rs"):
        assert lab.best(node, "10.66.0.0/16") is None


def test_rpki_invalid_hijacks_are_dropped(up):
    """rogue (AS65666) announces the customer's /24 and content's /24: both are RPKI invalid."""
    for node in ("rs", "isp1", "isp2"):
        for prefix in (CUST, "198.18.0.0/24"):
            origins = {p.aspath.split()[-1] for p in lab.paths(node, prefix)}
            assert "65666" not in origins, node
    assert all(p.rpki == "valid" for p in lab.paths("isp1", "198.18.0.0/24"))


def test_rpki_not_found_is_accepted(up):
    """100.64.66.0/24 has no ROA: 'notfound' is accepted, at lower local-pref than valid."""
    b = lab.best("isp1", "100.64.66.0/24")
    assert b.rpki == "not found" and b.local_pref == 100
    assert lab.best("isp1", "198.18.0.0/24").local_pref == 150


def test_blackhole_community_installs_discard_next_hop(up):
    """cust tags 203.0.113.66/32 with 65535:666: ISPs set next hop to the discard interface."""
    for isp in ("isp1", "isp2"):
        b = lab.best(isp, "203.0.113.66/32")
        assert b.nexthop == "192.0.2.1" and b.local_pref == 500
        assert "noExport" in b.communities
        assert "rtbh0" in lab.vtysh(isp, "show ip route 203.0.113.66/32")


def test_blackhole_route_is_not_leaked_to_ixp(up):
    assert lab.best("rs", "203.0.113.66/32") is None
    assert lab.best("content", "203.0.113.66/32") is None


# ---- failure scenarios ---------------------------------------------------------
def test_primary_link_failure_moves_outbound_to_isp2(link_down):
    """cust loses its ISP1 link: everything outbound goes via ISP2 (local-pref 100)."""
    link_down("cust", "eth1")
    expect = {
        ("cust", p): "isp2"
        for p in ("198.18.0.0/24", "198.51.100.0/24", "198.51.101.0/24")
    }
    expect[("rs", CUST)] = "isp2"  # the only remaining way in, prepends or not
    lab.wait_for(converged(expect))
    assert lab.best("cust", "198.18.0.0/24").local_pref == 100
    rs = lab.best("rs", CUST)
    assert rs.first_as == "65002" and rs.length == 4
    assert lab.best("isp1", CUST).peer != "cust"


def test_backup_link_failure_changes_nothing_outbound(link_down):
    link_down("cust", "eth2")
    expect = dict(NORMAL)
    expect[("isp2", CUST)] = (
        "rs"  # isp2 now only knows the customer through the IXP route server
    )
    expect[("rs", CUST)] = "isp1"
    lab.wait_for(converged(expect))
    assert lab.best("isp2", CUST).local_pref == 150


def test_isp1_loses_ixp_content_reachable_via_isp2(link_down):
    """ISP1 loses its IXP port. cust still reaches content, now through ISP2, at local-pref 100."""
    link_down("isp1", "eth2")
    link_down("ixp", "eth1")  # the switch port goes down with it
    expect = {
        ("cust", "198.18.0.0/24"): "isp2",
        ("isp1", "198.18.0.0/24"): None,
        ("rs", CUST): "isp2",
    }
    lab.wait_for(converged(expect))
    b = lab.best("cust", "198.18.0.0/24")
    assert b.aspath == "65002 65300" and b.local_pref == 100
    assert (
        lab.best("rs", CUST).peer == "isp2"
    )  # ISP1 no longer announces the customer there
    assert lab.best("isp1", CUST).peer == "cust"  # customer route survives at ISP1


def test_double_failure_isolates_customer_from_content(link_down):
    link_down("cust", "eth1")
    link_down("cust", "eth2")
    lab.wait_for(converged({("cust", "198.18.0.0/24"): None, ("rs", CUST): None}))
