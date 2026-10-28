"""Pre-change policies, checked by Batfish against the snapshot built from the
source of truth plus overlay. Written before the builder existed (see git history)."""

import pytest

from netcheck import expect

pytestmark = pytest.mark.batfish


# --- reachability ---------------------------------------------------------------
def test_users_reach_management_in_every_site(bf, inventory):
    """A user host must be able to reach its own site's router (management loopback)."""
    for site, subnet, switch in expect.vlan_subnets(inventory, "users"):
        src, dst = expect.host_in(subnet), expect.router_loopback(inventory, site)
        result = expect.trace(bf, switch, subnet, src, dst)
        assert (
            result.success
        ), f"{site}: users {src} cannot reach {dst}\n{result.detail}"


def test_users_reach_servers_inside_hq(bf, inventory):
    ((site, users, switch),) = expect.vlan_subnets(inventory, "users", site="hq")
    ((_, servers, _),) = expect.vlan_subnets(inventory, "servers", site="hq")
    src, dst = expect.host_in(users), expect.host_in(servers)
    result = expect.trace(bf, switch, users, src, dst)
    assert result.success, f"hq users {src} cannot reach servers {dst}\n{result.detail}"


# --- isolation ------------------------------------------------------------------
def test_guest_vlans_exist(inventory):
    # guards against the isolation test below passing because nothing was checked
    assert expect.vlan_subnets(inventory, "guest")


def test_guest_cannot_reach_management(bf, inventory):
    for site, subnet, switch in expect.vlan_subnets(inventory, "guest"):
        dst = expect.router_loopback(inventory, site)
        src = expect.host_in(subnet)
        result = expect.trace(bf, switch, subnet, src, dst)
        assert not result.success, (
            f"POLICY VIOLATION in {site}: guest host {src} can reach management "
            f"address {dst}\n{result.detail}"
        )


def test_guest_cannot_reach_users(bf, inventory):
    for site, guest, switch in expect.vlan_subnets(inventory, "guest"):
        ((_, users, _),) = expect.vlan_subnets(inventory, "users", site=site)
        src, dst = expect.host_in(guest), expect.host_in(users)
        result = expect.trace(bf, switch, guest, src, dst)
        assert not result.success, (
            f"POLICY VIOLATION in {site}: guest host {src} can reach user host {dst}\n"
            f"{result.detail}"
        )


# --- routing --------------------------------------------------------------------
def test_no_forwarding_loops(bf):
    loops = bf.q.detectLoops().answer().frame()
    assert loops.empty, f"forwarding loops found:\n{loops.to_string()}"


# --- configuration hygiene --------------------------------------------------------
def test_no_undefined_references(bf):
    undefined = bf.q.undefinedReferences().answer().frame()
    assert undefined.empty, (
        "configs reference things that are not defined:\n"
        + undefined[["File_Name", "Struct_Type", "Ref_Name", "Context"]].to_string()
    )


def test_every_config_file_parses_fully(bf):
    status = bf.q.fileParseStatus().answer().frame()
    bad = status[status["Status"] != "PASSED"]
    assert bad.empty, f"files Batfish could not fully parse:\n{bad.to_string()}"


def test_no_duplicate_ip_addresses(bf):
    owners = bf.q.ipOwners(duplicatesOnly=True).answer().frame()
    assert owners.empty, f"duplicate IPs:\n{owners.to_string()}"


# --- routing protocol sessions ------------------------------------------------------
def test_expected_ospf_sessions_are_established(bf):
    sessions = bf.q.ospfSessionCompatibility().answer().frame()
    established = {
        frozenset({row["Interface"].hostname, row["Remote_Interface"].hostname})
        for _, row in sessions.iterrows()
        if row["Session_Status"] == "ESTABLISHED"
    }
    expected = expect.ospf_pairs()
    assert expected, "policy.yml lists no OSPF sessions"
    missing = expected - established
    assert not missing, "OSPF sessions that should be up are not: " + ", ".join(
        sorted(" <-> ".join(sorted(p)) for p in missing)
    )
