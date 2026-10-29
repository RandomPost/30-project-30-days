"""Unit tests on real `vtysh ... json` output captured from the lab (tests/fixtures)."""

import json
from pathlib import Path as P

from bgplab.model import best_path, explain, parse_paths

FIX = P(__file__).parent / "fixtures"


def load(name):
    return parse_paths(json.loads((FIX / f"{name}.json").read_text()))


def test_customer_prefers_isp1_by_local_pref():
    ps = load("cust-198.18.0.0")
    b = best_path(ps)
    assert (b.peer, b.local_pref, b.reason) == ("isp1", 200, "Local Pref")
    assert len(ps) == 2


def test_route_server_picks_shorter_path_because_of_prepend():
    ps = load("rs-203.0.113.0")
    b = best_path(ps)
    assert b.peer == "isp1" and b.reason == "AS Path"
    loser = next(p for p in ps if not p.best)
    assert loser.aspath == "65002 65100 65100 65100"


def test_isp_localpref_beats_prepend_for_customer_route():
    b = best_path(load("isp2-203.0.113.0"))
    assert b.peer == "cust" and b.local_pref == 300


def test_rtbh_route_carries_blackhole_and_noexport():
    b = best_path(load("isp1-rtbh"))
    assert b.nexthop == "192.0.2.1"
    assert set(b.communities) == {"blackhole", "noExport"}
    assert b.rpki == "invalid"  # /32 is longer than the ROA max length: RTBH is exempt


def test_filtered_route_is_absent():
    assert load("isp1-leak") == []


def test_explain_names_deciding_step():
    text = explain("rs", "203.0.113.0/24", load("rs-203.0.113.0"))
    assert "shortest AS path" in text and "AS path length 4 > 2" in text


def test_explain_no_route():
    assert "no route" in explain("isp1", "10.66.0.0/16", [])
