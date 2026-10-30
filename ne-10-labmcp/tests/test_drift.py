from pathlib import Path

from labmcp import drift

FIX = Path(__file__).parent / "fixtures"
INTENDED = (FIX / "cust-intended.conf").read_text()
RUNNING = (
    FIX / "cust-running.conf"
).read_text()  # real `show running-config` from the lab


def test_real_running_config_has_no_drift():
    assert drift.diff(INTENDED, RUNNING) == []


def test_changed_local_pref_is_found_in_its_route_map():
    bad = RUNNING.replace("set local-preference 200", "set local-preference 50")
    out = drift.diff(INTENDED, bad)
    assert any(
        "ISP1-IN" in d and "set local-preference 200" in d and "not running" in d
        for d in out
    )
    assert any(
        "ISP1-IN" in d and "set local-preference 50" in d and "not intended" in d
        for d in out
    )
    assert len(out) == 2


def test_missing_stanza_is_reported():
    bad = RUNNING.replace(
        "route-map ISP2-OUT permit 10\n match ip address prefix-list CUST-PREFIX\n set as-path prepend 65100 65100\n",
        "",
    )
    assert any(
        "stanza missing" in d and "ISP2-OUT permit 10" in d
        for d in drift.diff(INTENDED, bad)
    )


def test_line_order_inside_a_stanza_is_ignored():
    a = "router bgp 1\n neighbor a\n neighbor b\n"
    b = "router bgp 1\n neighbor b\n neighbor a\n"
    assert drift.diff(a, b) == []


def test_comments_and_frr_headers_are_ignored():
    assert (
        drift.diff(
            "! x\nhostname a\nip route 1.1.1.0/24 Null0\n",
            "frr version 8.4\nhostname b\nip route 1.1.1.0/24 Null0\nend\n",
        )
        == []
    )
