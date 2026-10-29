import subprocess

import pytest

from bgplab import lab


def lab_running() -> bool:
    try:
        lab.vtysh("cust", "show bgp summary json")
        return True
    except Exception:
        return False


def pytest_collection_modifyitems(config, items):
    if lab_running():
        return
    skip = pytest.mark.skip(reason="BGP lab not running (make up)")
    for item in items:
        if "lab" in item.keywords:
            item.add_marker(skip)


def converged(expect):
    """expect: {(node, prefix): peer-name or None}. True when every best path matches."""

    def check():
        for (node, prefix), peer in expect.items():
            b = lab.best(node, prefix)
            if (b.peer if b else None) != peer:
                return False
        return True

    return check


@pytest.fixture(scope="session", autouse=False)
def up():
    for node in ("isp1", "isp2", "rs"):
        lab.ensure_rpki(node)
    lab.wait_for(
        lambda: lab.established("cust", "10.1.1.1")
        and lab.established("cust", "10.1.2.1")
        and lab.established("rs", "10.99.0.1")
        and lab.established("rs", "10.99.0.2")
    )
    lab.wait_for(
        lambda: lab.best("rs", "203.0.113.0/24") and lab.best("isp1", "198.18.0.0/24")
    )
    return True


@pytest.fixture
def link_down(up):
    """Take (node, iface) links down for a test; always bring them back and reconverge."""
    taken = []

    def down(node, iface):
        lab.set_link(node, iface, False)
        taken.append((node, iface))

    yield down
    for node, iface in taken:
        lab.set_link(node, iface, True)
    lab.wait_for(
        lambda: lab.established("cust", "10.1.1.1")
        and lab.established("cust", "10.1.2.1")
        and lab.established("isp1", "10.99.0.254")
        and lab.established("isp2", "10.99.0.254")
    )
    lab.wait_for(converged(NORMAL))


NORMAL = {
    ("cust", "198.18.0.0/24"): "isp1",
    ("cust", "198.51.100.0/24"): "isp1",
    ("cust", "198.51.101.0/24"): "isp1",
    ("rs", "203.0.113.0/24"): "isp1",
    ("isp1", "203.0.113.0/24"): "cust",
    ("isp2", "203.0.113.0/24"): "cust",
}
