"""What the lab is supposed to look like. Must match ospf-lab.clab.yml and configs/."""

from __future__ import annotations

LAB = "ospf"
ROUTERS = ("r1", "r2", "r3")
HOSTS = {"h1": "192.168.1.10", "h2": "192.168.3.10"}

LOOPBACKS = {"r1": "10.255.0.1", "r2": "10.255.0.2", "r3": "10.255.0.3"}
LANS = {"r1": "192.168.1.0/24", "r3": "192.168.3.0/24"}  # router -> attached LAN

# Router interface -> (peer router, peer address): the triangle's three links.
LINKS = {
    "r1": {"eth1": ("r2", "10.0.12.2"), "eth2": ("r3", "10.0.13.2")},
    "r2": {"eth1": ("r1", "10.0.12.1"), "eth2": ("r3", "10.0.23.2")},
    "r3": {"eth1": ("r2", "10.0.23.1"), "eth2": ("r1", "10.0.13.1")},
}
# Names accepted by `ospflab break` -> (router, interface) of one end of the link.
LINK_ENDS = {"r1-r3": ("r1", "eth2"), "r1-r2": ("r1", "eth1"), "r2-r3": ("r2", "eth2")}


def container(node: str) -> str:
    """containerlab's container name for a node."""
    return f"clab-{LAB}-{node}"


def expected_prefixes(router: str) -> list[str]:
    """OSPF-learned prefixes this router must have: every other router's loopback and
    every LAN it is not directly attached to."""
    prefixes = [f"{ip}/32" for r, ip in LOOPBACKS.items() if r != router]
    prefixes += [lan for r, lan in LANS.items() if r != router]
    # r2 has no LAN, so it learns both; r1 and r3 learn the other one.
    return sorted(prefixes)
