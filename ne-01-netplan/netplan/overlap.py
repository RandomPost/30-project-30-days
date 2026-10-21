"""Find overlapping subnets. CIDR blocks either nest or are disjoint."""

from __future__ import annotations

from dataclasses import dataclass

from .info import Network, parse_network


@dataclass(frozen=True)
class Overlap:
    outer: Network
    inner: Network
    outer_label: str
    inner_label: str

    @property
    def kind(self) -> str:
        return "duplicate" if self.outer == self.inner else "contains"


def parse_labelled(items: list[str]) -> list[tuple[str, Network]]:
    """`NAME=CIDR` or bare CIDR; the label defaults to the text as given."""
    out = []
    for item in items:
        name, sep, cidr = item.rpartition("=")
        net = parse_network(cidr if sep else item)
        out.append((name if sep else item.strip(), net))
    return out


def find_overlaps(subnets: list[tuple[str, Network]]) -> list[Overlap]:
    """Every overlapping pair (IPv4 and IPv6 are never compared with each other).

    Sorted by address then size, a sweep keeps a stack of enclosing blocks, so the
    cost is proportional to the number of overlaps rather than all pairs.
    """
    found: list[Overlap] = []
    for version in (4, 6):
        group = [(label, n) for label, n in subnets if n.version == version]
        group.sort(key=lambda p: (int(p[1].network_address), p[1].prefixlen))
        open_blocks: list[tuple[str, Network]] = []
        for label, net in group:
            start = int(net.network_address)
            open_blocks = [
                (lab, b) for lab, b in open_blocks if int(b.broadcast_address) >= start
            ]
            for outer_label, outer in open_blocks:
                found.append(Overlap(outer, net, outer_label, label))
            open_blocks.append((label, net))
    return found
