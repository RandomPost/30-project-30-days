"""VLSM planning: carve a parent block into the smallest subnets that fit."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .info import Network, usable_hosts


class PlanError(ValueError):
    """The request cannot be satisfied."""


@dataclass(frozen=True)
class Request:
    name: str
    hosts: int


@dataclass(frozen=True)
class Allocation:
    name: str
    hosts_needed: int
    network: Network
    usable: int

    @property
    def spare(self) -> int:
        return self.usable - self.hosts_needed


@dataclass(frozen=True)
class Plan:
    parent: Network
    allocations: list[Allocation]
    free: list[Network]

    @property
    def used_addresses(self) -> int:
        return sum(a.network.num_addresses for a in self.allocations)

    @property
    def utilisation(self) -> float:
        """Share of the parent block taken by allocated subnets."""
        return self.used_addresses / self.parent.num_addresses


def prefix_for_hosts(version: int, hosts: int, rfc3021: bool = False) -> int:
    """Longest prefix whose subnet still has at least `hosts` usable addresses.

    IPv4 needs room for network and broadcast, so 1 host needs a /30 (2 usable) unless
    `rfc3021` allows /31 for 2 hosts and /32 for 1. IPv6 reserves only the
    Subnet-Router anycast address.
    """
    if hosts < 1:
        raise PlanError("host count must be at least 1")
    bits = 32 if version == 4 else 128
    if version == 4:
        if rfc3021 and hosts == 1:
            return 32
        if rfc3021 and hosts == 2:
            return 31
        host_bits = max(2, (hosts + 1).bit_length())  # 2**b >= hosts + 2
    else:
        if rfc3021 and hosts == 1:
            return 128
        if rfc3021 and hosts == 2:
            return 127
        host_bits = max(1, hosts.bit_length())  # 2**b >= hosts + 1
    return bits - host_bits


def parse_requests(items: list[str]) -> list[Request]:
    """`NAME=HOSTS` or bare `HOSTS` (auto-named LAN1, LAN2 ... in input order)."""
    out: list[Request] = []
    for i, item in enumerate(items, start=1):
        name, sep, count = item.rpartition("=")
        text = count if sep else item
        try:
            hosts = int(text)
        except ValueError:
            raise PlanError(f"bad host count in {item!r}") from None
        if hosts < 1:
            raise PlanError(f"host count must be at least 1 in {item!r}")
        out.append(Request(name or f"LAN{i}", hosts))
    return out


def free_blocks(parent: Network, used: list[Network]) -> list[Network]:
    """Unallocated space as the minimal list of CIDR blocks, in address order."""
    if not used:
        return [parent]
    used = sorted(used, key=lambda n: int(n.network_address))
    free: list[Network] = []
    cursor = int(parent.network_address)
    end = int(parent.broadcast_address)
    addr = ipaddress.IPv4Address if parent.version == 4 else ipaddress.IPv6Address
    for net in used:
        start = int(net.network_address)
        if start > cursor:
            free.extend(
                ipaddress.summarize_address_range(addr(cursor), addr(start - 1))
            )
        cursor = int(net.broadcast_address) + 1
    if cursor <= end:
        free.extend(ipaddress.summarize_address_range(addr(cursor), addr(end)))
    return free


def plan(parent: Network, requests: list[Request], rfc3021: bool = False) -> Plan:
    """Allocate largest requirement first, each subnet aligned on its own size.

    Ties keep input order. Because blocks are handed out in descending size from the
    start of the parent, every block is naturally aligned and no space is wasted
    between them. Raises PlanError naming the first request that does not fit.
    """
    ordered = sorted(enumerate(requests), key=lambda p: (-p[1].hosts, p[0]))
    cursor = int(parent.network_address)
    end = int(parent.broadcast_address)
    addr = ipaddress.IPv4Address if parent.version == 4 else ipaddress.IPv6Address
    net_cls = ipaddress.IPv4Network if parent.version == 4 else ipaddress.IPv6Network
    allocations: list[Allocation] = []
    for _, req in ordered:
        prefix = prefix_for_hosts(parent.version, req.hosts, rfc3021)
        if prefix < parent.prefixlen:
            raise PlanError(
                f"{req.name}: {req.hosts} hosts need a /{prefix}, "
                f"larger than the parent {parent}"
            )
        size = 1 << ((32 if parent.version == 4 else 128) - prefix)
        start = -(-cursor // size) * size  # round up to alignment
        if start + size - 1 > end:
            left = end - cursor + 1
            raise PlanError(
                f"{req.name}: needs a /{prefix} ({size} addresses) but only {left} "
                f"remain in {parent}"
            )
        sub = net_cls((addr(start), prefix))
        allocations.append(Allocation(req.name, req.hosts, sub, usable_hosts(sub)))
        cursor = start + size
    free = free_blocks(parent, [a.network for a in allocations])
    return Plan(parent, allocations, free)
