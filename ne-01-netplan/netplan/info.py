"""Describe a single network. Pure functions, no I/O."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network

Network = IPv4Network | IPv6Network


@dataclass(frozen=True)
class NetworkInfo:
    cidr: str
    version: int
    network: str
    prefix: int
    netmask: str
    wildcard: str | None  # IPv6 has no wildcard mask
    broadcast: str | None  # IPv6 has no broadcast
    first_usable: str
    last_usable: str
    total_addresses: int
    usable_hosts: int
    kind: str  # "normal", "point-to-point (RFC 3021)", "host route", ...
    input_had_host_bits: bool


def parse_network(text: str) -> Network:
    """Parse a CIDR, accepting host bits (`192.168.1.5/24` -> 192.168.1.0/24)."""
    try:
        return ipaddress.ip_network(text.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid network {text!r}: {exc}") from None


def usable_hosts(net: Network) -> int:
    """Number of assignable host addresses, computed without iterating."""
    size = net.num_addresses
    if net.version == 4:
        if net.prefixlen >= 31:  # /31 point-to-point (RFC 3021) and /32 host route
            return size
        return size - 2  # network and broadcast
    if net.prefixlen >= 127:  # /127 (RFC 6164) and /128
        return size
    return size - 1  # Subnet-Router anycast address


def usable_range(net: Network) -> tuple[str, str]:
    first = int(net.network_address)
    last = int(net.broadcast_address)
    if net.version == 4 and net.prefixlen < 31:
        first, last = first + 1, last - 1
    elif net.version == 6 and net.prefixlen < 127:
        first += 1
    addr = ipaddress.IPv4Address if net.version == 4 else ipaddress.IPv6Address
    return str(addr(first)), str(addr(last))


def kind_of(net: Network) -> str:
    if net.version == 4:
        if net.prefixlen == 32:
            return "host route (single address)"
        if net.prefixlen == 31:
            return "point-to-point link (RFC 3021, no network/broadcast)"
        if net.prefixlen == 0:
            return "default route (whole IPv4 space)"
    else:
        if net.prefixlen == 128:
            return "host route (single address)"
        if net.prefixlen == 127:
            return "point-to-point link (RFC 6164)"
        if net.prefixlen == 64:
            return "standard LAN prefix (SLAAC needs /64)"
    return "normal"


def describe(text: str) -> NetworkInfo:
    net = parse_network(text)
    has_host_bits = False
    try:
        ipaddress.ip_network(text.strip(), strict=True)
    except ValueError:
        has_host_bits = True
    first, last = usable_range(net)
    v4 = net.version == 4
    return NetworkInfo(
        cidr=str(net),
        version=net.version,
        network=str(net.network_address),
        prefix=net.prefixlen,
        netmask=str(net.netmask),
        wildcard=str(net.hostmask) if v4 else None,
        broadcast=str(net.broadcast_address) if v4 and net.prefixlen < 31 else None,
        first_usable=first,
        last_usable=last,
        total_addresses=net.num_addresses,
        usable_hosts=usable_hosts(net),
        kind=kind_of(net),
        input_had_host_bits=has_host_bits,
    )
