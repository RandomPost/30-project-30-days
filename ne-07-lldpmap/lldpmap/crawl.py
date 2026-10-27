"""Breadth-first crawl from a seed device."""

from __future__ import annotations

from collections import deque
from typing import Callable, Optional

from lldpmap import parsers
from lldpmap.collect import CollectError, Collector
from lldpmap.models import Neighbor
from lldpmap.topology import Device, Link, Topology


def crawl(
    seed_host: str,
    seed_vendor: str,
    collector: Collector,
    max_depth: int = 3,
    resolve: Optional[Callable[[str], str]] = None,
    default_vendor: str = "frr",
) -> Topology:
    """Walk the network over LLDP/CDP.

    A neighbour is logged in to at the management address it advertises, or at
    resolve(name) when it advertises none. Each device is visited once, whatever the
    number of links to it. Devices more than `max_depth` hops from the seed are
    recorded (we know they exist) but not logged in to."""
    topo = Topology(seed=seed_host)
    # queue of (address, vendor, depth, name we expect to find there)
    pending: deque[tuple[str, str, int, str]] = deque(
        [(seed_host, seed_vendor, 0, seed_host)]
    )
    seen_hosts: set[str] = {seed_host}
    expanded: set[str] = set()

    while pending:
        host, vendor, depth, expect = pending.popleft()
        try:
            name, neighbors = collector.collect(host, vendor)
        except CollectError as exc:
            dev = topo.devices.setdefault(expect, Device(expect, vendor, host))
            dev.host, dev.note = host, f"unreachable: {exc}"
            continue
        if name in expanded:  # reached again by another address
            continue
        expanded.add(name)
        dev = topo.devices.get(name) or Device(name=name)
        dev.vendor, dev.host, dev.crawled, dev.note = vendor, host, True, None
        topo.devices[name] = dev

        for n in neighbors:
            topo.links.add(Link.of(name, n.local_port, n.remote_name, n.remote_port))
            nvendor = parsers.guess_vendor(n.remote_desc, default_vendor)
            if n.remote_name not in topo.devices:
                topo.devices[n.remote_name] = Device(name=n.remote_name, vendor=nvendor)
            if n.remote_name in expanded:
                continue
            target = _address(n, resolve)
            if depth + 1 > max_depth:
                _mark(topo, n.remote_name, "beyond depth limit")
            elif target is None:
                _mark(topo, n.remote_name, "no management address and no resolver")
            elif target not in seen_hosts:
                seen_hosts.add(target)
                pending.append((target, nvendor, depth + 1, n.remote_name))
    return topo


def _address(n: Neighbor, resolve: Optional[Callable[[str], str]]) -> Optional[str]:
    if n.remote_ip:
        return n.remote_ip
    return resolve(n.remote_name) if resolve else None


def _mark(topo: Topology, name: str, note: str) -> None:
    dev = topo.devices[name]
    if not dev.crawled and dev.note is None:
        dev.note = note
