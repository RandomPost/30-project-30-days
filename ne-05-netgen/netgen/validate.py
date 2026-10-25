"""Whole-inventory checks that a per-field schema cannot express."""

from __future__ import annotations

import ipaddress
from collections import defaultdict

from netgen.models import Device, Inventory, Interface, Site


def _addresses(site: Site):
    for dev in site.devices:
        if dev.loopback:
            yield dev, "loopback", dev.loopback
        for itf in dev.interfaces:
            if itf.ip:
                yield dev, itf.name, itf.ip


def check_duplicate_names(inv: Inventory) -> list[str]:
    errors = []
    seen_sites: set[str] = set()
    seen_devs: dict[str, str] = {}
    for site in inv.sites:
        if site.name in seen_sites:
            errors.append(f"duplicate site name {site.name!r}")
        seen_sites.add(site.name)
        for dev in site.devices:
            if dev.name in seen_devs:
                errors.append(
                    f"duplicate device name {dev.name!r} "
                    f"(sites {seen_devs[dev.name]!r} and {site.name!r})"
                )
            seen_devs[dev.name] = site.name
    return errors


def check_duplicate_ips(inv: Inventory) -> list[str]:
    owners: dict[str, list[str]] = defaultdict(list)
    for site in inv.sites:
        for dev, ifname, ip in _addresses(site):
            host = str(ipaddress.IPv4Interface(ip).ip)
            owners[host].append(f"{dev.name} {ifname}")
    errors = [
        f"duplicate IP {host} on {', '.join(who)}"
        for host, who in sorted(owners.items())
        if len(who) > 1
    ]
    for site in inv.sites:
        for dev in site.devices:
            nets: dict[str, str] = {}
            for itf in dev.interfaces:
                if not itf.ip or itf.shutdown:
                    continue
                net = str(ipaddress.IPv4Interface(itf.ip).network)
                if net in nets:
                    errors.append(
                        f"{dev.name}: {itf.name} and {nets[net]} are both in {net}"
                    )
                nets[net] = itf.name
    return errors


def check_vlans(site: Site) -> list[str]:
    errors = []
    ids: dict[int, str] = {}
    names: dict[str, int] = {}
    for v in site.vlans:
        if v.id in ids:
            errors.append(f"{site.name}: VLAN {v.id} defined twice")
        if v.name in names:
            errors.append(
                f"{site.name}: VLAN name {v.name!r} used by {names[v.name]} and {v.id}"
            )
        ids[v.id] = v.name
        names[v.name] = v.id
    for dev in site.devices:
        for itf in dev.interfaces:
            used = ([itf.vlan] if itf.vlan else []) + itf.trunk_vlans
            for vid in used:
                if vid not in ids:
                    errors.append(
                        f"{site.name}: {dev.name} {itf.name} uses VLAN {vid}, "
                        "which the site does not define"
                    )
    return errors


def _find(site: Site, end: str) -> tuple[Device | None, Interface | None]:
    dev_name, if_name = end.split(":")
    dev = next((d for d in site.devices if d.name == dev_name), None)
    itf = next((i for i in dev.interfaces if i.name == if_name), None) if dev else None
    return dev, itf


def check_links(site: Site) -> list[str]:
    errors = []
    used: dict[str, str] = {}
    for link in site.links:
        label = f"{site.name}: link {link.a} <-> {link.b}"
        ends = []
        for end in (link.a, link.b):
            dev, itf = _find(site, end)
            if dev is None:
                errors.append(f"{label}: unknown device in {end!r}")
            elif itf is None:
                errors.append(f"{label}: {end!r} is not a defined interface")
            if end in used:
                errors.append(f"{label}: {end!r} is already used by {used[end]}")
            used[end] = label
            ends.append(itf)
        a, b = ends
        if a is None or b is None:
            continue
        if a.mode != b.mode:
            errors.append(f"{label}: mode mismatch ({a.mode} vs {b.mode})")
        elif a.mode == "trunk" and a.trunk_vlans != b.trunk_vlans:
            errors.append(
                f"{label}: trunk VLAN mismatch ({a.trunk_vlans} vs {b.trunk_vlans})"
            )
        elif a.mode == "access" and a.vlan != b.vlan:
            errors.append(f"{label}: access VLAN mismatch ({a.vlan} vs {b.vlan})")
        elif a.mode == "routed" and a.ip and b.ip:
            ia, ib = ipaddress.IPv4Interface(a.ip), ipaddress.IPv4Interface(b.ip)
            if ia.network != ib.network:
                errors.append(
                    f"{label}: subnet mismatch ({ia.network} vs {ib.network})"
                )
    return errors


def check_ospf(site: Site) -> list[str]:
    return [
        f"{site.name}: {dev.name} runs OSPF on {itf.name} but has no loopback (router-id)"
        for dev in site.devices
        if not dev.loopback
        for itf in dev.interfaces
        if itf.ospf_area is not None
    ]


def validate(inv: Inventory) -> list[str]:
    """Return every problem found; an empty list means the inventory is consistent."""
    errors = check_duplicate_names(inv) + check_duplicate_ips(inv)
    for site in inv.sites:
        errors += check_vlans(site) + check_links(site) + check_ospf(site)
    return errors
