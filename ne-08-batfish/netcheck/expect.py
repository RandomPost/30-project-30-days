"""What the network is supposed to look like, derived from the source of truth, plus
the one helper that asks Batfish to trace a flow."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path

import yaml

from netgen.models import Inventory

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "network" / "policy.yml"
MGMT_RANGE = "10.255.0.0/16"  # router and switch loopbacks
SUCCESS = ("ACCEPTED", "DELIVERED_TO_SUBNET", "EXITS_NETWORK")


def ospf_pairs(policy_path: Path = DEFAULT_POLICY) -> set[frozenset[str]]:
    """Device pairs that must have an established OSPF session, from policy.yml."""
    doc = yaml.safe_load(Path(policy_path).read_text()) or {}
    return {frozenset(pair) for pair in doc.get("ospf_sessions", [])}


def vlan_subnets(inv: Inventory, vlan_name: str, site: str | None = None):
    """[(site, subnet, switch)] for every VLAN called `vlan_name`: the subnet of its
    SVI and the device that owns it."""
    found = []
    for s in inv.sites:
        if site and s.name != site:
            continue
        ids = {v.id for v in s.vlans if v.name == vlan_name}
        for dev in s.devices:
            for itf in dev.interfaces:
                if itf.mode == "svi" and itf.vlan in ids:
                    net = str(ipaddress.IPv4Interface(itf.ip).network)
                    found.append((s.name, net, dev.name))
    return found


def host_in(subnet: str, offset: int = 50) -> str:
    return str(ipaddress.ip_network(subnet).network_address + offset)


def router_loopback(inv: Inventory, site: str) -> str:
    for s in inv.sites:
        if s.name == site:
            for dev in s.devices:
                if dev.role == "router" and dev.loopback:
                    return str(ipaddress.IPv4Interface(dev.loopback).ip)
    raise KeyError(f"no router with a loopback in site {site}")


@dataclass
class TraceResult:
    success: bool
    detail: str


def trace(bf, switch: str, subnet: str, src: str, dst: str) -> TraceResult:
    """Send one ICMP packet from `src` into `switch` on the interface that owns
    `subnet`, and report what Batfish says happens to it."""
    from pybatfish.datamodel import HeaderConstraints

    props = bf.q.interfaceProperties(nodes=switch).answer().frame()
    ifaces = [
        row["Interface"].interface
        for _, row in props.iterrows()
        if str(row["Primary_Network"]) == subnet
    ]
    if not ifaces:
        raise LookupError(f"{switch} has no interface in {subnet}")
    frame = (
        bf.q.traceroute(
            startLocation=f"@enter({switch}[{ifaces[0]}])",
            headers=HeaderConstraints(srcIps=src, dstIps=dst, ipProtocols=["ICMP"]),
        )
        .answer()
        .frame()
    )
    trace_ = frame.iloc[0]["Traces"][0]
    lines = [
        f"flow {src} -> {dst} entering {switch}[{ifaces[0]}]: {trace_.disposition}"
    ]
    for hop in trace_.hops:
        lines.append(f"  hop {hop.node}")
        lines += [f"    {step.action}: {step.detail}" for step in hop.steps]
    return TraceResult(trace_.disposition in SUCCESS, "\n".join(lines))
