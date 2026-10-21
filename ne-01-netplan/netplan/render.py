"""Rich tables and JSON for the three commands."""

from __future__ import annotations

import os
from dataclasses import asdict

from rich.console import Console
from rich.table import Table

from .info import NetworkInfo, usable_range
from .overlap import Overlap
from .vlsm import Plan


def info_table(info: NetworkInfo) -> Table:
    t = Table(title=info.cidr, show_header=False, title_justify="left")
    t.add_column("Field", style="bold")
    t.add_column("Value")
    rows = [
        ("Network", info.network),
        ("Prefix", f"/{info.prefix}"),
        ("Netmask", info.netmask),
        ("Wildcard", info.wildcard or "n/a (IPv6)"),
        ("Broadcast", info.broadcast or "n/a"),
        ("First usable", info.first_usable),
        ("Last usable", info.last_usable),
        ("Total addresses", f"{info.total_addresses:,}"),
        ("Usable hosts", f"{info.usable_hosts:,}"),
        ("Type", info.kind),
    ]
    for key, value in rows:
        t.add_row(key, value)
    return t


def info_json(info: NetworkInfo) -> dict:
    return asdict(info)


def plan_table(plan: Plan) -> Table:
    t = Table(title=f"VLSM plan for {plan.parent}", title_justify="left")
    t.add_column("Name", min_width=5)
    t.add_column("Needed", justify="right", min_width=6)
    t.add_column("Subnet", no_wrap=True)
    t.add_column("Mask", no_wrap=True)
    t.add_column("Usable range", no_wrap=True)
    t.add_column("Usable", justify="right", min_width=6)
    t.add_column("Spare", justify="right", min_width=5)
    for a in plan.allocations:
        first, last = usable_range(a.network)
        t.add_row(
            a.name,
            str(a.hosts_needed),
            str(a.network),
            str(a.network.netmask),
            f"{first} - {last}",
            str(a.usable),
            str(a.spare),
        )
    return t


def free_table(plan: Plan) -> Table:
    t = Table(title="Unallocated space", title_justify="left")
    t.add_column("Block")
    t.add_column("Addresses", justify="right")
    for block in plan.free:
        t.add_row(str(block), f"{block.num_addresses:,}")
    return t


def plan_json(plan: Plan) -> dict:
    return {
        "parent": str(plan.parent),
        "utilisation": round(plan.utilisation, 4),
        "allocations": [
            {
                "name": a.name,
                "hosts_needed": a.hosts_needed,
                "subnet": str(a.network),
                "usable": a.usable,
                "spare": a.spare,
            }
            for a in plan.allocations
        ],
        "free": [str(b) for b in plan.free],
    }


def _labelled(label: str, net: object) -> str:
    return str(net) if label == str(net) else f"{label} ({net})"


def overlap_table(overlaps: list[Overlap]) -> Table:
    t = Table(title="Overlaps", title_justify="left")
    for col in ("Kind", "Outer", "Inner"):
        t.add_column(col)
    for o in overlaps:
        t.add_row(
            o.kind,
            _labelled(o.outer_label, o.outer),
            _labelled(o.inner_label, o.inner),
        )
    return t


def overlap_json(overlaps: list[Overlap]) -> list[dict]:
    return [
        {
            "kind": o.kind,
            "outer": str(o.outer),
            "outer_label": o.outer_label,
            "inner": str(o.inner),
            "inner_label": o.inner_label,
        }
        for o in overlaps
    ]


def make_console() -> Console:
    """A console that does not squash tables to 80 columns when output is piped."""
    console = Console()
    if not console.is_terminal and "COLUMNS" not in os.environ:
        console = Console(width=120)
    return console
