from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from lldpmap import diff as difflib
from lldpmap import graph, topology
from lldpmap.collect import Collector, NetmikoCollector
from lldpmap.crawl import crawl
from lldpmap.parsers import PARSERS

USER_VAR, PASSWORD_VAR = "LLDPMAP_USER", "LLDPMAP_PASSWORD"


def _credentials() -> tuple[str, str]:
    user, password = os.environ.get(USER_VAR), os.environ.get(PASSWORD_VAR)
    missing = [v for v, x in ((USER_VAR, user), (PASSWORD_VAR, password)) if not x]
    if missing:
        raise SystemExit(f"error: set {' and '.join(missing)} in the environment")
    return user, password


def cmd_crawl(a: argparse.Namespace, collector: Collector | None = None) -> int:
    collector = collector or NetmikoCollector(*_credentials())
    resolve = (
        (lambda name: a.name_template.format(name=name)) if a.name_template else None
    )
    topo = crawl(a.seed, a.vendor, collector, a.depth, resolve, a.default_vendor)
    topology.save(topo, a.output)
    crawled = sum(d.crawled for d in topo.devices.values())
    print(
        f"{len(topo.devices)} devices ({crawled} crawled), {len(topo.links)} links "
        f"-> {a.output}"
    )
    for d in sorted(topo.devices.values(), key=lambda d: d.name):
        if not d.crawled:
            print(f"  not crawled: {d.name} ({d.note})")
    if a.html:
        graph.render(topo, a.html)
        print(f"graph -> {a.html}")
    return 0


def cmd_diff(a: argparse.Namespace) -> int:
    old, new = topology.load(a.old), topology.load(a.new)
    delta = difflib.compare(old, new)
    print(delta.report(old, new))
    if a.html:
        graph.render(new, a.html, previous=old)
        print(f"graph -> {a.html}")
    return 1 if delta.changed else 0


def cmd_render(a: argparse.Namespace) -> int:
    graph.render(topology.load(a.run), a.output)
    print(f"graph -> {a.output}")
    return 0


def main(argv: list[str] | None = None, collector: Collector | None = None) -> int:
    p = argparse.ArgumentParser(prog="lldpmap", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("crawl", help="crawl from a seed device and save the topology")
    c.add_argument("seed", help="address or hostname of the seed device")
    c.add_argument("--vendor", choices=sorted(PARSERS), default="frr")
    c.add_argument(
        "--default-vendor",
        choices=sorted(PARSERS),
        default="frr",
        help="vendor assumed for neighbours whose description is unrecognised",
    )
    c.add_argument("--depth", type=int, default=3, help="max hops from the seed")
    c.add_argument(
        "--name-template",
        help="login address for neighbours that advertise "
        "none, e.g. 'clab-ospf-{name}'",
    )
    c.add_argument("-o", "--output", type=Path, required=True, help="topology JSON")
    c.add_argument("--html", type=Path, help="also write the interactive graph")
    c.set_defaults(fn=lambda a: cmd_crawl(a, collector))

    d = sub.add_parser(
        "diff", help="compare two saved topologies (exit 1 if different)"
    )
    d.add_argument("old", type=Path)
    d.add_argument("new", type=Path)
    d.add_argument("--html", type=Path, help="graph of NEW with changes highlighted")
    d.set_defaults(fn=cmd_diff)

    r = sub.add_parser("render", help="draw a saved topology")
    r.add_argument("run", type=Path)
    r.add_argument("-o", "--output", type=Path, required=True)
    r.set_defaults(fn=cmd_render)

    a = p.parse_args(argv)
    return a.fn(a)
