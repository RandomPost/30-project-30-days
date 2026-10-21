"""netplan command line: info | vlsm | overlap."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import render
from .info import describe, parse_network
from .overlap import find_overlaps, parse_labelled
from .vlsm import PlanError, parse_requests, plan


def _read_items(args_items: list[str], file: str | None) -> list[str]:
    items = list(args_items)
    if file:
        for line in Path(file).read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                items.append(line)
    return items


def cmd_info(a: argparse.Namespace) -> int:
    console = render.make_console()
    infos = [describe(c) for c in a.cidr]
    if a.json:
        print(json.dumps([render.info_json(i) for i in infos], indent=2))
        return 0
    for info in infos:
        console.print(render.info_table(info))
        if info.input_had_host_bits:
            console.print(
                "[yellow]note: host bits were set in the input and ignored[/]"
            )
    return 0


def cmd_vlsm(a: argparse.Namespace) -> int:
    requests = parse_requests(_read_items(a.requests, a.file))
    if not requests:
        raise PlanError("give at least one host requirement (NAME=HOSTS or HOSTS)")
    result = plan(parse_network(a.parent), requests, rfc3021=a.rfc3021)
    if a.json:
        print(json.dumps(render.plan_json(result), indent=2))
        return 0
    console = render.make_console()
    console.print(render.plan_table(result))
    console.print(f"Utilisation: {result.utilisation:.1%} of {result.parent}")
    if result.free:
        console.print(render.free_table(result))
    return 0


def cmd_overlap(a: argparse.Namespace) -> int:
    subnets = parse_labelled(_read_items(a.subnets, a.file))
    overlaps = find_overlaps(subnets)
    if a.json:
        print(json.dumps(render.overlap_json(overlaps), indent=2))
    elif overlaps:
        render.make_console().print(render.overlap_table(overlaps))
    else:
        print(f"no overlaps among {len(subnets)} subnets")
    return 1 if overlaps else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netplan", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    i = sub.add_parser("info", help="network, broadcast, usable range, mask, wildcard")
    i.add_argument("cidr", nargs="+", help="IPv4 or IPv6 CIDR, e.g. 192.168.1.0/24")
    i.add_argument("--json", action="store_true")
    i.set_defaults(fn=cmd_info)

    v = sub.add_parser("vlsm", help="split a parent block by host requirements")
    v.add_argument("parent", help="parent block, e.g. 192.168.10.0/24")
    v.add_argument("requests", nargs="*", help="NAME=HOSTS or HOSTS, e.g. Sales=100")
    v.add_argument("-f", "--file", help="file with one NAME=HOSTS per line")
    v.add_argument(
        "--rfc3021",
        action="store_true",
        help="use /31 for 2 hosts and /32 for 1 host (IPv6: /127, /128)",
    )
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_vlsm)

    o = sub.add_parser("overlap", help="report overlapping subnets (exit 1 if any)")
    o.add_argument("subnets", nargs="*", help="CIDR or NAME=CIDR")
    o.add_argument("-f", "--file", help="file with one subnet per line, # comments")
    o.add_argument("--json", action="store_true")
    o.set_defaults(fn=cmd_overlap)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ValueError, OSError) as exc:  # PlanError is a ValueError
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
