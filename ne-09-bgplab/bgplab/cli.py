"""`bgplab explain <node> <prefix>` and `bgplab matrix`."""

from __future__ import annotations

import argparse

from . import lab
from .model import explain

MATRIX_PREFIXES = [
    "203.0.113.0/24",
    "203.0.113.66/32",
    "198.18.0.0/24",
    "198.51.100.0/24",
    "10.66.0.0/16",
]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="bgplab")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("explain", help="why is this path best on this router")
    e.add_argument("node", choices=lab.NODES)
    e.add_argument("prefix")
    sub.add_parser("matrix", help="best path per router for the key prefixes")
    a = ap.parse_args(argv)
    if a.cmd == "explain":
        print(explain(a.node, a.prefix, lab.paths(a.node, a.prefix)))
    else:
        for prefix in MATRIX_PREFIXES:
            print(f"== {prefix}")
            for n in ("cust", "isp1", "isp2", "rs"):
                b = lab.best(n, prefix)
                print(
                    f"  {n:5} "
                    + (
                        f"via {b.peer:8} [{b.aspath or 'local'}] lp={b.local_pref}"
                        if b
                        else "-"
                    )
                )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
