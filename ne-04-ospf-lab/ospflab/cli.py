"""ospflab command line: verify | show | break | restore | failover."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time

from . import checks, lab
from .topology import HOSTS, LINK_ENDS, LINKS, LOOPBACKS, ROUTERS, container

PREFIX = "192.168.3.0/24"  # the prefix r1 reaches over the r1-r3 link, used by the demo


def run_checks() -> list[checks.Check]:
    results = []
    for node in (*ROUTERS, *HOSTS):
        up = lab.is_running(node)
        results.append(checks.Check(f"{node}: container running", up, container(node)))
    if not all(c.ok for c in results):
        return results
    for r in ROUTERS:
        results.append(
            checks.check_neighbors(r, lab.vtysh_json(r, "show ip ospf neighbor json"))
        )
    for r in ROUTERS:
        results.append(checks.check_routes(r, lab.vtysh_json(r, "show ip route json")))
    pings = [
        ("h1", HOSTS["h2"], "h1 -> h2 (LAN to LAN)"),
        ("h2", HOSTS["h1"], "h2 -> h1 (LAN to LAN)"),
    ]
    pings += [("h1", ip, f"h1 -> {r} loopback") for r, ip in LOOPBACKS.items()]
    pings += [("h2", ip, f"h2 -> {r} loopback") for r, ip in LOOPBACKS.items()]
    for src, dst, name in pings:
        ok, out = lab.ping(src, dst)
        sent, got = checks.parse_ping(out)
        results.append(checks.Check(f"ping {name} {dst}", ok, f"{got}/{sent} replies"))
    return results


def cmd_verify(a: argparse.Namespace) -> int:
    deadline = time.time() + a.wait
    while True:
        try:
            results = run_checks()
        except lab.LabError as exc:
            results = [checks.Check("lab reachable", False, str(exc))]
        failed = [c for c in results if not c.ok]
        if not failed or time.time() >= deadline:
            break
        print(
            f"waiting for OSPF to converge ({len(failed)} checks failing)...",
            flush=True,
        )
        time.sleep(3)
    for c in results:
        print(
            f"{'PASS' if c.ok else 'FAIL'}  {c.name}"
            + (f"  [{c.detail}]" if c.detail else "")
        )
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


def cmd_show(_a: argparse.Namespace) -> int:
    for r in ROUTERS:
        print(f"=== {r}: show ip ospf neighbor / show ip route ospf")
        print(lab.vtysh(r, "show ip ospf neighbor"))
        print(lab.vtysh(r, "show ip route ospf"))
    return 0


def _set_link(link: str, state: str) -> None:
    if link not in LINK_ENDS:
        raise ValueError(f"unknown link {link!r}; choose from {', '.join(LINK_ENDS)}")
    router, ifname = LINK_ENDS[link]
    p = lab.run(router, "ip", "link", "set", ifname, state)
    if p.returncode != 0:
        raise lab.LabError(
            p.stderr.strip() or f"could not set {router}:{ifname} {state}"
        )
    print(f"{link}: {router}:{ifname} {state}")


def cmd_break(a: argparse.Namespace) -> int:
    _set_link(a.link, "down")
    return 0


def cmd_restore(a: argparse.Namespace) -> int:
    _set_link(a.link, "up")
    return 0


def _r1_next_hops() -> list[str]:
    return checks.next_hops(
        lab.vtysh_json("r1", f"show ip route {PREFIX} json"), PREFIX
    )


def cmd_failover(a: argparse.Namespace) -> int:
    """Ping h1 -> h2 every 0.2 s, break r1-r3 mid-stream, report the outage, restore."""
    interval, total = 0.2, a.seconds
    count = int(total / interval)
    before = _r1_next_hops()
    print(f"before: r1 reaches {PREFIX} via {', '.join(before) or 'nothing'}")
    ping = subprocess.Popen(
        [
            "docker",
            "exec",
            container("h1"),
            "ping",
            "-c",
            str(count),
            "-i",
            str(interval),
            HOSTS["h2"],
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(a.break_at)
    t_break = time.time()
    _set_link(a.link, "down")
    during, t_conv = [], None
    while time.time() - t_break < 15:
        during = _r1_next_hops()
        if during and during != before:
            t_conv = time.time() - t_break
            break
        time.sleep(0.05)
    if t_conv is None:
        print("route never changed: no alternative path was found")
    else:
        print(
            f"after:  r1 reaches {PREFIX} via {', '.join(during)} (route changed {t_conv:.2f}s after the break)"
        )
    time.sleep(max(0.0, a.restore_at - (time.time() - t_break) - a.break_at))
    _set_link(a.link, "up")
    out, _ = ping.communicate(timeout=total + 30)
    sent, got = checks.parse_ping(out)
    lost, outage = checks.outage_from_sequences(
        checks.replied_sequences(out), sent, interval
    )
    print(
        f"ping h1 -> h2: {got}/{sent} replies, {lost} lost = about {outage:.1f}s without connectivity"
    )
    time.sleep(6)
    final = _r1_next_hops()
    print(f"restored: r1 reaches {PREFIX} via {', '.join(final)}")
    ok = t_conv is not None and got > 0 and final == before
    print("FAILOVER " + ("DEMONSTRATED" if ok else "NOT DEMONSTRATED"))
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ospflab", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser(
        "verify", help="check adjacencies, routing tables and end-to-end ping"
    )
    v.add_argument(
        "--wait", type=float, default=0, help="keep retrying for this many seconds"
    )
    v.set_defaults(fn=cmd_verify)
    sub.add_parser(
        "show", help="print OSPF neighbours and routes on every router"
    ).set_defaults(fn=cmd_show)
    for name, fn, helptext in (
        ("break", cmd_break, "shut one end of a link"),
        ("restore", cmd_restore, "bring it back"),
    ):
        s = sub.add_parser(name, help=helptext)
        s.add_argument("link", nargs="?", default="r1-r3", choices=sorted(LINK_ENDS))
        s.set_defaults(fn=fn)
    f = sub.add_parser(
        "failover", help="break a link during a ping and measure the outage"
    )
    f.add_argument("link", nargs="?", default="r1-r3", choices=sorted(LINK_ENDS))
    f.add_argument(
        "--seconds", type=float, default=16.0, help="length of the ping stream"
    )
    f.add_argument("--break-at", type=float, default=3.0)
    f.add_argument("--restore-at", type=float, default=9.0)
    f.set_defaults(fn=cmd_failover)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except (ValueError, lab.LabError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
