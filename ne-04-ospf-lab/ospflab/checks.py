"""Pure checks over FRR's JSON output. No Docker here, so they are unit-testable."""

from __future__ import annotations

from dataclasses import dataclass

from .topology import ROUTERS, expected_prefixes


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str = ""


def full_neighbors(neighbor_json: dict) -> dict[str, str]:
    """router-id -> interface name for neighbours in state Full."""
    out = {}
    for rid, entries in (neighbor_json.get("neighbors") or {}).items():
        for e in entries if isinstance(entries, list) else [entries]:
            state = e.get("nbrState") or e.get("state") or ""
            if state.startswith("Full"):
                out[rid] = (
                    e.get("ifaceName") or e.get("ifaceName".lower()) or "?"
                ).split(":")[0]
    return out


def check_neighbors(router: str, neighbor_json: dict, want: int = 2) -> Check:
    full = full_neighbors(neighbor_json)
    ok = len(full) == want
    shown = ", ".join(f"{rid} via {ifn}" for rid, ifn in sorted(full.items())) or "none"
    return Check(f"{router}: {want} OSPF neighbours Full", ok, shown)


def installed_ospf_routes(route_json: dict) -> dict[str, list[str]]:
    """prefix -> next-hop addresses for OSPF routes that made it into the kernel."""
    out = {}
    for prefix, routes in route_json.items():
        for r in routes:
            if r.get("protocol") != "ospf" or not (
                r.get("installed") or r.get("selected")
            ):
                continue
            hops = [
                n.get("ip", "connected")
                for n in r.get("nexthops", [])
                if n.get("active", True) and n.get("fib", True)
            ]
            if hops:
                out[prefix] = hops
    return out


def check_routes(router: str, route_json: dict) -> Check:
    have = installed_ospf_routes(route_json)
    want = expected_prefixes(router)
    missing = [p for p in want if p not in have]
    detail = ", ".join(f"{p} via {','.join(have[p])}" for p in want if p in have)
    if missing:
        detail = f"missing {', '.join(missing)}" + (
            f" (have {detail})" if detail else ""
        )
    return Check(
        f"{router}: OSPF routes to {len(want)} remote prefixes", not missing, detail
    )


def next_hops(route_json: dict, prefix: str) -> list[str]:
    """Next-hop addresses currently installed for `prefix` (any protocol), sorted."""
    hops = []
    for r in route_json.get(prefix, []):
        if not (r.get("installed") or r.get("selected")):
            continue
        hops += [
            n.get("ip", "connected")
            for n in r.get("nexthops", [])
            if n.get("fib", True)
        ]
    return sorted(hops)


def parse_ping(output: str) -> tuple[int, int]:
    """(sent, received) from busybox or iputils ping summary output."""
    import re

    m = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", output)
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def replied_sequences(output: str) -> list[int]:
    """ICMP sequence numbers that got a reply, from `ping` output."""
    import re

    return [int(x) for x in re.findall(r"seq=(\d+)", output)]


def outage_from_sequences(
    seqs: list[int], sent: int, interval: float
) -> tuple[int, float]:
    """(lost probes, outage seconds) given replies and a fixed probe interval."""
    lost = sent - len(set(seqs))
    return lost, lost * interval


def all_routers() -> tuple[str, ...]:
    return ROUTERS
