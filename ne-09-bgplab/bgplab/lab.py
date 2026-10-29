"""Talk to the running containerlab BGP lab through `docker exec`."""

from __future__ import annotations

import json
import subprocess
import time

from .model import Path, best_path, parse_paths

PREFIX = "clab-bgp-"
NODES = ("cust", "isp1", "isp2", "rs", "content", "rogue")


def _run(args: list[str], timeout: int = 20) -> str:
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}: {r.stderr.strip()}")
    return r.stdout


def vtysh(node: str, command: str) -> str:
    return _run(["docker", "exec", PREFIX + node, "vtysh", "-c", command])


def shell(node: str, command: str) -> str:
    return _run(["docker", "exec", PREFIX + node, "sh", "-c", command])


def paths(node: str, prefix: str) -> list[Path]:
    out = vtysh(node, f"show bgp ipv4 unicast {prefix} json")
    return parse_paths(json.loads(out or "{}"))


def best(node: str, prefix: str) -> Path | None:
    return best_path(paths(node, prefix))


def set_link(node: str, iface: str, up: bool) -> None:
    shell(node, f"ip link set {iface} {'up' if up else 'down'}")


def wait_for(check, timeout: float = 90.0, every: float = 2.0):
    """Poll `check()` until it returns a truthy value; return it or raise."""
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = check()
        except Exception as e:  # daemons still starting
            last = e
        if last and not isinstance(last, Exception):
            return last
        time.sleep(every)
    raise TimeoutError(f"not converged after {timeout:.0f}s; last: {last!r}")


def established(node: str, peer: str) -> bool:
    peers = (
        json.loads(vtysh(node, "show bgp summary json"))
        .get("ipv4Unicast", {})
        .get("peers", {})
    )
    return peers.get(peer, {}).get("state") == "Established"


def rpki_connected(node: str) -> bool:
    return "(connected)" in vtysh(node, "show rpki cache-connection")


def ensure_rpki(node: str, cache: str = "172.20.40.100", port: int = 3323) -> None:
    """FRR 8.4's RTR client can miss a cache that was not listening yet; re-adding it
    makes it reconnect at once."""
    if rpki_connected(node):
        return
    spec = f"rpki cache {cache} {port} preference 1"
    _run(
        [
            "docker",
            "exec",
            PREFIX + node,
            "vtysh",
            "-c",
            "configure terminal",
            "-c",
            "rpki",
            "-c",
            f"no {spec}",
            "-c",
            spec,
        ]
    )
